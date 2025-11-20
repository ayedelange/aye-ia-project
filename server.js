require('dotenv').config();
const express = require('express');
const cors = require('cors');
const Groq = require('groq-sdk');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const multer = require('multer');
const pdfParse = require('pdf-parse');
const mammoth = require('mammoth');

const app = express();
const port = process.env.PORT || 3000;

// Configuration Upload (Augmentation de la limite à 10MB)
const upload = multer({ 
    storage: multer.memoryStorage(),
    limits: { fileSize: 10 * 1024 * 1024 } 
});

const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });

// Base de Données
const db = new sqlite3.Database('./aye_ia.db');
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT, student_level TEXT, xp INTEGER DEFAULT 0, level INTEGER DEFAULT 1, isAdmin INTEGER DEFAULT 0, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`);
    db.run(`CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, role TEXT, content TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES users(id))`);
    const hash = bcrypt.hashSync("admin123", 8);
    db.run(`INSERT OR IGNORE INTO users (username, password, student_level, isAdmin) VALUES (?, ?, 'Directeur', 1)`, ["admin", hash]);
});

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// --- CERVEAU MIS À JOUR (IMAGE LINKS & DOCS) ---
const SYSTEM_PROMPT = `
Tu es 'Aye IA', un assistant pédagogique expert (Côte d'Ivoire).

RÈGLES CRUCIALES :
1. LECTURE DE DOCS : Si on t'envoie un texte issu d'un fichier, analyse-le, résume-le ou corrige-le selon la demande.
2. IMAGES & SCHÉMAS : Tu ne peux pas créer d'images pixels.
   - À la place, fournis un LIEN DE RECHERCHE GOOGLE IMAGES précis pour que l'élève puisse voir le schéma.
   - Format du lien : [Voir le Schéma (Clique ici)](https://www.google.com/search?tbm=isch&q=TERMES_DE_RECHERCHE)
   - Exemple : [Voir schéma câblage Arduino LED](https://www.google.com/search?tbm=isch&q=schema+cablage+arduino+led)
3. EXERCICES : Résous pas à pas. Utilise LaTeX ($E=mc^2$) pour les maths.
4. RÉSUMÉ : Si on te demande un résumé, fais une liste à puces des points clés.

Style : Bienveillant, clair, structuré.
`;

// --- ROUTES AUTH ---
app.post('/api/register', (req, res) => {
    const { username, password, studentLevel } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 8);
    db.run(`INSERT INTO users (username, password, student_level) VALUES (?, ?, ?)`, [username, hashedPassword, studentLevel], function(err) {
        if (err) return res.status(400).json({ error: "Pseudo pris." });
        res.json({ id: this.lastID, username, studentLevel, xp: 0, level: 1, isAdmin: 0 });
    });
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, user) => {
        if (err || !user) return res.status(400).json({ error: "Inconnu." });
        if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: "Erreur mot de passe." });
        res.json({ id: user.id, username: user.username, xp: user.xp, level: user.level, isAdmin: user.isAdmin, studentLevel: user.student_level });
    });
});

// --- ROUTE UPLOAD CORRIGÉE ---
app.post('/api/upload', upload.single('file'), async (req, res) => {
    const { userId, instruction } = req.body;
    const file = req.file;
    
    if (!file) return res.status(400).json({ error: "Aucun fichier reçu." });

    try {
        let textContent = "";
        
        // Extraction robuste
        if (file.mimetype === 'application/pdf') {
            const data = await pdfParse(file.buffer);
            textContent = data.text;
        } else if (file.mimetype.includes('word') || file.originalname.endsWith('.docx')) {
            const result = await mammoth.extractRawText({ buffer: file.buffer });
            textContent = result.value;
        } else {
            // Fichiers texte ou code
            textContent = file.buffer.toString('utf8');
        }

        // Vérification si texte vide (PDF scanné par exemple)
        if (!textContent || textContent.trim().length === 0) {
            return res.json({ reply: "⚠️ Je n'arrive pas à lire le texte de ce document. Si c'est un PDF scanné (image), je ne peux pas le lire. Essaie avec un document texte ou Word." });
        }

        // Limite de taille pour l'IA (environ 15000 caractères)
        const truncatedText = textContent.substring(0, 15000);
        
        const prompt = `CONTENU DU FICHIER "${file.originalname}" :\n\n${truncatedText}\n\n--- FIN DU FICHIER ---\n\nDEMANDE DE L'UTILISATEUR : ${instruction}`;

        const completion = await groq.chat.completions.create({
            messages: [
                { role: "system", content: SYSTEM_PROMPT },
                { role: "user", content: prompt }
            ],
            model: "llama-3.3-70b-versatile",
            temperature: 0.5
        });

        const reply = completion.choices[0]?.message?.content;

        if(userId) {
            db.run(`INSERT INTO messages (user_id, role, content) VALUES (?, 'user', ?)`, [userId, `[Fichier ${file.originalname}] ${instruction}`]);
            db.run(`INSERT INTO messages (user_id, role, content) VALUES (?, 'assistant', ?)`, [userId, reply]);
            db.run(`UPDATE users SET xp = xp + 30 WHERE id = ?`, [userId]);
        }

        res.json({ reply: reply });

    } catch (e) {
        console.error("Erreur Upload:", e);
        res.status(500).json({ error: "Erreur lors de l'analyse du fichier." });
    }
});

// --- ROUTE CHAT ---
app.post('/api/chat', async (req, res) => {
    const { message, history, userId } = req.body;
    try {
        if(userId) db.run(`INSERT INTO messages (user_id, role, content) VALUES (?, 'user', ?)`, [userId, message]);
        
        const completion = await groq.chat.completions.create({
            messages: [{ role: "system", content: SYSTEM_PROMPT }, ...(history || []), { role: "user", content: message }],
            model: "llama-3.3-70b-versatile",
            temperature: 0.7
        });
        
        const reply = completion.choices[0]?.message?.content;
        
        if(userId) {
            db.run(`INSERT INTO messages (user_id, role, content) VALUES (?, 'assistant', ?)`, [userId, reply]);
            db.run(`UPDATE users SET xp = xp + 10 WHERE id = ?`, [userId]);
            db.run(`UPDATE users SET level = 1 + (xp / 250) WHERE id = ?`, [userId]);
        }
        
        db.get(`SELECT xp, level FROM users WHERE id = ?`, [userId], (err, row) => {
            res.json({ reply: reply, xp: row ? row.xp : 0, level: row ? row.level : 1 });
        });
    } catch (e) { res.status(500).json({ reply: "Erreur connexion IA." }); }
});

app.get('/api/admin/users', (req, res) => {
    db.all(`SELECT * FROM users ORDER BY created_at DESC`, [], (err, rows) => res.json(rows));
});

app.listen(port, () => { console.log(`🚀 Aye IA V6 (Fix Upload & Images) sur http://localhost:${port}`); });