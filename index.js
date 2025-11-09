require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const cors = require('cors');

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret';
const BCRYPT_SALT_ROUNDS = parseInt(process.env.BCRYPT_SALT_ROUNDS || '12', 10);

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

const app = express();

// Middlewares
app.use(helmet());
app.use(express.json());

// CORS : adapte l'origine à ton frontend
app.use(cors({
  origin: process.env.CORS_ORIGIN || true, // en dev true, en prod mettre l'URL précise
  credentials: true
}));

// Rate limiter pour endpoints sensibles
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
});
app.use(limiter);

// --- Helper functions ---
async function findUserByEmail(email) {
  const res = await pool.query('SELECT id, username, email, password_hash, created_at FROM users WHERE email = $1', [email]);
  return res.rows[0];
}

// --- Routes ---
// Healthcheck
app.get('/', (req, res) => res.json({ ok: true }));

// REGISTER
app.post('/register',
  // validation
  body('email').isEmail().withMessage('Email invalide'),
  body('password').isLength({ min: 8 }).withMessage('Mot de passe >= 8 caractères'),
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ error: errors.array().map(e => e.msg).join(', ') });

      const { email, password, username } = req.body;

      // Vérifier si email existe déjà
      const existing = await findUserByEmail(email);
      if (existing) return res.status(409).json({ error: 'Email déjà utilisé' });

      const password_hash = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);

      const result = await pool.query(
        'INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id, email, username, created_at',
        [username || null, email, password_hash]
      );

      const user = result.rows[0];
      return res.status(201).json({ user: { id: user.id, email: user.email, username: user.username } });
    } catch (err) {
      console.error(err);
      return res.status(500).json({ error: 'Erreur serveur' });
    }
  }
);

// LOGIN
app.post('/login',
  body('email').isEmail().withMessage('Email invalide'),
  body('password').exists().withMessage('Mot de passe requis'),
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ error: errors.array().map(e => e.msg).join(', ') });

      const { email, password } = req.body;
      const user = await findUserByEmail(email);
      if (!user) return res.status(401).json({ error: 'Identifiants invalides' });

      const ok = await bcrypt.compare(password, user.password_hash);
      if (!ok) return res.status(401).json({ error: 'Identifiants invalides' });

      // Création du token
      const token = jwt.sign({ sub: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });

      return res.json({ token });
    } catch (err) {
      console.error(err);
      return res.status(500).json({ error: 'Erreur serveur' });
    }
  }
);

// Middleware d'authentification
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Token manquant' });
  const token = auth.split(' ')[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.sub;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Token invalide' });
  }
}

// Endpoint protégé d'exemple
app.get('/me', authMiddleware, async (req, res) => {
  try {
    const r = await pool.query('SELECT id, username, email, created_at FROM users WHERE id = $1', [req.userId]);
    if (r.rowCount === 0) return res.status(404).json({ error: 'Utilisateur introuvable' });
    res.json({ user: r.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Démarrage
app.listen(PORT, () => {
  console.log(`API listening on port ${PORT}`);
});

