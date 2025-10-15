// server.js (example, simplified for clarity)
require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { body, validationResult } = require('express-validator');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const { Pool } = require('pg');

const app = express();
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// Security middlewares
app.use(helmet());
app.use(express.json());
app.use(cookieParser());

// CORS: restrict to your frontend origin
app.use(cors({
  origin: process.env.FRONTEND_ORIGIN, // e.g. https://your-site.com
  credentials: true
}));

// Rate limiter for auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  message: 'Too many requests, try again later.'
});

// Helper: generate JWTs
function signAccessToken(user) {
  return jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '15m' });
}
function signRefreshToken(user) {
  return jwt.sign({ id: user.id }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '7d' });
}

// Middleware: require authentication
function authenticate(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'Missing token' });
  const token = auth.split(' ')[1];
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.user = payload;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// Middleware: role check
function requireRole(...allowed) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).send('Not authenticated');
    if (!allowed.includes(req.user.role)) return res.status(403).send('Forbidden');
    next();
  };
}

/* ---------- Auth endpoints ---------- */

// Register (example - admin-only in production or invite flow)
app.post('/api/auth/register',
  authLimiter,
  body('username').isAlphanumeric().isLength({ min: 3, max: 30 }),
  body('password').isLength({ min: 8 }),
  async (req, res) => {
    const errors = validationResult(req); if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
    const { username, password, role = 'viewer' } = req.body;
    const hashed = await bcrypt.hash(password, 12);
    const result = await pool.query(
      'INSERT INTO users(username, password_hash, role) VALUES ($1,$2,$3) RETURNING id, username, role',
      [username, hashed, role]
    );
    res.json({ user: result.rows[0] });
  }
);

// Login
app.post('/api/auth/login', authLimiter,
  body('username').exists(),
  body('password').exists(),
  async (req,res) => {
    const { username, password } = req.body;
    const r = await pool.query('SELECT id, username, password_hash, role FROM users WHERE username=$1', [username]);
    const user = r.rows[0];
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    const accessToken = signAccessToken(user);
    const refreshToken = signRefreshToken(user);
    // store refresh token server-side (optional) - recommended to support revocation
    await pool.query('INSERT INTO refresh_tokens(token, user_id, expires_at) VALUES ($1,$2,$3)', [refreshToken, user.id, new Date(Date.now()+7*24*3600*1000)]);

    // Send refresh token in cookie (httpOnly) and access token in body
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 7*24*3600*1000
    });
    res.json({ accessToken, user: { id: user.id, username: user.username, role: user.role } });
  }
);

// Refresh endpoint
app.post('/api/auth/refresh', async (req,res) => {
  const token = req.cookies.refreshToken;
  if (!token) return res.status(401).send('No refresh token');
  try {
    const payload = jwt.verify(token, process.env.REFRESH_TOKEN_SECRET);
    // validate token exists in DB
    const db = await pool.query('SELECT * FROM refresh_tokens WHERE token=$1', [token]);
    if (!db.rows.length) return res.status(401).send('Invalid refresh token');
    const userRow = await pool.query('SELECT id, username, role FROM users WHERE id=$1', [payload.id]);
    const user = userRow.rows[0];
    const newAccess = signAccessToken(user);
    res.json({ accessToken: newAccess });
  } catch (e) {
    return res.status(401).send('Invalid refresh token');
  }
});

// Logout (revoke refresh token)
app.post('/api/auth/logout', authenticate, async (req,res) => {
  const token = req.cookies.refreshToken;
  if (token) {
    await pool.query('DELETE FROM refresh_tokens WHERE token=$1', [token]);
    res.clearCookie('refreshToken');
  }
  res.json({ ok:true });
});

/* ---------- Protected API (players example) ---------- */

app.get('/api/players', authenticate, async (req,res) => {
  const r = await pool.query('SELECT id, name, position, age, goals FROM players ORDER BY name');
  res.json(r.rows);
});

app.post('/api/players', authenticate, requireRole('admin','manager'),
  body('name').isLength({min:1}), body('position').isString(), body('age').isInt({min:0}), body('goals').isInt({min:0}),
  async (req,res) => {
    const errors = validationResult(req); if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
    const { name, position, age, goals } = req.body;
    const r = await pool.query('INSERT INTO players(name, position, age, goals) VALUES ($1,$2,$3,$4) RETURNING *', [name, position, age, goals]);
    res.json(r.rows[0]);
  }
);

app.delete('/api/players/:id', authenticate, requireRole('admin'), async (req,res) => {
  await pool.query('DELETE FROM players WHERE id=$1', [req.params.id]);
  res.json({ ok:true });
});

/* ---------- start ---------- */
const port = process.env.PORT || 4000;
app.listen(port, () => console.log('API running on', port));
