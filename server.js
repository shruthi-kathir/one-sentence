const path = require('path');
const crypto = require('crypto');
const express = require('express');
const Database = require('better-sqlite3');
const { OAuth2Client } = require('google-auth-library');

// ---------- config ----------
const PORT = process.env.PORT || 3000;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const TIMEZONE = process.env.TIMEZONE || 'Asia/Kolkata'; // decides when "a new day" starts
const DB_FILE = process.env.DB_FILE || path.join(__dirname, 'data.db');
const MAX_LEN = 200;
const SESSION_DAYS = 30;
const IS_PROD = process.env.NODE_ENV === 'production';

// Optional: only let certain people in. Comma separated, e.g. "a@gmail.com,b@gmail.com"
const ALLOWED_EMAILS = (process.env.ALLOWED_EMAILS || '')
  .split(',').map(s => s.trim().toLowerCase()).filter(Boolean);

// The owner: this Google account can open /admin and see who signed in and what they posted.
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || '').trim().toLowerCase();

if (!GOOGLE_CLIENT_ID) {
  console.error('Missing GOOGLE_CLIENT_ID. Copy .env.example to .env and fill it in.');
  process.exit(1);
}

// ---------- database ----------
const db = new Database(DB_FILE);
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,            -- Google account id ("sub")
    email TEXT NOT NULL,
    name TEXT NOT NULL,
    picture TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL REFERENCES users(id),
    day TEXT NOT NULL,              -- YYYY-MM-DD in TIMEZONE
    sentence TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (user_id, day)           -- this is what enforces one sentence per day
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    expires_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS logins (   -- one row every time someone signs in (UTC time)
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL REFERENCES users(id),
    at TEXT NOT NULL DEFAULT (datetime('now'))
  );
`);

const q = {
  upsertUser: db.prepare(`
    INSERT INTO users (id, email, name, picture) VALUES (@id, @email, @name, @picture)
    ON CONFLICT(id) DO UPDATE SET email = excluded.email, name = excluded.name, picture = excluded.picture`),
  getUser: db.prepare('SELECT id, email, name, picture FROM users WHERE id = ?'),
  newSession: db.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)'),
  getSession: db.prepare('SELECT user_id, expires_at FROM sessions WHERE token = ?'),
  delSession: db.prepare('DELETE FROM sessions WHERE token = ?'),
  purgeSessions: db.prepare('DELETE FROM sessions WHERE expires_at < ?'),
  addEntry: db.prepare('INSERT INTO entries (user_id, day, sentence) VALUES (?, ?, ?)'),
  addLogin: db.prepare('INSERT INTO logins (user_id) VALUES (?)'),
  adminUsers: db.prepare(`
    SELECT u.name, u.email, u.picture, u.created_at AS joined,
      (SELECT MAX(at) FROM logins l WHERE l.user_id = u.id) AS last_login,
      (SELECT COUNT(*) FROM logins l WHERE l.user_id = u.id) AS logins,
      (SELECT COUNT(*) FROM entries e WHERE e.user_id = u.id) AS entries
    FROM users u ORDER BY COALESCE(last_login, joined) DESC`),
  adminEntries: db.prepare(`
    SELECT e.day, e.sentence, e.created_at, u.name, u.email
    FROM entries e JOIN users u ON u.id = e.user_id
    ORDER BY e.id DESC LIMIT 2000`),
  entriesForDay: db.prepare(`
    SELECT e.user_id, e.sentence, e.created_at, u.name, u.picture
    FROM entries e JOIN users u ON u.id = e.user_id
    WHERE e.day = ? ORDER BY e.id ASC`),
};

// ---------- helpers ----------
function todayStr() {
  // en-CA formats as YYYY-MM-DD
  return new Date().toLocaleDateString('en-CA', { timeZone: TIMEZONE });
}

function parseCookies(header) {
  const out = {};
  (header || '').split(';').forEach(part => {
    const i = part.indexOf('=');
    if (i > -1) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  });
  return out;
}

function setSessionCookie(res, token, maxAgeMs) {
  const parts = [
    `sid=${encodeURIComponent(token)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${Math.floor(maxAgeMs / 1000)}`,
  ];
  if (IS_PROD) parts.push('Secure');
  res.setHeader('Set-Cookie', parts.join('; '));
}

function requireAuth(req, res, next) {
  const token = parseCookies(req.headers.cookie).sid;
  if (!token) return res.status(401).json({ error: 'Not signed in' });
  const s = q.getSession.get(token);
  if (!s || s.expires_at < Date.now()) {
    if (s) q.delSession.run(token);
    return res.status(401).json({ error: 'Session expired' });
  }
  req.user = q.getUser.get(s.user_id);
  req.token = token;
  next();
}

function isAdminUser(user) {
  return !!ADMIN_EMAIL && !!user && user.email.toLowerCase() === ADMIN_EMAIL;
}

function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (!isAdminUser(req.user)) return res.status(403).json({ error: 'Owner only' });
    next();
  });
}

// ---------- app ----------
const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);
const app = express();
if (IS_PROD) app.set('trust proxy', 1);
app.use(express.json({ limit: '10kb' }));

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/credits', (req, res) => res.sendFile(path.join(__dirname, 'credits.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'admin.html'))); // the data itself is owner-only (see /api/admin)

// The front end needs the client ID to draw the Google button.
app.get('/api/config', (req, res) => res.json({ clientId: GOOGLE_CLIENT_ID }));

// Who am I? (used on page load to decide: login page or dashboard)
app.get('/api/me', requireAuth, (req, res) => {
  const { name, email, picture } = req.user;
  res.json({ name, email, picture, isAdmin: isAdminUser(req.user) });
});

// Google sends the browser a signed token; we verify it here.
app.post('/api/login', async (req, res) => {
  try {
    const credential = req.body && req.body.credential;
    if (!credential) return res.status(400).json({ error: 'Missing credential' });

    const ticket = await googleClient.verifyIdToken({ idToken: credential, audience: GOOGLE_CLIENT_ID });
    const p = ticket.getPayload();
    if (!p.email || !p.email_verified) return res.status(403).json({ error: 'Email not verified' });
    if (ALLOWED_EMAILS.length && !ALLOWED_EMAILS.includes(p.email.toLowerCase())) {
      return res.status(403).json({ error: 'This email is not allowed' });
    }

    q.upsertUser.run({ id: p.sub, email: p.email, name: p.name || p.email, picture: p.picture || null });
    q.addLogin.run(p.sub);

    q.purgeSessions.run(Date.now());
    const token = crypto.randomBytes(32).toString('hex');
    const maxAge = SESSION_DAYS * 24 * 60 * 60 * 1000;
    q.newSession.run(token, p.sub, Date.now() + maxAge);
    setSessionCookie(res, token, maxAge);
    res.json({ ok: true });
  } catch (err) {
    console.error('Login failed:', err.message);
    res.status(401).json({ error: 'Google sign-in could not be verified' });
  }
});

app.post('/api/logout', requireAuth, (req, res) => {
  q.delSession.run(req.token);
  setSessionCookie(res, '', 0);
  res.json({ ok: true });
});

// Everyone's sentences for a given day (defaults to today).
app.get('/api/entries', requireAuth, (req, res) => {
  const today = todayStr();
  const day = req.query.day || today;
  if (!/^\d{4}-\d{2}-\d{2}$/.test(day) || day > today) {
    return res.status(400).json({ error: 'Invalid day' });
  }
  const entries = q.entriesForDay.all(day).map(e => ({
    name: e.name,
    picture: e.picture,
    sentence: e.sentence,
    time: e.created_at,
    mine: e.user_id === req.user.id,
  }));
  res.json({ day, today, entries });
});

// Add today's sentence. The UNIQUE(user_id, day) rule means a second try fails.
app.post('/api/entries', requireAuth, (req, res) => {
  let sentence = req.body && req.body.sentence;
  if (typeof sentence !== 'string') return res.status(400).json({ error: 'Write a sentence first' });
  sentence = sentence.replace(/\s+/g, ' ').trim();
  if (!sentence) return res.status(400).json({ error: 'Write a sentence first' });
  if (sentence.length > MAX_LEN) return res.status(400).json({ error: `Keep it under ${MAX_LEN} characters` });

  try {
    q.addEntry.run(req.user.id, todayStr(), sentence);
    res.json({ ok: true });
  } catch (err) {
    if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.status(409).json({ error: "You've already written your sentence for today" });
    }
    console.error(err);
    res.status(500).json({ error: 'Something went wrong' });
  }
});

// Owner-only: everyone who signed in, and every sentence with its time (times are UTC).
app.get('/api/admin/overview', requireAdmin, (req, res) => {
  res.json({
    users: q.adminUsers.all(),
    entries: q.adminEntries.all(),
    today: todayStr(),
  });
});

app.listen(PORT, () => console.log(`Running on http://localhost:${PORT} (day cutoff: ${TIMEZONE})`));
