require('dotenv').config();
const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const Database = require('better-sqlite3');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const SSO_SECRET = process.env.SSO_SECRET;
const GRADE_DB_PATH = process.env.GRADE_DB_PATH;
const SSO_COOKIE = 'benross_sso';

if (!JWT_SECRET || !SSO_SECRET || !GRADE_DB_PATH) {
  console.error('JWT_SECRET, SSO_SECRET et GRADE_DB_PATH sont requis dans .env');
  process.exit(1);
}

// Base des comptes : partagée avec grade.benross.ch (table users uniquement).
const usersDb = new Database(GRADE_DB_PATH);
usersDb.pragma('journal_mode = WAL');

// Base propre à Reveo : les alertes de chaque utilisateur.
const db = new Database(path.join(__dirname, 'reveo.db'));
db.pragma('journal_mode = WAL');
db.exec(`CREATE TABLE IF NOT EXISTS alerts (
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  type TEXT NOT NULL,
  date TEXT NOT NULL,
  time TEXT NOT NULL,
  repeat TEXT NOT NULL,
  vib TEXT NOT NULL,
  dur INTEGER NOT NULL,
  place TEXT NOT NULL DEFAULT '',
  note TEXT NOT NULL DEFAULT '',
  on_flag INTEGER NOT NULL DEFAULT 1,
  travel INTEGER,
  parent TEXT
)`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_alerts_user ON alerts(user_id)`);

app.use(express.json({ limit: '200kb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

function setSsoCookie(res, user) {
  const t = jwt.sign({ id: user.id, username: user.username }, SSO_SECRET, { expiresIn: '30d' });
  res.cookie(SSO_COOKIE, t, { domain: '.benross.ch', httpOnly: true, secure: true, sameSite: 'lax', path: '/', maxAge: 30 * 24 * 3600 * 1000 });
}
function clearSsoCookie(res) {
  res.clearCookie(SSO_COOKIE, { domain: '.benross.ch', path: '/' });
}
function issueToken(user) {
  return jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
}
function auth(req, res, next) {
  const h = req.headers.authorization;
  if (!h || !h.startsWith('Bearer ')) return res.status(401).json({ error: 'Non authentifié' });
  try {
    req.user = jwt.verify(h.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Token invalide ou expiré' });
  }
}

/* ── Comptes (table partagée avec grade.benross.ch) ─────────────────────── */

app.post('/api/register', (req, res) => {
  const { username, email, password, full_name = '' } = req.body || {};
  if (!username?.trim() || !email?.trim() || !password) {
    return res.status(400).json({ error: 'Nom, email et mot de passe requis' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Mot de passe trop court (6 caractères minimum)' });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
    return res.status(400).json({ error: 'Adresse email invalide' });
  }
  try {
    const hash = bcrypt.hashSync(password, 10);
    const info = usersDb.prepare(
      'INSERT INTO users (username, email, password_hash, full_name) VALUES (?, ?, ?, ?)'
    ).run(username.trim(), email.trim().toLowerCase(), hash, full_name.trim());
    const user = { id: info.lastInsertRowid, username: username.trim() };
    setSsoCookie(res, user);
    res.status(201).json({ token: issueToken(user), username: user.username });
  } catch (e) {
    if (String(e.message).includes('UNIQUE')) {
      return res.status(409).json({ error: "Nom d'utilisateur ou email déjà utilisé" });
    }
    console.error(e);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username?.trim() || !password) return res.status(400).json({ error: 'Identifiants requis' });
  const user = usersDb.prepare('SELECT * FROM users WHERE username = ?').get(username.trim());
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'Identifiants incorrects' });
  }
  if (user.banned) return res.status(403).json({ error: 'Compte banni' });
  usersDb.prepare('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?').run(user.id);
  setSsoCookie(res, user);
  res.json({ token: issueToken(user), username: user.username });
});

app.post('/api/logout', (req, res) => {
  clearSsoCookie(res);
  res.json({ ok: true });
});

app.get('/api/whoami', (req, res) => {
  const h = req.headers.authorization;
  if (h && h.startsWith('Bearer ')) {
    try {
      const p = jwt.verify(h.slice(7), JWT_SECRET);
      return res.json({ username: p.username });
    } catch {
      /* tombe sur la vérification du cookie partagé ci-dessous */
    }
  }
  const c = req.cookies?.[SSO_COOKIE];
  if (c) {
    try {
      const p = jwt.verify(c, SSO_SECRET);
      const user = usersDb.prepare('SELECT id, username, banned FROM users WHERE id = ?').get(p.id);
      if (user && !user.banned) {
        return res.json({ username: user.username, token: issueToken(user) });
      }
    } catch {
      /* pas de session partagée valide */
    }
  }
  res.status(401).json({ error: 'Non authentifié' });
});

/* ── Profil (compte partagé avec grade.benross.ch) ───────────────────────── */

app.get('/api/profile', auth, (req, res) => {
  const u = usersDb.prepare(
    'SELECT id, username, email, full_name, created_at, last_login, avatar FROM users WHERE id = ?'
  ).get(req.user.id);
  if (!u) return res.status(404).json({ error: 'Utilisateur introuvable' });
  const nb_alerts = (db.prepare('SELECT COUNT(*) AS n FROM alerts WHERE user_id = ?').get(req.user.id) || { n: 0 }).n;
  const nb_active = (db.prepare('SELECT COUNT(*) AS n FROM alerts WHERE user_id = ? AND on_flag = 1').get(req.user.id) || { n: 0 }).n;
  res.json({ ...u, stats: { nb_alerts, nb_active } });
});

app.patch('/api/profile', auth, (req, res) => {
  const { full_name, email } = req.body || {};
  if (full_name !== undefined) {
    if (typeof full_name !== 'string' || full_name.length > 100) {
      return res.status(400).json({ error: 'Nom trop long (max 100 caractères)' });
    }
    usersDb.prepare('UPDATE users SET full_name = ? WHERE id = ?').run(full_name.trim(), req.user.id);
  }
  if (email !== undefined) {
    const e = String(email).trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e)) return res.status(400).json({ error: 'Adresse email invalide' });
    const existing = usersDb.prepare('SELECT id FROM users WHERE email = ? AND id != ?').get(e, req.user.id);
    if (existing) return res.status(409).json({ error: 'Email déjà utilisé par un autre compte' });
    usersDb.prepare('UPDATE users SET email = ? WHERE id = ?').run(e, req.user.id);
  }
  res.json({ ok: true });
});

app.patch('/api/profile/avatar', auth, (req, res) => {
  const { avatar } = req.body || {};
  if (avatar === null || avatar === undefined) {
    usersDb.prepare('UPDATE users SET avatar = NULL WHERE id = ?').run(req.user.id);
    return res.json({ ok: true });
  }
  if (typeof avatar !== 'string' || !avatar.startsWith('data:image/') || avatar.length > 200000) {
    return res.status(400).json({ error: 'Image invalide ou trop volumineuse' });
  }
  usersDb.prepare('UPDATE users SET avatar = ? WHERE id = ?').run(avatar, req.user.id);
  res.json({ ok: true });
});

app.post('/api/change-password', auth, (req, res) => {
  const { current_password, new_password } = req.body || {};
  if (!new_password || new_password.length < 6) {
    return res.status(400).json({ error: 'Le mot de passe doit contenir au moins 6 caractères' });
  }
  const u = usersDb.prepare('SELECT password_hash, must_change_password FROM users WHERE id = ?').get(req.user.id);
  if (!u) return res.status(404).json({ error: 'Utilisateur introuvable' });
  if (!u.must_change_password) {
    if (!current_password) return res.status(400).json({ error: 'Le mot de passe actuel est requis.' });
    if (!bcrypt.compareSync(current_password, u.password_hash)) {
      return res.status(403).json({ error: 'Mot de passe actuel incorrect.' });
    }
  }
  const hash = bcrypt.hashSync(new_password, 10);
  usersDb.prepare('UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?').run(hash, req.user.id);
  res.json({ ok: true });
});

/* ── Alertes (propres à Reveo, scoping par utilisateur) ─────────────────── */

function rowToAlert(r) {
  const a = {
    id: r.id, name: r.name, type: r.type, date: r.date, time: r.time,
    repeat: r.repeat, vib: r.vib, dur: r.dur, place: r.place, note: r.note,
    on: !!r.on_flag,
  };
  if (r.travel != null) a.travel = r.travel;
  if (r.parent != null) a.parent = r.parent;
  return a;
}

app.get('/api/alerts', auth, (req, res) => {
  const rows = db.prepare('SELECT * FROM alerts WHERE user_id = ?').all(req.user.id);
  res.json({ alerts: rows.map(rowToAlert) });
});

app.put('/api/alerts', auth, (req, res) => {
  const alerts = Array.isArray(req.body?.alerts) ? req.body.alerts : [];
  if (alerts.length > 500) return res.status(400).json({ error: 'Trop d\'alertes' });
  for (const a of alerts) {
    if (!a || typeof a.id !== 'string' || typeof a.name !== 'string' || typeof a.type !== 'string'
      || typeof a.date !== 'string' || typeof a.time !== 'string' || typeof a.repeat !== 'string'
      || typeof a.vib !== 'string' || typeof a.dur !== 'number') {
      return res.status(400).json({ error: 'Alerte invalide' });
    }
  }
  const tx = db.transaction((alerts) => {
    db.prepare('DELETE FROM alerts WHERE user_id = ?').run(req.user.id);
    const ins = db.prepare(`INSERT INTO alerts
      (id, user_id, name, type, date, time, repeat, vib, dur, place, note, on_flag, travel, parent)
      VALUES (@id, @user_id, @name, @type, @date, @time, @repeat, @vib, @dur, @place, @note, @on_flag, @travel, @parent)`);
    for (const a of alerts) {
      ins.run({
        id: a.id, user_id: req.user.id, name: a.name, type: a.type, date: a.date, time: a.time,
        repeat: a.repeat, vib: a.vib, dur: a.dur, place: a.place || '', note: a.note || '',
        on_flag: a.on ? 1 : 0, travel: a.travel ?? null, parent: a.parent ?? null,
      });
    }
  });
  tx(alerts);
  res.json({ ok: true });
});

app.listen(PORT, () => console.log(`Reveo server listening on port ${PORT}`));
