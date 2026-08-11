const crypto = require('crypto');
const { db } = require('./db');
const {
  hmacSign,
  hmacVerify,
  randomUid,
  ipHash,
  uaHash
} = require('./security');
const { alert } = require('./logger');

const SESSION_TTL = 30 * 24 * 3600 * 1000;   // 30 дней
const REFRESH_TTL = 60 * 24 * 3600 * 1000;   // 60 дней
const DEVICE_TTL = 365 * 24 * 3600 * 1000;

function secure(opts, req) {
  return { ...opts, secure: !!req.secure };
}

function parseCookies(req) {
  const out = {};
  const raw = req.headers.cookie || '';
  for (const part of raw.split(';')) {
    const i = part.indexOf('=');
    if (i > -1) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

function bindings(req) {
  return { ip: ipHash(req), ua: uaHash(req) };
}

function getDeviceId(req, res) {
  let d = parseCookies(req).reska_device;
  if (!d || !/^[a-f0-9]{24}$/.test(d)) {
    d = crypto.randomBytes(12).toString('hex');
    res.cookie('reska_device', d, secure({ httpOnly: true, sameSite: 'lax', maxAge: DEVICE_TTL }, req));
  }
  return d;
}

/* ---------- создание сессии (access + refresh + csrf) ---------- */
function createSession(req, res, userId) {
  const deviceId = getDeviceId(req, res);
  const b = bindings(req);
  const access = crypto.randomBytes(32).toString('hex');
  const refresh = crypto.randomBytes(32).toString('hex');

  db.prepare(
    'INSERT INTO sessions (token, user_id, device_id, ip_hash, ua_hash, expires_at) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(access, userId, deviceId, b.ip, b.ua, new Date(Date.now() + SESSION_TTL).toISOString());
  db.prepare(
    'INSERT INTO refresh_tokens (token, user_id, device_id, ip_hash, ua_hash, expires_at) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(refresh, userId, deviceId, b.ip, b.ua, new Date(Date.now() + REFRESH_TTL).toISOString());

  const csrf = hmacSign(access, 'csrf');
  res.cookie('reska_session', access, secure({ httpOnly: true, sameSite: 'lax', maxAge: SESSION_TTL }, req));
  res.cookie('reska_refresh', refresh, secure({ httpOnly: true, sameSite: 'lax', maxAge: REFRESH_TTL }, req));
  res.cookie('reska_csrf', csrf, secure({ httpOnly: false, sameSite: 'lax', maxAge: SESSION_TTL }, req));
  return { access, refresh, csrf, deviceId };
}

function revokeDevice(userId, deviceId) {
  db.prepare('DELETE FROM sessions WHERE user_id = ? AND device_id = ?').run(userId, deviceId);
  db.prepare('DELETE FROM refresh_tokens WHERE user_id = ? AND device_id = ?').run(userId, deviceId);
}

function getSessionUser(req) {
  const token = parseCookies(req).reska_session;
  if (!token) return null;
  const row = db
    .prepare(
      `SELECT s.expires_at AS _exp, s.ip_hash AS _ip, s.ua_hash AS _ua, s.device_id AS _dev, u.*
       FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?`
    )
    .get(token);
  if (!row) return null;
  if (row._exp && new Date(row._exp) < new Date()) {
    db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
    return null;
  }
  const b = bindings(req);
  if (row._ip && row._ip !== b.ip) {
    db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
    alert('session_ip_change', { req, meta: { userId: row.id } });
    return null;
  }
  if (row._ua && row._ua !== b.ua) {
    db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
    alert('session_ua_change', { req, meta: { userId: row.id } });
    return null;
  }
  return row;
}

/* ---------- ротация refresh-токена (получение новой access-сессии) ---------- */
function refreshAccess(req, res) {
  const rt = parseCookies(req).reska_refresh;
  if (!rt) return null;
  const row = db.prepare('SELECT * FROM refresh_tokens WHERE token = ?').get(rt);
  if (!row) return null;
  if (row.replaced_by) {
    revokeDevice(row.user_id, row.device_id);
    alert('refresh_reuse_detected', { req, meta: { userId: row.user_id } });
    return null;
  }
  if (new Date(row.expires_at) < new Date()) {
    db.prepare('DELETE FROM refresh_tokens WHERE token = ?').run(rt);
    return null;
  }
  const b = bindings(req);
  if (row.ip_hash !== b.ip || row.ua_hash !== b.ua) {
    revokeDevice(row.user_id, row.device_id);
    alert('refresh_binding_mismatch', { req, meta: { userId: row.user_id } });
    return null;
  }
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(row.user_id);
  if (!user) return null;

  const access = crypto.randomBytes(32).toString('hex');
  const newRefresh = crypto.randomBytes(32).toString('hex');
  db.prepare('UPDATE refresh_tokens SET replaced_by = ? WHERE token = ?').run(newRefresh, rt);
  db.prepare('DELETE FROM refresh_tokens WHERE token = ?').run(rt);
  db.prepare(
    'INSERT INTO refresh_tokens (token, user_id, device_id, ip_hash, ua_hash, expires_at) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(newRefresh, row.user_id, row.device_id, b.ip, b.ua, new Date(Date.now() + REFRESH_TTL).toISOString());
  db.prepare(
    'INSERT INTO sessions (token, user_id, device_id, ip_hash, ua_hash, expires_at) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(access, row.user_id, row.device_id, b.ip, b.ua, new Date(Date.now() + SESSION_TTL).toISOString());

  const csrf = hmacSign(access, 'csrf');
  res.cookie('reska_session', access, secure({ httpOnly: true, sameSite: 'lax', maxAge: SESSION_TTL }, req));
  res.cookie('reska_refresh', newRefresh, secure({ httpOnly: true, sameSite: 'lax', maxAge: REFRESH_TTL }, req));
  res.cookie('reska_csrf', csrf, secure({ httpOnly: false, sameSite: 'lax', maxAge: SESSION_TTL }, req));
  return user;
}

function destroySession(req, res) {
  const access = parseCookies(req).reska_session;
  if (access) db.prepare('DELETE FROM sessions WHERE token = ?').run(access);
  const rt = parseCookies(req).reska_refresh;
  if (rt) db.prepare('DELETE FROM refresh_tokens WHERE token = ?').run(rt);
  for (const n of ['reska_session', 'reska_refresh', 'reska_csrf']) res.clearCookie(n);
}

/* ---------- middleware ---------- */
function auth(req, res, next) {
  let user = getSessionUser(req);
  if (!user) user = refreshAccess(req, res);
  if (!user) return res.status(401).json({ error: 'Требуется авторизация' });
  req.user = user;
  req.userId = user.id;
  next();
}

function optionalAuth(req, res, next) {
  req.user = getSessionUser(req) || null;
  req.userId = req.user ? req.user.id : null;
  next();
}

function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Доступно только администратору' });
  }
  next();
}

function csrfProtect(req, res, next) {
  if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') return next();
  const session = parseCookies(req).reska_session;
  if (!session) return next();
  ensureCsrfCookie(req, res);
  const cookie = parseCookies(req).reska_csrf;
  const header = req.headers['x-csrf-token'];
  if (!cookie) {
    return res.status(403).json({ error: 'Проверка не пройдена', csrfFresh: true });
  }
  if (!header || cookie !== header || !hmacVerify(session, 'csrf', cookie)) {
    return res.status(403).json({ error: 'CSRF: проверка не пройдена' });
  }
  next();
}

/**
 * Автопочинка: если у браузера есть сессия, но нет CSRF-cookie
 * (например, сессия осталась от старой версии сервера) — выдаём его.
 */
function ensureCsrfCookie(req, res) {
  if (parseCookies(req).reska_csrf) return;
  const session = parseCookies(req).reska_session;
  if (!session) return;
  res.cookie('reska_csrf', hmacSign(session, 'csrf'), secure({ httpOnly: false, sameSite: 'lax', maxAge: SESSION_TTL }, req));
}

/* ---------- uid / id ---------- */
function uidOrId(param) {
  const s = String(param || '');
  if (/^\d+$/.test(s)) return { kind: 'id', value: Number(s) };
  return { kind: 'uid', value: s };
}

function findByIdOrUid(table, param) {
  const p = uidOrId(param);
  if (p.kind === 'id') return db.prepare(`SELECT * FROM ${table} WHERE id = ?`).get(p.value);
  return db.prepare(`SELECT * FROM ${table} WHERE uid = ?`).get(p.value);
}

/* ---------- публичные представления ---------- */
function publicUser(u) {
  if (!u) return null;
  return {
    id: u.id,
    uid: u.uid,
    username: u.username,
    name: u.name,
    bio: u.bio,
    status: u.status,
    avatar: u.avatar,
    role: u.role,
    e2ee_pub: u.e2ee_pub,
    e2ee_ver: u.e2ee_ver,
    created_at: u.created_at
  };
}

function now() {
  return new Date().toISOString();
}

function commentsFor(column, id) {
  const rows = db
    .prepare(
      `SELECT c.id, c.uid, c.text, c.parent_id, c.created_at, c.user_id,
              u.username, u.uid AS author_uid, u.name, u.avatar
       FROM comments c JOIN users u ON u.id = c.user_id
       WHERE c.${column} = ? ORDER BY c.created_at ASC`
    )
    .all(id);
  const byId = {};
  const roots = [];
  for (const r of rows) {
    r.comment = r.id;
    byId[r.id] = { ...r, replies: [] };
  }
  for (const r of rows) {
    const node = byId[r.id];
    if (r.parent_id && byId[r.parent_id]) byId[r.parent_id].replies.push(node);
    else roots.push(node);
  }
  return roots;
}

module.exports = {
  parseCookies,
  createSession,
  getSessionUser,
  refreshAccess,
  destroySession,
  revokeDevice,
  auth,
  optionalAuth,
  requireAdmin,
  csrfProtect,
  ensureCsrfCookie,
  uidOrId,
  findByIdOrUid,
  publicUser,
  now,
  commentsFor
};
