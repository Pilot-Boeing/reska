/**
 * logger.js — журнал действий + тревожные события.
 * Все payload шифруются (AES-256-GCM) — защита от чтения и подделки (MAC).
 */
const { db } = require('./db');
const { encryptString, decryptString } = require('./encryption');
const { getClientIp, clientUa, uaHash, ipHash } = require('./security');

function log(action, opts = {}) {
  try {
    const { userId = null, req = null, meta = {}, level = 'info' } = opts;
    const ip = req ? getClientIp(req) : '';
    const ua = req ? clientUa(req) : '';
    const payload = encryptString(JSON.stringify(meta));
    db.prepare(
      'INSERT INTO logs (user_id, action, level, ip, ua_hash, payload) VALUES (?, ?, ?, ?, ?, ?)'
    ).run(userId, String(action), String(level), ip, ua ? uaHash(req) : '', payload);
  } catch (e) {
    console.error('logger error:', e.message);
  }
}

/** Тревожное событие. */
function alert(action, opts = {}) {
  log(action, { ...opts, level: 'alert' });
  try {
    const row = db
      .prepare('SELECT COUNT(*) AS n FROM logs WHERE action = ? AND level = "alert" AND created_at > datetime("now", "-1 day")')
      .get(String(action));
    if (row.n <= 10) console.warn(`[ALERT] ${action} — тревожное событие`);
  } catch (e) {}
}

function recentLogs(limit = 50) {
  const rows = db
    .prepare('SELECT * FROM logs ORDER BY id DESC LIMIT ?')
    .all(limit)
    .map((r) => {
      let meta = {};
      try { meta = JSON.parse(decryptString(r.payload)); } catch (e) {}
      return { ...r, payload: undefined, meta };
    });
  return rows;
}

module.exports = { log, alert, recentLogs };
