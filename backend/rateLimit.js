/**
 * rateLimit.js — защита от DDoS (лимит запросов по IP) и брутфорса
 * (экспоненциальная задержка после неудачных входов).
 * In-memory, без внешних зависимостей.
 */
const { getClientIp } = require('./security');

/* =========================================================
   1. Окно-лимитер по IP (token bucket / fixed window)
   ========================================================= */
const windows = new Map();
setInterval(() => {
  const now = Date.now();
  for (const [key, w] of windows) {
    if (now - w.start > w.windowMs) windows.delete(key);
  }
}, 60 * 1000).unref();

function limiter({ windowMs = 60 * 1000, max = 120, name = 'general', message = 'Слишком много запросов' }) {
  return (req, res, next) => {
    const key = name + ':' + getClientIp(req);
    const now = Date.now();
    let w = windows.get(key);
    if (!w || now - w.start > windowMs) {
      w = { start: now, count: 0, windowMs };
      windows.set(key, w);
    }
    w.count++;
    if (w.count > max) {
      res.set('Retry-After', String(Math.ceil((w.start + windowMs - now) / 1000)));
      return res.status(429).json({ error: message });
    }
    next();
  };
}

/* =========================================================
   2. Брутфорс: счётчик попыток + экспоненциальная задержка
   ========================================================= */
const brute = new Map();
const DELAY_BASE = 5;   // секунд после 5-й попытки
const DELAY_CAP = 125;  // верхняя граница

function bruteKey(ip, username) {
  return `${ip}|${String(username || '').toLowerCase()}`;
}

function bruteState(key) {
  let s = brute.get(key);
  if (!s) {
    s = { fails: 0, lockUntil: 0 };
    brute.set(key, s);
  }
  return s;
}

function bruteCheck(key) {
  const s = bruteState(key);
  const now = Date.now();
  if (s.lockUntil > now) {
    return { ok: false, wait: Math.ceil((s.lockUntil - now) / 1000), fails: s.fails };
  }
  return { ok: true, wait: 0, fails: s.fails };
}

function bruteFail(key) {
  const s = bruteState(key);
  s.fails++;
  if (s.fails >= 5) {
    const exp = Math.min(s.fails - 5, 5); // 0..5
    const seconds = Math.min(DELAY_CAP, DELAY_BASE * Math.pow(2, exp));
    s.lockUntil = Date.now() + seconds * 1000;
  }
  return { fails: s.fails, wait: s.lockUntil > Date.now() ? Math.ceil((s.lockUntil - Date.now()) / 1000) : 0 };
}

function bruteSuccess(key) {
  brute.delete(key);
}

function bruteNeedsCaptcha(key, threshold = 3) {
  const s = bruteState(key);
  return s.fails >= threshold;
}

module.exports = {
  limiter,
  bruteKey,
  bruteCheck,
  bruteFail,
  bruteSuccess,
  bruteNeedsCaptcha
};
