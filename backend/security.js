/**
 * security.js — ядро защиты: ключи/.env, HMAC-подписи, подписанные токены,
 * CSRF (double-submit cookie), TOTP (RFC 6238), математическая капча,
 * генерация uid (base58), нормализация IP/User-Agent.
 *
 * Никаких внешних зависимостей — только node:crypto.
 */
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PROJECT_ROOT = path.join(__dirname, '..');
const ENV_PATH = path.join(PROJECT_ROOT, '.env');

/* =========================================================
   1. .env + мастер-ключ (автогенерация при первом запуске)
   ========================================================= */
const envCache = {};

function loadEnv() {
  if (Object.keys(envCache).length) return envCache;
  const raw = fs.existsSync(ENV_PATH) ? fs.readFileSync(ENV_PATH, 'utf8') : '';
  for (const line of raw.split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Za-z0-9_]+)\s*=\s*(.*)\s*$/);
    if (m) envCache[m[1]] = m[2].replace(/^["']|["']$/g, '');
  }
  process.env = { ...process.env, ...envCache };
  return envCache;
}

function saveEnv(key, value) {
  loadEnv();
  envCache[key] = value;
  let raw = fs.existsSync(ENV_PATH) ? fs.readFileSync(ENV_PATH, 'utf8') : '';
  const re = new RegExp(`^${key}=.*$`, 'm');
  const line = `${key}=${value}`;
  if (re.test(raw)) raw = raw.replace(re, line);
  else raw = raw.trim() + (raw.trim() ? '\n' : '') + line + '\n';
  fs.writeFileSync(ENV_PATH, raw);
  if (process.platform !== 'win32') fs.chmodSync(ENV_PATH, 0o600);
}

/** Мастер-ключ 32 байта (base64). Генерируется при первом запуске. */
function getMasterKey() {
  loadEnv();
  let key = envCache.SPACE_MASTER_KEY;
  if (!key) {
    key = crypto.randomBytes(32).toString('base64');
    saveEnv('SPACE_MASTER_KEY', key);
  }
  return Buffer.from(key, 'base64');
}

/** Секреты для подписи действий. Если в .env нет — детерминированно
 *  выводятся из мастер-ключа, чтобы переживать редеплои/инстансы
 *  (SPACE_MASTER_KEY нужно задать как env на Render). */
function getSecret(purpose) {
  loadEnv();
  const name = 'SPACE_SECRET_' + purpose.toUpperCase().replace(/[^A-Z0-9]/g, '_');
  let s = envCache[name];
  if (!s) {
    s = crypto.createHmac('sha256', getMasterKey()).update('secret:' + purpose).digest('base64');
    saveEnv(name, s);
  }
  return s;
}

/* =========================================================
   2. HMAC-подписи (защита от подделки действий)
   ========================================================= */
function hmacSign(data, purpose) {
  const h = crypto.createHmac('sha256', getSecret(purpose));
  h.update(String(data));
  return h.digest('hex');
}

function hmacVerify(data, purpose, sig) {
  if (!sig || typeof sig !== 'string') return false;
  const expected = Buffer.from(hmacSign(data, purpose), 'hex');
  const actual = Buffer.from(sig, 'hex');
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}

/* =========================================================
   3. Подписанные токены (state-токены 2FA, подтверждения и т.п.)
   Формат: base64url(payload).hmac(payload)
   ========================================================= */
function signToken(payload, ttlSec) {
  const body = {
    ...payload,
    exp: Math.floor(Date.now() / 1000) + ttlSec
  };
  const data = Buffer.from(JSON.stringify(body)).toString('base64url');
  const sig = hmacSign(data, 'token');
  return `${data}.${sig}`;
}

function verifyToken(token) {
  if (typeof token !== 'string') return null;
  const i = token.lastIndexOf('.');
  if (i < 0) return null;
  const data = token.slice(0, i);
  const sig = token.slice(i + 1);
  if (!hmacVerify(data, 'token', sig)) return null;
  try {
    const body = JSON.parse(Buffer.from(data, 'base64url').toString('utf8'));
    if (!body.exp || body.exp * 1000 < Date.now()) return null;
    return body;
  } catch (e) {
    return null;
  }
}

/* =========================================================
   4. CSRF — double-submit cookie + заголовок X-CSRF-Token
   ========================================================= */
function newCsrfToken() {
  return crypto.randomBytes(24).toString('hex');
}

function validCsrf(token) {
  return typeof token === 'string' && /^[a-f0-9]{48}$/.test(token);
}

/* =========================================================
   5. TOTP (RFC 6238) — без внешних библиотек
   ========================================================= */
const B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(buf) {
  let bits = 0;
  let value = 0;
  let out = '';
  for (let i = 0; i < buf.length; i++) {
    value = (value << 8) | buf[i];
    bits += 8;
    while (bits >= 5) {
      out += B32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32_ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

function base32Decode(str) {
  const clean = String(str).toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = 0;
  let value = 0;
  const bytes = [];
  for (const ch of clean) {
    const idx = B32_ALPHABET.indexOf(ch);
    if (idx < 0) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

function generateTotpSecret() {
  return base32Encode(crypto.randomBytes(20)); // 160 бит
}

function totpCode(secret, timeStep = 30) {
  const key = base32Decode(secret);
  const counter = Math.floor(Date.now() / 1000 / timeStep);
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac('sha1', key).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const bin = ((hmac[offset] & 0x7f) << 24) | (hmac[offset + 1] << 16) | (hmac[offset + 2] << 8) | hmac[offset + 3];
  return String(bin % 1000000).padStart(6, '0');
}

function verifyTotp(secret, code, window = 1) {
  const given = String(code || '').replace(/\s+/g, '');
  if (!/^\d{6}$/.test(given)) return false;
  for (let i = -window; i <= window; i++) {
    const t = Math.floor(Date.now() / 1000 / 30) + i;
    const buf = Buffer.alloc(8);
    buf.writeBigUInt64BE(BigInt(t));
    const hmac = crypto.createHmac('sha1', base32Decode(secret)).update(buf).digest();
    const offset = hmac[hmac.length - 1] & 0x0f;
    const bin = ((hmac[offset] & 0x7f) << 24) | (hmac[offset + 1] << 16) | (hmac[offset + 2] << 8) | hmac[offset + 3];
    if (String(bin % 1000000).padStart(6, '0') === given) return true;
  }
  return false;
}

function totpUri(secret, username) {
  const label = encodeURIComponent('РЕСКА:' + username);
  return `otpauth://totp/${label}?secret=${encodeURIComponent(secret)}&issuer=РЕСКА&algorithm=SHA1&digits=6&period=30`;
}

/* =========================================================
   6. Математическая капча (токен подписан HMAC)
   ========================================================= */
function captchaGenerate() {
  const a = 1 + crypto.randomInt(9);
  const b = 1 + crypto.randomInt(9);
  const plus = crypto.randomInt(2) === 1;
  let text, answer;
  if (plus) {
    text = `${a} + ${b}`;
    answer = a + b;
  } else {
    const big = Math.max(a, b);
    const small = Math.min(a, b);
    text = `${big} − ${small}`;
    answer = big - small;
  }
  const token = signToken({ c: answer, kind: 'captcha' }, 600);
  return { token, text };
}

function captchaVerify(token, answer) {
  const payload = verifyToken(token);
  if (!payload || payload.kind !== 'captcha') return false;
  return Number(answer) === payload.c;
}

/* =========================================================
   7. uid (base58, 12 символов) — защита от подбора ID
   ========================================================= */
const B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function randomUid(len = 12) {
  const bytes = crypto.randomBytes(len);
  let out = '';
  let n = bytes.readBigUInt64BE(0) % BigInt(B58_ALPHABET.length);
  for (let i = 0; i < len; i++) {
    if (i >= 8) n = BigInt(bytes[i % bytes.length]);
    out += B58_ALPHABET[Number(n % BigInt(B58_ALPHABET.length))];
    n /= BigInt(B58_ALPHABET.length);
  }
  return out;
}

/* =========================================================
   8. IP / User-Agent
   ========================================================= */
function getClientIp(req) {
  const trustProxy = !!(req.app && req.app.get && req.app.get('trust proxy'));
  if (trustProxy) {
    const fwd = req.headers['x-forwarded-for'];
    if (fwd) return String(fwd).split(',')[0].trim();
  }
  return req.socket && req.socket.remoteAddress ? req.socket.remoteAddress.replace(/^::ffff:/, '') : '0.0.0.0';
}

/** Нормализация IP: IPv4 → первые 3 октета (толерантность к динамике). */
function normalizeIp(ip) {
  const v6 = String(ip || '').replace(/^::ffff:/, '');
  if (v6.includes(':')) return v6; // IPv6 не трогаем
  const parts = v6.split('.');
  return parts.length === 4 ? parts.slice(0, 3).join('.') : v6;
}

function clientUa(req) {
  return String(req.headers['user-agent'] || '').slice(0, 256);
}

function uaHash(req) {
  return crypto.createHash('sha256').update(clientUa(req)).digest('hex');
}

function ipHash(req) {
  return crypto.createHash('sha256').update(normalizeIp(getClientIp(req))).digest('hex');
}

function secureCookie(res, name, value, opts = {}) {
  const secure = !!opts.secure;
  res.cookie(name, value, {
    httpOnly: true,
    sameSite: 'lax',
    secure,
    ...opts
  });
}

module.exports = {
  loadEnv,
  getMasterKey,
  getSecret,
  hmacSign,
  hmacVerify,
  signToken,
  verifyToken,
  newCsrfToken,
  validCsrf,
  generateTotpSecret,
  totpCode,
  verifyTotp,
  totpUri,
  captchaGenerate,
  captchaVerify,
  randomUid,
  getClientIp,
  normalizeIp,
  clientUa,
  uaHash,
  ipHash,
  secureCookie
};
