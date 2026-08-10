/**
 * validate.js — валидация и санитизация входных данных.
 * Без внешних библиотек (не требуется express-validator — меньше зависимостей,
 * контроль над поведением полный).
 */

const USERNAME_RE = /^[a-zA-Z0-9_.]{3,24}$/;
const UID_RE = /^[1-9A-HJ-NP-Za-km-z]{10,16}$/;

function sanitizeText(s, maxLen = 5000) {
  let t = String(s ?? '');
  // управляющие символы и null-байты
  t = t.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '');
  // теги <script>
  t = t.replace(/<\/?script\b[^>]*>/gi, '');
  // обработчики событий on*=...
  t = t.replace(/\son\w+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/gi, '');
  // javascript: URI
  t = t.replace(/javascript\s*:/gi, '');
  return t.slice(0, maxLen).trim();
}

function validUsername(u) {
  return typeof u === 'string' && USERNAME_RE.test(u);
}

function validPassword(p) {
  return typeof p === 'string' && p.length >= 6 && p.length <= 128;
}

function validName(n) {
  return typeof n === 'string' && n.trim().length >= 2 && n.length <= 60;
}

function validUid(u) {
  return typeof u === 'string' && UID_RE.test(u);
}

function cleanInt(v) {
  const n = Number(v);
  return Number.isInteger(n) && n > 0 ? n : null;
}

function requireFields(obj, fields) {
  for (const f of fields) {
    if (obj[f] === undefined || obj[f] === null || String(obj[f]).trim() === '') {
      return f;
    }
  }
  return null;
}

module.exports = {
  sanitizeText,
  validUsername,
  validPassword,
  validName,
  validUid,
  cleanInt,
  requireFields
};
