/**
 * phone.js — нормализация и хэширование номеров телефонов.
 * В БД хранится только HMAC-хэш нормализованного номера,
 * чтобы нельзя было восстановить номер даже при утечке базы.
 */

const crypto = require('crypto');

const SECRET = process.env.PHONE_HASH_SECRET || 'reska-phone-secret-v1';

/* приводим к виду 7XXXXXXXXXX (РФ); невалидные → '' */
function normalizePhone(raw) {
  let digits = String(raw || '').replace(/\D/g, '');
  if (digits.length === 11 && digits[0] === '8') digits = '7' + digits.slice(1);
  else if (digits.length === 10) digits = '7' + digits;
  if (!/^7\d{10}$/.test(digits)) return '';
  return digits;
}

function hashPhone(normalized) {
  return crypto.createHmac('sha256', SECRET).update(String(normalized)).digest('hex');
}

function hashFor(raw) {
  const n = normalizePhone(raw);
  if (!n) return '';
  return hashPhone(n);
}

module.exports = { normalizePhone, hashPhone, hashFor };
