/**
 * phone.js — нормализация и хэширование номеров телефонов.
 * В БД хранится только HMAC-хэш нормализованного номера,
 * чтобы нельзя было восстановить номер даже при утечке базы.
 */

const crypto = require('crypto');
const { getMasterKey, loadEnv } = require('./security');

/* Секрет для HMAC. Чтобы не менять поведение и не ломать уже посчитанные хэши
   на проде без конфигурации, секрет берётся так (приоритет сверху):
     1) PHONE_HASH_SECRET (env/.env)                — явный, рекомендуемый
     2) производный от SPACE_MASTER_KEY             — если мастер-ключ стабильно задан
     3) прежняя константа (только для совместимости, когда ничего не настроено)   */
const LEGACY_SECRET = 'reska-phone-secret-v1';

function currentSecret() {
  loadEnv();
  const env = process.env.PHONE_HASH_SECRET;
  if (env && String(env).trim()) return String(env).trim();
  if (process.env.SPACE_MASTER_KEY && String(process.env.SPACE_MASTER_KEY).trim()) {
    return crypto.createHmac('sha256', getMasterKey()).update('phone-hash-secret').digest('hex');
  }
  return LEGACY_SECRET;
}

const SECRET = currentSecret();

/* Поисковые хэши: текущий + старый (на случай смены секрета после редеплоя). */
function hashesFor(raw) {
  const n = normalizePhone(raw);
  if (!n) return [];
  if (SECRET === LEGACY_SECRET) return [hashPhone(n)];
  return [hashPhone(n), crypto.createHmac('sha256', LEGACY_SECRET).update(String(n)).digest('hex')];
}

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

module.exports = { normalizePhone, hashPhone, hashFor, hashesFor };
