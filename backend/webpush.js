/**
 * webpush.js — отправка push-уведомлений в браузер (Web Push, протокол VAPID).
 *
 * Ключи VAPID хранятся в таблице app_settings БД (бэкап ее => GitHub => Render),
 * поэтому они не теряются при перезапуске сервера (эфемерный диск Render).
 * Приоритет: env VAPID_PUBLIC_KEY / VAPID_PRIVATE_KEY (разовый, задаётся в Render).
 *
 * Подписки браузеров — таблица web_push_subs (endpoint + ключи шифрования).
 */

const webpush = require('web-push');
const { db } = require('./db');
const { log } = require('./logger');

const CONTACT = process.env.VAPID_SUBJECT || 'mailto:admin@reska.example';
const VAPID_PUB_ENV = process.env.VAPID_PUBLIC_KEY || '';
const VAPID_PRIV_ENV = process.env.VAPID_PRIVATE_KEY || '';

let vapid = null; /* { publicKey, privateKey } — VAPID-ключи в формате web-push */

function urlBase64ToUrlSafe(s) {
  return String(s || '').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/* VAPID-ключи: env > БД > генерация с сохранением в БД */
function getVapid() {
  if (vapid) return vapid;
  if (VAPID_PUB_ENV && VAPID_PRIV_ENV) {
    vapid = { publicKey: VAPID_PUB_ENV, privateKey: VAPID_PRIV_ENV };
    configure();
    return vapid;
  }
  try {
    const row = db.prepare("SELECT value FROM app_settings WHERE key = 'vapid_public'").get();
    const priv = db.prepare("SELECT value FROM app_settings WHERE key = 'vapid_private'").get();
    if (row && priv) {
      vapid = { publicKey: row.value, privateKey: priv.value };
      configure();
      return vapid;
    }
  } catch (e) {}
  const keys = webpush.generateVAPIDKeys();
  vapid = { publicKey: keys.publicKey, privateKey: keys.privateKey };
  try {
    db.prepare("INSERT OR REPLACE INTO app_settings (key, value, updated_at) VALUES ('vapid_public', ?, datetime('now'))").run(keys.publicKey);
    db.prepare("INSERT OR REPLACE INTO app_settings (key, value, updated_at) VALUES ('vapid_private', ?, datetime('now'))").run(keys.privateKey);
  } catch (e) {}
  configure();
  log('webpush_vapid_generated', {});
  return vapid;
}

function configure() {
  webpush.setVapidDetails(CONTACT, vapid.publicKey, vapid.privateKey);
}

/* Публичный VAPID-ключ (urlsafe) для фронтенда */
function publicKeyUrlSafe() {
  return urlBase64ToUrlSafe(getVapid().publicKey);
}

/* Сохранение web-подписки пользователя (upsert по endpoint) */
function saveSubscription(userId, sub) {
  const endpoint = String(sub.endpoint || '').trim();
  const p256dh = String(sub.keys && sub.keys.p256dh || '').trim();
  const auth = String(sub.keys && sub.keys.auth || '').trim();
  if (!endpoint || endpoint.length < 10 || !p256dh || !auth) {
    throw new Error('Некорректная web-подписка');
  }
  db.prepare(
    `INSERT INTO web_push_subs (user_id, endpoint, key_p256dh, key_auth, updated_at)
     VALUES (?, ?, ?, ?, datetime('now'))
     ON CONFLICT(endpoint) DO UPDATE SET
       user_id = excluded.user_id,
       key_p256dh = excluded.key_p256dh,
       key_auth = excluded.key_auth,
       updated_at = datetime('now')`
  ).run(userId, endpoint, p256dh, auth);
  log('webpush_subscribe', { userId, meta: { endpoint: endpoint.slice(0, 60) } });
}

function deleteSubscription(endpoint) {
  if (!endpoint) return;
  db.prepare('DELETE FROM web_push_subs WHERE endpoint = ?').run(endpoint);
}

function subscriptionsFor(userId) {
  return db.prepare('SELECT endpoint, key_p256dh, key_auth FROM web_push_subs WHERE user_id = ?').all(userId);
}

/**
 * Отправить всем web-подпискам пользователя. При 404/410 подписка удаляется.
 * Возвращает число отправленных.
 */
async function sendToUser(userId, { title, body, data = {} } = {}, onlineUsers) {
  try { getVapid(); } catch (e) { return 0; }
  if (onlineUsers && onlineUsers.has(userId)) return 0; /* онлайн — реального push не надо */
  const subs = subscriptionsFor(userId);
  if (!subs.length) return 0;
  const payload = JSON.stringify({ title, body, url: data && data.url ? String(data.url) : '/', tag: data && data.tag ? String(data.tag) : '' });
  let sent = 0;
  for (const s of subs) {
    const sub = { endpoint: s.endpoint, keys: { p256dh: s.key_p256dh, auth: s.key_auth } };
    try {
      await webpush.sendNotification(sub, payload);
      sent++;
    } catch (e) {
      if (e && (e.statusCode === 404 || e.statusCode === 410)) {
        deleteSubscription(s.endpoint);
      }
    }
  }
  return sent;
}

module.exports = {
  getVapid,
  publicKeyUrlSafe,
  saveSubscription,
  deleteSubscription,
  subscriptionsFor,
  sendToUser
};
