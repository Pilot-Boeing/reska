/**
 * fcm.js — отправка push-уведомлений через Firebase Cloud Messaging (HTTP v1).
 * Без внешних зависимостей: JWT подписывается через node:crypto (RS256).
 *
 * Конфигурация: файл backend/fcm-service-account.json (сервисный ключ Firebase).
 * Если файла нет — модуль работает вхолостую (лог один раз), сервер не падает.
 */

const fs = require('fs');
const path = require('path');
const https = require('https');
const crypto = require('crypto');
const { db } = require('./db');
const { log } = require('./logger');

const CRED_FILE = path.join(__dirname, 'fcm-service-account.json');
const FCM_SEND_URL = 'https://fcm.googleapis.com/v1/projects/%s/messages:send';
const TOKEN_URL = 'https://oauth2.googleapis.com/token';
const SCOPE = 'https://www.googleapis.com/auth/firebase.messaging';

let cachedCred = null;
let warned = false;

function loadCred() {
  if (cachedCred) return cachedCred;
  const envJson = process.env.FCM_SERVICE_ACCOUNT || '';
  if (envJson.trim()) {
    try {
      cachedCred = JSON.parse(envJson);
      return cachedCred;
    } catch (e) {
      console.warn('FCM: не удалось разобрать FCM_SERVICE_ACCOUNT:', e.message);
    }
  }
  if (!fs.existsSync(CRED_FILE)) {
    if (!warned) {
      warned = true;
      console.warn('FCM: файл backend/fcm-service-account.json не найден и не задан FCM_SERVICE_ACCOUNT — push-уведомления не отправляются.');
    }
    return null;
  }
  try {
    cachedCred = JSON.parse(fs.readFileSync(CRED_FILE, 'utf8'));
  } catch (e) {
    if (!warned) {
      warned = true;
      console.warn('FCM: не удалось прочитать сервисный ключ:', e.message);
    }
    return null;
  }
  return cachedCred;
}

function b64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function signJwt(cred) {
  const now = Math.floor(Date.now() / 1000);
  const header = b64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const payload = b64url(
    JSON.stringify({
      iss: cred.client_email,
      scope: SCOPE,
      aud: cred.token_uri,
      iat: now,
      exp: now + 3600
    })
  );
  const sign = crypto.createSign('RSA-SHA256');
  sign.update(`${header}.${payload}`);
  const sig = b64url(sign.sign(cred.private_key));
  return `${header}.${payload}.${sig}`;
}

let cachedToken = null;
let tokenExpiresAt = 0;

function getAccessToken() {
  const cred = loadCred();
  if (!cred) return null;
  if (cachedToken && Date.now() < tokenExpiresAt) return cachedToken;
  return new Promise((resolve, reject) => {
    const body = new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: signJwt(cred)
    }).toString();
    const req = https.request(
      TOKEN_URL,
      { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) } },
      (res) => {
        let raw = '';
        res.on('data', (d) => (raw += d));
        res.on('end', () => {
          try {
            const j = JSON.parse(raw);
            if (!j.access_token) return reject(new Error((j.error_description || j.error) || 'нет access_token'));
            cachedToken = j.access_token;
            tokenExpiresAt = Date.now() + (Number(j.expires_in) || 3600) * 1000 - 60 * 1000;
            resolve(cachedToken);
          } catch (e) {
            reject(e);
          }
        });
      }
    );
    req.on('error', reject);
    req.end(body);
  });
}

function sendOne(token, accessToken, cred, title, body, data) {
  const payload = {
    message: {
      token,
      notification: { title, body },
      data: { url: data && data.url ? String(data.url).slice(0, 200) : '' },
      android: {
        priority: 'high',
        notification: {
          channel_id: 'reska',
          icon: 'ic_stat_reska',
          sound: 'default'
        }
      }
    }
  };
  return new Promise((resolve, reject) => {
    const url = FCM_SEND_URL.replace('%s', encodeURIComponent(cred.project_id));
    const req = https.request(
      url,
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(JSON.stringify(payload))
        }
      },
      (res) => {
        let raw = '';
        res.on('data', (d) => (raw += d));
        res.on('end', () => {
          if (res.statusCode === 200) return resolve(null);
          let err = raw;
          try { err = (JSON.parse(raw).error && JSON.parse(raw).error.message) || raw; } catch (e) {}
          reject(new Error(`FCM ${res.statusCode}: ${err}`));
        });
      }
    );
    req.on('error', reject);
    req.end(JSON.stringify(payload));
  });
}

/**
 * Отправить уведомление пользователю на все его устройства.
 * Если пользователь сейчас онлайн (socket соединён) — пропускаем.
 */
async function notifyUser(userId, { title, body, data }, onlineUsers) {
  const cred = loadCred();
  if (!cred) return;
  if (onlineUsers && onlineUsers.has(userId)) return;
  const tokens = db.prepare('SELECT token FROM push_tokens WHERE user_id = ?').all(userId);
  if (!tokens.length) return;
  let accessToken;
  try {
    accessToken = await getAccessToken();
  } catch (e) {
    console.error('FCM: ошибка получения токена:', e.message);
    return;
  }
  if (!accessToken) return;
  for (const t of tokens) {
    try {
      await sendOne(t.token, accessToken, cred, title, body, data);
    } catch (e) {
      if (/UNREGISTERED|InvalidRegistration|NotRegistered/.test(e.message)) {
        db.prepare('DELETE FROM push_tokens WHERE token = ?').run(t.token);
      } else {
        console.error('FCM: ошибка отправки:', e.message);
      }
    }
  }
  log('push_sent', { userId, meta: { title, url: data && data.url } });
}

async function notifyFollowers(userId, { title, body, data }, onlineUsers) {
  const followers = db.prepare('SELECT user_id FROM follows WHERE following_id = ?').all(userId);
  for (const f of followers) {
    await notifyUser(f.user_id, { title, body, data }, onlineUsers);
  }
}

module.exports = { notifyUser, notifyFollowers, loadCred };
