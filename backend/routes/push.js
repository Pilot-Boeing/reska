const express = require('express');
const { db } = require('../db');
const { auth } = require('../helpers');
const { log } = require('../logger');
const webpush = require('../webpush');

const router = express.Router();

/* ---------- Web Push (браузер, VAPID) ---------- */

/* публичный VAPID-ключ (urlsafe base64) — для подписки в браузере */
router.get('/web-key', (req, res) => {
  res.json({ publicKey: webpush.publicKeyUrlSafe() });
});

/* регистрация web-подписки пользователя (upsert по endpoint) */
router.post('/web-sub', auth, (req, res) => {
  try {
    webpush.saveSubscription(req.userId, req.body);
    res.json({ ok: true });
  } catch (e) {
    log('webpush_subscribe_error', { req, userId: req.userId });
    res.status(400).json({ error: e.message || 'Некорректная web-подписка' });
  }
});

/* удаление web-подписки по endpoint (выход из приложения) */
router.delete('/web-sub', auth, (req, res) => {
  const endpoint = String(req.body.endpoint || '').trim();
  if (endpoint) webpush.deleteSubscription(endpoint);
  res.json({ ok: true });
});

/* ---------- FCM-токены устройств (Capacitor) ---------- */

/* регистрация FCM-токена устройства (upsert) */
router.post('/token', auth, (req, res) => {
  const token = String(req.body.token || '').trim();
  const platform = String(req.body.platform || 'android').slice(0, 20);
  if (!token || token.length < 20 || token.length > 512) {
    return res.status(400).json({ error: 'Некорректный push-токен' });
  }
  /* одно устройство — один токен; перепривязка при входе другим пользователем */
  db.prepare('DELETE FROM push_tokens WHERE token = ?').run(token);
  db.prepare(
    'INSERT OR IGNORE INTO push_tokens (user_id, token, platform, updated_at) VALUES (?, ?, ?, datetime("now"))'
  ).run(req.userId, token, platform);
  log('push_token_register', { req, userId: req.userId, meta: { platform } });
  res.json({ ok: true });
});

/* удаление токена (выход из приложения) */
router.delete('/token', auth, (req, res) => {
  const token = String(req.body.token || '').trim();
  if (token) {
    db.prepare('DELETE FROM push_tokens WHERE token = ?').run(token);
    log('push_token_unregister', { req, userId: req.userId });
  }
  res.json({ ok: true });
});

module.exports = router;
