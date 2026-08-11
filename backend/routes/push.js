const express = require('express');
const { db } = require('../db');
const { auth } = require('../helpers');
const { log } = require('../logger');

const router = express.Router();

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
