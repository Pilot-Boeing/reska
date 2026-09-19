const express = require('express');
const { auth } = require('../helpers');
const { db } = require('../db');

const router = express.Router();

/**
 * Возвращает ICE-серверы для WebRTC.
 * TURN обязателен для обхода NAT и блокировок РКН — трафик идёт поверх TLS (443),
 * маскируясь под обычный HTTPS. Параметры берутся из переменных окружения сервера.
 */
router.get('/config', auth, (req, res) => {
  const servers = [];
  const stun = process.env.STUN_URL;
  const turnUrl = process.env.TURN_URL;
  const turnUser = process.env.TURN_USER;
  const turnSecret = process.env.TURN_SECRET;
  if (stun) servers.push({ urls: stun.split(',').map((s) => s.trim()) });
  if (turnUrl && turnUser && turnSecret) {
    (Array.isArray(turnUrl) ? turnUrl : turnUrl.split(',').map((s) => s.trim())).forEach((u) =>
      servers.push({ urls: u, username: turnUser, credential: turnSecret })
    );
  }
  res.json({ iceServers: servers });
});

// История звонков текущего пользователя (исходящие и входящие)
router.get('/history', auth, (req, res) => {
  const rows = db.prepare(`
    SELECT c.id, c.type, c.status, c.duration, c.created_at,
           c.from_user AS from_id, c.to_user AS to_id,
           fu.uid AS from_uid, fu.name AS from_name, fu.username AS from_username, fu.avatar AS from_avatar,
           tu.uid AS to_uid, tu.name AS to_name, tu.username AS to_username, tu.avatar AS to_avatar
    FROM call_history c
    JOIN users fu ON fu.id = c.from_user
    JOIN users tu ON tu.id = c.to_user
    WHERE c.from_user = ? OR c.to_user = ?
    ORDER BY c.created_at DESC, c.id DESC
    LIMIT 100
  `).all(req.user.id);
  res.json({ calls: rows });
});

// Очистить историю целиком
router.delete('/history', auth, (req, res) => {
  db.prepare('DELETE FROM call_history WHERE from_user = ? OR to_user = ?').run(req.user.id, req.user.id);
  res.json({ ok: true });
});

// Удалить одну запись
router.delete('/history/:id', auth, (req, res) => {
  db.prepare('DELETE FROM call_history WHERE id = ? AND (from_user = ? OR to_user = ?)')
    .run(req.params.id, req.user.id, req.user.id);
  res.json({ ok: true });
});

module.exports = router;
