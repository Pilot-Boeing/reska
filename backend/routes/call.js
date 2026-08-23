const express = require('express');
const { auth } = require('../helpers');

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

module.exports = router;
