const express = require('express');
const { db } = require('../db');
const { auth, publicUser } = require('../helpers');
const { sanitizeText } = require('../validate');
const { normalizePhone, hashPhone } = require('../phone');

const router = express.Router();

function matchText(haystacks, q) {
  const needle = q.toLowerCase();
  return haystacks.some((h) => String(h || '').toLowerCase().includes(needle));
}

router.get('/', (req, res) => {
  const q = sanitizeText(req.query.q, 60);
  const type = String(req.query.type || 'all');
  if (!q) return res.json({ users: [], posts: [], videos: [] });

  const result = { users: [], posts: [], videos: [], query: q, type };

  if (type === 'all' || type === 'users') {
    result.users = db
      .prepare('SELECT * FROM users ORDER BY name LIMIT 200')
      .all()
      .filter((u) => matchText([u.username, u.name, u.status], q))
      .slice(0, 20)
      .map(publicUser);
  }
  if (type === 'all' || type === 'posts') {
    result.posts = db
      .prepare(
        `SELECT p.id, p.uid, p.text, p.media, p.media_type, p.created_at,
                p.user_id, u.username, u.name, u.avatar
         FROM posts p JOIN users u ON u.id = p.user_id
         ORDER BY p.id DESC LIMIT 200`
      )
      .all()
      .filter((p) => matchText([p.text], q))
      .slice(0, 20);
  }
  if (type === 'all' || type === 'videos') {
    result.videos = db
      .prepare(
        `SELECT v.id, v.uid, v.title, v.description, v.file, v.thumb, v.is_clip, v.views,
                v.user_id, u.username, u.name
         FROM videos v JOIN users u ON u.id = v.user_id
         ORDER BY v.id DESC LIMIT 200`
      )
      .all()
      .filter((v) => matchText([v.title, v.description], q))
      .slice(0, 20);
  }
  res.json(result);
});

/* поиск по контактам телефонной книги: клиент присылает номера,
   сервер сравнивает HMAC-хэши и возвращает найденных пользователей */
router.post('/contacts', auth, (req, res) => {
  const phones = req.body && req.body.phones;
  if (!Array.isArray(phones)) return res.status(400).json({ error: 'Нужен массив phones' });
  if (phones.length > 500) return res.status(400).json({ error: 'Слишком много номеров' });

  const order = []; /* уникальные нормализованные номера */
  const phoneByHash = new Map();
  for (const p of phones) {
    const digits = normalizePhone(p);
    if (!digits) continue;
    const h = hashPhone(digits);
    if (!phoneByHash.has(h)) {
      phoneByHash.set(h, digits);
      order.push(h);
    }
  }

  const matches = [];
  if (order.length) {
    const ph = order.map(() => '?').join(',');
    const rows = db
      .prepare(`SELECT * FROM users WHERE phone_hash IN (${ph}) AND phone != ''`)
      .all(...order);
    const byHash = new Map(rows.map((u) => [u.phone_hash, u]));
    for (const h of order) {
      const u = byHash.get(h);
      if (u) matches.push({ phone: phoneByHash.get(h), user: publicUser(u) });
    }
  }
  res.json({ matches });
});

module.exports = router;
