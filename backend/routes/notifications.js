const express = require('express');
const { db } = require('../db');
const { auth } = require('../helpers');
const { unreadCount, markRead, markAllRead, getSettings } = require('../notif');

const router = express.Router();

/* список уведомлений + непрочитанные */
router.get('/', auth, (req, res) => {
  const rows = db
    .prepare(
      `SELECT n.id, n.type, n.title, n.body, n.url, n.read, n.created_at,
              u.uid AS actor_uid, u.name AS actor_name, u.avatar AS actor_avatar
       FROM notifications n JOIN users u ON u.id = n.actor_id
       WHERE n.user_id = ? ORDER BY n.id DESC LIMIT 100`
    )
    .all(req.userId);
  res.json({ notifications: rows, unread: unreadCount(req.userId) });
});

/* настройки уведомлений */
router.get('/settings', auth, (req, res) => {
  res.json({ settings: getSettings(req.userId) });
});

router.put('/settings', auth, (req, res) => {
  const allowed = ['follows', 'likes', 'comments', 'mentions', 'messages', 'reactions', 'friend_requests'];
  const sets = {};
  allowed.forEach((k) => {
    if (req.body[k] !== undefined) sets[k] = req.body[k] ? 1 : 0;
  });
  if (!Object.keys(sets).length) return res.status(400).json({ error: 'Нет полей' });
  const cols = Object.keys(sets).map((k) => `${k} = ?`).join(', ');
  const vals = Object.values(sets);
  db.prepare(`INSERT OR IGNORE INTO notification_settings (user_id) VALUES (?)`).run(req.userId);
  db.prepare(`UPDATE notification_settings SET ${cols} WHERE user_id = ?`).run(...vals, req.userId);
  res.json({ settings: getSettings(req.userId) });
});

/* отметить одно прочитанным */
router.post('/read', auth, (req, res) => {
  const id = Number(req.body.id);
  if (!id) return res.status(400).json({ error: 'id обязателен' });
  markRead(req.userId, id);
  res.json({ unread: unreadCount(req.userId) });
});

/* отметить все прочитанными */
router.post('/read-all', auth, (req, res) => {
  markAllRead(req.userId);
  res.json({ unread: 0 });
});

module.exports = router;
