const express = require('express');
const { db } = require('../db');
const { auth } = require('../helpers');
const { unreadCount, markRead, markAllRead } = require('../notif');

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
