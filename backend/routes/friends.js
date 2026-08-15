const express = require('express');
const { db } = require('../db');
const { auth, publicUser, findByIdOrUid } = require('../helpers');
const { notify } = require('../notif');
const { sanitizeText } = require('../validate');

const router = express.Router();

function friendship(userId, targetId) {
  const a = Math.min(userId, targetId);
  const b = Math.max(userId, targetId);
  return !!db.prepare('SELECT 1 FROM friendships WHERE user_a = ? AND user_b = ?').get(a, b);
}

function requestBetween(userId, targetId) {
  return (
    db.prepare('SELECT * FROM friend_requests WHERE from_user = ? AND to_user = ?').get(userId, targetId) ||
    db.prepare('SELECT * FROM friend_requests WHERE from_user = ? AND to_user = ?').get(targetId, userId)
  );
}

function relation(userId, targetId) {
  if (userId === targetId) return 'self';
  if (friendship(userId, targetId)) return 'friends';
  const r = requestBetween(userId, targetId);
  if (!r) return 'none';
  if (r.from_user === userId && r.status === 'pending') return 'outgoing';
  if (r.from_user === targetId && r.status === 'pending') return 'incoming';
  if (r.from_user === userId && r.status === 'declined') return 'declined';
  return 'none';
}

function emit(io, userId, event, payload) {
  if (io) io.to(`user:${userId}`).emit(event, payload);
}

/* ---------- отправить заявку в друзья ---------- */
router.post('/:id/friend', auth, (req, res) => {
  const target = findByIdOrUid('users', req.params.id);
  if (!target) return res.status(404).json({ error: 'Пользователь не найден' });
  if (target.id === req.userId) return res.status(400).json({ error: 'Нельзя добавить себя в друзья' });
  if (friendship(req.userId, target.id)) return res.status(400).json({ error: 'Уже друзья' });

  const existing = requestBetween(req.userId, target.id);
  if (existing && existing.status === 'pending') {
    return res.json({ relation: relation(req.userId, target.id) });
  }
  if (existing) db.prepare('DELETE FROM friend_requests WHERE id = ?').run(existing.id);

  db.prepare('INSERT INTO friend_requests (from_user, to_user, status) VALUES (?, ?, ?)')
    .run(req.userId, target.id, 'pending');
  notify(req.app, target.id, req.user, 'friend_request', {
    body: 'хочет добавить вас в друзья',
    url: `profile/${req.user.uid}`
  });
  emit(req.app.get('io'), target.id, 'friend:request', { actorUid: req.user.uid, actorName: req.user.name });
  res.json({ relation: 'outgoing' });
});

/* ---------- принять заявку ---------- */
router.post('/:id/friend/accept', auth, (req, res) => {
  const target = findByIdOrUid('users', req.params.id);
  if (!target) return res.status(404).json({ error: 'Пользователь не найден' });
  const r = db
    .prepare("SELECT * FROM friend_requests WHERE from_user = ? AND to_user = ? AND status = 'pending'")
    .get(target.id, req.userId);
  if (!r) return res.status(400).json({ error: 'Нет входящей заявки' });

  const a = Math.min(req.userId, target.id);
  const b = Math.max(req.userId, target.id);
  db.prepare('INSERT OR IGNORE INTO friendships (user_a, user_b) VALUES (?, ?)').run(a, b);
  db.prepare('UPDATE friend_requests SET status = ? WHERE id = ?').run('accepted', r.id);

  notify(req.app, target.id, req.user, 'friend_accepted', {
    body: 'принял(а) вашу заявку в друзья',
    url: `profile/${req.user.uid}`
  });
  emit(req.app.get('io'), target.id, 'friend:accepted', { actorUid: req.user.uid, actorName: req.user.name });
  res.json({ relation: 'friends' });
});

/* ---------- отменить / отклонить / удалить из друзей ---------- */
router.delete('/:id/friend', auth, (req, res) => {
  const target = findByIdOrUid('users', req.params.id);
  if (!target) return res.status(404).json({ error: 'Пользователь не найден' });

  const a = Math.min(req.userId, target.id);
  const b = Math.max(req.userId, target.id);
  db.prepare('DELETE FROM friendships WHERE user_a = ? AND user_b = ?').run(a, b);
  db.prepare('DELETE FROM friend_requests WHERE from_user = ? AND to_user = ?').run(req.userId, target.id);
  db.prepare('DELETE FROM friend_requests WHERE from_user = ? AND to_user = ?').run(target.id, req.userId);
  res.json({ relation: 'none' });
});

/* ---------- список друзей ---------- */
router.get('/list', auth, (req, res) => {
  const onlineUsers = req.app.get('onlineUsers');
  const rows = db
    .prepare(
      `SELECT u.id, f.created_at AS friend_since
       FROM friendships f
       JOIN users u ON u.id = CASE WHEN f.user_a = ? THEN f.user_b ELSE f.user_a END
       WHERE f.user_a = ? OR f.user_b = ?
       ORDER BY u.name`
    )
    .all(req.userId, req.userId, req.userId)
    .map((r) => {
      const u = db.prepare('SELECT * FROM users WHERE id = ?').get(r.id);
      return { ...publicUser(u), friend_since: r.friend_since, online: !!(onlineUsers && onlineUsers.has(r.id)) };
    });
  res.json({ friends: rows });
});

/* ---------- входящие и исходящие заявки ---------- */
router.get('/requests', auth, (req, res) => {
  const incoming = db
    .prepare(
      `SELECT u.id, u.uid, u.username, u.name, u.avatar, r.created_at
       FROM friend_requests r JOIN users u ON u.id = r.from_user
       WHERE r.to_user = ? AND r.status = 'pending' ORDER BY r.created_at DESC`
    )
    .all(req.userId)
    .map((r) => publicUser(r));
  const outgoing = db
    .prepare(
      `SELECT u.id, u.uid, u.username, u.name, u.avatar, r.created_at
       FROM friend_requests r JOIN users u ON u.id = r.to_user
       WHERE r.from_user = ? AND r.status = 'pending' ORDER BY r.created_at DESC`
    )
    .all(req.userId)
    .map((r) => publicUser(r));
  res.json({ incoming, outgoing });
});

/* ---------- личные имена (алиасы) ---------- */
router.get('/aliases', auth, (req, res) => {
  const rows = db
    .prepare(
      `SELECT c.contact_id, c.alias, u.uid, u.username, u.name, u.avatar
       FROM contact_aliases c JOIN users u ON u.id = c.contact_id
       WHERE c.owner_id = ? ORDER BY c.alias`
    )
    .all(req.userId);
  res.json({ aliases: rows });
});

router.put('/:id/alias', auth, (req, res) => {
  const target = findByIdOrUid('users', req.params.id);
  if (!target) return res.status(404).json({ error: 'Пользователь не найден' });
  if (target.id === req.userId) return res.status(400).json({ error: 'Нельзя дать имя самому себе' });
  const alias = sanitizeText(req.body.alias, 40);
  if (!alias) {
    db.prepare('DELETE FROM contact_aliases WHERE owner_id = ? AND contact_id = ?').run(req.userId, target.id);
    return res.json({ alias: '' });
  }
  db.prepare(
    'INSERT INTO contact_aliases (owner_id, contact_id, alias) VALUES (?, ?, ?) ' +
      'ON CONFLICT(owner_id, contact_id) DO UPDATE SET alias = excluded.alias'
  ).run(req.userId, target.id, alias);
  res.json({ alias });
});

router.delete('/:id/alias', auth, (req, res) => {
  const target = findByIdOrUid('users', req.params.id);
  if (!target) return res.status(404).json({ error: 'Пользователь не найден' });
  db.prepare('DELETE FROM contact_aliases WHERE owner_id = ? AND contact_id = ?').run(req.userId, target.id);
  res.json({ alias: '' });
});

module.exports = router;
