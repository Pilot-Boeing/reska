const express = require('express');
const { db } = require('../db');
const { auth, publicUser, findByIdOrUid } = require('../helpers');
const { sanitizeText } = require('../validate');
const { randomUid } = require('../security');
const { log } = require('../logger');

const router = express.Router();

function chatForUser(id, userId) {
  const chat = findByIdOrUid('chats', id);
  if (!chat) return null;
  if (chat.user_a !== userId && chat.user_b !== userId) return null;
  return chat;
}

router.get('/', auth, (req, res) => {
  const me = req.userId;
  const rows = db
    .prepare(
      `SELECT c.id, c.uid, c.created_at,
              u.id AS other_id, u.username, u.name, u.avatar,
              (SELECT CASE WHEN m.e2ee = 1 THEN '🔒 Зашифровано' ELSE m.text END
                 FROM messages m WHERE m.chat_id = c.id ORDER BY m.id DESC LIMIT 1) AS last_text,
              (SELECT m.created_at FROM messages m WHERE m.chat_id = c.id
                 ORDER BY m.id DESC LIMIT 1) AS last_at,
              (SELECT COUNT(*) FROM messages m
                 WHERE m.chat_id = c.id AND m.sender_id != ? AND m.read = 0) AS unread
       FROM chats c
       JOIN users u ON u.id = CASE WHEN c.user_a = ? THEN c.user_b ELSE c.user_a END
       WHERE c.user_a = ? OR c.user_b = ?
       ORDER BY last_at DESC`
    )
    .all(me, me, me, me);
  res.json({
    chats: rows.map((r) => ({
      id: r.id,
      uid: r.uid,
      created_at: r.created_at,
      other: publicUser(r),
      last_text: r.last_text || '',
      last_at: r.last_at,
      unread: r.unread || 0
    }))
  });
});

router.post('/', auth, (req, res) => {
  const otherId = Number(req.body.user_id);
  if (!otherId || otherId === req.userId) {
    return res.status(400).json({ error: 'Некорректный собеседник' });
  }
  const other = db.prepare('SELECT id FROM users WHERE id = ?').get(otherId);
  if (!other) return res.status(404).json({ error: 'Пользователь не найден' });

  const [a, b] = req.userId < otherId ? [req.userId, otherId] : [otherId, req.userId];
  const existing = db.prepare('SELECT id, uid FROM chats WHERE user_a = ? AND user_b = ?').get(a, b);
  if (existing) return res.json({ chatId: existing.id, uid: existing.uid });

  const r = db.prepare('INSERT INTO chats (uid, user_a, user_b) VALUES (?, ?, ?)').run(randomUid(), a, b);
  const row = db.prepare('SELECT uid FROM chats WHERE id = ?').get(Number(r.lastInsertRowid));
  res.status(201).json({ chatId: Number(r.lastInsertRowid), uid: row.uid });
});

const MESSAGE_QUERY = `
  SELECT m.id, m.chat_id, m.sender_id, m.text, m.e2ee, m.read, m.edited, m.created_at,
         u.username, u.name, u.avatar
  FROM messages m JOIN users u ON u.id = m.sender_id
`;

function reactionsFor(messageId) {
  const rows = db
    .prepare('SELECT emoji, COUNT(*) AS n FROM message_reactions WHERE message_id = ? GROUP BY emoji')
    .all(messageId);
  return rows.map((r) => ({ emoji: r.emoji, count: r.n }));
}

function messageWithMeta(row, userId) {
  if (!row) return null;
  const reactions = reactionsFor(row.id);
  const myEmoji = db
    .prepare('SELECT emoji FROM message_reactions WHERE message_id = ? AND user_id = ?')
    .all(row.id, userId)
    .map((r) => r.emoji);
  return { ...row, reactions, myEmoji };
}

function socketFor(io, otherId) {
  return io ? io.to(`user:${otherId}`) : null;
}

router.post('/:id/typing', auth, (req, res) => {
  const chat = chatForUser(req.params.id, req.userId);
  if (!chat) return res.status(403).json({ error: 'Нет доступа к чату' });
  const otherId = chat.user_a === req.userId ? chat.user_b : chat.user_a;
  const io = req.app.get('io');
  if (io) io.to(`user:${otherId}`).emit('chat:typing', { chatId: chat.id, chatUid: chat.uid, userId: req.userId });
  res.json({ ok: true });
});

router.get('/:id/messages', auth, (req, res) => {
  const chat = chatForUser(req.params.id, req.userId);
  if (!chat) return res.status(403).json({ error: 'Нет доступа к чату' });
  const messages = db
    .prepare(`${MESSAGE_QUERY} WHERE m.chat_id = ? ORDER BY m.id ASC`)
    .all(chat.id)
    .map((row) => messageWithMeta(row, req.userId));
  res.json({ messages, chatUid: chat.uid });
});

router.post('/:id/messages', auth, (req, res) => {
  const chat = chatForUser(req.params.id, req.userId);
  if (!chat) return res.status(403).json({ error: 'Нет доступа к чату' });

  const e2ee = req.body.e2ee === true || req.body.e2ee === 1 || req.body.e2ee === '1' ? 1 : 0;
  let text;
  if (e2ee) {
    text = String(req.body.text || '').slice(0, 20000); // шифротекст не трогаем
  } else {
    text = sanitizeText(req.body.text, 4000);
  }
  if (!text) return res.status(400).json({ error: 'Сообщение пустое' });

  const r = db
    .prepare('INSERT INTO messages (chat_id, sender_id, text, e2ee) VALUES (?, ?, ?, ?)')
    .run(chat.id, req.userId, text, e2ee);
  const message = messageWithMeta(
    db.prepare(`${MESSAGE_QUERY} WHERE m.id = ?`).get(Number(r.lastInsertRowid)),
    req.userId
  );

  const otherId = chat.user_a === req.userId ? chat.user_b : chat.user_a;
  const io = req.app.get('io');
  const payload = { message, chatId: chat.id, chatUid: chat.uid, otherId };
  if (io) {
    io.to(`user:${req.userId}`).emit('chat:message', payload);
    io.to(`user:${otherId}`).emit('chat:message', payload);
  }
  log('message', { req, userId: req.userId, meta: { chatId: chat.id, e2ee } });
  res.status(201).json({ message });
});

router.post('/:id/read', auth, (req, res) => {
  const chat = chatForUser(req.params.id, req.userId);
  if (!chat) return res.status(403).json({ error: 'Нет доступа к чату' });
  db.prepare(
    'UPDATE messages SET read = 1 WHERE chat_id = ? AND sender_id != ? AND read = 0'
  ).run(chat.id, req.userId);
  const otherId = chat.user_a === req.userId ? chat.user_b : chat.user_a;
  const io = req.app.get('io');
  if (io) io.to(`user:${otherId}`).emit('chat:read', { chatId: chat.id, readerId: req.userId });
  res.json({ ok: true });
});

router.patch('/:id/messages/:mid', auth, (req, res) => {
  const chat = chatForUser(req.params.id, req.userId);
  if (!chat) return res.status(403).json({ error: 'Нет доступа к чату' });
  const msg = db.prepare('SELECT * FROM messages WHERE id = ? AND chat_id = ?').get(Number(req.params.mid), chat.id);
  if (!msg) return res.status(404).json({ error: 'Сообщение не найдено' });
  if (msg.sender_id !== req.userId) return res.status(403).json({ error: 'Нельзя редактировать чужое сообщение' });

  const e2ee = msg.e2ee === 1;
  let text;
  if (e2ee) text = String(req.body.text || '').slice(0, 20000);
  else {
    text = sanitizeText(req.body.text, 4000);
    if (!text) return res.status(400).json({ error: 'Сообщение пустое' });
  }
  db.prepare('UPDATE messages SET text = ?, edited = 1 WHERE id = ?').run(text, msg.id);
  const updated = messageWithMeta(
    db.prepare(`${MESSAGE_QUERY} WHERE m.id = ?`).get(msg.id),
    req.userId
  );
  const otherId = chat.user_a === req.userId ? chat.user_b : chat.user_a;
  const io = req.app.get('io');
  const payload = { message: updated, chatId: chat.id, chatUid: chat.uid, otherId, action: 'edit' };
  if (io) {
    io.to(`user:${req.userId}`).emit('chat:message', payload);
    io.to(`user:${otherId}`).emit('chat:message', payload);
  }
  log('message_edit', { req, userId: req.userId, meta: { chatId: chat.id, messageId: msg.id } });
  res.json({ message: updated });
});

router.delete('/:id/messages/:mid', auth, (req, res) => {
  const chat = chatForUser(req.params.id, req.userId);
  if (!chat) return res.status(403).json({ error: 'Нет доступа к чату' });
  const msg = db.prepare('SELECT * FROM messages WHERE id = ? AND chat_id = ?').get(Number(req.params.mid), chat.id);
  if (!msg) return res.status(404).json({ error: 'Сообщение не найдено' });
  if (msg.sender_id !== req.userId && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Нельзя удалить чужое сообщение' });
  }
  db.prepare('DELETE FROM message_reactions WHERE message_id = ?').run(msg.id);
  db.prepare('DELETE FROM messages WHERE id = ?').run(msg.id);
  const otherId = chat.user_a === req.userId ? chat.user_b : chat.user_a;
  const io = req.app.get('io');
  const payload = { messageId: msg.id, chatId: chat.id, chatUid: chat.uid, otherId, action: 'delete' };
  if (io) {
    io.to(`user:${req.userId}`).emit('chat:message', payload);
    io.to(`user:${otherId}`).emit('chat:message', payload);
  }
  log('message_delete', { req, userId: req.userId, meta: { chatId: chat.id, messageId: msg.id } });
  res.json({ ok: true });
});

router.post('/:id/messages/:mid/reaction', auth, (req, res) => {
  const chat = chatForUser(req.params.id, req.userId);
  if (!chat) return res.status(403).json({ error: 'Нет доступа к чату' });
  const msg = db.prepare('SELECT id FROM messages WHERE id = ? AND chat_id = ?').get(Number(req.params.mid), chat.id);
  if (!msg) return res.status(404).json({ error: 'Сообщение не найдено' });
  const emoji = String(req.body.emoji || '').trim().slice(0, 8);
  if (!emoji) return res.status(400).json({ error: 'Нет эмодзи' });

  db.prepare('INSERT OR IGNORE INTO message_reactions (message_id, user_id, emoji) VALUES (?, ?, ?)').run(msg.id, req.userId, emoji);
  const updated = messageWithMeta(
    db.prepare(`${MESSAGE_QUERY} WHERE m.id = ?`).get(msg.id),
    req.userId
  );
  const otherId = chat.user_a === req.userId ? chat.user_b : chat.user_a;
  const io = req.app.get('io');
  const payload = { message: updated, chatId: chat.id, chatUid: chat.uid, otherId, action: 'reaction' };
  if (io) {
    io.to(`user:${req.userId}`).emit('chat:message', payload);
    io.to(`user:${otherId}`).emit('chat:message', payload);
  }
  res.json({ message: updated });
});

module.exports = router;
