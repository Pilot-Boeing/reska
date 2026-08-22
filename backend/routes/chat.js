const express = require('express');
const fs = require('fs');
const path = require('path');
const { db, UPLOAD_DIR } = require('../db');
const { auth, publicUser, findByIdOrUid } = require('../helpers');
const { sanitizeText } = require('../validate');
const { randomUid } = require('../security');
const { log } = require('../logger');
const { notify } = require('../notif');
const { uploadChatMedia } = require('../upload');

const router = express.Router();

function chatForUser(id, userId) {
  const chat = findByIdOrUid('chats', id);
  if (!chat) return null;
  if (chat.kind === 'group') {
    if (chat.user_a === userId) return chat;
    const member = db.prepare('SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?').get(chat.id, userId);
    return member ? chat : null;
  }
  if (chat.user_a !== userId && chat.user_b !== userId) return null;
  return chat;
}

function otherIds(chat, userId) {
  if (chat.kind === 'group') {
    return db
      .prepare('SELECT user_id FROM chat_members WHERE chat_id = ? AND user_id != ?')
      .all(chat.id, userId)
      .map((r) => r.user_id);
  }
  const other = chat.user_a === userId ? chat.user_b : chat.user_a;
  return other ? [other] : [];
}

router.get('/', auth, (req, res) => {
  const me = req.userId;
  const rows = db
    .prepare(
      `SELECT c.id, c.uid, c.kind, c.group_id, c.user_a, c.created_at,
              u.id AS other_id, u.username, u.name, u.avatar,
              g.name AS group_name, g.description AS group_description,
              (SELECT COUNT(*) FROM chat_members cm WHERE cm.chat_id = c.id) AS member_count,
              (SELECT CASE
                 WHEN m.media_type = 'image' THEN '🖼 Фото'
                 WHEN m.media_type = 'video' THEN '🎬 Видео'
                 WHEN m.media_type = 'audio' THEN '🎤 Аудио'
                 WHEN m.media_type = 'round' THEN '⭕ Кружок'
                 WHEN m.media_type = 'file' THEN '📎 ' || COALESCE(m.media_name, 'Файл')
                 WHEN m.e2ee = 1 THEN '🔒 Зашифровано'
                 ELSE m.text END
                 FROM messages m WHERE m.chat_id = c.id ORDER BY m.id DESC LIMIT 1) AS last_text,
              (SELECT m.created_at FROM messages m WHERE m.chat_id = c.id
                 ORDER BY m.id DESC LIMIT 1) AS last_at,
              (SELECT COUNT(*) FROM messages m
                 WHERE m.chat_id = c.id AND m.sender_id != ? AND m.read = 0) AS unread
       FROM chats c
       LEFT JOIN users u ON u.id = CASE WHEN c.user_a = ? THEN c.user_b ELSE c.user_a END
       LEFT JOIN groups g ON g.id = c.group_id
       WHERE c.user_a = ? OR c.user_b = ? OR c.id IN (SELECT chat_id FROM chat_members WHERE user_id = ?)
       ORDER BY last_at DESC`
    )
    .all(me, me, me, me, me);
  res.json({
    chats: rows.map((r) => {
      const base = {
        id: r.id,
        uid: r.uid,
        kind: r.kind,
        created_at: r.created_at,
        last_text: r.last_text || '',
        last_at: r.last_at,
        unread: r.unread || 0
      };
      if (r.kind === 'group') {
        return {
          ...base,
          group_id: r.group_id,
          name: r.group_name || 'Группа',
          description: r.group_description || '',
          member_count: r.member_count || 1,
          is_owner: r.user_a === me
        };
      }
      return { ...base, other: publicUser(r) };
    })
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

  /* ---------- чат с самим собой (заметки/избранное) ---------- */
  router.post('/self', auth, (req, res) => {
    const existing = db.prepare('SELECT id, uid FROM chats WHERE user_a = ? AND user_b = ?').get(req.userId, req.userId);
    if (existing) return res.json({ chatId: existing.id, uid: existing.uid });
    const r = db.prepare('INSERT INTO chats (uid, user_a, user_b) VALUES (?, ?, ?)').run(randomUid(), req.userId, req.userId);
    const row = db.prepare('SELECT uid FROM chats WHERE id = ?').get(Number(r.lastInsertRowid));
    log('self_chat_create', { req, userId: req.userId });
    res.status(201).json({ chatId: Number(r.lastInsertRowid), uid: row.uid });
  });

  const MESSAGE_QUERY = `
  SELECT m.id, m.chat_id, m.sender_id, m.text, m.e2ee, m.read, m.edited, m.created_at,
         m.media, m.media_type, m.media_name, m.media_mime, m.media_size, m.media_duration,
         m.reply_to,
         u.uid AS sender_uid, u.username, u.name, u.avatar,
         r.id AS reply_id, ru.name AS reply_name, r.text AS reply_text, r.media_type AS reply_media
  FROM messages m JOIN users u ON u.id = m.sender_id
  LEFT JOIN messages r ON r.id = m.reply_to
  LEFT JOIN users ru ON ru.id = r.sender_id
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
  const reply = row.reply_id
    ? { id: row.reply_id, name: row.reply_name, text: row.reply_text, media_type: row.reply_media }
    : null;
  return { ...row, reactions, myEmoji, reply };
}

function socketFor(io, otherId) {
  return io ? io.to(`user:${otherId}`) : null;
}

router.post('/:id/typing', auth, (req, res) => {
  const chat = chatForUser(req.params.id, req.userId);
  if (!chat) return res.status(403).json({ error: 'Нет доступа к чату' });
  const io = req.app.get('io');
  if (io) {
    otherIds(chat, req.userId).forEach((id) =>
      io.to(`user:${id}`).emit('chat:typing', { chatId: chat.id, chatUid: chat.uid, userId: req.userId })
    );
  }
  res.json({ ok: true });
});

router.get('/:id/messages', auth, (req, res) => {
  const chat = chatForUser(req.params.id, req.userId);
  if (!chat) return res.status(403).json({ error: 'Нет доступа к чату' });
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 50, 1), 100);
  const before = req.query.before ? Number(req.query.before) : 0;
  const params = [chat.id];
  let sql = `${MESSAGE_QUERY} WHERE m.chat_id = ?`;
  if (before) { sql += ' AND m.id < ?'; params.push(before); }
  sql += ' ORDER BY m.id DESC LIMIT ' + (limit + 1);
  const rows = db.prepare(sql).all(...params);
  const hasMore = rows.length > limit;
  const page = (hasMore ? rows.slice(0, limit) : rows).reverse();
  res.json({ messages: page.map((row) => messageWithMeta(row, req.userId)), hasMore, chatUid: chat.uid });
});

router.post('/:id/messages', auth, (req, res, next) => {
  const chat = chatForUser(req.params.id, req.userId);
  if (!chat) return res.status(403).json({ error: 'Нет доступа к чату' });
  req.chat = chat;
  next();
}, uploadChatMedia('file'), (req, res) => {
  const chat = req.chat;

  const isGroup = chat.kind === 'group';
  const e2ee = !isGroup && (req.body.e2ee === true || req.body.e2ee === 1 || req.body.e2ee === '1') ? 1 : 0;
  let text;
  if (e2ee) {
    text = String(req.body.text || '').slice(0, 20000); // шифротекст не трогаем
  } else {
    text = sanitizeText(req.body.text, 4000);
  }

  const media = req.file ? `chats/${chat.id}/${req.file.filename}` : '';
  const mediaType = req.file ? mediaTypeFromMime(req.file.mimetype, req.body.kind) : '';
  const mediaName = req.file
    ? String(req.file.originalname || 'Файл').slice(0, 200)
    : '';
  const mediaMime = req.file ? req.file.mimetype : '';
  const mediaSize = req.file ? Number(req.file.size) || 0 : 0;
  const mediaDuration = Number(req.body.duration) || 0;

  if (!text && !media) return res.status(400).json({ error: 'Сообщение пустое' });
  if (req.file && req.file.error) {
    return res.status(400).json({ error: String(req.file.error) });
  }

  let replyTo = null;
  if (req.body.reply_to) {
    const orig = db.prepare('SELECT id, chat_id FROM messages WHERE id = ?').get(Number(req.body.reply_to));
    if (orig && orig.chat_id === chat.id) replyTo = orig.id;
  }

  const r = db
    .prepare(
      `INSERT INTO messages (chat_id, sender_id, text, e2ee, media, media_type, media_name, media_mime, media_size, media_duration, reply_to)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .run(chat.id, req.userId, text, e2ee, media, mediaType, mediaName, mediaMime, mediaSize, mediaDuration, replyTo);
  const message = messageWithMeta(
    db.prepare(`${MESSAGE_QUERY} WHERE m.id = ?`).get(Number(r.lastInsertRowid)),
    req.userId
  );

  const targets = otherIds(chat, req.userId);
  const io = req.app.get('io');
  const payload = { message, chatId: chat.id, chatUid: chat.uid };
  if (io) {
    io.to(`user:${req.userId}`).emit('chat:message', payload);
    targets.forEach((id) => io.to(`user:${id}`).emit('chat:message', payload));
  }
  const preview = mediaPreview(message, text);
  const title = isGroup
    ? (db.prepare('SELECT name FROM groups WHERE id = ?').get(chat.group_id) || {}).name || 'Группа'
    : req.user.name;
  targets.forEach((id) =>
    notify(req.app, id, req.user, 'message', {
      title: isGroup ? title : undefined,
      body: preview,
      url: `messages/${chat.uid}`
    })
  );
  log('message', { req, userId: req.userId, meta: { chatId: chat.id, e2ee, hasMedia: !!media } });
  res.status(201).json({ message });
});

function mediaTypeFromMime(mime, kind) {
  if (kind === 'round') return 'round';
  const m = String(mime || '').toLowerCase();
  if (m.startsWith('image/')) return 'image';
  if (m.startsWith('video/')) return 'video';
  if (m.startsWith('audio/')) return 'audio';
  if (m.startsWith('application/ogg')) return 'audio';
  return 'file';
}

function mediaPreview(message, rawText) {
  if (!message.media) {
    if (message.e2ee) return '🔒 Зашифрованное сообщение';
    const t = String(rawText || '');
    return t.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 100);
  }
  switch (message.media_type) {
    case 'image': return '🖼 Фото';
    case 'video': return '🎬 Видео';
    case 'audio': return '🎤 Аудио';
    case 'round': return '⭕ Кружок';
    default: return '📎 ' + (message.media_name || 'Файл');
  }
}

router.post('/:id/read', auth, (req, res) => {
  const chat = chatForUser(req.params.id, req.userId);
  if (!chat) return res.status(403).json({ error: 'Нет доступа к чату' });
  db.prepare(
    'UPDATE messages SET read = 1 WHERE chat_id = ? AND sender_id != ? AND read = 0'
  ).run(chat.id, req.userId);
  const io = req.app.get('io');
  if (io) otherIds(chat, req.userId).forEach((id) => io.to(`user:${id}`).emit('chat:read', { chatId: chat.id, readerId: req.userId }));
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
  const io = req.app.get('io');
  const payload = { message: updated, chatId: chat.id, chatUid: chat.uid, action: 'edit' };
  if (io) {
    io.to(`user:${req.userId}`).emit('chat:message', payload);
    otherIds(chat, req.userId).forEach((id) => io.to(`user:${id}`).emit('chat:message', payload));
  }
  log('message_edit', { req, userId: req.userId, meta: { chatId: chat.id, messageId: msg.id } });
  res.json({ message: updated });
});

function deleteMediaFile(relPath) {
  if (!relPath) return;
  const abs = path.join(UPLOAD_DIR, String(relPath).replace(/^\/+/, ''));
  if (abs.startsWith(UPLOAD_DIR) && fs.existsSync(abs)) {
    try { fs.unlinkSync(abs); } catch (e) {}
  }
}

router.delete('/:id/messages/:mid', auth, (req, res) => {
  const chat = chatForUser(req.params.id, req.userId);
  if (!chat) return res.status(403).json({ error: 'Нет доступа к чату' });
  const msg = db.prepare('SELECT * FROM messages WHERE id = ? AND chat_id = ?').get(Number(req.params.mid), chat.id);
  if (!msg) return res.status(404).json({ error: 'Сообщение не найдено' });
  if (msg.sender_id !== req.userId && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Нельзя удалить чужое сообщение' });
  }
  deleteMediaFile(msg.media);
  db.prepare('DELETE FROM message_reactions WHERE message_id = ?').run(msg.id);
  db.prepare('DELETE FROM messages WHERE id = ?').run(msg.id);
  const io = req.app.get('io');
  const payload = { messageId: msg.id, chatId: chat.id, chatUid: chat.uid, action: 'delete' };
  if (io) {
    io.to(`user:${req.userId}`).emit('chat:message', payload);
    otherIds(chat, req.userId).forEach((id) => io.to(`user:${id}`).emit('chat:message', payload));
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
  const io = req.app.get('io');
  const payload = { message: updated, chatId: chat.id, chatUid: chat.uid, action: 'reaction' };
  if (io) {
    io.to(`user:${req.userId}`).emit('chat:message', payload);
    otherIds(chat, req.userId).forEach((id) => io.to(`user:${id}`).emit('chat:message', payload));
  }
  res.json({ message: updated });
});

router.delete('/:id', auth, (req, res) => {
  const chat = findByIdOrUid('chats', req.params.id);
  if (!chat) return res.status(404).json({ error: 'Чат не найден' });
  const io = req.app.get('io');
  if (chat.kind === 'group') {
    if (chat.user_a !== req.userId) return res.status(403).json({ error: 'Только создатель удаляет группу' });
    const targets = otherIds(chat, req.userId);
    db.prepare('DELETE FROM chats WHERE id = ?').run(chat.id);
    db.prepare('DELETE FROM groups WHERE id = ?').run(chat.group_id);
    if (io) targets.forEach((id) => io.to(`user:${id}`).emit('chat:deleted', { chatId: chat.id, chatUid: chat.uid }));
    log('group_delete', { req, userId: req.userId, meta: { groupId: chat.group_id } });
  } else {
    if (chat.user_a !== req.userId && chat.user_b !== req.userId) {
      return res.status(403).json({ error: 'Нет доступа к чату' });
    }
    const targets = otherIds(chat, req.userId);
    db.prepare('DELETE FROM chats WHERE id = ?').run(chat.id);
    if (io) targets.forEach((id) => io.to(`user:${id}`).emit('chat:deleted', { chatId: chat.id, chatUid: chat.uid }));
    log('chat_delete', { req, userId: req.userId, meta: { chatId: chat.id } });
  }
  res.json({ ok: true });
});

module.exports = router;
