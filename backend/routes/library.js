const express = require('express');
const { db } = require('../db');
const { auth, publicUser } = require('../helpers');
const { sanitizeText } = require('../validate');
const { randomUid } = require('../security');

const router = express.Router();
const iso = () => new Date().toISOString();

function groupRow(r) {
  return {
    id: r.id,
    uid: r.uid,
    name: r.name,
    description: r.description,
    chatUid: r.chat_uid || '',
    member_count: r.member_count || 1,
    created_at: r.created_at,
    updated_at: r.updated_at
  };
}

function groupById(id) {
  return db.prepare('SELECT * FROM groups WHERE id = ?').get(Number(id));
}
function groupForUser(id, userId) {
  const g = groupById(id);
  if (!g) return null;
  if (g.user_id === userId) return g;
  const chat = db.prepare('SELECT id FROM chats WHERE group_id = ?').get(g.id);
  if (chat) {
    const m = db.prepare('SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?').get(chat.id, userId);
    if (m) return g;
  }
  return null;
}
function chatForGroup(groupId) {
  return db.prepare('SELECT id, uid FROM chats WHERE group_id = ?').get(groupId);
}

/* =========================================================
   ГРУППЫ (создание группового чата и состав)
   ========================================================= */
router.post('/groups', auth, (req, res) => {
  const name = sanitizeText(req.body.name, 80);
  const description = sanitizeText(req.body.description, 2000);
  if (!name) return res.status(400).json({ error: 'Укажите название' });
  const ts = iso();
  const r = db
    .prepare('INSERT INTO groups (uid, user_id, name, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(randomUid(), req.userId, name, description, ts, ts);
  const gid = Number(r.lastInsertRowid);
  const chat = db
    .prepare("INSERT INTO chats (uid, user_a, user_b, kind, group_id) VALUES (?, ?, NULL, 'group', ?)")
    .run(randomUid(), req.userId, gid);
  const chatId = Number(chat.lastInsertRowid);
  db.prepare("INSERT OR IGNORE INTO chat_members (chat_id, user_id, role) VALUES (?, ?, 'owner')").run(chatId, req.userId);
  const members = Array.isArray(req.body.members) ? req.body.members : [];
  const ins = db.prepare('INSERT OR IGNORE INTO chat_members (chat_id, user_id, role) VALUES (?, ?, ?)');
  for (const mid of members.slice(0, 50)) {
    const id = Number(mid);
    if (id && id !== req.userId) ins.run(chatId, id, 'member');
  }
  const row = db
    .prepare(
      `SELECT g.*, c.uid AS chat_uid,
              (SELECT COUNT(*) FROM chat_members cm WHERE cm.chat_id = c.id) AS member_count
       FROM groups g JOIN chats c ON c.group_id = g.id WHERE g.id = ?`
    )
    .get(gid);
  res.status(201).json({ group: groupRow(row) });
});

/* ---------- состав группы ---------- */
router.get('/groups/:id/members', auth, (req, res) => {
  const g = groupForUser(req.params.id, req.userId);
  if (!g) return res.status(404).json({ error: 'Группа не найдена' });
  const chat = chatForGroup(g.id);
  const members = db
    .prepare(
      `SELECT u.id, u.uid, u.username, u.name, u.avatar, u.status, cm.role, cm.created_at
       FROM chat_members cm JOIN users u ON u.id = cm.user_id
       WHERE cm.chat_id = ? ORDER BY cm.role = 'owner' DESC, u.name ASC`
    )
    .all(chat.id)
    .map((m) => ({ ...publicUser(m), role: m.role }));
  res.json({ members });
});

router.post('/groups/:id/members', auth, (req, res) => {
  const g = groupForUser(req.params.id, req.userId);
  if (!g) return res.status(404).json({ error: 'Группа не найдена' });
  if (g.user_id !== req.userId) return res.status(403).json({ error: 'Только создатель добавляет участников' });
  const userId = Number(req.body.user_id);
  if (!userId) return res.status(400).json({ error: 'Некорректный пользователь' });
  const u = db.prepare('SELECT id FROM users WHERE id = ?').get(userId);
  if (!u) return res.status(404).json({ error: 'Пользователь не найден' });
  const chat = chatForGroup(g.id);
  db.prepare('INSERT OR IGNORE INTO chat_members (chat_id, user_id, role) VALUES (?, ?, ?)').run(chat.id, userId, 'member');
  res.json({ ok: true });
});

router.delete('/groups/:id/members/:userId', auth, (req, res) => {
  const g = groupForUser(req.params.id, req.userId);
  if (!g) return res.status(404).json({ error: 'Группа не найдена' });
  if (g.user_id !== req.userId) return res.status(403).json({ error: 'Только создатель исключает участников' });
  const uid = Number(req.params.userId);
  if (uid === g.user_id) return res.status(400).json({ error: 'Нельзя исключить создателя' });
  const chat = chatForGroup(g.id);
  db.prepare('DELETE FROM chat_members WHERE chat_id = ? AND user_id = ?').run(chat.id, uid);
  res.json({ ok: true });
});

module.exports = router;
