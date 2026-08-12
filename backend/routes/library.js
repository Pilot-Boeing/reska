const express = require('express');
const { db } = require('../db');
const { auth } = require('../helpers');
const { sanitizeText } = require('../validate');
const { randomUid } = require('../security');

const router = express.Router();
const iso = () => new Date().toISOString();

function noteRow(r) {
  return { id: r.id, uid: r.uid, title: r.title, body: r.body, created_at: r.created_at, updated_at: r.updated_at };
}
function groupRow(r) {
  return { id: r.id, uid: r.uid, name: r.name, description: r.description, created_at: r.created_at, updated_at: r.updated_at };
}

/* =========================================================
   КОНСПЕКТЫ
   ========================================================= */
router.get('/notes', auth, (req, res) => {
  const rows = db.prepare('SELECT * FROM notes WHERE user_id = ? ORDER BY updated_at DESC').all(req.userId);
  res.json({ notes: rows.map(noteRow) });
});

router.post('/notes', auth, (req, res) => {
  const title = sanitizeText(req.body.title, 120);
  const body = sanitizeText(req.body.body, 20000);
  if (!title) return res.status(400).json({ error: 'Укажите заголовок' });
  const ts = iso();
  const r = db
    .prepare('INSERT INTO notes (uid, user_id, title, body, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(randomUid(), req.userId, title, body, ts, ts);
  res.status(201).json({ note: noteRow(db.prepare('SELECT * FROM notes WHERE id = ?').get(Number(r.lastInsertRowid))) });
});

router.put('/notes/:id', auth, (req, res) => {
  const n = db.prepare('SELECT * FROM notes WHERE id = ?').get(Number(req.params.id));
  if (!n) return res.status(404).json({ error: 'Конспект не найден' });
  if (n.user_id !== req.userId) return res.status(403).json({ error: 'Чужая заметка' });
  const title = sanitizeText(req.body.title, 120);
  const body = sanitizeText(req.body.body, 20000);
  if (!title) return res.status(400).json({ error: 'Укажите заголовок' });
  db.prepare("UPDATE notes SET title = ?, body = ?, updated_at = ? WHERE id = ?").run(title, body, iso(), n.id);
  res.json({ note: noteRow(db.prepare('SELECT * FROM notes WHERE id = ?').get(n.id)) });
});

router.delete('/notes/:id', auth, (req, res) => {
  const n = db.prepare('SELECT * FROM notes WHERE id = ?').get(Number(req.params.id));
  if (!n) return res.status(404).json({ error: 'Конспект не найден' });
  if (n.user_id !== req.userId) return res.status(403).json({ error: 'Чужая заметка' });
  db.prepare('DELETE FROM notes WHERE id = ?').run(n.id);
  res.json({ ok: true });
});

/* =========================================================
   ГРУППЫ
   ========================================================= */
router.get('/groups', auth, (req, res) => {
  const rows = db.prepare('SELECT * FROM groups WHERE user_id = ? ORDER BY updated_at DESC').all(req.userId);
  res.json({ groups: rows.map(groupRow) });
});

router.post('/groups', auth, (req, res) => {
  const name = sanitizeText(req.body.name, 80);
  const description = sanitizeText(req.body.description, 2000);
  if (!name) return res.status(400).json({ error: 'Укажите название' });
  const ts = iso();
  const r = db
    .prepare('INSERT INTO groups (uid, user_id, name, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(randomUid(), req.userId, name, description, ts, ts);
  res.status(201).json({ group: groupRow(db.prepare('SELECT * FROM groups WHERE id = ?').get(Number(r.lastInsertRowid))) });
});

router.put('/groups/:id', auth, (req, res) => {
  const g = db.prepare('SELECT * FROM groups WHERE id = ?').get(Number(req.params.id));
  if (!g) return res.status(404).json({ error: 'Группа не найдена' });
  if (g.user_id !== req.userId) return res.status(403).json({ error: 'Чужая группа' });
  const name = sanitizeText(req.body.name, 80);
  const description = sanitizeText(req.body.description, 2000);
  if (!name) return res.status(400).json({ error: 'Укажите название' });
  db.prepare("UPDATE groups SET name = ?, description = ?, updated_at = ? WHERE id = ?").run(name, description, iso(), g.id);
  res.json({ group: groupRow(db.prepare('SELECT * FROM groups WHERE id = ?').get(g.id)) });
});

router.delete('/groups/:id', auth, (req, res) => {
  const g = db.prepare('SELECT * FROM groups WHERE id = ?').get(Number(req.params.id));
  if (!g) return res.status(404).json({ error: 'Группа не найдена' });
  if (g.user_id !== req.userId) return res.status(403).json({ error: 'Чужая группа' });
  db.prepare('DELETE FROM groups WHERE id = ?').run(g.id);
  res.json({ ok: true });
});

module.exports = router;
