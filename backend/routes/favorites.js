const express = require('express');
const { db } = require('../db');
const { auth, publicUser } = require('../helpers');

const router = express.Router();

const ITEM_TYPES = ['post', 'video', 'user'];
const iso = () => new Date().toISOString();

function rowToFav(r) {
  const f = {
    id: r.id,
    item_type: r.item_type,
    item_id: r.item_id,
    created_at: r.created_at,
    type: r.item_type
  };
  if (r.item_type === 'post') {
    const p = db.prepare('SELECT uid, text, media_type AS mediaType FROM posts WHERE uid = ?').get(r.item_id);
    const u = db.prepare('SELECT id, uid, username, name, avatar FROM users WHERE id = (SELECT user_id FROM posts WHERE uid = ?)').get(r.item_id);
    f.uid = p ? p.uid : r.item_id;
    f.text = p ? p.text : '';
    f.author_uid = u ? u.uid : '';
    f.author = u ? u.name : '';
    f.author_username = u ? u.username : '';
    f.avatar = u ? u.avatar : '';
  } else if (r.item_type === 'video') {
    const v = db.prepare('SELECT uid, title, thumb FROM videos WHERE uid = ?').get(r.item_id);
    const u = db.prepare('SELECT uid, username, name, avatar FROM users WHERE id = (SELECT user_id FROM videos WHERE uid = ?)').get(r.item_id);
    f.uid = v ? v.uid : r.item_id;
    f.title = v ? v.title : '';
    f.thumb = v ? v.thumb : '';
    f.author_uid = u ? u.uid : '';
    f.author = u ? u.name : '';
    f.author_username = u ? u.username : '';
    f.avatar = u ? u.avatar : '';
  } else if (r.item_type === 'user') {
    const u = db.prepare('SELECT id, uid, username, name, avatar FROM users WHERE uid = ?').get(r.item_id);
    f.uid = u ? u.uid : r.item_id;
    f.name = u ? u.name : '';
    f.username = u ? u.username : '';
    f.avatar = u ? u.avatar : '';
  }
  return f;
}

function itemExists(itemType, itemId) {
  if (itemType === 'post') return db.prepare('SELECT 1 FROM posts WHERE uid = ?').get(itemId);
  if (itemType === 'video') return db.prepare('SELECT 1 FROM videos WHERE uid = ?').get(itemId);
  if (itemType === 'user') return db.prepare('SELECT 1 FROM users WHERE uid = ?').get(itemId);
  return null;
}

/* ---------- список избранного ---------- */
router.get('/', auth, (req, res) => {
  const rows = db
    .prepare('SELECT * FROM favorites WHERE user_id = ? ORDER BY created_at DESC')
    .all(req.userId);
  res.json({ favorites: rows.map(rowToFav) });
});

/* ---------- добавить в избранное ---------- */
router.post('/', auth, (req, res) => {
  const itemType = String(req.body.item_type || '').trim();
  const itemId = String(req.body.item_id || '').trim();
  if (!ITEM_TYPES.includes(itemType)) return res.status(400).json({ error: 'Некорректный тип' });
  if (!itemId) return res.status(400).json({ error: 'Укажите item_id' });
  if (!itemExists(itemType, itemId)) return res.status(404).json({ error: 'Объект не найден' });

  const existing = db
    .prepare('SELECT * FROM favorites WHERE user_id = ? AND item_type = ? AND item_id = ?')
    .get(req.userId, itemType, itemId);
  if (existing) return res.status(200).json({ favorite: rowToFav(existing), created: false });

  const r = db
    .prepare('INSERT INTO favorites (user_id, item_type, item_id, created_at) VALUES (?, ?, ?, ?)')
    .run(req.userId, itemType, itemId, iso());
  const row = db.prepare('SELECT * FROM favorites WHERE id = ?').get(Number(r.lastInsertRowid));
  res.status(201).json({ favorite: rowToFav(row), created: true });
});

/* ---------- удалить из избранного ---------- */
router.delete('/:id', auth, (req, res) => {
  const id = Number(req.params.id);
  const row = db.prepare('SELECT * FROM favorites WHERE id = ? AND user_id = ?').get(id, req.userId);
  if (!row) return res.status(404).json({ error: 'Не найдено' });
  db.prepare('DELETE FROM favorites WHERE id = ?').run(id);
  res.json({ ok: true });
});

module.exports = router;
