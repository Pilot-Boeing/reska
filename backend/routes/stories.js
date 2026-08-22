const express = require('express');
const { db } = require('../db');
const { auth } = require('../helpers');
const { uploadStory } = require('../upload');
const { randomUid } = require('../security');

const router = express.Router();

const STORY_TTL_HOURS = 24;

router.post('/', auth, uploadStory('media'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Файл не загружен' });
  const mediaType = String(req.file.mimetype).startsWith('image/') ? 'image' : 'video';
  const expires = new Date(Date.now() + STORY_TTL_HOURS * 3600 * 1000).toISOString();
  const r = db
    .prepare('INSERT INTO stories (uid, user_id, media, media_type, expires_at) VALUES (?, ?, ?, ?, ?)')
    .run(randomUid(), req.userId, `stories/${req.file.filename}`, mediaType, expires);
  res.status(201).json({ ok: true, id: Number(r.lastInsertRowid) });
});

router.get('/', auth, (req, res) => {
  const me = req.userId;
  const now = new Date().toISOString();
  const authors = db
    .prepare(
      `SELECT DISTINCT u.id, u.uid, u.username, u.name, u.avatar
       FROM users u
       LEFT JOIN follows f ON f.following_id = u.id AND f.user_id = ?
       LEFT JOIN friendships fr ON (fr.user_a = ? AND fr.user_b = u.id) OR (fr.user_a = u.id AND fr.user_b = ?)
       WHERE u.id = ? OR f.user_id IS NOT NULL OR fr.user_a IS NOT NULL`
    )
    .all(me, me, me, me);
  const groups = [];
  for (const a of authors) {
    const stories = db
      .prepare(
        `SELECT s.id, s.uid, s.media, s.media_type, s.created_at,
                (SELECT 1 FROM story_views v WHERE v.story_id = s.id AND v.user_id = ?) AS viewed
         FROM stories s WHERE s.user_id = ? AND s.expires_at > ? ORDER BY s.created_at ASC`
      )
      .all(me, a.id, now);
    if (!stories.length) continue;
    groups.push({
      user: { id: a.id, uid: a.uid, username: a.username, name: a.name, avatar: a.avatar },
      stories: stories.map((s) => ({ ...s, viewed: !!s.viewed }))
    });
  }
  res.json({ groups });
});

router.post('/:id/view', auth, (req, res) => {
  const id = Number(req.params.id);
  const story = db.prepare('SELECT id FROM stories WHERE id = ?').get(id);
  if (!story) return res.status(404).json({ error: 'Story не найдена' });
  db.prepare('INSERT OR IGNORE INTO story_views (story_id, user_id) VALUES (?, ?)').run(id, req.userId);
  res.json({ ok: true });
});

router.delete('/:id', auth, (req, res) => {
  const id = Number(req.params.id);
  const story = db.prepare('SELECT id, user_id FROM stories WHERE id = ?').get(id);
  if (!story) return res.status(404).json({ error: 'Story не найдена' });
  if (story.user_id !== req.userId) return res.status(403).json({ error: 'Нельзя удалить чужую story' });
  db.prepare('DELETE FROM stories WHERE id = ?').run(id);
  res.json({ ok: true });
});

module.exports = router;
