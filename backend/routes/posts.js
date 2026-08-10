const express = require('express');
const fs = require('fs');
const path = require('path');
const { db, UPLOAD_DIR, POST_DIR } = require('../db');
const { uploadPostMedia } = require('../upload');
const { auth, publicUser, commentsFor, findByIdOrUid } = require('../helpers');
const { sanitizeText } = require('../validate');
const { randomUid } = require('../security');
const { log } = require('../logger');

const router = express.Router();

const POST_QUERY = `
  SELECT p.id, p.uid, p.text, p.media, p.media_type, p.created_at,
         p.user_id, u.uid AS author_uid, u.username, u.name, u.avatar,
         (SELECT COUNT(*) FROM post_likes pl WHERE pl.post_id = p.id) AS likes,
         (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id) AS comments
  FROM posts p JOIN users u ON u.id = p.user_id
`;

function postWithMeta(row, userId) {
  if (!row) return null;
  const liked = userId
    ? !!db.prepare('SELECT 1 FROM post_likes WHERE post_id = ? AND user_id = ?').get(row.id, userId)
    : false;
  return { ...row, liked };
}

function deleteMedia(relPath) {
  if (!relPath) return;
  const abs = path.join(UPLOAD_DIR, String(relPath).replace(/^\/+/, ''));
  if (abs.startsWith(UPLOAD_DIR) && fs.existsSync(abs)) {
    try { fs.unlinkSync(abs); } catch (e) {}
  }
}

router.get('/', (req, res) => {
  const userId = req.userId || null;
  const rows = db.prepare(`${POST_QUERY} ORDER BY p.created_at DESC, p.id DESC`).all();
  res.json({ posts: rows.map((r) => postWithMeta(r, userId)) });
});

router.post('/', auth, uploadPostMedia('media'), (req, res) => {
  const text = sanitizeText(req.body.text, 5000);
  let media = '';
  let mediaType = '';
  if (req.file) {
    media = `posts/${req.file.filename}`;
    mediaType = String(req.file.mimetype).startsWith('image/') ? 'image' : 'video';
  }
  if (!text && !media) return res.status(400).json({ error: 'Пост не может быть пустым' });

  const r = db
    .prepare('INSERT INTO posts (uid, user_id, text, media, media_type) VALUES (?, ?, ?, ?, ?)')
    .run(randomUid(), req.userId, text, media, mediaType);
  const row = db.prepare(`${POST_QUERY} WHERE p.id = ?`).get(Number(r.lastInsertRowid));
  log('post_create', { req, userId: req.userId, meta: { postId: row.id, hasMedia: !!media } });
  res.status(201).json({ post: postWithMeta(row, req.userId) });
});

router.delete('/:id', auth, (req, res) => {
  const post = findByIdOrUid('posts', req.params.id);
  if (!post) return res.status(404).json({ error: 'Пост не найден' });
  if (post.user_id !== req.userId && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Нельзя удалить чужой пост' });
  }
  deleteMedia(post.media);
  db.prepare('DELETE FROM posts WHERE id = ?').run(post.id);
  log('post_delete', { req, userId: req.userId, meta: { postId: post.id } });
  res.json({ ok: true });
});

router.post('/:id/like', auth, (req, res) => {
  const id = targetId('posts', req.params.id);
  if (!id) return res.status(404).json({ error: 'Пост не найден' });
  db.prepare('INSERT OR IGNORE INTO post_likes (post_id, user_id) VALUES (?, ?)').run(id, req.userId);
  const n = db.prepare('SELECT COUNT(*) AS n FROM post_likes WHERE post_id = ?').get(id).n;
  res.json({ liked: true, likes: n });
});

router.delete('/:id/like', auth, (req, res) => {
  const id = targetId('posts', req.params.id);
  if (!id) return res.status(404).json({ error: 'Пост не найден' });
  db.prepare('DELETE FROM post_likes WHERE post_id = ? AND user_id = ?').run(id, req.userId);
  const n = db.prepare('SELECT COUNT(*) AS n FROM post_likes WHERE post_id = ?').get(id).n;
  res.json({ liked: false, likes: n });
});

function targetId(type, p) {
  const item = findByIdOrUid(type, p);
  return item ? item.id : null;
}


router.get('/:id/comments', (req, res) => {
  const p = findByIdOrUid('posts', req.params.id);
  if (!p) return res.status(404).json({ error: 'Пост не найден' });
  res.json({ comments: commentsFor('post_id', p.id) });
});

router.post('/:id/comments', auth, (req, res) => {
  const post = findByIdOrUid('posts', req.params.id);
  if (!post) return res.status(404).json({ error: 'Пост не найден' });
  const text = sanitizeText(req.body.text, 2000);
  if (!text) return res.status(400).json({ error: 'Комментарий пустой' });
  const parentId = req.body.parent_id ? Number(req.body.parent_id) : null;
  if (parentId) {
    const parent = db
      .prepare('SELECT id FROM comments WHERE id = ? AND post_id = ?')
      .get(parentId, post.id);
    if (!parent) return res.status(400).json({ error: 'Ответ на несуществующий комментарий' });
  }
  const r = db
    .prepare('INSERT INTO comments (uid, post_id, user_id, text, parent_id) VALUES (?, ?, ?, ?, ?)')
    .run(randomUid(), post.id, req.userId, text, parentId);
  const row = db
    .prepare(
      `SELECT c.id, c.uid, c.text, c.parent_id, c.created_at, c.user_id,
              u.username, u.name, u.avatar
       FROM comments c JOIN users u ON u.id = c.user_id WHERE c.id = ?`
    )
    .get(Number(r.lastInsertRowid));
  res.status(201).json({ comment: row });
});

module.exports = router;
