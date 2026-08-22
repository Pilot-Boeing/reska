const express = require('express');
const fs = require('fs');
const path = require('path');
const { db, UPLOAD_DIR, POST_DIR } = require('../db');
const { uploadPostMedia } = require('../upload');
const { auth, publicUser, commentsFor, findByIdOrUid } = require('../helpers');
const { sanitizeText } = require('../validate');
const { randomUid } = require('../security');
const { log } = require('../logger');
const { notify, notifyFollowers } = require('../notif');

const router = express.Router();

const POST_QUERY = `
  SELECT p.id, p.uid, p.text, p.media, p.media_type, p.created_at,
         p.user_id, p.repost_of,
         u.uid AS author_uid, u.username, u.name, u.avatar,
         (SELECT COUNT(*) FROM post_likes pl WHERE pl.post_id = p.id) AS likes,
         (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id) AS comments,
         rp.id AS r_id, ru.name AS r_name, ru.username AS r_username, ru.avatar AS r_avatar,
         rp.text AS r_text, rp.media AS r_media, rp.media_type AS r_media_type
  FROM posts p JOIN users u ON u.id = p.user_id
  LEFT JOIN posts rp ON rp.id = p.repost_of
  LEFT JOIN users ru ON ru.id = rp.user_id
`;

function postWithMeta(row, userId) {
  if (!row) return null;
  const liked = userId
    ? !!db.prepare('SELECT 1 FROM post_likes WHERE post_id = ? AND user_id = ?').get(row.id, userId)
    : false;
  const reactions = userId
    ? getReactions('post_reactions', 'post_id', row.id, userId)
    : getReactions('post_reactions', 'post_id', row.id, null);
  const repost = row.r_id
    ? { id: row.r_id, name: row.r_name, username: row.r_username, avatar: row.r_avatar, text: row.r_text, media: row.r_media, media_type: row.r_media_type }
    : null;
  return { ...row, liked, reactions, repost };
}

function getReactions(table, col, id, userId) {
  const agg = db
    .prepare(`SELECT emoji, COUNT(*) AS n FROM ${table} WHERE ${col} = ? GROUP BY emoji ORDER BY n DESC, emoji`)
    .all(id);
  let myEmoji = [];
  if (userId) {
    myEmoji = db.prepare(`SELECT emoji FROM ${table} WHERE ${col} = ? AND user_id = ?`).all(id, userId).map((r) => r.emoji);
  }
  return { list: agg.map((r) => ({ emoji: r.emoji, count: r.n })), myEmoji };
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
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 10, 1), 50);
  const before = req.query.before ? Number(req.query.before) : 0;
  const where = before ? `WHERE p.id < ${before}` : '';
  const rows = db
    .prepare(`${POST_QUERY} ${where} ORDER BY p.created_at DESC, p.id DESC LIMIT ${limit + 1}`)
    .all();
  const hasMore = rows.length > limit;
  const page = hasMore ? rows.slice(0, limit) : rows;
  res.json({ posts: page.map((r) => postWithMeta(r, userId)), hasMore });
});

router.post('/', auth, uploadPostMedia('media'), (req, res) => {
  const repostOf = Number(req.body.repost_of) || 0;
  let text = sanitizeText(req.body.text, 5000);
  let media = '';
  let mediaType = '';
  if (req.file) {
    media = `posts/${req.file.filename}`;
    mediaType = String(req.file.mimetype).startsWith('image/') ? 'image' : 'video';
  }
  if (repostOf) {
    const orig = db.prepare('SELECT id FROM posts WHERE id = ?').get(repostOf);
    if (!orig) return res.status(404).json({ error: 'Оригинальный пост не найден' });
    if (!text && !media) text = ''; // репост может быть без текста
  } else if (!text && !media) {
    return res.status(400).json({ error: 'Пост не может быть пустым' });
  }

  const r = db
    .prepare('INSERT INTO posts (uid, user_id, text, media, media_type, repost_of) VALUES (?, ?, ?, ?, ?, ?)')
    .run(randomUid(), req.userId, text, media, mediaType, repostOf || null);
  const row = db.prepare(`${POST_QUERY} WHERE p.id = ?`).get(Number(r.lastInsertRowid));
  log('post_create', { req, userId: req.userId, meta: { postId: row.id, hasMedia: !!media, repost: !!repostOf } });
  if (!repostOf) {
    notifyFollowers(
      req.userId,
      { title: req.user.name, body: 'опубликовал(а) новый пост', data: { url: 'feed' } },
      req.app.get('onlineUsers')
    );
  }
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
  const post = db.prepare('SELECT user_id FROM posts WHERE id = ?').get(id);
  if (post && post.user_id !== req.userId) {
    notify(req.app, post.user_id, req.user, 'like', {
      body: 'лайкнул(а) ваш пост',
      url: 'feed'
    });
  }
  res.json({ liked: true, likes: n });
});

router.delete('/:id/like', auth, (req, res) => {
  const id = targetId('posts', req.params.id);
  if (!id) return res.status(404).json({ error: 'Пост не найден' });
  db.prepare('DELETE FROM post_likes WHERE post_id = ? AND user_id = ?').run(id, req.userId);
  const n = db.prepare('SELECT COUNT(*) AS n FROM post_likes WHERE post_id = ?').get(id).n;
  res.json({ liked: false, likes: n });
});

router.post('/:id/react', auth, (req, res) => {
  const id = targetId('posts', req.params.id);
  if (!id) return res.status(404).json({ error: 'Пост не найден' });
  const emoji = String(req.body.emoji || '').trim();
  if (!emoji) return res.status(400).json({ error: 'Укажите emoji' });
  const existing = db.prepare('SELECT 1 FROM post_reactions WHERE post_id = ? AND user_id = ? AND emoji = ?').get(id, req.userId, emoji);
  if (existing) {
    db.prepare('DELETE FROM post_reactions WHERE post_id = ? AND user_id = ? AND emoji = ?').run(id, req.userId, emoji);
  } else {
    db.prepare('INSERT INTO post_reactions (post_id, user_id, emoji) VALUES (?, ?, ?)').run(id, req.userId, emoji);
  }
  const post = db.prepare('SELECT user_id FROM posts WHERE id = ?').get(id);
  if (!existing && post && post.user_id !== req.userId) {
    notify(req.app, post.user_id, req.user, 'react', { body: `${emoji} ваш пост`, url: 'feed' });
  }
  const reactions = getReactions('post_reactions', 'post_id', id, req.userId);
  res.json({ reactions });
});

router.delete('/:id/react', auth, (req, res) => {
  const id = targetId('posts', req.params.id);
  if (!id) return res.status(404).json({ error: 'Пост не найден' });
  const emoji = String(req.body.emoji || '').trim();
  db.prepare('DELETE FROM post_reactions WHERE post_id = ? AND user_id = ? AND emoji = ?').run(id, req.userId, emoji);
  const reactions = getReactions('post_reactions', 'post_id', id, req.userId);
  res.json({ reactions });
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
  const short = row.text.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 100);
  if (post.user_id !== req.userId) {
    notify(req.app, post.user_id, req.user, 'comment', {
      body: `комментарий: ${short}`,
      url: 'feed'
    });
  }
  if (parentId) {
    const parent = db.prepare('SELECT user_id FROM comments WHERE id = ?').get(parentId);
    if (parent && parent.user_id !== req.userId && parent.user_id !== post.user_id) {
      notify(req.app, parent.user_id, req.user, 'comment', {
        body: `ответил(а): ${short}`,
        url: 'feed'
      });
    }
  }
  res.status(201).json({ comment: row });
});

module.exports = router;
