const express = require('express');
const fs = require('fs');
const path = require('path');
const { db, THUMB_DIR, UPLOAD_DIR } = require('../db');
const { uploadVideo } = require('../upload');
const { auth, commentsFor, findByIdOrUid } = require('../helpers');
const { sanitizeText } = require('../validate');
const { thumbSVG } = require('../demo-assets');
const { getClientIp } = require('../security');
const { encryptBuffer } = require('../encryption');
const { randomUid } = require('../security');
const { log } = require('../logger');
const { notify, notifyFollowers } = require('../notif');

const router = express.Router();

const VIDEO_QUERY = `
  SELECT v.id, v.uid, v.title, v.description, v.file, v.thumb, v.is_clip, v.views, v.created_at,
         v.user_id, u.uid AS author_uid, u.username, u.name, u.avatar,
         (SELECT COUNT(*) FROM video_likes vl WHERE vl.video_id = v.id) AS likes
  FROM videos v JOIN users u ON u.id = v.user_id
`;

function videoWithMeta(row, userId) {
  if (!row) return null;
  const liked = userId
    ? !!db.prepare('SELECT 1 FROM video_likes WHERE video_id = ? AND user_id = ?').get(row.id, userId)
    : false;
  const reactions = userId
    ? getVReactions(row.id, userId)
    : getVReactions(row.id, null);
  return { ...row, liked, reactions };
}

function getVReactions(id, userId) {
  const agg = db
    .prepare(`SELECT emoji, COUNT(*) AS n FROM video_reactions WHERE video_id = ? GROUP BY emoji ORDER BY n DESC, emoji`)
    .all(id);
  let myEmoji = [];
  if (userId) myEmoji = db.prepare('SELECT emoji FROM video_reactions WHERE video_id = ? AND user_id = ?').all(id, userId).map((r) => r.emoji);
  return { list: agg.map((r) => ({ emoji: r.emoji, count: r.n })), myEmoji };
}

function deleteMedia(relPath) {
  if (!relPath) return;
  const abs = path.join(UPLOAD_DIR, String(relPath).replace(/^\/+/, ''));
  if (abs.startsWith(UPLOAD_DIR) && fs.existsSync(abs)) {
    try { fs.unlinkSync(abs); } catch (e) {}
  }
}

function encryptedThumb(title) {
  const name = `thumb_${Date.now()}_${Math.floor(Math.random() * 1e6)}.svg.enc`;
  const svg = thumbSVG(title, String(Math.random()));
  fs.writeFileSync(path.join(THUMB_DIR, name), encryptBuffer(Buffer.from(svg, 'utf8')));
  return `thumbs/${name}`;
}

/* учёт просмотров: не чаще раза в N минут на IP и не для автора */
const recentViews = new Map();
setInterval(() => {
  const now = Date.now();
  for (const [k, t] of recentViews) if (now - t > 30 * 60 * 1000) recentViews.delete(k);
}, 10 * 60 * 1000).unref();

router.get('/', (req, res) => {
  const userId = req.userId || null;
  const clip = req.query.clip === '1' ? 1 : req.query.clip === '0' ? 0 : null;
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 10, 1), 50);
  const before = req.query.before ? Number(req.query.before) : 0;
  let sql = VIDEO_QUERY;
  const params = [];
  const conds = [];
  if (clip !== null) { conds.push('v.is_clip = ?'); params.push(clip); }
  if (before) { conds.push('v.id < ?'); params.push(before); }
  if (conds.length) sql += ' WHERE ' + conds.join(' AND ');
  sql += ' ORDER BY v.created_at DESC, v.id DESC LIMIT ' + (limit + 1);
  const rows = db.prepare(sql).all(...params);
  const hasMore = rows.length > limit;
  const page = hasMore ? rows.slice(0, limit) : rows;
  res.json({ videos: page.map((r) => videoWithMeta(r, userId)), hasMore });
});

router.get('/:id', (req, res) => {
  const userId = req.userId || null;
  const row = db.prepare(`${VIDEO_QUERY} WHERE v.id = ?`).get((findByIdOrUid('videos', req.params.id) || {}).id);
  if (!row) return res.status(404).json({ error: 'Видео не найдено' });
  res.json({ video: videoWithMeta(row, userId) });
});

router.post('/', auth, uploadVideo('video'), (req, res) => {
  const title = sanitizeText(req.body.title, 120);
  if (!req.file) return res.status(400).json({ error: 'Выберите видеофайл' });
  if (!title) return res.status(400).json({ error: 'Укажите название' });

  const isClip = req.body.is_clip === '1' || req.body.is_clip === 'true' ? 1 : 0;
  const thumb = encryptedThumb(title);

  const r = db
    .prepare('INSERT INTO videos (uid, user_id, title, description, file, thumb, is_clip) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .run(randomUid(), req.userId, title, sanitizeText(req.body.description, 2000), `videos/${req.file.filename}`, thumb, isClip);
  const row = db.prepare(`${VIDEO_QUERY} WHERE v.id = ?`).get(Number(r.lastInsertRowid));
  log('video_create', { req, userId: req.userId, meta: { videoId: row.id } });
  const dest = isClip ? 'clips' : 'videos';
  notifyFollowers(
    req.userId,
    { title: req.user.name, body: `новое видео: ${title}`, data: { url: dest } },
    req.app.get('onlineUsers')
  );
  res.status(201).json({ video: videoWithMeta(row, req.userId) });
});

router.post('/:id/view', (req, res) => {
  const v = findByIdOrUid('videos', req.params.id);
  if (!v) return res.status(404).json({ error: 'Видео не найдено' });
  const incognito = req.query.incognito === '1' || (req.user && req.user.incognito === 1);
  if (incognito) {
    const views = db.prepare('SELECT views FROM videos WHERE id = ?').get(v.id).views;
    return res.json({ views, incognito: true });
  }
  const ip = getClientIp(req);
  const key = `${v.id}|${ip}`;
  const now = Date.now();
  if (recentViews.has(key)) return res.json({ views: v.views });
  recentViews.set(key, now);
  if (req.userId && v.user_id === req.userId) return res.json({ views: v.views });
  db.prepare('UPDATE videos SET views = views + 1 WHERE id = ?').run(v.id);
  const views = db.prepare('SELECT views FROM videos WHERE id = ?').get(v.id).views;
  res.json({ views });
});

router.post('/:id/like', auth, (req, res) => {
  const v = findByIdOrUid('videos', req.params.id);
  if (!v) return res.status(404).json({ error: 'Видео не найдено' });
  db.prepare('INSERT OR IGNORE INTO video_likes (video_id, user_id) VALUES (?, ?)').run(v.id, req.userId);
  const n = db.prepare('SELECT COUNT(*) AS n FROM video_likes WHERE video_id = ?').get(v.id).n;
  if (v.user_id !== req.userId) {
    notify(req.app, v.user_id, req.user, 'like', {
      body: 'лайкнул(а) ваше видео',
      url: `watch/${v.uid}`
    });
  }
  res.json({ liked: true, likes: n });
});

router.delete('/:id/like', auth, (req, res) => {
  const v = findByIdOrUid('videos', req.params.id);
  if (!v) return res.status(404).json({ error: 'Видео не найдено' });
  db.prepare('DELETE FROM video_likes WHERE video_id = ? AND user_id = ?').run(v.id, req.userId);
  const n = db.prepare('SELECT COUNT(*) AS n FROM video_likes WHERE video_id = ?').get(v.id).n;
  res.json({ liked: false, likes: n });
});

router.post('/:id/react', auth, (req, res) => {
  const v = findByIdOrUid('videos', req.params.id);
  if (!v) return res.status(404).json({ error: 'Видео не найдено' });
  const emoji = String(req.body.emoji || '').trim();
  if (!emoji) return res.status(400).json({ error: 'Укажите emoji' });
  const existing = db.prepare('SELECT 1 FROM video_reactions WHERE video_id = ? AND user_id = ? AND emoji = ?').get(v.id, req.userId, emoji);
  if (existing) {
    db.prepare('DELETE FROM video_reactions WHERE video_id = ? AND user_id = ? AND emoji = ?').run(v.id, req.userId, emoji);
  } else {
    db.prepare('INSERT INTO video_reactions (video_id, user_id, emoji) VALUES (?, ?, ?)').run(v.id, req.userId, emoji);
  }
  if (!existing && v.user_id !== req.userId) {
    notify(req.app, v.user_id, req.user, 'react', { body: `${emoji} ваше видео`, url: 'videos' });
  }
  res.json({ reactions: getVReactions(v.id, req.userId) });
});

router.delete('/:id/react', auth, (req, res) => {
  const v = findByIdOrUid('videos', req.params.id);
  if (!v) return res.status(404).json({ error: 'Видео не найдено' });
  const emoji = String(req.body.emoji || '').trim();
  db.prepare('DELETE FROM video_reactions WHERE video_id = ? AND user_id = ? AND emoji = ?').run(v.id, req.userId, emoji);
  res.json({ reactions: getVReactions(v.id, req.userId) });
});

router.get('/:id/comments', (req, res) => {
  const v = findByIdOrUid('videos', req.params.id);
  if (!v) return res.status(404).json({ error: 'Видео не найдено' });
  res.json({ comments: commentsFor('video_id', v.id) });
});

router.post('/:id/comments', auth, (req, res) => {
  const video = findByIdOrUid('videos', req.params.id);
  if (!video) return res.status(404).json({ error: 'Видео не найдено' });
  const text = sanitizeText(req.body.text, 2000);
  if (!text) return res.status(400).json({ error: 'Комментарий пустой' });
  const parentId = req.body.parent_id ? Number(req.body.parent_id) : null;
  if (parentId) {
    const parent = db
      .prepare('SELECT id FROM comments WHERE id = ? AND video_id = ?')
      .get(parentId, video.id);
    if (!parent) return res.status(400).json({ error: 'Ответ на несуществующий комментарий' });
  }
  const r = db
    .prepare('INSERT INTO comments (uid, video_id, user_id, text, parent_id) VALUES (?, ?, ?, ?, ?)')
    .run(randomUid(), video.id, req.userId, text, parentId);
  const row = db
    .prepare(
      `SELECT c.id, c.uid, c.text, c.parent_id, c.created_at, c.user_id,
              u.username, u.name, u.avatar
       FROM comments c JOIN users u ON u.id = c.user_id WHERE c.id = ?`
    )
    .get(Number(r.lastInsertRowid));
  const short = row.text.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 100);
  if (video.user_id !== req.userId) {
    notify(req.app, video.user_id, req.user, 'comment', {
      body: `комментарий: ${short}`,
      url: `watch/${video.uid}`
    });
  }
  if (parentId) {
    const parent = db.prepare('SELECT user_id FROM comments WHERE id = ?').get(parentId);
    if (parent && parent.user_id !== req.userId && parent.user_id !== video.user_id) {
      notify(req.app, parent.user_id, req.user, 'comment', {
        body: `ответил(а): ${short}`,
        url: `watch/${video.uid}`
      });
    }
  }
  res.status(201).json({ comment: row });
});

router.delete('/:id', auth, (req, res) => {
  const video = findByIdOrUid('videos', req.params.id);
  if (!video) return res.status(404).json({ error: 'Видео не найдено' });
  if (video.user_id !== req.userId && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Нельзя удалить чужое видео' });
  }
  deleteMedia(video.file);
  deleteMedia(video.thumb);
  db.prepare('DELETE FROM videos WHERE id = ?').run(video.id);
  log('video_delete', { req, userId: req.userId, meta: { videoId: video.id } });
  res.json({ ok: true });
});

module.exports = router;
