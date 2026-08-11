const express = require('express');
const { db } = require('../db');
const { uploadAvatar } = require('../upload');
const { auth, publicUser, findByIdOrUid } = require('../helpers');
const { sanitizeText, validName } = require('../validate');
const { log } = require('../logger');

const router = express.Router();

function matchText(haystacks, q) {
  const needle = q.toLowerCase();
  return haystacks.some((h) => String(h || '').toLowerCase().includes(needle));
}

const PUB_RE = /^[A-Za-z0-9_=+\/-]{40,2048}$/;

router.get('/', auth, (req, res) => {
  const q = String(req.query.q || '').trim().slice(0, 60);
  const exclude = req.query.exclude === 'me';
  let list = db
    .prepare('SELECT * FROM users ORDER BY name LIMIT 200')
    .all()
    .filter((u) => (q ? matchText([u.username, u.name], q) : true))
    .slice(0, 50)
    .map(publicUser);
  if (exclude) list = list.filter((u) => u.id !== req.userId);
  res.json({ users: list });
});

router.get('/:id', (req, res) => {
  const user = findByIdOrUid('users', req.params.id);
  if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
  const id = user.id;

  const stats = {
    posts: db.prepare('SELECT COUNT(*) AS n FROM posts WHERE user_id = ?').get(id).n,
    videos: db.prepare('SELECT COUNT(*) AS n FROM videos WHERE user_id = ?').get(id).n,
    followers: db.prepare('SELECT COUNT(*) AS n FROM follows WHERE following_id = ?').get(id).n,
    following: db.prepare('SELECT COUNT(*) AS n FROM follows WHERE user_id = ?').get(id).n
  };
  let isFollowing = false;
  if (req.userId && req.userId !== id) {
    isFollowing = !!db
      .prepare('SELECT 1 FROM follows WHERE user_id = ? AND following_id = ?')
      .get(req.userId, id);
  }
  const posts = db
    .prepare('SELECT id, uid, text, media, media_type, created_at FROM posts WHERE user_id = ? ORDER BY id DESC LIMIT 10')
    .all(id);
  const videos = db
    .prepare('SELECT id, uid, title, file, thumb, views, is_clip FROM videos WHERE user_id = ? ORDER BY id DESC LIMIT 10')
    .all(id);
  const onlineUsers = req.app.get('onlineUsers');
  const online = !!(onlineUsers && onlineUsers.has(id));
  res.json({ user: { ...publicUser(user), online }, stats, isFollowing, posts, videos });
});

router.put('/:id', auth, (req, res) => {
  const user = findByIdOrUid('users', req.params.id);
  if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
  if (user.id !== req.userId) return res.status(403).json({ error: 'Нельзя редактировать чужой профиль' });
  const name = sanitizeText(req.body.name, 60);
  const bio = sanitizeText(req.body.bio, 200);
  const status = sanitizeText(req.body.status, 60);
  if (!validName(name)) return res.status(400).json({ error: 'Имя: от 2 до 60 символов' });
  const incognito = req.body.incognito === true || req.body.incognito === 1 || req.body.incognito === '1' ? 1 : 0;
  db.prepare('UPDATE users SET name = ?, bio = ?, status = ?, incognito = ? WHERE id = ?')
    .run(name, bio, status, incognito, user.id);
  const updated = db.prepare('SELECT * FROM users WHERE id = ?').get(user.id);
  res.json({ user: publicUser(updated) });
});

router.post('/:id/avatar', auth, uploadAvatar('avatar'), (req, res) => {
  const user = findByIdOrUid('users', req.params.id);
  if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
  if (user.id !== req.userId) return res.status(403).json({ error: 'Нельзя менять чужой аватар' });
  if (!req.file) return res.status(400).json({ error: 'Файл не загружен' });
  const old = user.avatar;
  db.prepare('UPDATE users SET avatar = ? WHERE id = ?').run(`avatars/${req.file.filename}`, user.id);
  if (old) {
    const fs = require('fs');
    const path = require('path');
    const { UPLOAD_DIR } = require('../db');
    const abs = path.join(UPLOAD_DIR, String(old).replace(/^\/+/, ''));
    if (abs.startsWith(UPLOAD_DIR) && fs.existsSync(abs)) try { fs.unlinkSync(abs); } catch (e) {}
  }
  const updated = db.prepare('SELECT * FROM users WHERE id = ?').get(user.id);
  res.json({ user: publicUser(updated) });
});

router.post('/:id/follow', auth, (req, res) => {
  const target = findByIdOrUid('users', req.params.id);
  if (!target) return res.status(404).json({ error: 'Пользователь не найден' });
  if (target.id === req.userId) return res.status(400).json({ error: 'Нельзя подписаться на себя' });
  db.prepare('INSERT OR IGNORE INTO follows (user_id, following_id) VALUES (?, ?)').run(req.userId, target.id);
  const followers = db.prepare('SELECT COUNT(*) AS n FROM follows WHERE following_id = ?').get(target.id).n;
  res.json({ isFollowing: true, followers });
});

router.delete('/:id/follow', auth, (req, res) => {
  const target = findByIdOrUid('users', req.params.id);
  if (!target) return res.status(404).json({ error: 'Пользователь не найден' });
  db.prepare('DELETE FROM follows WHERE user_id = ? AND following_id = ?').run(req.userId, target.id);
  const followers = db.prepare('SELECT COUNT(*) AS n FROM follows WHERE following_id = ?').get(target.id).n;
  res.json({ isFollowing: false, followers });
});

/* ---------- E2EE: публичный ключ (для шифрования сообщений) ---------- */
router.put('/:id/e2ee', auth, (req, res) => {
  const user = findByIdOrUid('users', req.params.id);
  if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
  if (user.id !== req.userId) return res.status(403).json({ error: 'Ключ можно менять только себе' });
  const pub = String(req.body.pub || '').trim();
  if (!PUB_RE.test(pub)) return res.status(400).json({ error: 'Некорректный публичный ключ' });
  const ver = Number.isInteger(Number(req.body.ver)) ? Number(req.body.ver) : 0;
  db.prepare('UPDATE users SET e2ee_pub = ?, e2ee_ver = ? WHERE id = ?').run(pub, ver, user.id);
  log('e2ee_key_upload', { req, userId: user.id });
  res.json({ ok: true });
});

router.get('/:id/e2ee', (req, res) => {
  const user = findByIdOrUid('users', req.params.id);
  if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
  res.json({ pub: user.e2ee_pub || null, ver: user.e2ee_ver || 0 });
});

module.exports = router;
