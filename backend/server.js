const path = require('path');
const fs = require('fs');
const http = require('http');
const https = require('https');
const express = require('express');
const { Server } = require('socket.io');
const { db, UPLOAD_DIR } = require('./db');
const { optionalAuth, csrfProtect, ensureCsrfCookie, parseCookies } = require('./helpers');
const { limiter } = require('./rateLimit');
const { ipHash, uaHash } = require('./security');
const { readPlainRange, filePlainSize } = require('./encryption');
const { scheduleBackups } = require('./backup');
const { ensureTls } = require('./tls');

const app = express();
app.set('trust proxy', false);
app.set('io', null);

/* ---------- ограничение частоты запросов ---------- */
app.use('/api/auth', limiter({ windowMs: 60 * 1000, max: 40, name: 'auth', message: 'Слишком часто. Подождите.' }));
app.use('/api', limiter({ windowMs: 60 * 1000, max: 400, name: 'api', message: 'Слишком много запросов' }));

/* ---------- защитные заголовки ---------- */
app.use((req, res, next) => {
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=()',
    'Content-Security-Policy':
      "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
      "img-src 'self' data: blob:; media-src 'self' blob:; connect-src 'self' ws: wss:; " +
      "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
  });
  if (req.secure) {
    res.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  next();
});

app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));
app.use(optionalAuth);

const FRONTEND_DIR = path.join(__dirname, '..', 'frontend');

/* ---------- зашифрованные медиа (дешифровка на лету, поддержка Range) ---------- */
const MIME_BY_EXT = {
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.png': 'image/png',
  '.webp': 'image/webp',
  '.gif': 'image/gif',
  '.svg': 'image/svg+xml',
  '.mp4': 'video/mp4',
  '.webm': 'video/webm',
  '.mov': 'video/quicktime',
  '.mkv': 'video/x-matroska',
  '.ogg': 'video/ogg',
  '.bin': 'application/octet-stream'
};

app.get('/api/media/*', (req, res) => {
  const rel = String(req.params[0] || '').replace(/^\/+/, '');
  if (!/^(avatars|posts|videos|thumbs)\/[A-Za-z0-9_.-]+$/.test(rel)) {
    return res.status(403).json({ error: 'Доступ запрещён' });
  }
  const abs = path.join(UPLOAD_DIR, rel);
  if (!abs.startsWith(UPLOAD_DIR) || !fs.existsSync(abs)) {
    return res.status(404).json({ error: 'Файл не найден' });
  }
  const ext = path.extname(rel.replace(/\.enc$/, ''));
  const mime = MIME_BY_EXT[ext] || 'application/octet-stream';
  const total = filePlainSize(abs);
  const cache = 'public, max-age=31536000, immutable';

  const range = req.headers.range;
  if (range) {
    const m = /bytes=(\d*)-(\d*)/.exec(range);
    let start = m && m[1] ? parseInt(m[1], 10) : 0;
    let end = m && m[2] ? parseInt(m[2], 10) : total - 1;
    if (!Number.isFinite(start) || start < 0) start = 0;
    if (!Number.isFinite(end) || end < 0) end = total - 1;
    if (start > end || start >= total) {
      res.set('Content-Range', `bytes */${total}`);
      return res.status(416).end();
    }
    end = Math.min(end, total - 1);
    const { buffer } = readPlainRange(abs, start, end - start + 1);
    res.status(206);
    res.set({
      'Content-Type': mime,
      'Accept-Ranges': 'bytes',
      'Content-Range': `bytes ${start}-${end}/${total}`,
      'Content-Length': buffer.length,
      'Cache-Control': cache
    });
    return res.end(buffer);
  }
  const { buffer } = readPlainRange(abs, 0, total);
  res.set({
    'Content-Type': mime,
    'Accept-Ranges': 'bytes',
    'Content-Length': buffer.length,
    'Cache-Control': cache
  });
  res.end(buffer);
});

app.use(express.static(FRONTEND_DIR));

/* ---------- API ---------- */
app.use('/api', (req, res, next) => {
  ensureCsrfCookie(req, res);
  next();
});
app.use('/api', csrfProtect);
app.use('/api/auth', require('./routes/auth'));
app.use('/api/posts', require('./routes/posts'));
app.use('/api/videos', require('./routes/videos'));
app.use('/api/users', require('./routes/users'));
app.use('/api/chats', require('./routes/chat'));
app.use('/api/search', require('./routes/search'));

app.get('/api/health', (req, res) =>
  res.json({ ok: true, db: db.prepare('SELECT 1 AS x').get().x })
);

app.use((err, req, res, next) => {
  const status = err && err.status ? err.status : 500;
  const message = err && err.message ? err.message : 'Ошибка сервера';
  if (status >= 500) console.error(err);
  res.status(status).json({ error: message });
});

/* ---------- WebSocket (auth по токену сессии + привязка IP/UA) ---------- */
const httpServer = http.createServer(app);
const io = new Server(httpServer);
app.set('io', io);

io.use((socket, next) => {
  const token = socket.handshake.auth && socket.handshake.auth.token;
  if (!token) return next(new Error('unauthorized'));
  const row = db
    .prepare('SELECT user_id, ip_hash, ua_hash FROM sessions WHERE token = ?')
    .get(String(token));
  if (!row) return next(new Error('unauthorized'));
  const ip = ipHash(socket.request);
  const ua = uaHash(socket.request);
  if (row.ip_hash && row.ip_hash !== ip) return next(new Error('binding_ip'));
  if (row.ua_hash && row.ua_hash !== ua) return next(new Error('binding_ua'));
  socket.userId = row.user_id;
  next();
});

const onlineUsers = new Set();
app.set('onlineUsers', onlineUsers);

io.on('connection', (socket) => {
  socket.join(`user:${socket.userId}`);
  onlineUsers.add(socket.userId);
  socket.on('disconnect', () => {
    onlineUsers.delete(socket.userId);
  });
});

/* ---------- HTTP + HTTPS ---------- */
async function start() {
  const port = Number(process.env.PORT) || 3000;
  const httpsPort = Number(process.env.HTTPS_PORT) || 3443;

  const tls = await ensureTls();
  const httpsServer = https.createServer(tls, app);
  io.attach(httpsServer);

  httpServer.listen(port, () => {
    console.log('┌─────────────────────────────────────────────┐');
    console.log('│   РЕСКА — социальная сеть + видео + чат     │');
    console.log('└─────────────────────────────────────────────┘');
    console.log(`   HTTP  : http://localhost:${port}`);
    console.log(`   HTTPS : https://localhost:${httpsPort}  (самоподписанный)`);
    console.log('   Первый зарегистрированный пользователь получит роль администратора.');
    console.log('   Автобэкапы БД: каждые 6 часов (backups/*.db.enc).');
  });

  httpsServer.listen(httpsPort, () => {
    console.log(`   HTTPS  слушает порт ${httpsPort}`);
  });

  try {
    scheduleBackups();
  } catch (e) {
    console.error('Ошибка первого бэкапа:', e.message);
  }
}

start();
