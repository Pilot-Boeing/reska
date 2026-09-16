const path = require('path');
const fs = require('fs');
const http = require('http');
const https = require('https');
const express = require('express');
const { Server } = require('socket.io');
const { db, UPLOAD_DIR, DB_PATH } = require('./db');
const { optionalAuth, csrfProtect, ensureCsrfCookie, parseCookies } = require('./helpers');
const { limiter } = require('./rateLimit');
const { createPlainReadable, filePlainSize } = require('./encryption');
const { scheduleBackups } = require('./backup');
const { ensureTls } = require('./tls');

const app = express();
app.set('trust proxy', 1);
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
    'Permissions-Policy': 'camera=(self), microphone=(self), geolocation=(), payment=()',
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
  '.ogg': 'audio/ogg',
  '.opus': 'audio/ogg',
  '.oga': 'audio/ogg',
  '.m4a': 'audio/mp4',
  '.aac': 'audio/aac',
  '.mp3': 'audio/mpeg',
  '.wav': 'audio/wav',
  '.flac': 'audio/flac',
  '.bin': 'application/octet-stream'
};

function canAccessChatMedia(chatId, userId) {
  if (!userId) return false;
  const chat = db.prepare('SELECT id, kind, user_a, user_b FROM chats WHERE id = ?').get(chatId);
  if (!chat) return false;
  if (chat.kind === 'group') {
    const member = db
      .prepare('SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?')
      .get(chat.id, userId);
    return !!member;
  }
  return chat.user_a === userId || chat.user_b === userId;
}

function fileNameForHeader(name) {
  const clean = String(name || '')
    .replace(/[^\p{L}\p{N}._ -]/gu, '_')
    .replace(/\.\./g, '.')
    .slice(0, 180);
  return clean || 'file';
}

app.get('/api/media/*', (req, res) => {
  const rel = String(req.params[0] || '').replace(/^\/+/, '');
  const isChat = rel.startsWith('chats/');
  const allowed = isChat
    ? /^chats\/\d+\/[A-Za-z0-9_.-]+$/.test(rel)
    : /^(avatars|covers|posts|videos|thumbs|stories)\/[A-Za-z0-9_.-]+$/.test(rel);
  if (!allowed) {
    return res.status(403).json({ error: 'Доступ запрещён' });
  }
  if (isChat) {
    const chatId = Number(rel.split('/')[1]);
    if (!canAccessChatMedia(chatId, req.userId)) {
      return res.status(403).json({ error: 'Нет доступа к файлу чата' });
    }
  }
  const abs = path.join(UPLOAD_DIR, rel);
  if (!abs.startsWith(UPLOAD_DIR) || !fs.existsSync(abs)) {
    return res.status(404).json({ error: 'Файл не найден' });
  }
  const ext = path.extname(rel.replace(/\.enc$/, ''));
  const mime = MIME_BY_EXT[ext.toLowerCase()] || 'application/octet-stream';
  const total = filePlainSize(abs);
  const cache = 'public, max-age=31536000, immutable';

  const dl = req.query.name;
  const isInline = mime.startsWith('image/') || mime.startsWith('video/') || mime.startsWith('audio/');
  if (dl && !isInline) {
    res.set('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(fileNameForHeader(dl))}`);
  }

  const range = req.headers.range;
  let start = 0;
  let end = total - 1;
  let status = 200;
  if (range) {
    const m = /^bytes=(\d*)-(\d*)$/.exec(String(range).trim());
    if (!m || (m[1] === '' && m[2] === '')) {
      return res.status(400).json({ error: 'Недопустимый Range' });
    }
    if (m[1] === '') {
      const suffix = Number(m[2]);
      if (!Number.isInteger(suffix) || suffix <= 0) {
        return res.status(400).json({ error: 'Недопустимый Range' });
      }
      start = Math.max(0, total - suffix);
      end = total - 1;
    } else {
      start = Number(m[1]);
      end = m[2] === '' ? total - 1 : Number(m[2]);
      if (!Number.isInteger(start) || start < 0) {
        return res.status(400).json({ error: 'Недопустимый Range' });
      }
      if (!Number.isInteger(end) || end < start) {
        return res.status(400).json({ error: 'Недопустимый Range' });
      }
    }
    if (start > end || start >= total) {
      res.set('Content-Range', `bytes */${total}`);
      return res.status(416).end();
    }
    end = Math.min(end, total - 1);
    status = 206;
  }

  res.status(status);
  res.set({
    'Content-Type': mime,
    'Accept-Ranges': 'bytes',
    'Content-Length': end - start + 1,
    'Cache-Control': cache
  });
  if (status === 206) res.set('Content-Range', `bytes ${start}-${end}/${total}`);
  if (total === 0) return res.end();

  const stream = createPlainReadable(abs, start, end - start + 1);
  stream.on('error', () => {
    if (!res.headersSent) res.status(500).end();
    else res.destroy();
  });
  stream.pipe(res);
});

const BUILD_VER = (() => {
  try {
    const { execSync } = require('child_process');
    const h = execSync('git rev-parse --short HEAD', { stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim();
    if (h) return h;
  } catch (e) {}
  try { return require('./package.json').version; } catch (e) { return String(Date.now()); }
})();

/* главная страница: подставляем версию сборки в ссылки статики (кеш-бастинг) */
app.get('/', (req, res) => {
  try {
    const html = fs.readFileSync(path.join(FRONTEND_DIR, 'index.html'), 'utf8').replace(/__BUILD__/g, BUILD_VER);
    res.set('Cache-Control', 'no-cache');
    res.send(html);
  } catch (e) {
    res.status(500).send('index.html not found');
  }
});

app.use(express.static(FRONTEND_DIR, {
  setHeaders: (res, filePath) => {
    if (/\.(js|css)$/.test(filePath)) res.set('Cache-Control', 'public, max-age=31536000, immutable');
  }
}));

/* ---------- API ---------- */
app.use('/api', (req, res, next) => {
  ensureCsrfCookie(req, res);
  next();
});
app.use('/api', csrfProtect);
app.use('/api/auth', require('./routes/auth'));
app.use('/api/posts', require('./routes/posts'));
app.use('/api/videos', require('./routes/videos'));
app.use('/api/users', require('./routes/friends'));
app.use('/api/users', require('./routes/users'));
app.use('/api/chats', require('./routes/chat'));
app.use('/api/push', require('./routes/push'));
app.use('/api/notifications', require('./routes/notifications'));
app.use('/api/library', require('./routes/library'));
app.use('/api/favorites', require('./routes/favorites'));
app.use('/api/search', require('./routes/search'));
app.use('/api/stories', require('./routes/stories'));
app.use('/api/call', require('./routes/call'));

app.get('/api/health', (req, res) =>
  res.json({ ok: true, db: db.prepare('SELECT 1 AS x').get().x })
);

app.use((err, req, res, next) => {
  const status = err && err.status ? err.status : 500;
  const message = err && err.message ? err.message : 'Ошибка сервера';
  if (status >= 500) console.error(err);
  res.status(status).json({ error: message });
});

/* ---------- WebSocket (auth по session-cookie из handshake, не по голому токену) ---------- */
const httpServer = http.createServer(app);
const io = new Server(httpServer);
app.set('io', io);

io.use((socket, next) => {
  const session = parseCookies(socket.request).reska_session;
  if (!session) return next(new Error('unauthorized'));
  const row = db
    .prepare('SELECT user_id, expires_at FROM sessions WHERE token = ?')
    .get(String(session));
  if (!row) return next(new Error('unauthorized'));
  if (row.expires_at && new Date(row.expires_at) < new Date()) return next(new Error('unauthorized'));
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

require('./call').setupCalls(io, app);

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

/* ---------- Авто-бэкап БД в GitHub (Render без карты) ---------- */
if (process.env.GITHUB_TOKEN) {
  const { uploadDbFrom } = require('./db-github-backup');
  const INTERVAL = (Number(process.env.GITHUB_BACKUP_MIN) > 0 ? Number(process.env.GITHUB_BACKUP_MIN) : 5) * 60 * 1000;
  // Первая выгрузка сразу после старта, чтобы бэкап появился в GitHub как можно раньше
  // (например, при первом деплое, когда в репо ещё нет файла).
  setTimeout(() => { uploadDbFrom(DB_PATH).catch(() => {}); }, 5000);
  setInterval(() => { uploadDbFrom(DB_PATH).catch(() => {}); }, INTERVAL);
  process.on('SIGTERM', () => {
    console.log('[backup] SIGTERM — выгружаю БД в GitHub...');
    uploadDbFrom(DB_PATH).catch(() => {}).finally(() => process.exit(0));
  });
  console.log('[backup] Авто-бэкап БД в GitHub включён (первая выгрузка +5с, далее каждые', INTERVAL / 60000, 'мин)');
}

  process.on('uncaughtException', (err) => {
    console.error('Необработанное исключение (процесс не завершён):', err);
  });
  process.on('unhandledRejection', (err) => {
    console.error('Необработанный rejection (процесс не завершён):', err);
  });

  start().catch((err) => {
    console.error('Ошибка запуска сервера:', err);
    process.exit(1);
  });
