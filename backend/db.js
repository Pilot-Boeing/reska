const path = require('path');
const fs = require('fs');
const { DatabaseSync } = require('node:sqlite');
const { randomUid } = require('./security');

const DATA_DIR = path.join(__dirname, '..');

function safeMkdir(list) {
  try {
    for (const d of list) fs.mkdirSync(d, { recursive: true });
    return true;
  } catch (e) {
    return false;
  }
}

let DB_PATH = process.env.SPACE_DB_PATH
  ? path.resolve(process.env.SPACE_DB_PATH)
  : path.join(DATA_DIR, 'space.db');

let UPLOAD_DIR = process.env.SPACE_UPLOAD_DIR
  ? path.resolve(process.env.SPACE_UPLOAD_DIR)
  : path.join(DATA_DIR, 'uploads');

const uploadSubs = () => [
  UPLOAD_DIR,
  path.join(UPLOAD_DIR, 'avatars'),
  path.join(UPLOAD_DIR, 'posts'),
  path.join(UPLOAD_DIR, 'videos'),
  path.join(UPLOAD_DIR, 'thumbs'),
  path.join(UPLOAD_DIR, 'chats')
];

if (!safeMkdir(uploadSubs())) {
  console.warn(`[db] нет доступа к ${UPLOAD_DIR} — использую дефолт ${path.join(DATA_DIR, 'uploads')}`);
  UPLOAD_DIR = path.join(DATA_DIR, 'uploads');
  safeMkdir(uploadSubs());
}

if (!safeMkdir([path.dirname(DB_PATH)])) {
  console.warn(`[db] нет доступа к ${path.dirname(DB_PATH)} — использую дефолт ${path.join(DATA_DIR, 'space.db')}`);
  DB_PATH = path.join(DATA_DIR, 'space.db');
  safeMkdir([path.dirname(DB_PATH)]);
}

const AVATAR_DIR = path.join(UPLOAD_DIR, 'avatars');
const POST_DIR = path.join(UPLOAD_DIR, 'posts');
const VIDEO_DIR = path.join(UPLOAD_DIR, 'videos');
const THUMB_DIR = path.join(UPLOAD_DIR, 'thumbs');
const CHAT_DIR = path.join(UPLOAD_DIR, 'chats');

const db = new DatabaseSync(DB_PATH);
db.exec('PRAGMA journal_mode = WAL;');
db.exec('PRAGMA foreign_keys = ON;');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  uid TEXT UNIQUE,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  password_changed_at TEXT,
  name TEXT NOT NULL,
  bio TEXT DEFAULT '',
  status TEXT DEFAULT '',
  avatar TEXT DEFAULT '',
  role TEXT NOT NULL DEFAULT 'user',
  incognito INTEGER NOT NULL DEFAULT 0,
  e2ee_pub TEXT DEFAULT '',
  e2ee_ver INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_id TEXT,
  ip_hash TEXT,
  ua_hash TEXT,
  expires_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_id TEXT,
  ip_hash TEXT,
  ua_hash TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL,
  replaced_by TEXT
);

CREATE TABLE IF NOT EXISTS devices (
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  trusted INTEGER NOT NULL DEFAULT 0,
  trusted_until TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  last_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS totp (
  user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  secret TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS follows (
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  following_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (user_id, following_id)
);

CREATE TABLE IF NOT EXISTS friend_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  from_user INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  to_user INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  status TEXT NOT NULL DEFAULT 'pending',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE (from_user, to_user)
);

CREATE TABLE IF NOT EXISTS friendships (
  user_a INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  user_b INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (user_a, user_b),
  CHECK (user_a < user_b)
);

CREATE TABLE IF NOT EXISTS contact_aliases (
  owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  contact_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  alias TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (owner_id, contact_id)
);

CREATE TABLE IF NOT EXISTS notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  actor_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  type TEXT NOT NULL DEFAULT '',
  title TEXT NOT NULL DEFAULT '',
  body TEXT NOT NULL DEFAULT '',
  url TEXT NOT NULL DEFAULT '',
  read INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id, id);

CREATE TABLE IF NOT EXISTS posts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  uid TEXT UNIQUE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  text TEXT DEFAULT '',
  media TEXT DEFAULT '',
  media_type TEXT DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS post_likes (
  post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (post_id, user_id)
);

CREATE TABLE IF NOT EXISTS videos (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  uid TEXT UNIQUE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  description TEXT DEFAULT '',
  file TEXT NOT NULL,
  thumb TEXT DEFAULT '',
  is_clip INTEGER NOT NULL DEFAULT 0,
  views INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS video_likes (
  video_id INTEGER NOT NULL REFERENCES videos(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (video_id, user_id)
);

CREATE TABLE IF NOT EXISTS comments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  uid TEXT UNIQUE,
  post_id INTEGER REFERENCES posts(id) ON DELETE CASCADE,
  video_id INTEGER REFERENCES videos(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  text TEXT NOT NULL,
  parent_id INTEGER REFERENCES comments(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS chats (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  uid TEXT UNIQUE,
  user_a INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  user_b INTEGER REFERENCES users(id) ON DELETE CASCADE,
  kind TEXT NOT NULL DEFAULT 'dm',
  group_id INTEGER REFERENCES groups(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE (user_a, user_b)
);

CREATE TABLE IF NOT EXISTS chat_members (
  chat_id INTEGER NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL DEFAULT 'member',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (chat_id, user_id)
);

CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  chat_id INTEGER NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
  sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  text TEXT NOT NULL,
  e2ee INTEGER NOT NULL DEFAULT 0,
  read INTEGER NOT NULL DEFAULT 0,
  edited INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS message_reactions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  emoji TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE (message_id, user_id, emoji)
);

CREATE TABLE IF NOT EXISTS push_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token TEXT NOT NULL UNIQUE,
  platform TEXT NOT NULL DEFAULT 'android',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  action TEXT NOT NULL,
  level TEXT NOT NULL DEFAULT 'info',
  ip TEXT DEFAULT '',
  ua_hash TEXT DEFAULT '',
  payload TEXT DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS notes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  uid TEXT UNIQUE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  body TEXT DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS groups (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  uid TEXT UNIQUE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_posts_user ON posts(user_id);
CREATE INDEX IF NOT EXISTS idx_videos_user ON videos(user_id);
CREATE INDEX IF NOT EXISTS idx_comments_post ON comments(post_id);
CREATE INDEX IF NOT EXISTS idx_comments_video ON comments(video_id);
CREATE INDEX IF NOT EXISTS idx_messages_chat ON messages(chat_id);
CREATE INDEX IF NOT EXISTS idx_logs_user ON logs(user_id);
CREATE INDEX IF NOT EXISTS idx_logs_action ON logs(action);
CREATE INDEX IF NOT EXISTS idx_refresh_user ON refresh_tokens(user_id);
`);

/* =========================================================
   Миграция: добавляет недостающие колонки (idempotent)
   ========================================================= */
function hasColumn(table, col) {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all().map((c) => c.name);
  return cols.includes(col);
}

function addColumn(table, col, ddl) {
  if (!hasColumn(table, col)) db.exec(`ALTER TABLE ${table} ADD COLUMN ${col} ${ddl}`);
}

function ensureUid(table) {
  if (!hasColumn(table, 'uid')) return;
  const rows = db.prepare(`SELECT id FROM ${table} WHERE uid IS NULL`).all();
  const upd = db.prepare(`UPDATE ${table} SET uid = ? WHERE id = ?`);
  for (const r of rows) upd.run(randomUid(), r.id);
}

/**
 * Старые БД создавались с `user_b INTEGER NOT NULL`. Для групповых чатов
 * user_b = NULL (нет второго собеседника), поэтому пересобираем таблицу.
 */
function rebuildChatsForGroups() {
  const cols = db.prepare('PRAGMA table_info(chats)').all();
  const ub = cols.find((c) => c.name === 'user_b');
  if (!ub || !ub.notnull) return;
  db.exec('PRAGMA foreign_keys = OFF');
  db.exec('BEGIN');
  try {
    db.exec(`CREATE TABLE chats_new (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      uid TEXT UNIQUE,
      user_a INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      user_b INTEGER REFERENCES users(id) ON DELETE CASCADE,
      kind TEXT NOT NULL DEFAULT 'dm',
      group_id INTEGER REFERENCES groups(id) ON DELETE CASCADE,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      UNIQUE (user_a, user_b)
    )`);
    db.exec(`INSERT INTO chats_new (id, uid, user_a, user_b, kind, group_id, created_at)
             SELECT id, uid, user_a, user_b, kind, group_id, created_at FROM chats`);
    db.exec('DROP TABLE chats');
    db.exec('ALTER TABLE chats_new RENAME TO chats');
    db.exec('COMMIT');
  } catch (e) {
    try { db.exec('ROLLBACK'); } catch (e2) {}
  } finally {
    db.exec('PRAGMA foreign_keys = ON');
  }
  try {
    db.exec("DELETE FROM sqlite_sequence WHERE name = 'chats'");
    db.exec("INSERT INTO sqlite_sequence (name, seq) SELECT 'chats', COALESCE(MAX(id), 0) FROM chats");
  } catch (e) {}
}

function migrate() {
  addColumn('users', 'uid', 'TEXT');
  addColumn('users', 'password_changed_at', 'TEXT');
  addColumn('users', 'incognito', 'INTEGER NOT NULL DEFAULT 0');
  addColumn('users', 'e2ee_pub', 'TEXT DEFAULT \'\'');
  addColumn('users', 'e2ee_ver', 'INTEGER NOT NULL DEFAULT 0');
  addColumn('users', 'phone', 'TEXT DEFAULT \'\'');
  addColumn('users', 'phone_hash', 'TEXT DEFAULT \'\'');
  addColumn('posts', 'uid', 'TEXT');
  addColumn('videos', 'uid', 'TEXT');
  addColumn('comments', 'uid', 'TEXT');
  addColumn('chats', 'uid', 'TEXT');
  addColumn('chats', 'kind', "TEXT NOT NULL DEFAULT 'dm'");
  addColumn('chats', 'group_id', 'INTEGER');
  addColumn('messages', 'e2ee', 'INTEGER NOT NULL DEFAULT 0');
  addColumn('messages', 'edited', 'INTEGER NOT NULL DEFAULT 0');
  addColumn('messages', 'media', "TEXT DEFAULT ''");
  addColumn('messages', 'media_type', "TEXT DEFAULT ''");
  addColumn('messages', 'media_name', "TEXT DEFAULT ''");
  addColumn('messages', 'media_mime', "TEXT DEFAULT ''");
  addColumn('messages', 'media_size', 'INTEGER NOT NULL DEFAULT 0');
  addColumn('messages', 'media_duration', 'REAL NOT NULL DEFAULT 0');
  addColumn('sessions', 'device_id', 'TEXT');
  addColumn('sessions', 'ip_hash', 'TEXT');
  addColumn('sessions', 'ua_hash', 'TEXT');
  addColumn('sessions', 'expires_at', 'TEXT');

  for (const t of ['users', 'posts', 'videos', 'comments', 'chats']) ensureUid(t);

  rebuildChatsForGroups();

  // бэкфилл хэшей телефонов для уже существующих пользователей
  try {
    const { hashFor } = require('./phone');
    const rows = db.prepare("SELECT id, phone FROM users WHERE phone != '' AND (phone_hash = '' OR phone_hash IS NULL)").all();
    for (const r of rows) {
      const h = hashFor(r.phone);
      if (h) db.prepare('UPDATE users SET phone_hash = ? WHERE id = ?').run(h, r.id);
    }
  } catch (e) {}

  // нормализация логинов в нижний регистр (раньше логин был чувствителен к регистру)
  try {
    const rows = db.prepare('SELECT id, username FROM users').all();
    for (const r of rows) {
      const low = String(r.username).toLowerCase();
      if (low !== r.username) {
        const collision = db.prepare('SELECT 1 FROM users WHERE lower(username) = ? AND id != ?').get(low, r.id);
        if (!collision) db.prepare('UPDATE users SET username = ? WHERE id = ?').run(low, r.id);
      }
    }
  } catch (e) {}
}

migrate();

module.exports = {
  db,
  DB_PATH,
  UPLOAD_DIR,
  AVATAR_DIR,
  POST_DIR,
  VIDEO_DIR,
  THUMB_DIR,
  CHAT_DIR
};
