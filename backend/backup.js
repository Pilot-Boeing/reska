/**
 * backup.js — автоматическое резервное копирование БД.
 * VACUUM INTO (консистентный снапшот) → шифрование AES-256-GCM → ротация 10 копий.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { db, DB_PATH } = require('./db');
const { encryptBuffer, decryptBuffer } = require('./encryption');

const BACKUP_DIR = path.join(__dirname, '..', 'backups');
const KEEP = 10;
const INTERVAL = 6 * 60 * 60 * 1000; // 6 часов

function ensureDir() {
  if (!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR, { recursive: true });
}

function quoteSqlPath(p) {
  return String(p).replace(/'/g, "''");
}

/**
 * Создать зашифрованный бэкап. Возвращает имя файла.
 */
function backupNow() {
  ensureDir();
  try { db.exec('PRAGMA wal_checkpoint(FULL);'); } catch (e) {}
  const ts = new Date().toISOString().replace(/[:.]/g, '-');
  const tmpPath = path.join(BACKUP_DIR, `tmp-${ts}.db`);
  const encPath = path.join(BACKUP_DIR, `space-${ts}.db.enc`);

  db.exec(`VACUUM INTO '${quoteSqlPath(tmpPath)}'`);
  const plain = fs.readFileSync(tmpPath);
  fs.writeFileSync(encPath, encryptBuffer(plain));
  fs.unlinkSync(tmpPath);

  rotate();
  return path.basename(encPath);
}

function rotate() {
  const files = fs
    .readdirSync(BACKUP_DIR)
    .filter((f) => /^space-.*\.db\.enc$/.test(f))
    .sort()
    .reverse();
  for (const f of files.slice(KEEP)) {
    fs.unlinkSync(path.join(BACKUP_DIR, f));
  }
}

function listBackups() {
  ensureDir();
  return fs
    .readdirSync(BACKUP_DIR)
    .filter((f) => /^space-.*\.db\.enc$/.test(f))
    .sort()
    .reverse()
    .map((f) => {
      const st = fs.statSync(path.join(BACKUP_DIR, f));
      return { file: f, size: st.size, mtime: st.mtime };
    });
}

/**
 * Восстановление: дешифрует бэкап и записывает в space.db.
 * Использовать только при остановленном сервере!
 */
function restoreBackup(encFile) {
  const p = path.join(BACKUP_DIR, encFile);
  if (!fs.existsSync(p)) throw new Error('Бэкап не найден: ' + encFile);
  const enc = fs.readFileSync(p);
  const plain = decryptBuffer(enc); // проверяет MAC
  fs.writeFileSync(DB_PATH, plain);
  for (const suffix of ['-wal', '-shm']) {
    try { fs.unlinkSync(DB_PATH + suffix); } catch (e) {}
  }
  return true;
}

function scheduleBackups() {
  backupNow();
  const t = setInterval(() => {
    try { backupNow(); } catch (e) { console.error('Ошибка бэкапа:', e.message); }
  }, INTERVAL);
  t.unref();
  return t;
}

module.exports = { backupNow, listBackups, restoreBackup, scheduleBackups, BACKUP_DIR };
