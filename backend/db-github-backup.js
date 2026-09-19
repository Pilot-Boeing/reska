// Авто-бэкап БД (sqlite) в GitHub-репозиторий через Contents API.
// Позволяет сохранять данные между перезапусками Render (эфемерный диск)
// без привязки банковской карты. Требует переменных окружения:
//   GITHUB_TOKEN    — Personal Access Token с правами repo / contents:write
//   GITHUB_REPO     — "owner/repo" (по умолчанию "Pilot-Boeing/reska")
//   GITHUB_DB_PATH  — путь к файлу БД в репозитории (по умолчанию "space.db")
//   GITHUB_BRANCH  — ветка (по умолчанию "main")

const fs = require('fs');
const path = require('path');
const os = require('os');
const { execFileSync } = require('child_process');

let warnedNoToken = false;

// Ставится, если архив в GitHub есть, но не читается текущим ключом.
// Пока флаг поднят, авто-выгрузка приостановлена: нельзя затирать архив пустой БД.
let backupBlocked = false;

function config() {
  const token = process.env.GITHUB_TOKEN;
  if (!token) {
    if (!warnedNoToken) {
      console.log('[backup] GITHUB_TOKEN не задан — авто-бэкап БД отключён');
      warnedNoToken = true;
    }
    return null;
  }
  let repo = process.env.GITHUB_REPO || 'Pilot-Boeing/reska-db';
  // принимаем как "owner/repo", так и полную ссылку https://github.com/owner/repo(.git)
  repo = String(repo).replace(/^https?:\/\/github\.com\//i, '').replace(/\.git$/i, '').replace(/\/+$/, '');
  if (repo.includes('/')) repo = repo.split('/').slice(0, 2).join('/');
  return {
    token,
    repo,
    dbPath: process.env.GITHUB_DB_PATH || 'space.db',
    branch: process.env.GITHUB_BRANCH || 'main',
  };
}

// Локальная БД «пустая» (её безопасно заменить архивом из GitHub), если файла нет,
// он не открывается/повреждён, не содержит таблицы users или таблица пуста.
function looksEmpty(localPath) {
  try {
    const { DatabaseSync } = require('node:sqlite');
    const conn = new DatabaseSync(localPath, { readOnly: true });
    try {
      const t = conn.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='users'").get();
      if (!t) return true;
      const r = conn.prepare('SELECT COUNT(*) AS n FROM users').get();
      return !r || r.n === 0;
    } finally {
      try { conn.close(); } catch (_) {}
    }
  } catch (_) {
    return true;
  }
}

// Синхронное восстановление БД из GitHub ПЕРЕД открытием файла (используется в db.js).
function restoreDbSync(localPath) {
  const c = config();
  if (!c) return false;
  // Если локальная БД уже содержит реальные данные — не трогаем её.
  if (fs.existsSync(localPath) && !looksEmpty(localPath)) return false;
  const encPath = JSON.stringify(path.join(__dirname, 'encryption.js'));
  const script = `
    const TOKEN = process.env.GHTOKEN;
    const DEST = process.env.GH_PATH;
    const url = ${JSON.stringify(`https://api.github.com/repos/${c.repo}/contents/${encodeURIComponent(c.dbPath)}?ref=${c.branch}`)};
    const fs = require('fs');
    const { decryptBuffer, MAGIC } = require(${encPath});
    const SQLITE_MAGIC = 'SQLite format 3\\u0000';
    fetch(url, { headers: { Authorization: 'Bearer ' + TOKEN, 'User-Agent': 'reska', Accept: 'application/vnd.github+json' } })
      .then(async r => {
        if (r.status === 404) { console.log('[backup] Файла бэкапа ещё нет в GitHub — создам новую БД'); return { __404: true }; }
        if (!r.ok) throw new Error('HTTP ' + r.status + ': ' + (await r.text()).slice(0, 300));
        return r.json();
      })
      .then(j => {
        if (j && j.__404) return;
        if (!j || !j.content) throw new Error('нет содержимого файла в GitHub');
        const raw = Buffer.from(j.content, 'base64');
        let data;
        if (raw.length > MAGIC.length && raw.subarray(0, MAGIC.length).equals(MAGIC)) {
          data = decryptBuffer(raw);
        } else if (raw.subarray(0, SQLITE_MAGIC.length).toString('latin1') === SQLITE_MAGIC) {
          data = raw;
        } else {
          throw new Error('неизвестный формат бэкапа БД (не зашифрован и не sqlite)');
        }
        fs.writeFileSync(DEST, data);
        console.log('[backup] БД восстановлена из GitHub:', DEST);
      })
      .catch(e => {
        const msg = String(e.message);
        console.error('[backup] restore ошибка:', msg);
        // Бэкап есть, но не читается (ключ не совпал или формат битый).
        // Маркер блокировки: не затирать архив и не падать в штатном режиме.
        if (/расшифровать|неизвестный формат/.test(msg)) {
          process.stdout.write('\\nBACKUP_BLOCKED\\n');
        }
        process.exitCode = 2;
      });
  `;
  try {
    execFileSync(process.execPath, ['-e', script], {
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 60000,
      env: { ...process.env, GHTOKEN: c.token, GH_PATH: localPath },
    });
    return fs.existsSync(localPath);
  } catch (e) {
    const out = String((e.stdout || '') + (e.stderr || '') + e.message || '');
    if (out.includes('BACKUP_BLOCKED')) {
      backupBlocked = true;
      console.error(
        '[backup] Бэкап в GitHub есть, но не расшифровывается текущим SPACE_MASTER_KEY.\n' +
        '[backup] Файл архива оставлен без изменений; авто-выгрузка приостановлена, чтобы не затереть его.\n' +
        '[backup] Запуск продолжается с локальной БД. Чтобы вернуть данные: задайте прежний SPACE_MASTER_KEY\n' +
        '[backup] (тот, которым бэкап был создан) и перезапустите. Если ключ неизвестен, приложение стартует\n' +
        '[backup] пустым и после появления данных начнёт выгружать новый архив.'
      );
      return fs.existsSync(localPath);
    }
    if (!out.includes('Command failed')) console.error('[backup] Не удалось восстановить БД из GitHub:', e.message);
    return false;
  }
}

// Асинхронная выгрузка локальной БД в GitHub (по таймеру / при SIGTERM).
async function uploadDbFrom(localPath) {
  const c = config();
  if (!c) return false;
  if (!fs.existsSync(localPath)) return false;
  if (backupBlocked) {
    console.log('[backup] Авто-выгрузка БД приостановлена: архив не расшифровывается текущим ключом (не затираем его)');
    return false;
  }
  try {
    // Консистентный снапшот БД через VACUUM INTO (не только основной файл: WAL тоже участвует),
    // чтобы выгруженная копия не прерывала работу живой БД (node:sqlite в режиме WAL).
    const tmpPath = path.join(os.tmpdir(), `reska-db-${Date.now()}-${process.pid}.db`);
    let plain;
    try {
      const { DatabaseSync } = require('node:sqlite');
      const conn = new DatabaseSync(localPath, { readOnly: false });
      try {
        conn.exec('PRAGMA wal_checkpoint(TRUNCATE);');
        conn.exec(`VACUUM INTO '${String(tmpPath).replace(/'/g, "''")}'`);
      } finally {
        conn.close();
      }
      plain = fs.readFileSync(tmpPath);
      fs.unlinkSync(tmpPath);
    } catch (e) {
      console.error('[backup] Ошибка подготовки снапшота БД:', e.message);
      return false;
    }
    // Шифруем только при стабильном мастер-ключе в env: иначе на Render без SPACE_MASTER_KEY
    // каждый рестарт давал бы новый случайный ключ и бэкап становился бы нечитаемым.
    const stableKey = process.env.SPACE_MASTER_KEY && String(process.env.SPACE_MASTER_KEY).trim();
    let buf = plain;
    if (stableKey) {
      const { encryptBuffer } = require('./encryption');
      buf = encryptBuffer(plain);
    }
    const content = buf.toString('base64');
    const url = `https://api.github.com/repos/${c.repo}/contents/${encodeURIComponent(c.dbPath)}`;
    let sha;
    try {
      const getRes = await fetch(`${url}?ref=${c.branch}`, {
        headers: { Authorization: `Bearer ${c.token}`, 'User-Agent': 'reska', Accept: 'application/vnd.github+json' },
      });
      if (getRes.ok) { const j = await getRes.json(); if (j && j.sha) sha = j.sha; }
    } catch (_) { /* файл может отсутствовать */ }
    const putBody = { message: 'db backup (auto)', content };
    if (sha) putBody.sha = sha;
    const putRes = await fetch(url, {
      method: 'PUT',
      headers: { Authorization: `Bearer ${c.token}`, 'User-Agent': 'reska', 'Content-Type': 'application/json', Accept: 'application/vnd.github+json' },
      body: JSON.stringify(putBody),
    });
    if (!putRes.ok) {
      const t = await putRes.text();
      throw new Error(`GitHub PUT ${putRes.status}: ${t.slice(0, 200)}`);
    }
    console.log('[backup] БД выгружена в GitHub:', `(${buf.length} байт)`);
    return true;
  } catch (e) {
    console.error('[backup] Ошибка выгрузки БД в GitHub:', e.message);
    return false;
  }
}

module.exports = { restoreDbSync, uploadDbFrom };
