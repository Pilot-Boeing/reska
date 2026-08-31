// Авто-бэкап БД (sqlite) в GitHub-репозиторий через Contents API.
// Позволяет сохранять данные между перезапусками Render (эфемерный диск)
// без привязки банковской карты. Требует переменных окружения:
//   GITHUB_TOKEN    — Personal Access Token с правами repo / contents:write
//   GITHUB_REPO     — "owner/repo" (по умолчанию "Pilot-Boeing/reska")
//   GITHUB_DB_PATH  — путь к файлу БД в репозитории (по умолчанию "space.db")
//   GITHUB_BRANCH  — ветка (по умолчанию "main")

const fs = require('fs');
const { execSync } = require('child_process');

let warnedNoToken = false;

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

// Синхронное восстановление БД из GitHub ПЕРЕД открытием файла (используется в db.js).
function restoreDbSync(localPath) {
  const c = config();
  if (!c) return false;
  if (fs.existsSync(localPath)) return false;
  const url = `https://api.github.com/repos/${c.repo}/contents/${encodeURIComponent(c.dbPath)}?ref=${c.branch}`;
  const script = `
    const TOKEN = process.env.GHTOKEN;
    const url = ${JSON.stringify(url)};
    fetch(url, { headers: { Authorization: 'Bearer ' + TOKEN, 'User-Agent': 'reska', Accept: 'application/vnd.github+json' } })
      .then(r => { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
      .then(j => { if (!j.content) throw new Error('нет content'); require('fs').writeFileSync(${JSON.stringify(localPath)}, Buffer.from(j.content, 'base64')); console.log('[backup] БД восстановлена из GitHub:', ${JSON.stringify(localPath)}); })
      .catch(e => { console.error('[backup] restore ошибка:', e.message); process.exit(2); });
  `;
  try {
    execSync('node -e ' + JSON.stringify(script), {
      stdio: 'inherit',
      timeout: 30000,
      env: { ...process.env, GHTOKEN: c.token },
    });
    return fs.existsSync(localPath);
  } catch (e) {
    console.error('[backup] Не удалось восстановить БД из GitHub:', e.message);
    return false;
  }
}

// Асинхронная выгрузка локальной БД в GitHub (по таймеру / при SIGTERM).
async function uploadDbFrom(localPath) {
  const c = config();
  if (!c) return false;
  if (!fs.existsSync(localPath)) return false;
  try {
    const buf = fs.readFileSync(localPath);
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
