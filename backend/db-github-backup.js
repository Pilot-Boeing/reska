// Авто-бэкап БД (sqlite) в GitHub-репозиторий через Contents API.
// Позволяет сохранять данные между перезапусками Render (эфемерный диск)
// без привязки банковской карты. Требует переменных окружения:
//   GITHUB_TOKEN    — Personal Access Token с правами repo / contents:write
//   GITHUB_REPO     — "owner/repo" (по умолчанию "Pilot-Boeing/reska")
//   GITHUB_DB_PATH  — путь к файлу БД в репозитории (по умолчанию "space.db")
//   GITHUB_BRANCH  — ветка (по умолчанию "main")
//
// Примечание: restoreDbSync использует curl (доступен на Render/Linux).
// Если GITHUB_TOKEN не задан — функции тихо пропускаются.

const fs = require('fs');
const { execSync } = require('child_process');

function config() {
  const token = process.env.GITHUB_TOKEN;
  if (!token) return null;
  return {
    token,
    repo: process.env.GITHUB_REPO || 'Pilot-Boeing/reska',
    dbPath: process.env.GITHUB_DB_PATH || 'space.db',
    branch: process.env.GITHUB_BRANCH || 'main',
  };
}

// Синхронное восстановление БД из GitHub ПЕРЕД открытием файла.
// Используется в db.js до new DatabaseSync(DB_PATH).
function restoreDbSync(localPath) {
  const c = config();
  if (!c) return false;
  if (fs.existsSync(localPath)) return false;
  const url = `https://api.github.com/repos/${c.repo}/contents/${encodeURIComponent(c.dbPath)}?ref=${c.branch}`;
  try {
    const out = execSync(
      `curl -s -f -H "Authorization: Bearer ${c.token}" -H "User-Agent: reska" -H "Accept: application/vnd.github+json" "${url}"`,
      { encoding: 'utf8', maxBuffer: 100 * 1024 * 1024, timeout: 30000 }
    );
    const json = JSON.parse(out);
    if (json && json.content) {
      fs.writeFileSync(localPath, Buffer.from(json.content, 'base64'));
      console.log('[backup] БД восстановлена из GitHub-бэкапа:', localPath);
      return true;
    }
  } catch (e) {
    // 404 = файл ещё не загружался; другие ошибки — просто логируем
    console.error('[backup] Не удалось восстановить БД из GitHub:', e.message);
  }
  return false;
}

// Асинхронная выгрузка локальной БД в GitHub (вызывается по таймеру / при остановке).
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
      if (getRes.ok) {
        const j = await getRes.json();
        if (j && j.sha) sha = j.sha;
      }
    } catch (_) { /* файл может отсутствовать */ }
    const putRes = await fetch(url, {
      method: 'PUT',
      headers: { Authorization: `Bearer ${c.token}`, 'User-Agent': 'reska', 'Content-Type': 'application/json', Accept: 'application/vnd.github+json' },
      body: JSON.stringify({ message: 'db backup (auto)', content }),
    });
    if (!putRes.ok) {
      const t = await putRes.text();
      throw new Error(`GitHub PUT ${putRes.status}: ${t.slice(0, 160)}`);
    }
    console.log('[backup] БД выгружена в GitHub-бэкап:', localPath, `(${buf.length} байт)`);
    return true;
  } catch (e) {
    console.error('[backup] Ошибка выгрузки БД в GitHub:', e.message);
    return false;
  }
}

module.exports = { restoreDbSync, uploadDbFrom };
