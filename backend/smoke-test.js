/**
 * smoke-test.js — сквозной тест бэкенда.
 * Запускает сервер на отдельном порту с временной БД, прогоняет API-поток
 * (captcha → регистрация → CSRF → посты → медиа → чат → 2FA → сессии) и
 * сообщает о прохождении. Выход: 0 — всё ОК, 1 — есть ошибки.
 *
 *   npm run smoke
 */
const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const PORT = 31230 + Math.floor(Math.random() * 500);
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'space-smoke-'));
const DB = path.join(TMP, 'test.db');
const UP = path.join(TMP, 'uploads');

const BASE = `http://127.0.0.1:${PORT}`;
let passed = 0;
let failed = 0;

function ok(name) {
  passed++;
  console.log(`  ✔ ${name}`);
}
function bad(name, detail) {
  failed++;
  console.log(`  ✘ ${name}${detail ? ' — ' + detail : ''}`);
}

function check(name, cond, detail) {
  if (cond) ok(name);
  else bad(name, detail);
}

/* ---------- HTTP-клиент с cookie-джаром и CSRF ---------- */
function jarFrom(res) {
  const jar = {};
  let list = [];
  if (res.headers.getSetCookie) list = res.headers.getSetCookie();
  else {
    const raw = res.headers.get('set-cookie') || '';
    list = raw.split(/,(?=\s*[A-Za-z0-9_]+=)/);
  }
  for (const c of list) {
    const m = /^([^=]+)=([^;]*)/.exec(c);
    if (m) jar[m[1]] = m[2];
  }
  return jar;
}

function merge(a, b) {
  Object.assign(a, b);
  return a;
}

async function api(method, url, { body, jar, raw } = {}) {
  const headers = {};
  if (jar) headers.cookie = Object.entries(jar).map(([k, v]) => `${k}=${v}`).join('; ');
  if (method !== 'GET' && jar && jar.resk_csrf) headers['x-csrf-token'] = jar.resk_csrf;
  if (body && !raw) headers['content-type'] = 'application/json';
  const res = await fetch(BASE + url, {
    method,
    headers,
    body: body ? (raw ? body : JSON.stringify(body)) : undefined,
    redirect: 'manual'
  });
  let data = null;
  const rawText = await res.text();
  try { data = JSON.parse(rawText); } catch (e) { data = rawText; }
  return { res, data };
}

function captchaAnswer(text) {
  const m = /(\d+)\s*([+\-−])\s*(\d+)/.exec(String(text));
  if (!m) return 0;
  const a = parseInt(m[1], 10);
  const b = parseInt(m[3], 10);
  return m[2] === '+' ? a + b : a - b;
}

function totp(secret, t) {
  const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = String(secret).toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = 0, value = 0;
  const bytes = [];
  for (const ch of clean) {
    value = (value << 5) | B32.indexOf(ch);
    bits += 5;
    if (bits >= 8) { bytes.push((value >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  const key = Buffer.from(bytes);
  const counter = Math.floor(t / 1000 / 30);
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac('sha1', key).update(buf).digest();
  const off = hmac[hmac.length - 1] & 0x0f;
  const bin = ((hmac[off] & 0x7f) << 24) | (hmac[off + 1] << 16) | (hmac[off + 2] << 8) | hmac[off + 3];
  return String(bin % 1000000).padStart(6, '0');
}

/* ---------- PNG для проверки шифрования медиа ---------- */
const PNG = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==',
  'base64'
);

async function main() {
  const server = spawn(process.execPath, ['backend/server.js'], {
    env: {
      ...process.env,
      PORT: String(PORT),
      HTTPS_PORT: String(PORT + 1),
      SPACE_DB_PATH: DB,
      SPACE_UPLOAD_DIR: UP,
      NODE_ENV: 'test'
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  let out = '';
  server.stdout.on('data', (d) => (out += d));
  server.stderr.on('data', (d) => (out += d));

  const deadline = Date.now() + 30000;
  while (Date.now() < deadline) {
    try {
      const r = await fetch(`${BASE}/api/health`, { redirect: 'manual' });
      if (r.ok) break;
    } catch (e) {}
    await new Promise((r) => setTimeout(r, 300));
  }
  try {
    const r = await fetch(`${BASE}/api/health`, { redirect: 'manual' });
    check('сервер поднялся', r.ok);
    if (!r.ok) throw new Error('server not up');
  } catch (e) {
    console.error('Лог сервера:\n' + out);
    server.kill();
    process.exit(1);
  }

  /* 1. заголовки безопасности */
  let r = await api('GET', '/');
  check('заголовки безопасности (nosniff)', r.res.headers.get('x-content-type-options') === 'nosniff');
  check('CSP присутствует', !!r.res.headers.get('content-security-policy'));

  /* 2. регистрация требует капчу */
  r = await api('POST', '/api/auth/register', { body: { username: 'u_admin', password: 'pass1234', name: 'Admin Smoke' } });
  check('регистрация без капчи отклонена', r.res.status === 400 && r.data.needCaptcha === true);

  /* 3. капча + регистрация (первый = админ) */
  r = await api('GET', '/api/auth/captcha');
  const cap = r.data;
  check('капча выдана', !!cap.token && !!cap.text);
  const jarA = {};
  r = await api('POST', '/api/auth/register', {
    body: { username: 'u_admin', password: 'pass1234', name: 'Admin Smoke', captcha_token: cap.token, captcha_answer: captchaAnswer(cap.text) },
    jar: jarA
  });
  merge(jarA, jarFrom(r.res));
  check('регистрация админа', r.res.status === 201 && r.data.user.role === 'admin', String(r.res.status));
  const adminUid = r.data.user.uid;
  check('uid у пользователя', /^[1-9A-HJ-NP-Za-km-z]{10,16}$/.test(adminUid || ''));

  /* 4. me + CSRF-заголовок */
  r = await api('GET', '/api/auth/me', { jar: jarA });
  check('me возвращает профиль', r.res.status === 200 && r.data.user.username === 'u_admin');

  /* 5. CSRF защита: запрос без заголовка отклоняется */
  const noCsrfHeaders = { cookie: Object.entries(jarA).map(([k, v]) => `${k}=${v}`).join('; '), 'content-type': 'application/json' };
  let resNoCsrf = await fetch(`${BASE}/api/posts`, { method: 'POST', headers: noCsrfHeaders, body: JSON.stringify({ text: 'x' }) });
  check('запрос без CSRF отклонён', resNoCsrf.status === 403);

  /* 5a. Автопочинка: убрали CSRF-cookie (как старая сессия) → 403 → me выдаёт cookie → пост проходит */
  const jarStale = { ...jarA };
  delete jarStale.resk_csrf;
  r = await api('POST', '/api/posts', { body: { text: 'x' }, jar: jarStale });
  check('403 без CSRF-cookie', r.res.status === 403 && r.data.csrfFresh === true, String(r.res.status));
  r = await api('GET', '/api/auth/me', { jar: jarStale });
  const healedCsrf = jarFrom(r.res).resk_csrf;
  check('me выдаёт CSRF-cookie', !!healedCsrf);
  merge(jarStale, { resk_csrf: healedCsrf });
  r = await api('POST', '/api/posts', { body: { text: 'после автопочинки' }, jar: jarStale });
  check('пост после автопочинки CSRF', r.res.status === 201, String(r.res.status));

  /* 6. пост */
  r = await api('POST', '/api/posts', { body: { text: 'Первый пост!' }, jar: jarA });
  check('создание поста', r.res.status === 201 && r.data.post.uid, String(r.res.status));
  const postUid = r.data.post.uid;
  r = await api('GET', '/api/posts', { jar: jarA });
  check('лента постов', Array.isArray(r.data.posts) && r.data.posts.length >= 1);

  /* 7. пост с картинкой (зашифрованной) */
  const form = new FormData();
  form.append('text', 'Пост с картинкой');
  form.append('media', new Blob([PNG], { type: 'image/png' }), 'pic.png');
  r = await api('POST', '/api/posts', { body: form, jar: jarA, raw: true });
  check('пост с медиа', r.res.status === 201 && r.data.post.media, String(r.res.status));
  const mediaPath = r.data.post.media;
  const mediaRes = await fetch(`${BASE}/api/media/${mediaPath}`);
  const mediaBuf = Buffer.from(await mediaRes.arrayBuffer());
  check('медиа отдаётся (расшифровано)', mediaRes.status === 200 && mediaBuf.equals(PNG), `${mediaRes.status}`);
  check('Content-Type медиа', mediaRes.headers.get('content-type') === 'image/png');

  /* 8. Range-запрос к медиа */
  const rangeRes = await fetch(`${BASE}/api/media/${mediaPath}`, { headers: { range: 'bytes=0-9' } });
  check('Range-запрос (206)', rangeRes.status === 206 && rangeRes.headers.get('content-range')?.includes('/' + PNG.length));

  /* 9. комментарии + лайк */
  r = await api('POST', `/api/posts/${postUid}/comments`, { body: { text: 'Коммент' }, jar: jarA });
  check('комментарий', r.res.status === 201 && r.data.comment.uid);
  r = await api('POST', `/api/posts/${postUid}/like`, { jar: jarA });
  check('лайк поста', r.data.liked === true && r.data.likes === 1);

  /* 10. второй пользователь + чат + сообщения */
  r = await api('GET', '/api/auth/captcha');
  const cap2 = r.data;
  const jarB = {};
  r = await api('POST', '/api/auth/register', {
    body: { username: 'u_user', password: 'pass1234', name: 'User Smoke', captcha_token: cap2.token, captcha_answer: captchaAnswer(cap2.text) },
    jar: jarB
  });
  merge(jarB, jarFrom(r.res));
  check('регистрация обычного пользователя', r.res.status === 201 && r.data.user.role === 'user');

  r = await api('GET', '/api/users', { jar: jarA });
  const userB = r.data.users.find((u) => u.username === 'u_user');
  check('список пользователей', !!userB);
  r = await api('POST', '/api/chats', { body: { user_id: userB.id }, jar: jarA });
  check('чат создан', r.res.status === 201 && !!r.data.uid, String(r.res.status));
  const chatUid = r.data.uid;

  r = await api('POST', `/api/chats/${chatUid}/messages`, { body: { text: 'Привет из smoke!' }, jar: jarA });
  check('сообщение обычное', r.res.status === 201 && r.data.message.e2ee === 0);

  r = await api('POST', `/api/chats/${chatUid}/messages`, { body: { text: 'U2FsdGVkX1+ciAoOduQnDQ==', e2ee: true }, jar: jarA });
  check('сообщение e2ee', r.res.status === 201 && r.data.message.e2ee === 1);

  r = await api('GET', `/api/chats/${chatUid}/messages`, { jar: jarB });
  check('чтение чата другим участником', r.res.status === 200 && r.data.messages.length === 2);
  r = await api('GET', '/api/chats', { jar: jarB });
  check('превью e2ee скрыто', r.data.chats.some((c) => c.last_text === '🔒 Зашифровано'));

  /* 11. 2FA: включение + вход по коду */
  r = await api('POST', '/api/auth/2fa/setup', { jar: jarB });
  check('2FA setup', r.res.status === 200 && !!r.data.secret && !!r.data.token, String(r.res.status));
  const sec = r.data.secret;
  const code = totp(sec, Date.now());
  r = await api('POST', '/api/auth/2fa/verify', { body: { token: r.data.token, code }, jar: jarB });
  check('2FA подтверждена', r.res.status === 200, String(r.res.status) + ' ' + JSON.stringify(r.data).slice(0, 80));

  await api('POST', '/api/auth/logout', { jar: jarB });
  r = await api('POST', '/api/auth/login', { body: { username: 'u_user', password: 'pass1234' }, jar: jarB });
  check('вход без кода → шаг 2FA', r.data.step === 'totp' && !!r.data.totpToken);
  r = await api('POST', '/api/auth/login/2fa', { body: { totp_token: r.data.totpToken, code }, jar: jarB });
  merge(jarB, jarFrom(r.res));
  check('вход по 2FA коду', r.res.status === 200 && r.data.user.username === 'u_user', String(r.res.status));

  /* 12. сессии */
  r = await api('GET', '/api/auth/sessions', { jar: jarB });
  check('список сессий', r.res.status === 200 && r.data.sessions.length >= 1 && r.data.currentDevice);

  /* 13. E2EE публичный ключ */
  r = await api('PUT', `/api/users/${userB.uid}/e2ee`, { body: { pub: 'MIIB' + 'A'.repeat(60), ver: 1 }, jar: jarB });
  check('загрузка e2ee-ключа', r.res.status === 200, String(r.res.status));
  r = await api('GET', `/api/users/${userB.uid}/e2ee`, { jar: jarA });
  check('чтение e2ee-ключа', r.data.pub === 'MIIB' + 'A'.repeat(60));

  /* 14. поиск + профиль по uid */
  r = await api('GET', `/api/users/${adminUid}`, { jar: jarB });
  check('профиль по uid', r.res.status === 200 && r.data.user.username === 'u_admin');
  r = await api('GET', `/api/search?q=${encodeURIComponent('smoke')}`, { jar: jarA });
  check('поиск', r.res.status === 200 && (r.data.users.length + r.data.posts.length) > 0);

  /* 15. смена пароля и выход со всех устройств */
  r = await api('POST', '/api/auth/password', { body: { current_password: 'pass1234', new_password: 'newpass99' }, jar: jarA });
  check('смена пароля', r.res.status === 200, String(r.res.status));
  r = await api('POST', '/api/auth/logout-all', { jar: jarA });
  check('выход со всех устройств', r.res.status === 200);
  r = await api('GET', '/api/auth/me', { jar: jarA });
  check('сессия после logout-all закрыта', r.res.status === 401);

  server.kill();
  await new Promise((res) => server.once('exit', res));
  for (let i = 0; i < 5; i++) {
    try { fs.rmSync(TMP, { recursive: true, force: true }); break; }
    catch (e) { await new Promise((r) => setTimeout(r, 250)); }
  }

  console.log('\n──────────────────────────────');
  console.log(`Smoke: ${passed} passed, ${failed} failed`);
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error('Ошибка smoke-теста:', e);
  process.exit(1);
});
