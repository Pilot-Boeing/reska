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
  if (method !== 'GET' && jar && jar.reska_csrf) headers['x-csrf-token'] = jar.reska_csrf;
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
  delete jarStale.reska_csrf;
  r = await api('POST', '/api/posts', { body: { text: 'x' }, jar: jarStale });
  check('403 без CSRF-cookie', r.res.status === 403 && r.data.csrfFresh === true, String(r.res.status));
  r = await api('GET', '/api/auth/me', { jar: jarStale });
  const healedCsrf = jarFrom(r.res).reska_csrf;
  check('me выдаёт CSRF-cookie', !!healedCsrf);
  merge(jarStale, { reska_csrf: healedCsrf });
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

  /* 10.1 медиа-сообщение: файл в чате */
  const chatForm = new FormData();
  chatForm.append('text', 'Вот файл');
  chatForm.append('duration', '3.5');
  chatForm.append('file', new Blob([PNG], { type: 'image/png' }), 'chat-pic.png');
  r = await api('POST', `/api/chats/${chatUid}/messages`, { body: chatForm, jar: jarA, raw: true });
  check('медиа-сообщение', r.res.status === 201 && r.data.message.media, String(r.res.status));
  const chatMediaPath = r.data.message.media;
  check('тип медиа image', r.data.message.media_type === 'image');
  const chatMediaRes = await fetch(`${BASE}/api/media/${chatMediaPath}`, {
    headers: { cookie: Object.entries(jarA).map(([k, v]) => `${k}=${v}`).join('; ') }
  });
  const chatMediaBuf = Buffer.from(await chatMediaRes.arrayBuffer());
  check('медиа чата отдаётся', chatMediaRes.status === 200 && chatMediaBuf.equals(PNG), `${chatMediaRes.status}`);
  const chatMediaAnonymous = await fetch(`${BASE}/api/media/${chatMediaPath}`);
  const anonText = await chatMediaAnonymous.text();
  check('медиа чата без сессии → 403/401', chatMediaAnonymous.status === 403 || chatMediaAnonymous.status === 401 || /Доступ/.test(anonText), `${chatMediaAnonymous.status}`);
  const chatListA = await api('GET', '/api/chats', { jar: jarA });
  check('превью фото в списке чатов', chatListA.data.chats.some((c) => c.last_text === '🖼 Фото'));
  r = await api('DELETE', `/api/chats/${chatUid}/messages/${r.data.message.id}`, { jar: jarA });
  check('удаление медиа-сообщения', r.res.status === 200);
  const chatMediaGone = await fetch(`${BASE}/api/media/${chatMediaPath}`, {
    headers: { cookie: Object.entries(jarA).map(([k, v]) => `${k}=${v}`).join('; ') }
  });
  check('файл удалён с диска', chatMediaGone.status === 404, `${chatMediaGone.status}`);

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

  /* 15. друзья: заявка → входящая → принятие → список → удаление */
  r = await api('GET', `/api/users/${userB.uid}`, { jar: jarA });
  check('relation none до заявки', r.res.status === 200 && r.data.relation === 'none', r.data.relation);

  r = await api('POST', `/api/users/${userB.uid}/friend`, { jar: jarA });
  check('заявка в друзья отправлена', r.res.status === 200 && r.data.relation === 'outgoing', String(r.res.status));

  r = await api('POST', `/api/users/${userB.uid}/friend`, { jar: jarA });
  check('повторная заявка возвращает статус', r.res.status === 200 && r.data.relation === 'outgoing', String(r.res.status));

  r = await api('GET', `/api/users/${userB.uid}`, { jar: jarA });
  check('relation outgoing', r.data.relation === 'outgoing', r.data.relation);

  r = await api('GET', '/api/users/requests', { jar: jarA });
  check('исходящие заявки у отправителя', r.res.status === 200 && r.data.outgoing.some((u) => u.uid === userB.uid));

  r = await api('GET', '/api/users/requests', { jar: jarB });
  check('входящие заявки у получателя', r.res.status === 200 && r.data.incoming.some((u) => u.uid === adminUid));

  r = await api('GET', '/api/users/list', { jar: jarA });
  check('список друзей пока пуст', r.res.status === 200 && r.data.friends.length === 0);

  r = await api('POST', `/api/users/${adminUid}/friend/accept`, { jar: jarB });
  check('принятие заявки', r.res.status === 200 && r.data.relation === 'friends', String(r.res.status));

  r = await api('GET', `/api/users/${userB.uid}`, { jar: jarA });
  check('relation friends', r.data.relation === 'friends', r.data.relation);

  r = await api('GET', '/api/users/list', { jar: jarA });
  check('друг в списке', r.res.status === 200 && r.data.friends.some((u) => u.uid === userB.uid));

  r = await api('GET', '/api/users/list', { jar: jarB });
  check('друг в списке у второй стороны', r.res.status === 200 && r.data.friends.some((u) => u.uid === adminUid));

  r = await api('POST', `/api/users/${userB.uid}/friend`, { jar: jarA });
  check('заявка при дружбе отклонена', r.res.status === 400, String(r.res.status));

  r = await api('DELETE', `/api/users/${userB.uid}/friend`, { jar: jarA });
  check('удаление из друзей', r.res.status === 200 && r.data.relation === 'none', String(r.res.status));

  r = await api('GET', `/api/users/${userB.uid}`, { jar: jarA });
  check('relation none после удаления', r.data.relation === 'none', r.data.relation);

  r = await api('DELETE', `/api/users/${userB.uid}/friend`, { jar: jarB });
  check('заявка удалена другой стороной', r.res.status === 200, String(r.res.status));

  r = await api('POST', `/api/users/${userB.uid}/friend`, { jar: jarA });
  check('новая заявка после очистки', r.res.status === 200 && r.data.relation === 'outgoing');
  r = await api('DELETE', `/api/users/${userB.uid}/friend`, { jar: jarA });
  check('отмена исходящей заявки', r.res.status === 200 && r.data.relation === 'none');

  /* 16. смена пароля и выход со всех устройств */
  r = await api('POST', '/api/auth/password', { body: { current_password: 'pass1234', new_password: 'newpass99' }, jar: jarA });
  check('смена пароля', r.res.status === 200, String(r.res.status));
  r = await api('POST', '/api/auth/logout-all', { jar: jarA });
  check('выход со всех устройств', r.res.status === 200);
  r = await api('GET', '/api/auth/me', { jar: jarA });
  check('сессия после logout-all закрыта', r.res.status === 401);

  /* 17. телефон в профиле */
  r = await api('PUT', `/api/users/${userB.uid}`, { body: { name: 'B Smoke', phone: '+7 999 123-45-67' }, jar: jarB });
  check('обновление телефона', r.res.status === 200 && r.data.user.phone === '+7 999 123-45-67', String(r.res.status));
  r = await api('PUT', `/api/users/${userB.uid}`, { body: { name: 'B Smoke', phone: 'bad' }, jar: jarB });
  check('плохой телефон отклонён', r.res.status === 400);

  r = await api('GET', `/api/users/${userB.uid}`, { jar: jarB });
  check('свой телефон виден владельцу', r.data.user.phone === '+7 999 123-45-67', r.data.user.phone);
  r = await api('GET', `/api/users/${userB.uid}`, { jar: jarA });
  check('чужой телефон не утекает', !('phone' in r.data.user));

  /* 17a. личные имена (алиасы) */
  r = await api('POST', '/api/auth/login', { body: { username: 'u_admin', password: 'newpass99' }, jar: jarA });
  merge(jarA, jarFrom(r.res));
  check('повторный вход админа', r.res.status === 200, String(r.res.status));

  r = await api('GET', '/api/users/aliases', { jar: jarA });
  check('список алиасов пуст', r.res.status === 200 && r.data.aliases.length === 0);

  r = await api('PUT', `/api/users/${userB.uid}/alias`, { body: { alias: 'Мой друг' }, jar: jarA });
  check('установка алиаса', r.res.status === 200 && r.data.alias === 'Мой друг', String(r.res.status));

  r = await api('PUT', `/api/users/${userB.uid}/alias`, { body: { alias: '   ' }, jar: jarA });
  check('пустой алиас удаляет', r.res.status === 200 && r.data.alias === '');

  r = await api('PUT', `/api/users/${userB.uid}/alias`, { body: { alias: 'Друг 2' }, jar: jarA });
  check('переустановка алиаса', r.res.status === 200 && r.data.alias === 'Друг 2');

  r = await api('GET', '/api/users/aliases', { jar: jarA });
  check('алиас в списке', r.data.aliases.some((a) => a.uid === userB.uid && a.alias === 'Друг 2'));

  r = await api('GET', '/api/users/aliases', { jar: jarB });
  check('алиасы видны только владельцу', r.res.status === 200 && r.data.aliases.length === 0);

  r = await api('PUT', `/api/users/${userB.uid}/alias`, { body: { alias: 'x' }, jar: jarB });
  check('алиас на себя запрещён', r.res.status === 400);

  r = await api('DELETE', `/api/users/${userB.uid}/alias`, { jar: jarA });
  check('удаление алиаса', r.res.status === 200 && r.data.alias === '');

  r = await api('GET', '/api/users/aliases', { jar: jarA });
  check('алиас удалён из списка', r.data.aliases.length === 0);

  r = await api('PUT', `/api/users/${userB.uid}/alias`, { body: { alias: 'Друг 3' }, jar: jarA });
  check('алиас для чата', r.res.status === 200);
  r = await api('POST', `/api/chats/${chatUid}/messages`, { body: { text: 'проверка sender_uid' }, jar: jarB });
  check('сообщение для проверки sender_uid', r.res.status === 201);
  r = await api('GET', `/api/chats/${chatUid}/messages`, { jar: jarA });
  const sndMsg = r.data.messages.find((m) => m.text === 'проверка sender_uid');
  check('sender_uid в сообщении', !!sndMsg && sndMsg.sender_uid === userB.uid, JSON.stringify(sndMsg));
  r = await api('DELETE', `/api/users/${userB.uid}/alias`, { jar: jarA });
  check('алиас убран', r.res.status === 200);

  /* 18. библиотека: конспекты и группы (серверное хранение) */
  r = await api('GET', '/api/library/notes', { jar: jarB });
  check('список конспектов пуст', r.res.status === 200 && Array.isArray(r.data.notes));
  r = await api('POST', '/api/library/notes', { body: { title: 'Тактика', body: 'заметка #тест' }, jar: jarB });
  check('создание конспекта', r.res.status === 201 && r.data.note.title === 'Тактика', String(r.res.status));
  const noteId = r.data.note.id;
  r = await api('PUT', `/api/library/notes/${noteId}`, { body: { title: 'Тактика 2', body: 'x' }, jar: jarB });
  check('обновление конспекта', r.res.status === 200 && r.data.note.title === 'Тактика 2');
  r = await api('GET', '/api/library/notes', { jar: jarB });
  check('конспект в списке', r.data.notes.some((n) => n.id === noteId));
  r = await api('DELETE', `/api/library/notes/${noteId}`, { jar: jarB });
  check('удаление конспекта', r.res.status === 200);
  const jarA2 = {};
  r = await api('POST', '/api/auth/login', { body: { username: 'u_admin', password: 'newpass99' }, jar: jarA2 });
  merge(jarA2, jarFrom(r.res));
  const adminId = r.data.user.id;
  r = await api('POST', '/api/library/notes', { body: { title: 'note-admin' }, jar: jarA2 });
  const noteAdmin = r.data.note;
  r = await api('PUT', `/api/library/notes/${noteAdmin.id}`, { body: { title: 'hack' }, jar: jarB });
  check('чужой конспект нельзя редактировать', r.res.status === 403, String(r.res.status));
  r = await api('DELETE', `/api/library/notes/${noteAdmin.id}`, { jar: jarB });
  check('чужой конспект нельзя удалять', r.res.status === 403, String(r.res.status));

  r = await api('POST', '/api/library/groups', { body: { name: 'Группа А', description: 'описание' }, jar: jarB });
  check('создание группы', r.res.status === 201 && r.data.group.name === 'Группа А' && !!r.data.group.chatUid, String(r.res.status));
  const groupId = r.data.group.id;
  const groupChatUid = r.data.group.chatUid;
  r = await api('PUT', `/api/library/groups/${groupId}`, { body: { name: 'Группа Б' }, jar: jarB });
  check('обновление группы', r.res.status === 200 && r.data.group.name === 'Группа Б');

  r = await api('POST', `/api/library/groups/${groupId}/members`, { body: { user_id: adminId }, jar: jarB });
  check('добавление участника создателем', r.res.status === 200, String(r.res.status));
  r = await api('GET', `/api/library/groups/${groupId}/members`, { jar: jarA2 });
  check('состав группы виден участнику', r.res.status === 200 && r.data.members.length === 2);
  r = await api('POST', `/api/library/groups/${groupId}/members`, { body: { user_id: adminId }, jar: jarA2 });
  check('добавлять участника может только создатель', r.res.status === 403, String(r.res.status));

  r = await api('GET', `/api/chats/${groupChatUid}/messages`, { jar: jarA2 });
  check('участник видит чат группы', r.res.status === 200 && Array.isArray(r.data.messages));
  r = await api('POST', `/api/chats/${groupChatUid}/messages`, { body: { text: 'привет всем' }, jar: jarA2 });
  check('участник пишет в группу', r.res.status === 201, String(r.res.status));
  r = await api('GET', '/api/chats', { jar: jarA2 });
  const groupInChats = r.data.chats.find((c) => c.uid === groupChatUid);
  check('группа в списке чатов участника', !!(groupInChats && groupInChats.kind === 'group'));

  const jarC = {};
  r = await api('GET', '/api/auth/captcha');
  const cap3 = r.data;
  r = await api('POST', '/api/auth/register', {
    body: { username: 'u_outsider', password: 'Password123', name: 'Outsider', captcha_token: cap3.token, captcha_answer: captchaAnswer(cap3.text) },
    jar: jarC
  });
  merge(jarC, jarFrom(r.res));
  const outsiderId = r.data.user.id;
  r = await api('GET', `/api/chats/${groupChatUid}/messages`, { jar: jarC });
  check('не участник не видит чат группы', r.res.status === 403, String(r.res.status));

  r = await api('DELETE', `/api/library/groups/${groupId}/members/${adminId}`, { jar: jarB });
  check('исключение участника создателем', r.res.status === 200);
  r = await api('GET', `/api/chats/${groupChatUid}/messages`, { jar: jarA2 });
  check('исключённый теряет доступ', r.res.status === 403, String(r.res.status));

  r = await api('DELETE', `/api/library/groups/${groupId}`, { jar: jarB });
  check('удаление группы', r.res.status === 200);

  /* 18. удаление чатов */
  r = await api('POST', '/api/chats', { body: { user_id: outsiderId }, jar: jarA2 });
  check('чат с аутсайдером создан', r.res.status === 201 && !!r.data.uid, String(r.res.status));
  const dmUid = r.data.uid;
  r = await api('DELETE', `/api/chats/${dmUid}`, { jar: jarB });
  check('удалять чужой чат нельзя', r.res.status === 403, String(r.res.status));
  r = await api('DELETE', `/api/chats/${dmUid}`, { jar: jarA2 });
  check('удаление личного чата', r.res.status === 200, String(r.res.status));
  r = await api('GET', '/api/chats', { jar: jarA2 });
  check('чат исчез из списка', !r.data.chats.some((c) => c.uid === dmUid));

  r = await api('POST', '/api/library/groups', { body: { name: 'Группа У' }, jar: jarB });
  check('группа для удаления создана', r.res.status === 201 && !!r.data.group.chatUid, String(r.res.status));
  const gdelId = r.data.group.id;
  const gdelChat = r.data.group.chatUid;
  r = await api('DELETE', `/api/chats/${gdelChat}`, { jar: jarA2 });
  check('не создатель не удалит группу', r.res.status === 403, String(r.res.status));
  r = await api('DELETE', `/api/chats/${gdelChat}`, { jar: jarB });
  check('удаление группы через чат', r.res.status === 200, String(r.res.status));
  r = await api('GET', '/api/library/groups', { jar: jarB });
  check('группа исчезла из списка', !r.data.groups.some((g) => g.id === gdelId));

  /* 19. уведомления: центр (like/comment/follow/friend/message) */
  r = await api('POST', `/api/posts/${postUid}/like`, { jar: jarB });
  check('лайк от другого юзера', r.res.status === 200);
  r = await api('POST', `/api/posts/${postUid}/comments`, { body: { text: 'уведомляющий коммент' }, jar: jarB });
  check('комментарий от другого юзера', r.res.status === 201);
  r = await api('POST', `/api/users/${adminUid}/follow`, { jar: jarB });
  check('подписка от другого юзера', r.res.status === 200);
  r = await api('POST', `/api/users/${adminUid}/friend`, { jar: jarB });
  check('заявка в друзья админу', r.res.status === 200 && r.data.relation === 'outgoing', String(r.res.status));
  r = await api('POST', `/api/chats/${chatUid}/messages`, { body: { text: 'уведомляющее сообщение' }, jar: jarB });
  check('сообщение для уведомления', r.res.status === 201);

  r = await api('GET', '/api/notifications', { jar: jarA });
  check('список уведомлений', r.res.status === 200 && Array.isArray(r.data.notifications) && r.data.notifications.length >= 5, String(r.res.status));
  check('счётчик непрочитанных', r.data.unread >= 5, String(r.data.unread));
  const unreadBeforeRead = r.data.unread;
  const nTypes = new Set(r.data.notifications.slice(0, 10).map((n) => n.type));
  check('типы уведомлений (like/comment/follow/friend/message)',
    ['like', 'comment', 'follow', 'friend_request', 'message'].every((t) => nTypes.has(t)), [...nTypes].join(','));
  check('в уведомлении есть данные актора', r.data.notifications[0].actor_uid && r.data.notifications[0].actor_name);

  const notifId = r.data.notifications[0].id;
  r = await api('POST', '/api/notifications/read', { body: { id: notifId }, jar: jarA });
  check('прочитано одно уведомление', r.res.status === 200 && r.data.unread === unreadBeforeRead - 1,
    `before=${unreadBeforeRead} after=${r.data.unread}`);

  r = await api('POST', '/api/notifications/read', { body: {}, jar: jarA });
  check('read без id → 400', r.res.status === 400, String(r.res.status));

  r = await api('POST', '/api/notifications/read-all', { jar: jarA });
  check('все прочитаны', r.res.status === 200 && r.data.unread === 0);

  r = await api('GET', '/api/notifications', { jar: jarA });
  check('счётчик после read-all = 0', r.data.unread === 0 && r.data.notifications.every((n) => n.read === 1));

  r = await api('GET', '/api/notifications', { jar: jarC });
  check('чужой не видит чужие уведомления', r.res.status === 200 && r.data.notifications.length === 0);

  /* 20. поиск по контактам телефонной книги */
  r = await api('POST', '/api/search/contacts', { body: { phones: ['+7 999 123-45-67', '89991234567', '8 (999) 123-45-67'] }, jar: jarB });
  check('контакт найден', r.res.status === 200 && r.data.matches.length === 1, JSON.stringify(r.data).slice(0, 150));
  check('совпадение с u_user', r.data.matches[0] && r.data.matches[0].user.username === 'u_user');
  check('номер в ответе нормализован', r.data.matches[0] && r.data.matches[0].phone === '79991234567');

  r = await api('POST', '/api/search/contacts', { body: { phones: ['+1 202 555 0100', '+49 30 12345'] }, jar: jarB });
  check('чужие (не РФ) номера не найдены', r.res.status === 200 && r.data.matches.length === 0);

  r = await api('POST', '/api/search/contacts', { body: { phones: ['+7 999 123-45-67'] }, jar: {} });
  check('контакты без авторизации → 401', r.res.status === 401, String(r.res.status));

  r = await api('POST', '/api/search/contacts', { body: {}, jar: jarB });
  check('contacts без phones → 400', r.res.status === 400, String(r.res.status));

  r = await api('POST', '/api/search/contacts', { body: { phones: ['+7 999 123-45-67'] }, jar: jarC });
  check('номер не утекает при совпадении', r.res.status === 200 && r.data.matches.length === 1 && !('phone' in r.data.matches[0].user));

  // Реакции на постах (Этап 2)
  r = await api('POST', '/api/posts', { body: { text: 'reaction test' }, jar: jarA });
  const reactPostId = r.data.post.id;
  r = await api('POST', '/api/posts/' + reactPostId + '/react', { body: { emoji: '🔥' }, jar: jarA });
  check('реакция на пост добавляется', r.res.status === 200 && Array.isArray(r.data.reactions.list) && r.data.reactions.list.length === 1 && r.data.reactions.list[0].emoji === '🔥');
  r = await api('POST', '/api/posts/' + reactPostId + '/react', { body: { emoji: '🔥' }, jar: jarA });
  check('повторная реакция удаляет (toggle)', r.res.status === 200 && r.data.reactions.list.length === 0);

  // Реплаи в чате (Этап 2)
  r = await api('POST', '/api/chats/self', { jar: jarA });
  const selfUid = r.data.uid;
  r = await api('POST', '/api/chats/' + selfUid + '/messages', { body: { text: 'первое' }, jar: jarA });
  const firstMsgId = r.data.message.id;
  r = await api('POST', '/api/chats/' + selfUid + '/messages', { body: { text: 'ответ', reply_to: firstMsgId }, jar: jarA });
  check('реплай в чате сохраняет reply_to', r.res.status === 201 && r.data.message.reply && r.data.message.reply.id === firstMsgId);

  // Пересылка сообщений (Этап 2)
  r = await api('POST', '/api/chats/forward', { body: { message_id: firstMsgId, chat_uids: [chatUid] }, jar: jarA });
  check('пересылка сообщения в другой чат', r.res.status === 200 && r.data.ok === true && r.data.count === 1);

  // Репосты постов (Этап 2)
  r = await api('POST', '/api/posts', { body: { text: 'оригинальный пост' }, jar: jarA });
  const origPostId = r.data.post.id;
  r = await api('POST', '/api/posts', { body: { repost_of: origPostId }, jar: jarA });
  check('репост поста создаётся с цитатой', r.res.status === 201 && r.data.post.repost && r.data.post.repost.id === origPostId);
  r = await api('GET', '/api/posts', { jar: jarA });
  const repostInFeed = r.data.posts.find((p) => p.repost && p.repost.id === origPostId);
  check('репост отображается в ленте с данными оригинала', !!repostInFeed);

  // Онлайн-статус (Этап 2)
  r = await api('GET', '/api/chats', { jar: jarA });
  const dmChat = r.data.chats.find((c) => c.kind !== 'group');
  check('в списке чатов есть поле online', dmChat && typeof dmChat.online === 'boolean');

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
