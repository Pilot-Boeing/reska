
/* =========================================================
   РЕСКА — клиент (SPA без фреймворков)
   Безопасность: CSRF double-submit, капча, 2FA (TOTP),
   E2EE сообщений (WebCrypto ECDH + AES-GCM), uid-ссылки.
   ========================================================= */

/* ---------- утилиты ---------- */
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

const esc = (s) =>
  String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

/* Хэштеги: #слово → ссылка на поиск (#/search?q=слово) */
function linkifyTags(text) {
  return esc(text).replace(
    /(^|\s)#([\p{L}\p{N}_]+)/gu,
    '$1<a class="tag" href="#/search?q=$2">#$2</a>'
  );
}

const DEFAULT_AVATAR =
  "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='200' height='200'%3E%3Cdefs%3E%3ClinearGradient id='g' x1='0' y1='0' x2='1' y2='1'%3E%3Cstop offset='0' stop-color='%23a855f7'/%3E%3Cstop offset='1' stop-color='%237c3aed'/%3E%3C/linearGradient%3E%3C/defs%3E%3Crect width='200' height='200' rx='40' fill='url(%23g)'/%3E%3Ctext x='100' y='120' font-family='Arial' font-size='80' font-weight='bold' fill='white' text-anchor='middle'%3E?%3C/text%3E%3C/svg%3E";

const mediaUrl = (p) => (p ? '/api/media/' + p : DEFAULT_AVATAR);

function getCookie(name) {
  const m = new RegExp('(?:^|; )' + name.replace(/([.$?*|{}()[\]\\/+^])/g, '\\$1') + '=([^;]*)').exec(document.cookie);
  return m ? decodeURIComponent(m[1]) : null;
}

function timeAgo(dateStr) {
  if (!dateStr) return '';
  const d = /T/.test(dateStr) ? new Date(dateStr) : new Date(dateStr.replace(' ', 'T') + 'Z');
  const sec = Math.floor((Date.now() - d.getTime()) / 1000);
  if (sec < 60) return 'только что';
  const min = Math.floor(sec / 60);
  if (min < 60) return min + ' мин назад';
  const h = Math.floor(min / 60);
  if (h < 24) return h + ' ч назад';
  const days = Math.floor(h / 24);
  if (days < 7) return days + ' дн назад';
  return d.toLocaleDateString('ru-RU');
}

function fmtTime(iso) {
  if (!iso) return '';
  const d = /T/.test(iso) ? new Date(iso) : new Date(iso.replace(' ', 'T') + 'Z');
  const pad = (n) => String(n).padStart(2, '0');
  const hm = pad(d.getHours()) + ':' + pad(d.getMinutes());
  const now = new Date();
  if (d.toDateString() === now.toDateString()) return 'сегодня, ' + hm;
  const y = new Date(now);
  y.setDate(now.getDate() - 1);
  if (d.toDateString() === y.toDateString()) return 'вчера, ' + hm;
  const dm = pad(d.getDate()) + '.' + pad(d.getMonth() + 1);
  if (d.getFullYear() === now.getFullYear()) return dm + ', ' + hm;
  return dm + '.' + String(d.getFullYear()).slice(2) + ', ' + hm;
}

function fmtViews(n) {
  n = Number(n) || 0;
  if (n >= 1e6) return (n / 1e6).toFixed(1).replace('.0', '') + 'M';
  if (n >= 1e3) return (n / 1e3).toFixed(1).replace('.0', '') + 'K';
  return String(n);
}

function fmtSize(bytes) {
  const b = Number(bytes) || 0;
  if (b >= 1073741824) return (b / 1073741824).toFixed(1).replace('.0', '') + ' ГБ';
  if (b >= 1048576) return (b / 1048576).toFixed(1).replace('.0', '') + ' МБ';
  if (b >= 1024) return (b / 1024).toFixed(0) + ' КБ';
  return b + ' Б';
}

function fmtDuration(sec) {
  const s = Math.round(Number(sec) || 0);
  return Math.floor(s / 60) + ':' + String(s % 60).padStart(2, '0');
}

function friendBtnLabel(rel) {
  switch (rel) {
    case 'friends': return '✓ Друзья';
    case 'outgoing': return '⏳ Заявка отправлена';
    case 'incoming': return '✔ Принять заявку';
    default: return '＋ Добавить в друзья';
  }
}

function b64encode(buf) {
  let s = '';
  for (let i = 0; i < buf.length; i++) s += String.fromCharCode(buf[i]);
  return btoa(s);
}
function b64decode(str) {
  const bin = atob(str);
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return u8;
}

/* ---------- API (CSRF + обработка 401) ---------- */
async function api(path, opts = {}) {
  const method = opts.method || 'GET';
  const headers = {};
  if (!(opts.body instanceof FormData) && opts.body !== undefined) headers['Content-Type'] = 'application/json';
  const csrf = getCookie('reska_csrf');
  if (method !== 'GET' && csrf) headers['X-CSRF-Token'] = csrf;

  let res;
  try {
    res = await fetch('/api' + path, {
      method,
      headers,
      body: opts.body instanceof FormData ? opts.body : opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
      credentials: 'same-origin'
    });
  } catch (e) {
    const err = new Error('Нет связи с сервером');
    err.status = 0;
    throw err;
  }
  let data = null;
  const raw = await res.text();
  try { data = JSON.parse(raw); } catch (e) { data = raw; }
  if (!res.ok) {
    if (res.status === 403 && data && data.csrfFresh && !opts.csrfRetried) {
      return api(path, { ...opts, csrfRetried: true });
    }
    if (res.status === 401 && me && !opts.silent) sessionExpired();
    const err = new Error((data && data.error) || 'Ошибка запроса');
    err.status = res.status;
    err.data = data;
    throw err;
  }
  return data;
}

/* ---------- состояние ---------- */
let me = null;
let socket = null;
let activeChatUid = null;
let activeChat = null;
let chatsCache = [];
let chatMsgState = null;
let chatReplyTarget = null;
let currentSearch = '';

/* ---------- экран загрузки ---------- */
function setSplashStatus(msg) {
  const el = $('#splash-status');
  if (el) el.textContent = msg;
}

function splashBusy(busy) {
  const sp = $('.splash-spinner');
  const rt = $('#splash-retry');
  if (sp) sp.style.visibility = busy ? 'visible' : 'hidden';
  if (rt) rt.classList.toggle('hidden', busy);
}

function hideSplash() {
  const s = $('#splash');
  if (!s) return;
  s.classList.add('fade');
  setTimeout(() => s.remove(), 400);
}

/* ---------- индикатор сети (интернет + сервер) ---------- */
function showNetBanner(msg, kind) {
  const b = $('#net-banner');
  if (!b) return;
  b.className = 'net-banner show ' + (kind === 'server' ? 'server' : '');
  b.innerHTML = (kind === 'server' ? '<span class="nb-spin"></span>' : '⚠ ') + esc(msg);
}

function hideNetBanner() {
  const b = $('#net-banner');
  if (!b) return;
  b.className = 'net-banner hidden';
}

function updateNetStatus() {
  if (!navigator.onLine) {
    showNetBanner('Нет подключения к интернету');
  } else if (socket && !socket.connected) {
    showNetBanner('Соединение с сервером потеряно, переподключение…', 'server');
  } else {
    hideNetBanner();
  }
}

window.addEventListener('online', updateNetStatus);
window.addEventListener('offline', updateNetStatus);

/* ---------- E2EE (WebCrypto: ECDH P-256 + AES-GCM) ---------- */
const E2EE = {
  STORE: 'reska_e2ee_v1',

  load() {
    try { return JSON.parse(localStorage.getItem(this.STORE)) || null; } catch (e) { return null; }
  },

  async ensureKeys() {
    let kp = this.load();
    if (kp && kp.pub && kp.priv) return kp;
    const pair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey']);
    const rawPub = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
    const priv = await crypto.subtle.exportKey('jwk', pair.privateKey);
    kp = { pub: b64encode(rawPub), priv, ver: Date.now() };
    localStorage.setItem(this.STORE, JSON.stringify(kp));
    return kp;
  },

  async pushPubKey(userUid) {
    const kp = await this.ensureKeys();
    try {
      await api(`/users/${userUid}/e2ee`, { method: 'PUT', body: { pub: kp.pub, ver: kp.ver } });
    } catch (e) {}
  },

  async deriveAes(privJwk, otherRawPubB64) {
    const priv = await crypto.subtle.importKey('jwk', privJwk, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveKey']);
    const pub = await crypto.subtle.importKey('raw', b64decode(otherRawPubB64), { name: 'ECDH', namedCurve: 'P-256' }, false, []);
    return crypto.subtle.deriveKey({ name: 'ECDH', public: pub }, priv, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  },

  async encrypt(text, otherRawPubB64) {
    const kp = await this.ensureKeys();
    const aes = await this.deriveAes(kp.priv, otherRawPubB64);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aes, new TextEncoder().encode(text)));
    return { ct: b64encode(ct), iv: b64encode(iv) };
  },

  async decrypt(ctB64, ivB64, otherRawPubB64) {
    const kp = await this.ensureKeys();
    const aes = await this.deriveAes(kp.priv, otherRawPubB64);
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64decode(ivB64) }, aes, b64decode(ctB64));
    return new TextDecoder().decode(plain);
  }
};

const pubKeyCache = new Map();
async function otherPubKey(uid) {
  if (!uid) return null;
  if (pubKeyCache.has(uid)) return pubKeyCache.get(uid);
  try {
    const res = await api(`/users/${uid}/e2ee`, { silent: true });
    pubKeyCache.set(uid, res.pub || null);
    return res.pub || null;
  } catch (e) {
    return null;
  }
}

/* ---------- Push-уведомления (FCM через Capacitor) ---------- */
const PUSH_STORE = 'reska_push_token';
let pushListenersBound = false;

function capPush() {
  return !!(window.Capacitor && window.Capacitor.Plugins && window.Capacitor.Plugins.PushNotifications);
}

function pushToken() {
  try { return localStorage.getItem(PUSH_STORE) || null; } catch (e) { return null; }
}

async function registerPushToken(token) {
  if (!token) return;
  try {
    const platform = window.Capacitor && window.Capacitor.getPlatform ? window.Capacitor.getPlatform() : 'web';
    await api('/push/token', { method: 'POST', body: { token, platform } });
  } catch (e) {}
}

async function unregisterPushToken() {
  const token = pushToken();
  if (!token) return;
  try { await api('/push/token', { method: 'DELETE', body: { token }, silent: true }); } catch (e) {}
}

async function initPush() {
  if (!capPush()) return;
  try {
    const P = window.Capacitor.Plugins.PushNotifications;

    if (!pushListenersBound) {
      pushListenersBound = true;
      P.addListener('registration', (data) => {
        if (data && data.value) {
          try { localStorage.setItem(PUSH_STORE, data.value); } catch (e) {}
          registerPushToken(data.value);
        }
      });
      P.addListener('registrationError', (err) => {
        console.warn('Push registration error:', err && err.message);
      });
      P.addListener('notificationReceived', (n) => {
        const title = n && n.title ? n.title : '';
        const body = n && n.body ? n.body : '';
        if (title && body) toast(`${title}: ${body}`);
      });
      P.addListener('notificationActionPerformed', (d) => {
        const url = d && d.notification && d.notification.data && d.notification.data.url;
        if (url) go('/' + String(url).replace(/^\/+/, ''));
      });
    }

    let granted = false;
    const perm = await P.checkPermissions();
    if (perm && perm.receive === 'granted') granted = true;
    else {
      const req = await P.requestPermissions();
      granted = req && req.receive === 'granted';
    }
    if (!granted) return;

    try { await P.createChannel({ id: 'reska', name: 'Уведомления РЕСКА', importance: 5, vibration: true }); } catch (e) {}
    await P.register();
    const prev = pushToken();
    if (prev) registerPushToken(prev);
  } catch (e) {
    console.warn('Push init error:', e.message);
  }
}


/* ---------- роутер ---------- */
function parseHash() {
  const h = location.hash.replace(/^#\/?/, '');
  const [pathPart, qs] = h.split('?');
  const segs = pathPart.split('/').filter(Boolean);
  return { segs, query: new URLSearchParams(qs || '') };
}

function go(hash) {
  if (location.hash === '#' + hash) render();
  else location.hash = hash;
}

const AUTH_ROUTES = new Set([
  'feed', 'videos', 'clips', 'watch', 'clip', 'messages', 'profile',
  'edit-profile', 'security', 'search', 'videos-new', 'clips-new',
  'notes', 'favorites', 'groups', 'friends', 'notifications'
]);

async function render() {
  if (!me) return;
  const { segs, query } = parseHash();
  const route = segs[0] || 'feed';
  setActiveNav(route);
  updateFab(route);

  try {
    switch (route) {
      case 'feed': await viewFeed(); break;
      case 'videos': await viewVideos(false); break;
      case 'clips': await viewVideos(true); break;
      case 'watch': await viewWatch(segs[1]); break;
      case 'messages': await viewMessages(segs[1]); break;
      case 'profile': await viewProfile(segs[1] === 'me' ? me.uid : segs[1]); break;
      case 'edit-profile': viewEditProfile(); break;
      case 'security': viewSecurity(); break;
      case 'search': currentSearch = query.get('q') || currentSearch; await viewSearch(query.get('type') || 'all'); break;
      case 'videos-new': viewVideoForm(false); break;
      case 'clips-new': viewVideoForm(true); break;
      case 'notes': viewNotes(); break;
      case 'favorites': viewFavorites(); break;
      case 'groups': viewGroups(); break;
      case 'friends': await viewFriends(); break;
      case 'notifications': await viewNotifications(); break;
      default: await viewFeed();
    }
    window.scrollTo(0, 0);
  } catch (e) {
    if (e.status === 401) return showAuth();
    $('#view').innerHTML = `<div class="empty">Ошибка: ${esc(e.message)}</div>`;
  }
}

/* FAB показываем только там, где уместно создавать контент */
function updateFab(route) {
  const fab = $('#fab-main');
  const menu = $('#fab-menu');
  if (!fab) return;
  const show = ['feed', 'videos', 'search'].includes(route);
  fab.style.display = show ? '' : 'none';
  if (!show) menu.classList.add('hidden');
}

function setActiveNav(route) {
  const map = {
    feed: 'feed', videos: 'videos', clips: 'clips', watch: 'videos',
    messages: 'messages', notes: 'notes', favorites: 'favorites', groups: 'groups',
    search: 'search', friends: 'friends', notifications: 'notifications'
  };
  const key = map[route] || (route === 'profile' ? 'profile' : 'feed');
  $$('.slink, .mobilenav a').forEach((a) => a.classList.toggle('active', a.dataset.nav === key));
}

/* ---------- авторизация ---------- */
function showAuth() {
  hideSplash();
  $('#app').classList.add('hidden');
  $('#auth-screen').classList.remove('hidden');
  $('#auth-form').reset();
  resetAuthState();
}

function showApp() {
  $('#auth-screen').classList.add('hidden');
  $('#app').classList.remove('hidden');
}

async function boot() {
  setSplashStatus('Проверка сессии…');
  try {
    const data = await api('/auth/me', { silent: true });
    me = data.user;
    afterLogin();
  } catch (e) {
    if (e.status === 0) {
      setSplashStatus('Нет связи с сервером');
      splashBusy(false);
      $('#splash-retry').addEventListener('click', () => {
        setSplashStatus('Проверка сессии…');
        splashBusy(true);
        boot();
      }, { once: true });
    } else {
      showAuth();
    }
  }
}

async function afterLogin() {
  showApp();
  hideSplash();
  updateNavUser();
  E2EE.pushPubKey(me.uid);
  initPush();
  connectSocket();
  await Promise.all([loadAliases(), loadNotifBadge()]);
  render();
}

const aliases = new Map(); /* uid -> alias (личные имена) */

async function loadAliases() {
  try {
    const data = await api('/users/aliases', { silent: true });
    aliases.clear();
    (data.aliases || []).forEach((a) => aliases.set(a.uid, a.alias));
  } catch (e) {}
}

function displayName(u) {
  if (!u) return '';
  const a = u.uid && aliases.get(u.uid);
  return a || u.name || u.username || '';
}

function sessionExpired() {
  if (socket) { socket.disconnect(); socket = null; }
  me = null;
  toast('Сессия истекла, войдите заново', 'error');
  showAuth();
}
function updateNavUser() {
  $('#nav-avatar').src = mediaUrl(me.avatar);
  $('#nav-name').textContent = me.name;
}

const authState = { captchaToken: null, needCaptcha: false, totpToken: null };

function resetAuthState() {
  authState.captchaToken = null;
  authState.needCaptcha = false;
  authState.totpToken = null;
  $('#captcha-field').classList.add('hidden');
  $('#totp-field').classList.add('hidden');
}

async function loadCaptcha() {
  try {
    const data = await api('/auth/captcha');
    authState.captchaToken = data.token;
    $('#captcha-question').textContent = data.text;
    $('#captcha-field').classList.remove('hidden');
  } catch (e) {}
}

/* ---------- socket ---------- */
async function connectSocket() {
  const data = await api('/auth/token', { silent: true }).catch(() => ({ token: null }));
  if (!data.token) return;
  socket = io({ auth: { token: data.token } });

  socket.on('connect', updateNetStatus);
  socket.on('disconnect', updateNetStatus);
  socket.on('reconnect_attempt', updateNetStatus);
  socket.on('reconnect', updateNetStatus);
  socket.on('connect_error', updateNetStatus);

  socket.on('chat:message', async (payload) => {
    const mine = payload.message ? payload.message.sender_id === me.id : false;
    const action = payload.action || 'new';
    const inActiveChat = activeChatUid === payload.chatUid;

    if (action === 'delete') {
      if (inActiveChat) removeMessageEl(payload.messageId);
      return refreshChatList();
    }

    if (mine && action === 'edit' && inActiveChat) {
      const m = await decryptMessage(payload.message, payload.chatUid);
      updateMessageEl(payload.message.id, m);
      return;
    }
    if (mine && action === 'reaction' && inActiveChat) {
      const m = await decryptMessage(payload.message, payload.chatUid);
      updateMessageEl(payload.message.id, m);
      return;
    }

    if (!mine && inActiveChat) {
      const m = await decryptMessage(payload.message, payload.chatUid);
      appendMessage(m);
      markChatRead(payload.chatUid);
    } else if (!mine) {
      bumpBadge();
    }
    if (!mine) refreshChatList();
  });

  socket.on('chat:typing', (payload) => {
    if (activeChatUid === payload.chatUid) showTyping();
  });

  socket.on('chat:read', () => { loadChatBadges(); if (!activeChat || activeChat.kind !== 'group') updateReadMarks(); });

  socket.on('chat:deleted', (payload) => {
    chatsCache = chatsCache.filter((c) => c.uid !== payload.chatUid);
    if (activeChatUid === payload.chatUid) {
      activeChatUid = null;
      activeChat = null;
      go('/messages');
      toast('Чат был удалён', 'error');
    } else {
      renderChatList();
    }
    loadChatBadges();
  });

  socket.on('friend:request', (payload) => {
    toast(`🤝 ${payload.actorName || 'Кто-то'} хочет добавить вас в друзья`);
  });

  socket.on('friend:accepted', (payload) => {
    toast(`🤝 ${payload.actorName || 'Кто-то'} принял(а) вашу заявку в друзья`);
    if (parseHash().segs[0] === 'friends') viewFriends();
  });

  socket.on('notify:new', (payload) => {
    if (payload && payload.unread != null) setNotifBadges(payload.unread);
    if (payload && payload.type === 'message') { refreshChatList(); loadChatBadges(); }
  });
}

function setNotifBadges(total) {
  const a = $('#notif-badge');
  const b = $('#notif-badge-mn');
  const val = total > 99 ? '99+' : String(total || '');
  [a, b].forEach((el) => {
    if (!el) return;
    el.textContent = val;
    el.classList.toggle('hidden', !total);
  });
}

async function loadNotifBadge() {
  try {
    const data = await api('/notifications', { silent: true });
    if (data && data.unread != null) setNotifBadges(data.unread);
  } catch (e) {}
}

function setMsgBadges(total) {
  const a = $('#msg-badge');
  const b = $('#msg-badge-mn');
  const val = total > 99 ? '99+' : String(total || '');
  [a, b].forEach((el) => {
    if (!el) return;
    el.textContent = val;
    el.classList.toggle('hidden', !total);
  });
}

function bumpBadge() {
  setMsgBadges((Number($('#msg-badge').textContent) || 0) + 1);
}

async function loadChatBadges() {
  try {
    const data = await api('/chats', { silent: true });
    chatsCache = data.chats;
    const total = chatsCache.reduce((s, c) => s + (c.unread || 0), 0);
    setMsgBadges(total);
  } catch (e) {}
}

/* ---------- toast ---------- */
function toast(msg, type) {
  const el = document.createElement('div');
  el.className = 'toast' + (type === 'error' ? ' error' : '');
  el.textContent = msg;
  $('#toast-root').appendChild(el);
  setTimeout(() => el.remove(), 3200);
}

/* ---------- ошибка записи медиа (микрофон/камера) ---------- */
function showMediaError(kind, why, err) {
  const isRound = kind === 'round';
  const device = isRound ? 'камеру' : 'микрофон';
  const needsCam = isRound;
  let title = 'Нет доступа к ' + device;
  let reason;
  let help;
  const name = err ? (err.name || '') : '';

  if (why) {
    reason = why;
  } else if (name === 'NotAllowedError' || name === 'SecurityError' || name === 'PermissionDeniedError') {
    reason = 'Разрешение отклонено браузером или системой.';
    help = needsCam
      ? 'Нажмите значок 🔒 (или ⓘ) слева от адресной строки → «Разрешения» → разрешите «Камера» и «Микрофон», затем обновите страницу.'
      : 'Нажмите значок 🔒 (или ⓘ) слева от адресной строки → «Разрешения» → разрешите «Микрофон», затем обновите страницу.';
  } else if (name === 'NotFoundError' || name === 'DevicesNotFoundError') {
    reason = needsCam ? 'Камера не найдена.' : 'Микрофон не найден.';
    help = 'Подключите ' + device + ' и проверьте, что она не занята другой программой.';
  } else if (name === 'NotReadableError' || name === 'TrackStartError') {
    reason = needsCam ? 'Камера уже используется другой программой.' : 'Микрофон уже используется другой программой.';
    help = 'Закройте программы, использующие ' + device + ' (звонки, запись, видеоконференции), и повторите.';
  } else if (name === 'OverconstrainedError') {
    reason = 'Устройство не поддерживает требуемые параметры записи.';
    help = 'Попробуйте запись аудио или проверьте настройки камеры.';
  } else if (name === 'TypeError') {
    reason = 'Не удалось инициализировать запись.';
    help = 'Обновите страницу (Ctrl+Shift+R) и повторите.';
  } else {
    reason = (err && err.message) ? err.message : 'Не удалось получить доступ.';
    help = 'Убедитесь, что ' + device + ' работает, разрешите доступ в настройках сайта и повторите.';
  }

  const modal = document.createElement('div');
  modal.className = 'modal-backdrop';
  modal.innerHTML = `
    <div class="modal card">
      <button class="close-x">✕</button>
      <h2 style="display:flex;align-items:center;gap:8px">${isRound ? '⭕' : '🎤'} ${esc(title)}</h2>
      <p style="margin:10px 0;color:var(--text)">${esc(reason)}</p>
      <div class="card" style="background:var(--bg2);padding:12px;font-size:13px;color:var(--muted);line-height:1.5">
        💡 ${esc(help)}
      </div>
      <div style="display:flex;gap:8px;margin-top:18px">
        <button class="btn btn-primary" data-act="retry">Повторить</button>
        <button class="btn btn-ghost" data-act="close">Закрыть</button>
      </div>
    </div>`;
  $('#modal-root').appendChild(modal);
  modal.addEventListener('click', (e) => {
    if (e.target === modal || e.target.classList.contains('close-x') || e.target.closest('[data-act="close"]')) modal.remove();
    else if (e.target.closest('[data-act="retry"]')) {
      modal.remove();
      const chatView = $('#view .chat-input');
      if (chatView) {
        const btn = $(`.chat-tool[data-tool="${isRound ? 'round' : 'audio'}"]`, chatView.parentElement);
        if (btn) btn.click();
      }
    }
  });
}

/* ---------- share / favorites ---------- */
function shareLink(hash, label) {
  const url = location.origin + location.pathname + '#' + hash;
  if (navigator.share) {
    navigator.share({ title: label + ' — РЕСКА', url }).catch(() => {});
  } else {
    navigator.clipboard.writeText(url).then(() => toast('Ссылка скопирована')).catch(() => {});
  }
}

/* =========================================================
   ЛЕНТА ПОСТОВ
   ========================================================= */
function buildPost(post) {
  const node = $('#tpl-post').content.cloneNode(true);
  const root = $('article', node);
  root.dataset.id = post.id;
  root.dataset.uid = post.uid || '';

  const authorId = post.author_uid || post.user_id;
  $('.post-avatar-link', node).href = '#/profile/' + authorId;
  $('.post-avatar-link img', node).src = mediaUrl(post.avatar);
  const authorEl = $('.post-author', node);
  authorEl.href = '#/profile/' + authorId;
  authorEl.textContent = displayName(post);
  $('.post-time', node).textContent = timeAgo(post.created_at);
  const textEl = $('.post-text', node);
  textEl.innerHTML = linkifyTags(post.text);
  if (post.text && post.text.length > 400) {
    textEl.classList.add('collapsed');
    const btn = document.createElement('button');
    btn.className = 'read-more-btn';
    btn.textContent = 'Читать далее';
    btn.addEventListener('click', () => {
      if (textEl.classList.contains('collapsed')) {
        textEl.classList.remove('collapsed');
        btn.textContent = 'Свернуть';
      } else {
        textEl.classList.add('collapsed');
        btn.textContent = 'Читать далее';
      }
    });
    $('.post-head', node).insertAdjacentElement('afterend', btn);
  }

  if (post.media) {
    const wrap = $('.post-media-wrap', node);
    const src = mediaUrl(post.media);
    if (post.media_type === 'image') {
      wrap.innerHTML = `<img class="post-media" src="${esc(src)}" alt="медиа" loading="lazy">`;
    } else {
      wrap.innerHTML = `<video class="post-media" src="${esc(src)}" controls preload="metadata"></video>`;
    }
  }

  const likeBtn = $('[data-action="like"]', node);
  likeBtn.classList.toggle('liked', !!post.liked);
  likeBtn.querySelector('.pact-ico').textContent = post.liked ? '❤️' : '🤍';
  likeBtn.querySelector('.like-count').textContent = post.likes || '';
  $('[data-action="toggle-comments"] .comment-count', node).textContent = post.comments || '';
  $('.comment-self-avatar', node).src = mediaUrl(me.avatar);

  renderPostReactions($('.post-reactions', node), post.reactions);

  if (post.user_id === me.id || me.role === 'admin') $('.post-del', node).classList.remove('hidden');

  return node;
}

function renderPostReactions(container, reactions) {
  if (!container) return;
  container.innerHTML = '';
  const list = (reactions && reactions.list) || [];
  list.forEach((r) => {
    const chip = document.createElement('button');
    chip.className = 'reaction-chip' + ((reactions.myEmoji || []).includes(r.emoji) ? ' mine' : '');
    chip.textContent = r.emoji + ' ' + r.count;
    chip.addEventListener('click', () => {
      const root = chip.closest('.post');
      togglePostReaction(root.dataset.id, r.emoji, root);
    });
    container.appendChild(chip);
  });
}

async function togglePostReaction(id, emoji, root) {
  const box = $('.post-reactions', root);
  try {
    const res = await api(`/posts/${id}/react`, { method: 'POST', body: JSON.stringify({ emoji }), headers: { 'Content-Type': 'application/json' } });
    renderPostReactions(box, res.reactions);
  } catch (e) { toast(e.message, 'error'); }
}

const FEED_PAGE = 10;
let feedState = { before: 0, hasMore: true, loading: false, observer: null };

async function viewFeed(reset = true) {
  const view = $('#view');
  if (reset) {
    feedState = { before: 0, hasMore: true, loading: false, observer: null };
    view.innerHTML = `<div class="feed" id="post-feed"></div>`;
  }
  const feed = $('#post-feed');
  if (!feed) return;
  if (reset) {
    feed.innerHTML = skeletonCards(3);
    let data;
    try {
      data = await api(`/posts?limit=${FEED_PAGE}&before=0`);
    } catch (e) { feed.innerHTML = `<div class="empty">Ошибка загрузки</div>`; return; }
    feed.innerHTML = '';
    if (!data.posts.length) { feed.innerHTML = `<div class="empty">Пока нет постов. Напишите первый!</div>`; return; }
    data.posts.forEach((p) => feed.appendChild(buildPost(p)));
    feedState.hasMore = data.hasMore;
    feedState.before = data.posts[data.posts.length - 1].id;
    wirePostEvents(feed);
    setupFeedObserver(feed);
    return;
  }
  if (!feedState.hasMore || feedState.loading) return;
  feedState.loading = true;
  const sentinel = $('.feed-sentinel', feed);
  if (sentinel) sentinel.textContent = 'Загрузка…';
  let data;
  try {
    data = await api(`/posts?limit=${FEED_PAGE}&before=${feedState.before}`);
  } catch (e) { feedState.loading = false; if (sentinel) sentinel.textContent = 'Ошибка'; return; }
  if (sentinel) sentinel.remove();
  data.posts.forEach((p) => feed.appendChild(buildPost(p)));
  feedState.hasMore = data.hasMore;
  if (data.posts.length) feedState.before = data.posts[data.posts.length - 1].id;
  feedState.loading = false;
  if (feedState.hasMore) appendSentinel(feed);
}

function appendSentinel(feed) {
  if ($('.feed-sentinel', feed)) return;
  const s = document.createElement('div');
  s.className = 'feed-sentinel muted';
  s.textContent = 'Загрузка…';
  feed.appendChild(s);
}

function setupFeedObserver(feed) {
  if (feedState.observer) feedState.observer.disconnect();
  feedState.observer = new IntersectionObserver((entries) => {
    if (entries.some((e) => e.isIntersecting)) viewFeed(false);
  }, { root: null, rootMargin: '700px' });
  feedState.observer.observe(feed);
}

function skeletonCards(n) {
  let h = '';
  for (let i = 0; i < n; i++) h += `<div class="card skeleton-card"><div class="sk-line"></div><div class="sk-line short"></div><div class="sk-block"></div></div>`;
  return h;
}

function wirePostEvents(feed) {
  let postLastTap = 0;
  feed.addEventListener('click', async (e) => {
    const postNode = e.target.closest('.post');
    if (postNode && !e.target.closest('button, a, input, video, .comment-form')) {
      const now = Date.now();
      if (now - postLastTap < 320) {
        postLastTap = 0;
        const likeBtn = $('[data-action="like"]', postNode);
        if (likeBtn && !likeBtn.classList.contains('liked')) {
          try {
            const res = await api(`/posts/${postNode.dataset.uid || postNode.dataset.id}/like`, { method: 'POST' });
            likeBtn.classList.add('liked');
            likeBtn.querySelector('.pact-ico').textContent = '❤️';
            likeBtn.querySelector('.like-count').textContent = res.likes || '';
            const heart = document.createElement('div');
            heart.className = 'post-heart';
            heart.textContent = '❤️';
            $('.post-text', postNode).appendChild(heart);
            setTimeout(() => heart.remove(), 700);
          } catch (err) { toast(err.message, 'error'); }
        }
        return;
      }
      postLastTap = now;
    }
    const actionBtn = e.target.closest('[data-action]');
    if (!actionBtn) return;
    const root = actionBtn.closest('.post');
    const id = root.dataset.uid || root.dataset.id;
    const action = actionBtn.dataset.action;

      if (action === 'like') {
        try {
          const res = actionBtn.classList.contains('liked')
            ? await api(`/posts/${id}/like`, { method: 'DELETE' })
            : await api(`/posts/${id}/like`, { method: 'POST' });
          actionBtn.classList.toggle('liked', res.liked);
          actionBtn.querySelector('.pact-ico').textContent = res.liked ? '❤️' : '🤍';
          actionBtn.querySelector('.like-count').textContent = res.likes || '';
        } catch (err) { toast(err.message, 'error'); }
      }

      if (action === 'react') {
        const existing = $('.reaction-picker', root);
        if (existing) { existing.remove(); return; }
        const picker = document.createElement('div');
        picker.className = 'reaction-picker';
        const emojis = ['👍', '❤️', '🔥', '😄', '🎉', '😮', '😢', '💯'];
        emojis.forEach((em) => {
          const b = document.createElement('button');
          b.textContent = em;
          b.addEventListener('click', () => {
            picker.remove();
            togglePostReaction(id, em, root);
          });
          picker.appendChild(b);
        });
        actionBtn.insertAdjacentElement('afterend', picker);
      }


    if (action === 'toggle-comments') {
      const wrap = $('.comments-wrap', root);
      const opening = wrap.classList.contains('hidden');
      wrap.classList.toggle('hidden');
      if (opening && !wrap.dataset.loaded) {
        await loadComments(root, 'post', id);
        wrap.dataset.loaded = '1';
      }
    }

    if (action === 'share') {
      const authorHref = $('.post-avatar-link', root).href;
      shareLink(authorHref, 'Поделиться профилем');
    }

    if (action === 'del-post') {
      if (!confirm('Удалить пост?')) return;
      try {
        await api(`/posts/${id}`, { method: 'DELETE' });
        root.remove();
        toast('Пост удалён');
      } catch (err) { toast(err.message, 'error'); }
    }
  });

  feed.addEventListener('submit', async (e) => {
    const form = e.target.closest('.comment-form, .reply-form');
    if (!form) return;
    e.preventDefault();
    const input = $('input', form);
    const text = input.value.trim();
    if (!text) return;
    const root = form.closest('.post');
    const id = root.dataset.uid || root.dataset.id;
    const parent = form.closest('.comment');
    const parentId = parent ? Number(parent.dataset.id) : null;
    try {
      const res = await api(`/posts/${id}/comments`, { method: 'POST', body: { text, parent_id: parentId } });
      if (parent) $('.comment-replies', parent).appendChild(buildComment(res.comment, 'post'));
      else $('.comments-list', root).appendChild(buildComment(res.comment, 'post'));
      const count = $('[data-action="toggle-comments"] .comment-count', root);
      count.textContent = (Number(count.textContent) || 0) + 1;
      input.value = '';
      input.blur();
    } catch (err) { toast(err.message, 'error'); }
  });
}

async function loadComments(root, target, id) {
  try {
    const data = await api(`/${target}s/${id}/comments`, { silent: true });
    const list = $('.comments-list', root);
    list.innerHTML = '';
    data.comments.forEach((c) => list.appendChild(buildComment(c, target)));
  } catch (e) { toast(e.message, 'error'); }
}

function buildComment(c, target) {
  const node = $('#tpl-comment').content.cloneNode(true);
  const root = $('.comment', node);
  root.dataset.id = c.id;
  $('.avatar', node).src = mediaUrl(c.avatar);
  const a = $('.comment-author', node);
  a.href = '#/profile/' + (c.author_uid || c.user_id);
  a.textContent = displayName(c);
  $('.comment-text', node).textContent = c.text;
  $('.reply-btn', node).addEventListener('click', () => {
    const rf = $('.reply-form', root);
    rf.classList.toggle('hidden');
    if (!rf.classList.contains('hidden')) $('input', rf).focus();
  });
  if (c.replies && c.replies.length) {
    const container = $('.comment-replies', node);
    c.replies.forEach((r) => container.appendChild(buildComment(r, target)));
  }
  return node;
}

/* =========================================================
   ВИДЕО СЕТКА + ОВЕРЛЕЙ-ПЛЕЕР
   ========================================================= */
function buildVideoCard(v) {
  const node = $('#tpl-video-card').content.cloneNode(true);
  const card = $('[data-role="video-card"]', node);
  card.dataset.id = v.id;
  card.dataset.uid = v.uid;
  $('img', node).src = mediaUrl(v.thumb);
  $('img', node).alt = v.title;
  $('.views-badge', node).textContent = '👁 ' + fmtViews(v.views);
  $('.video-title', node).innerHTML = linkifyTags(v.title);
  $('.video-author', node).textContent = `${displayName(v)} · ${fmtViews(v.views)} просмотров`;
  if (v.is_clip) $('.clip-badge', node).classList.remove('hidden');
  card.addEventListener('click', () => openVideoOverlay(v.id));

  const delBtn = $('[data-action="video-del"]', node);
  if (v.user_id === me.id || me.role === 'admin') delBtn.classList.remove('hidden');
  delBtn.addEventListener('click', async (e) => {
    e.stopPropagation();
    if (!confirm('Удалить видео?')) return;
    try {
      await api('/videos/' + v.uid, { method: 'DELETE' });
      card.remove();
      toast('Видео удалено');
    } catch (err) { toast(err.message, 'error'); }
  });

  return node;
}

const VIDEO_PAGE = 12;
let videoState = { before: 0, hasMore: true, loading: false, observer: null };
let clipState = { before: 0, hasMore: true, loading: false, observer: null };
let videosIsClips = false;

async function viewVideos(isClips) {
  videosIsClips = isClips;
  const view = $('#view');
  if (isClips) {
    clipState = { before: 0, hasMore: true, loading: false, observer: null };
    view.innerHTML = '';
    const feed = document.createElement('div');
    feed.className = 'clips-feed';
    feed.id = 'clips-feed';
    view.appendChild(feed);
    const nav = document.createElement('div');
    nav.className = 'clips-nav';
    nav.innerHTML = `<button data-dir="up" title="Назад">^</button><button data-dir="down" title="Вперёд">▼</button>`;
    view.appendChild(nav);
    const addBtn = document.createElement('a');
    addBtn.className = 'fab fab-clips';
    addBtn.href = '#/clips-new';
    addBtn.title = 'Добавить клип';
    addBtn.innerHTML = '＋';
    view.appendChild(addBtn);
    await loadClips(true);
    return;
  }
  videoState = { before: 0, hasMore: true, loading: false, observer: null };
  view.innerHTML = `
    <div class="page-head">
      <h1 class="page-title" style="margin:0">🎬 Видео</h1>
      <a class="btn btn-primary" href="#/videos-new">＋ Загрузить видео</a>
    </div>
    <div class="video-grid" id="video-grid"></div>`;
  await loadVideos(true);
}

async function loadVideos(reset) {
  const g = $('#video-grid');
  if (!g) return;
  if (reset) {
    g.innerHTML = skeletonCards(6);
    let data;
    try { data = await api(`/videos?clip=0&limit=${VIDEO_PAGE}&before=0`); }
    catch (e) { g.innerHTML = `<div class="empty">Ошибка загрузки</div>`; return; }
    g.innerHTML = '';
    if (!data.videos.length) { g.innerHTML = `<div class="empty">Нет видео. Загрузите первым!</div>`; return; }
    data.videos.forEach((v) => g.appendChild(buildVideoCard(v)));
    videoState.hasMore = data.hasMore;
    videoState.before = data.videos[data.videos.length - 1].id;
    setupVideoObserver();
    return;
  }
  if (!videoState.hasMore || videoState.loading) return;
  videoState.loading = true;
  let data;
  try { data = await api(`/videos?clip=0&limit=${VIDEO_PAGE}&before=${videoState.before}`); }
  catch (e) { videoState.loading = false; return; }
  data.videos.forEach((v) => g.appendChild(buildVideoCard(v)));
  videoState.hasMore = data.hasMore;
  if (data.videos.length) videoState.before = data.videos[data.videos.length - 1].id;
  videoState.loading = false;
}

function setupVideoObserver() {
  if (videoState.observer) videoState.observer.disconnect();
  videoState.observer = new IntersectionObserver((entries) => {
    if (entries.some((e) => e.isIntersecting)) loadVideos(false);
  }, { rootMargin: '600px' });
  const g = $('#video-grid');
  if (g) videoState.observer.observe(g.lastElementChild || g);
}

async function loadClips(reset) {
  const feed = $('#clips-feed');
  if (!feed) return;
  if (reset) {
    feed.innerHTML = '';
    const s = document.createElement('div');
    s.className = 'clips-empty muted';
    s.textContent = 'Загрузка…';
    feed.appendChild(s);
    let data;
    try { data = await api(`/videos?clip=1&limit=${VIDEO_PAGE}&before=0`); }
    catch (e) { feed.innerHTML = `<div class="empty">Ошибка загрузки</div>`; return; }
    feed.innerHTML = '';
    if (!data.videos.length) { feed.innerHTML = `<div class="clips-empty empty">Нет клипов. Добавьте видео как клип!<div style="margin-top:14px"><a class="btn btn-primary" href="#/clips-new">＋ Добавить клип</a></div></div>`; return; }
    data.videos.forEach((v) => feed.appendChild(buildClipCard(v)));
    clipState.hasMore = data.hasMore;
    clipState.before = data.videos[data.videos.length - 1].id;
    setupClipObserver();
    return;
  }
  if (!clipState.hasMore || clipState.loading) return;
  clipState.loading = true;
  let data;
  try { data = await api(`/videos?clip=1&limit=${VIDEO_PAGE}&before=${clipState.before}`); }
  catch (e) { clipState.loading = false; return; }
  data.videos.forEach((v) => feed.appendChild(buildClipCard(v)));
  clipState.hasMore = data.hasMore;
  if (data.videos.length) clipState.before = data.videos[data.videos.length - 1].id;
  clipState.loading = false;
}

function setupClipObserver() {
  if (clipState.observer) clipState.observer.disconnect();
  clipState.observer = new IntersectionObserver((entries) => {
    if (entries.some((e) => e.isIntersecting)) loadClips(false);
  }, { rootMargin: '800px' });
  const feed = $('#clips-feed');
  if (feed) clipState.observer.observe(feed.lastElementChild || feed);
}

async function viewClipsReel(videos) {
  const view = $('#view');
  view.innerHTML = '';
  if (!videos.length) {
    view.innerHTML = `<div class="clips-empty">
      <div class="empty">Нет клипов. Добавьте видео как клип!<div style="margin-top:14px"><a class="btn btn-primary" href="#/clips-new">＋ Добавить клип</a></div></div>
    </div>`;
    return;
  }
  const feed = document.createElement('div');
  feed.className = 'clips-feed';
  feed.id = 'clips-feed';
  videos.forEach((v) => feed.appendChild(buildClipCard(v)));
  view.appendChild(feed);
  const nav = document.createElement('div');
  nav.className = 'clips-nav';
  nav.innerHTML = `<button data-dir="up" title="Назад">^</button><button data-dir="down" title="Вперёд">▼</button>`;
  view.appendChild(nav);

  const addBtn = document.createElement('a');
  addBtn.className = 'fab fab-clips';
  addBtn.href = '#/clips-new';
  addBtn.title = 'Добавить клип';
  addBtn.innerHTML = '＋';
  view.appendChild(addBtn);

  const clips = $$('.clip', feed);
  const vids = clips.map(n => $('video', n));

  const playObserver = new IntersectionObserver((entries) => {
    entries.forEach((e) => {
      const vid = $('video', e.target);
      if (!vid) return;
      if (e.isIntersecting && e.intersectionRatio >= 0.7) {
        vid.play().catch(() => {});
        e.target.dataset.playing = '1';
      } else {
        vid.pause();
        delete e.target.dataset.playing;
      }
    });
  }, { threshold: [0, 0.7, 1] });
  clips.forEach(c => playObserver.observe(c));

  const navObserver = new IntersectionObserver((entries) => {
    entries.forEach((e) => {
      const idx = Number(e.target.dataset.idx);
      if (e.isIntersecting && e.intersectionRatio >= 0.7) {
        clips.forEach((cl, i) => cl.classList.toggle('active', i === idx));
      }
    });
  }, { threshold: 0.7 });
  clips.forEach((c, i) => { c.dataset.idx = String(i); navObserver.observe(c); });

  function scrollToClip(dir) {
    const active = $('.clip.active', feed) || clips[0];
    const idx = clips.indexOf(active);
    const next = dir === 'down' ? Math.min(idx + 1, clips.length - 1) : Math.max(idx - 1, 0);
    if (next >= 0 && next < clips.length) clips[next].scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
  $$('.clips-nav button', view).forEach(b => b.addEventListener('click', () => scrollToClip(b.dataset.dir)));

  let lastTap = 0;
  clips.forEach((clip, ci) => {
    const vid = vids[ci];
    vid.addEventListener('timeupdate', () => {
      const pct = vid.duration ? (vid.currentTime / vid.duration) * 100 : 0;
      const bar = $('.clip-progress span', clip);
      if (bar) bar.style.width = pct + '%';
    });

    const pauseIcon = document.createElement('div');
    pauseIcon.className = 'clip-paused-icon';
    pauseIcon.textContent = '▶';
    clip.appendChild(pauseIcon);

    $('.clip-play-pause', clip).addEventListener('click', () => {
      const now = Date.now();
      if (now - lastTap < 300) {
        lastTap = 0;
        toggleLike(clip, vids[ci], true);
        showHeart(clip);
      } else {
        lastTap = now;
        if (vid.paused) { vid.play(); clip.classList.remove('playing-paused'); }
        else { vid.pause(); clip.classList.add('playing-paused'); }
      }
    });

    $('.clip-mute', clip).addEventListener('click', () => {
      vid.muted = !vid.muted;
      $('.clip-mute', clip).classList.toggle('unmuted', !vid.muted);
    });

    $('.clip-follow', clip).addEventListener('click', (e) => {
      e.preventDefault();
      const btn = e.currentTarget;
      btn.classList.toggle('followed');
      btn.textContent = btn.classList.contains('followed') ? '✓ Подписка' : 'Подписаться';
    });

    $('.clip-sound-text', clip).parentElement?.addEventListener('click', () => {
      const st = $('.clip-sound-text', clip);
      st.style.animationPlayState = st.style.animationPlayState === 'paused' ? 'running' : 'paused';
    });
  });

  function showHeart(clip) {
    const h = $('.clip-heart', clip);
    h.className = 'clip-heart show';
    setTimeout(() => { h.className = 'clip-heart'; }, 800);
  }

  async function toggleLike(clip, vid, fromDoubleTap) {
    const btn = $('[data-action="like"]', clip);
    const vidUid = clip.dataset.uid;
    try {
      const isLiked = btn.classList.contains('liked');
      const res = await api(`/videos/${vidUid}/like`, { method: isLiked ? 'DELETE' : 'POST' });
      btn.classList.toggle('liked', res.liked);
      btn.querySelector('.clip-act-ico').textContent = res.liked ? '❤️' : '🤍';
      btn.querySelector('.clip-like-count').textContent = res.likes || '0';
    } catch (err) { toast(err.message, 'error'); }
  }

  function openCommentsSheet(vidUid) {
    const sheet = $('#tpl-comments-sheet').content.cloneNode(true);
    const panel = $('[data-role="comments-sheet"]', sheet);
    const list = $('.comments-sheet-list', panel);
    const count = $('.comments-sheet-count', panel);
    document.body.appendChild(panel);
    requestAnimationFrame(() => { requestAnimationFrame(() => panel.classList.add('show')); });

    function close() {
      panel.classList.remove('show');
      setTimeout(() => panel.remove(), 280);
    }
    $('.comments-sheet-backdrop', panel).addEventListener('click', close);
    $('.comments-sheet-close', panel).addEventListener('click', close);

    async function load() {
      try {
        const data = await api(`/videos/${vidUid}/comments`);
        count.textContent = `Комментарии (${data.comments.length})`;
        list.innerHTML = '';
        if (!data.comments.length) {
          list.innerHTML = '<div class="muted" style="text-align:center;padding:20px">Пока нет комментариев</div>';
          return;
        }
        data.comments.forEach(c => {
          const el = document.createElement('div');
          el.className = 'citem';
          el.innerHTML = `<img src="${mediaUrl(c.avatar)}" alt=""><div class="citem-body"><div class="citem-author">${esc(c.name)}</div><div class="citem-text">${esc(c.text)}</div></div>`;
          list.appendChild(el);
        });
      } catch (err) { toast(err.message, 'error'); }
    }

    const form = $('.comments-sheet-form', panel);
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const input = form.querySelector('input');
      const text = input.value.trim();
      if (!text) return;
      try {
        await api(`/videos/${vidUid}/comments`, { method: 'POST', body: { text } });
        input.value = '';
        load();
      } catch (err) { toast(err.message, 'error'); }
    });

    load();
  }

  $('[data-action="toggle-comments"]').forEach?.(() => {});
  clips.forEach(clip => {
    $('[data-action="toggle-comments"]', clip).addEventListener('click', () => openCommentsSheet(clip.dataset.uid));
  });

  document.addEventListener('keydown', function keyNav(e) {
    if (!$('.clips-feed')) return;
    if (e.key === 'ArrowDown') { e.preventDefault(); scrollToClip('down'); }
    if (e.key === 'ArrowUp') { e.preventDefault(); scrollToClip('up'); }
  });

  view._clipCleanup = () => {
    playObserver.disconnect();
    navObserver.disconnect();
  };
}

function buildClipCard(v) {
  const node = $('#tpl-clip').content.cloneNode(true);
  const clip = $('[data-role="clip"]', node);
  clip.dataset.id = v.id;
  clip.dataset.uid = v.uid;
  const video = $('video', node);
  video.src = mediaUrl(v.file);
  video.poster = mediaUrl(v.thumb);
  const av = $('.clip-avatar', node);
  av.style.backgroundImage = `url(${mediaUrl(v.avatar)})`;
  $('.clip-author-name', node).textContent = displayName(v);
  $('.clip-author-block', node).href = '#/profile/' + v.author_uid;
  $('.clip-like-count', node).textContent = v.likes || '0';
  $('.clip-comment-count', node).textContent = v.comments != null ? v.comments : '0';
  $('.clip-title', node).innerHTML = linkifyTags(v.title || '');
  const soundEl = $('.clip-sound-text', node);
  soundEl.textContent = '♫ ' + (v.title || 'Оригинальный звук') + '     ♫ ' + (v.title || 'Оригинальный звук') + '     ';

  $('[data-action="like"]', node).addEventListener('click', (e) => {
    const btn = e.currentTarget;
    const clipEl = btn.closest('.clip');
    const vid = $('video', clipEl);
    toggleLikeGlobal(clipEl, vid);
  });

  $('[data-action="share"]', node).addEventListener('click', () => shareLink('#/watch/' + v.uid, v.title));

  const delBtn = $('[data-action="delete"]', node);
  if (v.user_id === me.id || me.role === 'admin') delBtn.classList.remove('hidden');
  delBtn.addEventListener('click', async (e) => {
    e.stopPropagation();
    if (!confirm('Удалить видео?')) return;
    try {
      await api('/videos/' + v.uid, { method: 'DELETE' });
      const clipEl = delBtn.closest('.clip');
      if (clipEl) clipEl.remove();
      toast('Видео удалено');
      const feed = $('.clips-feed');
      if (feed && !feed.querySelector('.clip')) go('/clips');
    } catch (err) { toast(err.message, 'error'); }
  });

  return node;
}

function toggleLikeGlobal(clipEl, vid) {
  const btn = $('[data-action="like"]', clipEl);
  const vidUid = clipEl.dataset.uid;
  const isLiked = btn.classList.contains('liked');
  api(`/videos/${vidUid}/like`, { method: isLiked ? 'DELETE' : 'POST' }).then((res) => {
    btn.classList.toggle('liked', res.liked);
    btn.querySelector('.clip-act-ico').textContent = res.liked ? '❤️' : '🤍';
    btn.querySelector('.clip-like-count').textContent = res.likes || '0';
  }).catch((err) => toast(err.message, 'error'));
}

async function openVideoOverlay(id) {
  if (!id) return go('/videos');
  const data = await api(`/videos/${id}`);
  const v = data.video;
  api(`/videos/${id}/view`, { method: 'POST', silent: true }).then((r) => { v.views = r.views; }).catch(() => {});

  const modal = document.createElement('div');
  modal.className = 'modal-backdrop';
  modal.style.alignItems = 'flex-start';
  modal.style.overflowY = 'auto';
  modal.innerHTML = `
    <div class="modal watch" style="max-width:820px;margin:30px auto;width:100%">
      <button class="close-x">✕</button>
      <video class="player" src="${esc(mediaUrl(v.file))}" poster="${esc(mediaUrl(v.thumb))}" controls autoplay></video>
       <h1 class="watch-title">${linkifyTags(v.title)}</h1>
       <div class="watch-meta">
         <a href="#/profile/${esc(v.author_uid || v.user_id)}">
           <img class="avatar sm" src="${mediaUrl(v.avatar)}" alt="">
           <b>${esc(v.name)}</b>
         </a>
         <span class="video-stats">👁 ${fmtViews(v.views)}</span>
         <span class="video-stats">${timeAgo(v.created_at)}</span>
          <div class="watch-actions">
            <button class="pact ${v.liked ? 'liked' : ''}" data-action="vlike">
              <span class="pact-ico">${v.liked ? '❤️' : '🤍'}</span><span class="like-count">${v.likes || ''}</span>
            </button>
            <button class="pact" data-action="vreact" title="Реакция"><span class="pact-ico">😊</span></button>
            <button class="pact" data-action="share"><span class="pact-ico">🔗</span><span>Поделиться</span></button>
            ${v.user_id === me.id || me.role === 'admin' ? `<button class="pact pact-del" data-action="vdel"><span class="pact-ico">🗑</span><span>Удалить</span></button>` : ''}
          </div>
          <div class="post-reactions" id="video-reactions"></div>
       </div>
       ${v.description ? `<div class="watch-desc card">${linkifyTags(v.description)}</div>` : ''}
      <div class="comments-block card">
        <h3>Комментарии</h3>
        <form class="comment-form" id="vcomment-form">
          <img class="avatar sm comment-self-avatar" src="${mediaUrl(me.avatar)}" alt="">
          <input type="text" placeholder="Написать комментарий..." autocomplete="off">
          <button type="submit" class="btn btn-primary btn-sm">➤</button>
        </form>
        <div id="vcomment-list" style="margin-top:16px"></div>
      </div>
    </div>`;
  $('#modal-root').appendChild(modal);

  modal.addEventListener('click', (e) => {
    if (e.target === modal || e.target.classList.contains('close-x')) {
      const vid = $('video', modal);
      if (vid) vid.pause();
      modal.remove();
    }
  });

  const likeBtn = $('[data-action="vlike"]', modal);
  likeBtn.addEventListener('click', async () => {
    try {
      const res = likeBtn.classList.contains('liked')
        ? await api(`/videos/${id}/like`, { method: 'DELETE' })
        : await api(`/videos/${id}/like`, { method: 'POST' });
      likeBtn.classList.toggle('liked', res.liked);
      likeBtn.querySelector('.pact-ico').textContent = res.liked ? '❤️' : '🤍';
      likeBtn.querySelector('.like-count').textContent = res.likes || '';
    } catch (err) { toast(err.message, 'error'); }
  });

  $('[data-action="share"]', modal).addEventListener('click', () => shareLink('#/watch/' + id, v.title));

  const vReactBtn = $('[data-action="vreact"]', modal);
  renderPostReactions($('#video-reactions', modal), v.reactions);
  vReactBtn.addEventListener('click', () => {
    const picker = $('.reaction-picker', modal);
    if (picker) { picker.remove(); return; }
    const p = document.createElement('div');
    p.className = 'reaction-picker';
    ['👍', '❤️', '🔥', '😄', '🎉', '😮', '😢', '💯'].forEach((em) => {
      const b = document.createElement('button');
      b.textContent = em;
      b.addEventListener('click', async () => {
        p.remove();
        try {
          const res = await api(`/videos/${id}/react`, { method: 'POST', body: JSON.stringify({ emoji: em }), headers: { 'Content-Type': 'application/json' } });
          renderPostReactions($('#video-reactions', modal), res.reactions);
        } catch (e) { toast(e.message, 'error'); }
      });
      p.appendChild(b);
    });
    vReactBtn.insertAdjacentElement('afterend', p);
  });

  const vdel = $('[data-action="vdel"]', modal);
  if (vdel) vdel.addEventListener('click', async () => {
    if (!confirm('Удалить видео?')) return;
    try {
      await api('/videos/' + id, { method: 'DELETE' });
      modal.remove();
      toast('Видео удалено');
      go(v.is_clip ? '/clips' : '/videos');
    } catch (err) { toast(err.message, 'error'); }
  });

  try {
    const cdata = await api(`/videos/${id}/comments`, { silent: true });
    const list = $('#vcomment-list', modal);
    cdata.comments.forEach((c) => list.appendChild(buildComment(c, 'video')));
  } catch (e) {}

  $('#vcomment-form', modal).addEventListener('submit', async (e) => {
    e.preventDefault();
    const input = $('input', e.target);
    const text = input.value.trim();
    if (!text) return;
    try {
      const res = await api(`/videos/${id}/comments`, { method: 'POST', body: { text } });
      $('#vcomment-list', modal).appendChild(buildComment(res.comment, 'video'));
      input.value = '';
    } catch (err) { toast(err.message, 'error'); }
  });
}

async function viewWatch(id) {
  if (!id) return go('/videos');
  await openVideoOverlay(id);
}

function viewVideoForm(isClip) {
  const view = $('#view');
  view.innerHTML = `
    <div class="form-card card">
      <h1 class="page-title">${isClip ? '🎬 Добавить клип' : '▶ Загрузить видео'}</h1>
      <form id="video-form">
        <div class="form-row">
          <label>Название *</label>
          <input name="title" required maxlength="120" placeholder="Название ролика">
        </div>
        <div class="form-row">
          <label>Описание</label>
          <textarea name="description" rows="3" placeholder="Что в этом видео..."></textarea>
        </div>
        <div class="form-row">
          <label>Видеофайл (mp4, webm) *</label>
          <div class="file-zone" id="file-zone">
            <div>📁 Нажмите, чтобы выбрать файл</div>
            <div class="fname hidden"></div>
          </div>
          <input type="file" name="video" accept="video/mp4,video/webm,video/quicktime" class="hidden" id="video-file">
        </div>
        ${isClip ? '' : `<div class="form-row checkbox-row">
          <input type="checkbox" name="is_clip" value="1"> Опубликовать как клип (вертикальное видео)
        </div>`}
        <button type="submit" class="btn btn-primary btn-block">Опубликовать</button>
      </form>
    </div>`;

  const zone = $('#file-zone');
  const fileInput = $('#video-file');
  zone.addEventListener('click', () => fileInput.click());
  ['dragenter', 'dragover'].forEach((ev) => zone.addEventListener(ev, (e) => { e.preventDefault(); zone.classList.add('drag'); }));
  ['dragleave', 'drop'].forEach((ev) => zone.addEventListener(ev, (e) => { e.preventDefault(); zone.classList.remove('drag'); }));
  zone.addEventListener('drop', (e) => { fileInput.files = e.dataTransfer.files; updateFileLabel(); });
  fileInput.addEventListener('change', updateFileLabel);
  function updateFileLabel() {
    if (fileInput.files[0]) {
      $('.fname', view).classList.remove('hidden');
      $('.fname', view).textContent = '✓ ' + fileInput.files[0].name;
    }
  }

  $('#video-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const form = e.target;
    const fd = new FormData(form);
    if (isClip) fd.set('is_clip', '1');
    try {
      await api('/videos', { method: 'POST', body: fd });
      toast('Видео опубликовано!');
      go(isClip ? '/clips' : '/videos');
    } catch (err) { toast(err.message, 'error'); }
  });
}
/* =========================================================
   МЕССЕНДЖЕР (E2EE)
   ========================================================= */
async function viewMessages(openChatUid) {
  const data = await api('/chats');
  chatsCache = data.chats;
  const total = chatsCache.reduce((s, c) => s + (c.unread || 0), 0);
  setMsgBadges(total);

  if (openChatUid) {
    await openChat(openChatUid);
    return;
  }

  const view = $('#view');
  view.innerHTML = `
    <div class="chat-list-screen card">
      <div class="chat-list-head">
        <div class="page-title" style="margin:0">💬 Чаты</div>
      </div>
      <button class="btn btn-primary btn-block" data-action="new-chat">＋ Новый чат</button>
      <button class="btn btn-block self-chat-btn" data-action="self-chat">📝 Сообщения себе</button>
      <button class="btn btn-block" data-action="new-group">👥 Создать группу</button>
      <div id="chat-list"></div>
    </div>`;

  renderChatList();
  $('#chat-list').addEventListener('click', (e) => {
    const item = e.target.closest('[data-chat-uid]');
    if (item) go('/messages/' + item.dataset.chatUid);
  });
  $('[data-action="new-chat"]').addEventListener('click', openNewChatModal);
  $('[data-action="self-chat"]').addEventListener('click', startSelfChat);
  $('[data-action="new-group"]').addEventListener('click', openNewGroupModal);
}

function renderChatList() {
  const list = $('#chat-list');
  if (!list) return;
  list.innerHTML = '';
  if (!chatsCache.length) {
    list.innerHTML = `<div class="chat-placeholder" style="padding:20px 10px">Чатов пока нет</div>`;
    return;
  }
  chatsCache.forEach((c) => {
    const isGroup = c.kind === 'group';
    const isSelf = !isGroup && c.other && c.other.id === me.id;
    const name = isGroup ? c.name : (isSelf ? '📝 Сообщения себе' : displayName(c.other));
    const last = isGroup
      ? (c.last_text || 'Группа создана')
      : (isSelf && !c.last_text ? 'Заметки, избранное, черновики' : (c.last_text || 'Нет сообщений'));
    const avatar = isGroup
      ? `<span class="avatar sm group-avatar">👥</span>`
      : `<img class="avatar sm" src="${mediaUrl(c.other.avatar)}" alt="">`;
    const el = document.createElement('div');
    el.className = 'chat-item' + (c.uid === activeChatUid ? ' active' : '') + (isSelf ? ' self' : '');
    el.dataset.chatUid = c.uid;
    el.innerHTML = `
      ${avatar}
      <div class="chat-item-info">
        <div class="chat-item-name">
          <span>${esc(name)}${isGroup ? ` <span class="muted" style="font-weight:400;font-size:11px">· ${c.member_count || 1} уч.</span>` : ''}</span>
          <span class="muted" style="font-weight:400;font-size:11px">${c.last_at ? fmtTime(c.last_at) : ''}</span>
        </div>
        <div class="chat-item-last">${esc(last)}</div>
      </div>
      ${c.unread ? `<span class="badge">${c.unread}</span>` : ''}`;
    list.appendChild(el);
  });
}

async function startSelfChat() {
  try {
    const res = await api('/chats/self', { method: 'POST' });
    go('/messages/' + res.uid);
  } catch (err) {
    toast(err.message, 'error');
  }
}

async function refreshChatList() {
  try {
    const data = await api('/chats', { silent: true });
    chatsCache = data.chats;
    renderChatList();
  } catch (e) {}
}

async function decryptMessage(m, chatUid) {
  if (!m.e2ee) return m;
  try {
    const chat = chatsCache.find((c) => c.uid === chatUid);
    const senderUid = chat && chat.other ? chat.other.uid : null;
    const pub = senderUid ? await otherPubKey(senderUid) : null;
    if (!pub) throw new Error('no key');
    const data = JSON.parse(m.text);
    const text = await E2EE.decrypt(data.ct, data.iv, pub);
    return { ...m, text, e2eeText: false };
  } catch (e) {
    return { ...m, text: '🔒 Зашифровано', e2eeText: true };
  }
}
async function openChat(chatUid) {
  activeChatUid = chatUid;
  activeChat = chatsCache.find((c) => c.uid === chatUid) || null;
  const data = await api(`/chats/${chatUid}/messages`);
  const chat = activeChat;
  const isGroup = !!(chat && chat.kind === 'group');
  const isSelf = !!(chat && !isGroup && chat.other && chat.other.id === me.id);
  const view = $('#view');
  let head = '';
  if (isGroup) {
    head = `<b>${esc(chat.name)}</b>
      <span class="muted" style="font-size:12px">${chat.member_count || 1} участн.</span>
      <button class="btn btn-ghost btn-sm group-members-btn" style="margin-left:auto">👥 Состав</button>
      <button class="btn btn-ghost btn-sm chat-del" title="Удалить группу">🗑</button>`;
  } else if (isSelf) {
    head = `<img class="avatar sm" src="${mediaUrl(chat.other.avatar)}" alt="">
      <b>📝 Сообщения себе</b>
      <span class="muted">заметки · избранное · черновики</span>
      <button class="btn btn-ghost btn-sm chat-del" style="margin-left:auto" title="Удалить чат">🗑</button>`;
  } else if (chat && chat.other) {
    head = `<a href="#/profile/${esc(chat.other.uid)}"><img class="avatar sm" src="${mediaUrl(chat.other.avatar)}" alt=""></a>
      <b>${esc(displayName(chat.other))}</b>
      <span class="e2ee-tag" title="Сообщения шифруются на вашем устройстве (E2EE)">🔒 E2EE</span>
      <button class="btn btn-ghost btn-sm chat-del" title="Удалить чат">🗑</button>`;
  }
  view.innerHTML = `
    <div class="chat-screen card">
      <div class="chat-head">
        <button class="btn btn-ghost btn-sm chat-back" title="Назад к чатам">←</button>
        ${head}
      </div>
      <div class="chat-messages" id="chat-messages"></div>
      <div class="chat-preview hidden" id="chat-preview"></div>
      <form class="chat-input" id="chat-input">
        <div class="chat-tools">
          <button type="button" class="chat-tool" data-tool="file" title="Файл">📎</button>
          <button type="button" class="chat-tool" data-tool="media" title="Фото/видео">🖼</button>
          <button type="button" class="chat-tool" data-tool="audio" title="Аудиосообщение">🎤</button>
          <button type="button" class="chat-tool" data-tool="round" title="Кружок (видео)">⭕</button>
        </div>
        <input type="text" placeholder="Сообщение..." autocomplete="off" maxlength="4000" id="chat-text">
        <button type="submit" class="btn btn-primary" id="chat-send">➤</button>
      </form>
      <div class="chat-reply-bar hidden" id="chat-reply-bar">
        <div class="reply-quote"><b class="reply-name"></b><span class="reply-text"></span></div>
        <button type="button" class="reply-cancel" id="reply-cancel">✕</button>
      </div>
    </div>`;

  $('.chat-back', view).addEventListener('click', () => go('/messages'));
  const mb = $('.group-members-btn', view);
  if (mb) mb.addEventListener('click', () => openGroupMembers(chat));
  const del = $('.chat-del', view);
  if (del) del.addEventListener('click', () => deleteChat(chat, isGroup));

  const msgs = [];
  for (const m of data.messages) msgs.push(await decryptMessage(m, chatUid));
  msgs.forEach((m) => appendMessage(m));
  scrollChat();

  chatReplyTarget = null;
  const replyBar = $('#chat-reply-bar', view);
  if (replyBar) {
    replyBar.classList.add('hidden');
    $('#reply-cancel', view).addEventListener('click', () => {
      chatReplyTarget = null;
      replyBar.classList.add('hidden');
    });
  }

  chatMsgState = {
    chatUid,
    before: msgs.length ? msgs[0].id : 0,
    hasMore: !!data.hasMore,
    loading: false
  };
  const box = $('#chat-messages', view);
  if (box) {
    box.addEventListener('scroll', () => {
      if (box.scrollTop < 60 && chatMsgState && chatMsgState.hasMore && !chatMsgState.loading) {
        loadChatHistory();
      }
    });
  }

  typingTimer = null;
  const chatInput = $('input#chat-text', view);
  chatInput.addEventListener('input', () => {
    if (chatInput.value.trim() && !typingTimer) sendTyping(chatUid);
  });

  const previewBox = $('#chat-preview', view);
  const sendBtn = $('#chat-send', view);
  let attach = null;   // { file, type, name, duration }
  let recorder = null;
  let recStream = null;
  let recTimer = null;
  let recStart = 0;
  let recMax = 0;

  function revokeAttach() {
    if (attach && attach.url) { URL.revokeObjectURL(attach.url); }
    attach = null;
    previewBox.classList.add('hidden');
    previewBox.innerHTML = '';
    sendBtn.textContent = '➤';
    sendBtn.classList.remove('rec');
  }

  function showAttachPreview() {
    if (!attach) return;
    previewBox.classList.remove('hidden');
    previewBox.innerHTML = '';
    const p = document.createElement('div');
    p.className = 'chat-preview-inner';
    if (attach.type === 'image' && attach.url) {
      p.innerHTML = `<img src="${attach.url}" alt=""><span class="chat-preview-name">${esc(attach.name)}</span>`;
    } else if (attach.type === 'video' && attach.url) {
      p.innerHTML = `<video src="${attach.url}" controls preload="metadata"></video><span class="chat-preview-name">${esc(attach.name)}</span>`;
    } else if (attach.type === 'audio' && attach.url) {
      p.innerHTML = `<audio src="${attach.url}" controls preload="metadata"></audio>`;
    } else if (attach.type === 'round' && attach.url) {
      p.innerHTML = `<video class="round-preview" src="${attach.url}" autoplay loop muted playsinline></video>`;
    } else {
      p.innerHTML = `<span class="chat-preview-file">📎 ${esc(attach.name)} · ${fmtSize(attach.file && attach.file.size)}</span>`;
    }
    const rm = document.createElement('button');
    rm.type = 'button';
    rm.className = 'chat-preview-rm';
    rm.title = 'Отменить';
    rm.textContent = '✕';
    rm.addEventListener('click', () => { if (recorder) stopRec(true); else revokeAttach(); });
    p.appendChild(rm);
    previewBox.appendChild(p);
    sendBtn.textContent = '➤';
  }

  function startRec(type) {
    if (recorder) return;
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia || typeof MediaRecorder === 'undefined') {
      const why = !navigator.mediaDevices || !navigator.mediaDevices.getUserMedia
        ? (window.isSecureContext ? 'нет API getUserMedia' : 'страница открыта не по HTTPS (безопасный контекст)')
        : 'нет MediaRecorder';
      showMediaError(type, why, null);
      return;
    }
    const isRound = type === 'round';
    recMax = isRound ? 120 : 60;
    let mime = '';
    const candidates = isRound
      ? ['video/webm;codecs=vp8,opus', 'video/webm', 'video/mp4']
      : ['audio/webm;codecs=opus', 'audio/webm', 'audio/mp4'];
    for (const c of candidates) { if (MediaRecorder.isTypeSupported(c)) { mime = c; break; } }
    const opts = { audio: true };
    if (isRound) opts.video = { facingMode: 'user', width: { ideal: 720 }, height: { ideal: 1280 } };
    navigator.mediaDevices.getUserMedia(opts).then((stream) => {
      recStream = stream;
      try {
        recorder = new MediaRecorder(stream, mime ? { mimeType: mime } : undefined);
      } catch (e) {
        recorder = new MediaRecorder(stream);
      }
      const chunks = [];
      recorder.ondataavailable = (e) => { if (e.data && e.data.size) chunks.push(e.data); };
      recorder.onstop = () => {
        const type = recorder.mimeType || (isRound ? 'video/webm' : 'audio/webm');
        const ext = /mp4/.test(type) ? 'mp4' : 'webm';
        const blob = new Blob(chunks, { type });
        const dur = Math.round((Date.now() - recStart) / 1000);
        if (attach) revokeAttach();
        attach = {
          file: blob,
          type: isRound ? 'round' : 'audio',
          name: (isRound ? 'round_' : 'voice_') + Date.now() + '.' + ext,
          duration: dur,
          url: URL.createObjectURL(blob)
        };
        stopStream(recStream); recStream = null;
        recorder = null;
        clearRecUi();
        showAttachPreview();
        toast(isRound ? 'Кружок готов, отправьте' : 'Аудио готово, отправьте');
      };
      recorder.start(250);
      recStart = Date.now();
      renderRecUi(isRound);
      recTimer = setInterval(() => {
        const el = $('#chat-preview .rec-timer');
        if (el) el.textContent = fmtDuration((Date.now() - recStart) / 1000);
        if (recMax && Date.now() - recStart >= recMax * 1000) stopRec(false);
      }, 250);
    }).catch((err) => showMediaError(isRound ? 'round' : 'audio', null, err));
  }

  function renderRecUi(isRound) {
    previewBox.classList.remove('hidden');
    previewBox.innerHTML = `
      <div class="rec-inner ${isRound ? 'round' : ''}">
        ${isRound ? `<video class="rec-live" autoplay muted playsinline></video>` : '<span class="rec-dot"></span>'}
        <span class="rec-timer">0:00</span>
        <span class="rec-label">${isRound ? '⭕ Кружок (до 2:00)' : '🎤 Аудио (до 1:00)'}</span>
        <button type="button" class="btn btn-primary btn-sm rec-stop">⏹</button>
      </div>`;
    if (isRound && recStream) {
      const v = $('.rec-live', previewBox);
      v.srcObject = recStream;
    }
    sendBtn.textContent = '⏺';
    sendBtn.classList.add('rec');
    const stop = $('.rec-stop', previewBox);
    if (stop) stop.addEventListener('click', () => stopRec(false));
  }

  function clearRecUi() {
    if (recTimer) { clearInterval(recTimer); recTimer = null; }
  }

  function stopRec(cancel) {
    if (!recorder) return;
    clearRecUi();
    if (cancel) {
      recorder.onstop = null;
      try { recorder.stop(); } catch (e) {}
      stopStream(recStream); recStream = null;
      recorder = null;
      revokeAttach();
      toast('Запись отменена');
      return;
    }
    try { recorder.stop(); } catch (e) {}
  }

  function stopStream(s) {
    if (!s) return;
    s.getTracks().forEach((t) => t.stop());
  }

  function openFilePicker(accept, kind) {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = accept;
    input.onchange = () => {
      const f = input.files && input.files[0];
      if (!f) return;
      if (recorder) stopRec(true);
      revokeAttach();
      const isImg = f.type.startsWith('image/');
      const isVid = f.type.startsWith('video/');
      const isAud = f.type.startsWith('audio/');
      attach = {
        file: f,
        type: isImg ? 'image' : isVid ? 'video' : isAud ? 'audio' : 'file',
        name: f.name,
        duration: 0,
        url: isImg || isVid || isAud ? URL.createObjectURL(f) : null
      };
      showAttachPreview();
      chatInput.focus();
    };
    input.click();
  }

  $$('.chat-tool', view).forEach((btn) => btn.addEventListener('click', () => {
    const tool = btn.dataset.tool;
    if (tool === 'file') openFilePicker('*', 'file');
    else if (tool === 'media') openFilePicker('image/*,video/*', 'media');
    else if (tool === 'audio') startRec('audio');
    else if (tool === 'round') startRec('round');
  }));

  $('#chat-input', view).addEventListener('submit', async (e) => {
    e.preventDefault();
    const input = chatInput;
    const text = input.value.trim();
    if (!text && !attach) return;

    try {
      let body;
      const useE2ee = !isGroup && !attach;
      let pub = null;
      if (!isGroup) {
        const other = chat && chat.other ? chat.other : null;
        if (other) pub = await otherPubKey(other.uid);
      }
      let fd = null;
      if (attach) {
        fd = new FormData();
        if (text) fd.append('text', text);
        if (attach.duration) fd.append('duration', String(attach.duration));
        if (attach.type === 'round') fd.append('kind', 'round');
        fd.append('file', attach.file, attach.name);
        if (pub && text) {
          const enc = await E2EE.encrypt(text, pub);
          fd.set('text', JSON.stringify(enc));
          fd.append('e2ee', '1');
        }
      } else {
        body = { text, e2ee: false };
        if (pub) {
          try {
            const enc = await E2EE.encrypt(text, pub);
            body = { text: JSON.stringify(enc), e2ee: true };
          } catch (err) {
            toast('Шифрование недоступно, отправлено открытым текстом', 'error');
          }
        }
      }
      if (chatReplyTarget) {
        if (fd) fd.append('reply_to', String(chatReplyTarget));
        else body.reply_to = chatReplyTarget;
      }
      input.value = '';
      if (attach) revokeAttach();
      const res = await api(`/chats/${chatUid}/messages`, { method: 'POST', body: fd || body });
      const m = await decryptMessage(res.message, chatUid);
      appendMessage(m);
      scrollChat();
      refreshChatList();
      chatReplyTarget = null;
      const rb = $('#chat-reply-bar');
      if (rb) rb.classList.add('hidden');
    } catch (err) { toast(err.message, 'error'); }
  });

  markChatRead(chatUid);
}

async function deleteChat(chat, isGroup) {
  if (!chat) return;
  const label = isGroup ? 'группу' : 'чат';
  const who = isGroup ? chat.name : (chat.other ? chat.other.name : '');
  if (!confirm(`Удалить ${label} «${who}»? Все сообщения будут удалены.`)) return;
  try {
    await api('/chats/' + chat.uid, { method: 'DELETE' });
    toast(isGroup ? 'Группа удалена' : 'Чат удалён');
    chatsCache = chatsCache.filter((c) => c.uid !== chat.uid);
    activeChatUid = null;
    activeChat = null;
    go('/messages');
  } catch (err) { toast(err.message, 'error'); }
}

function downloadMediaUrl(m) {
  const base = mediaUrl(m.media);
  const sep = base.includes('?') ? '&' : '?';
  return base + sep + 'name=' + encodeURIComponent(m.media_name || 'file');
}

function mediaNode(m) {
  const url = mediaUrl(m.media);
  const type = m.media_type || '';
  if (type === 'image') {
    const img = document.createElement('img');
    img.className = 'msg-media-img';
    img.src = url;
    img.alt = '';
    img.loading = 'lazy';
    return img;
  }
  if (type === 'audio') {
    const audio = document.createElement('audio');
    audio.className = 'msg-media-audio';
    audio.src = url;
    audio.controls = true;
    audio.preload = 'metadata';
    return audio;
  }
  if (type === 'round') {
    const wrap = document.createElement('div');
    wrap.className = 'msg-media-round';
    const video = document.createElement('video');
    video.src = url;
    video.muted = true;
    video.loop = true;
    video.playsInline = true;
    video.preload = 'metadata';
    video.addEventListener('click', () => {
      if (video.paused) { video.muted = false; video.play(); }
      else { video.pause(); video.muted = true; }
    });
    wrap.appendChild(video);
    const badge = document.createElement('span');
    badge.className = 'round-duration';
    badge.textContent = fmtDuration(m.media_duration);
    wrap.appendChild(badge);
    return wrap;
  }
  if (type === 'video') {
    const video = document.createElement('video');
    video.className = 'msg-media-video';
    video.src = url;
    video.controls = true;
    video.playsInline = true;
    video.preload = 'metadata';
    return video;
  }
  const a = document.createElement('a');
  a.className = 'msg-media-file';
  a.href = downloadMediaUrl(m);
  a.textContent = '📎 ' + (m.media_name || 'Файл') + (m.media_size ? ' · ' + fmtSize(m.media_size) : '');
  a.target = '_blank';
  a.rel = 'noopener';
  return a;
}

function captionNode(m) {
  const cap = document.createElement('div');
  cap.className = 'msg-caption';
  cap.textContent = m.text;
  if (m.e2eeText) cap.classList.add('e2ee');
  if (m.edited && !m.e2eeText) cap.textContent += ' (ред.)';
  return cap;
}

function setChatReply(mid, name, text, mediaType) {
  chatReplyTarget = mid;
  const bar = $('#chat-reply-bar');
  if (!bar) return;
  const rt = mediaType ? 'Вложение' : '';
  bar.querySelector('.reply-name').textContent = name || 'Пользователь';
  bar.querySelector('.reply-text').textContent = (text || rt || '').slice(0, 90);
  bar.classList.remove('hidden');
  const input = $('input#chat-text');
  if (input) input.focus();
}

function openForwardModal(messageId) {
  if (!chatsCache.length) { toast('Нет чатов для пересылки', 'error'); return; }
  const modal = document.createElement('div');
  modal.className = 'modal-backdrop';
  let items = '';
  chatsCache.forEach((c) => {
    const name = c.kind === 'group' ? c.name : (c.other && c.other.id === me.id ? '📝 Сообщения себе' : displayName(c.other));
    items += `<label class="fwd-item"><input type="checkbox" value="${esc(c.uid)}"><span>${esc(name)}</span></label>`;
  });
  modal.innerHTML = `
    <div class="modal card">
      <button class="close-x">✕</button>
      <h2 class="page-title">Переслать сообщение</h2>
      <div class="fwd-list">${items}</div>
      <button class="btn btn-primary btn-block" id="fwd-send">Отправить</button>
    </div>`;
  $('#modal-root').appendChild(modal);
  modal.addEventListener('click', (e) => {
    if (e.target === modal || e.target.classList.contains('close-x')) modal.remove();
  });
  $('#fwd-send', modal).addEventListener('click', async () => {
    const uids = $$('input:checked', modal).map((i) => i.value);
    if (!uids.length) { toast('Выберите чат', 'error'); return; }
    try {
      const r = await api('/chats/forward', { method: 'POST', body: JSON.stringify({ message_id: messageId, chat_uids: uids }), headers: { 'Content-Type': 'application/json' } });
      toast(`Переслано в ${r.count} чат(ов)`);
      modal.remove();
    } catch (e) { toast(e.message, 'error'); }
  });
}

function appendMessage(m, atTop) {
  const container = $('#chat-messages');
  if (!container) return;
  const node = $('#tpl-message').content.cloneNode(true);
  const div = $('.msg', node);
  div.classList.toggle('mine', m.sender_id === me.id);
  div.dataset.mid = m.id;
  if (activeChat && activeChat.kind === 'group') {
    const author = document.createElement('span');
    author.className = 'msg-author';
    const authorName = m.sender_id === me.id ? (me.name || 'Вы') : displayName({ uid: m.sender_uid, name: m.name });
    author.textContent = authorName;
    div.insertBefore(author, $('.msg-bubble', node));
  }
  const bubble = $('.msg-bubble', node);
  if (m.reply) {
    const rt = m.reply.media_type
      ? (m.reply.media_type === 'image' ? '🖼 Фото' : m.reply.media_type === 'video' ? '🎬 Видео' : m.reply.media_type === 'audio' ? '🎤 Аудио' : m.reply.media_type === 'round' ? '⭕ Кружок' : '📎 Файл')
      : '';
    const rq = document.createElement('div');
    rq.className = 'msg-reply';
    rq.innerHTML = `<span class="msg-reply-name">${esc(m.reply.name || 'Пользователь')}</span><span class="msg-reply-text">${esc((m.reply.text || rt || 'Вложение').slice(0, 90))}</span>`;
    div.insertBefore(rq, bubble);
  }
  if (m.media) {
    bubble.appendChild(mediaNode(m));
    if (m.text) bubble.appendChild(captionNode(m));
  } else {
    bubble.textContent = m.text;
    if (m.e2eeText) bubble.classList.add('e2ee');
    if (m.edited && !m.e2eeText) bubble.textContent += ' (ред.)';
  }
  const time = $('.msg-time', node);
  time.textContent = fmtTime(m.created_at);
  time.title = m.created_at;
  if (m.sender_id === me.id) {
    const mark = document.createElement('span');
    mark.className = 'msg-read sent';
    mark.textContent = '✓';
    time.appendChild(mark);
  }
  const actions = document.createElement('div');
  actions.className = 'msg-actions';
  if (m.sender_id === me.id) {
    const ed = document.createElement('button');
    ed.textContent = '✏';
    ed.title = 'Редактировать';
    ed.addEventListener('click', () => editMessage(div, m));
    actions.appendChild(ed);
    const del = document.createElement('button');
    del.textContent = '🗑';
    del.title = 'Удалить';
    del.addEventListener('click', () => deleteMessage(m));
    actions.appendChild(del);
  }
  const react = document.createElement('button');
  react.textContent = '😊';
  react.title = 'Реакция';
  react.addEventListener('click', () => {
    const picker = $('.reaction-picker', div);
    if (picker) picker.remove();
    else {
      const p = document.createElement('div');
      p.className = 'reaction-picker';
      ['👍', '❤️', '🔥', '😄', '🎉'].forEach((em) => {
        const b = document.createElement('button');
        b.textContent = em;
        b.addEventListener('click', () => { toggleReaction(m, em); p.remove(); });
        p.appendChild(b);
      });
      div.appendChild(p);
    }
  });
  actions.appendChild(react);

  const replyBtn = document.createElement('button');
  replyBtn.textContent = '↩';
  replyBtn.title = 'Ответить';
  replyBtn.addEventListener('click', () => setChatReply(m.id, m.sender_id === me.id ? (me.name || 'Вы') : displayName({ uid: m.sender_uid, name: m.name }), m.text, m.media_type));
  actions.appendChild(replyBtn);

  const fwd = document.createElement('button');
  fwd.textContent = '➡';
  fwd.title = 'Переслать';
  fwd.addEventListener('click', () => openForwardModal(m.id));
  actions.appendChild(fwd);
  div.appendChild(actions);
  const rx = m.reactions && m.reactions.length ? m.reactions : null;
  if (rx) {
    const box = document.createElement('div');
    box.className = 'msg-reactions';
    rx.forEach((r) => {
      const chip = document.createElement('button');
      chip.className = 'reaction-chip' + ((m.myEmoji || []).includes(r.emoji) ? ' mine' : '');
      chip.textContent = r.emoji + ' ' + r.count;
      chip.addEventListener('click', () => toggleReaction(m, r.emoji));
      box.appendChild(chip);
    });
    div.appendChild(box);
  }
  if (window.matchMedia('(max-width: 860px)').matches) {
    div.addEventListener('click', (e) => {
      if (e.target.closest('a, button, video, audio, .msg-actions, .reaction-picker')) return;
      const wasOpen = div.classList.contains('actions-open');
      $$('#chat-messages .msg.actions-open').forEach((o) => o.classList.remove('actions-open'));
      if (!wasOpen) div.classList.add('actions-open');
    });
  }
  if (atTop && container.firstChild) container.insertBefore(node, container.firstChild);
  else container.appendChild(node);
}

async function loadChatHistory() {
  if (!chatMsgState || !chatMsgState.hasMore || chatMsgState.loading) return;
  chatMsgState.loading = true;
  let data;
  try {
    data = await api(`/chats/${chatMsgState.chatUid}/messages?before=${chatMsgState.before}&limit=50`);
  } catch (e) { chatMsgState.loading = false; return; }
  if (!data.messages.length) { chatMsgState.hasMore = false; chatMsgState.loading = false; return; }
  const box = $('#chat-messages');
  const prevHeight = box ? box.scrollHeight : 0;
  const prevTop = box ? box.scrollTop : 0;
  for (const m of data.messages) {
    const dm = await decryptMessage(m, chatMsgState.chatUid);
    appendMessage(dm, true);
  }
  if (box) box.scrollTop = prevTop + (box.scrollHeight - prevHeight);
  chatMsgState.hasMore = !!data.hasMore;
  chatMsgState.before = data.messages[0].id;
  chatMsgState.loading = false;
}

function removeMessageEl(id) {
  const el = document.querySelector(`#chat-messages .msg[data-mid="${id}"]`);
  if (el) el.remove();
}

function updateMessageEl(id, m) {
  const el = document.querySelector(`#chat-messages .msg[data-mid="${id}"]`);
  if (!el) return;
  const bubble = $('.msg-bubble', el);
  if (m.media) {
    let cap = $('.msg-caption', bubble);
    if (m.text) {
      if (cap) {
        cap.textContent = m.text;
        cap.classList.toggle('e2ee', !!m.e2eeText);
        if (m.edited && !m.e2eeText) cap.textContent += ' (ред.)';
      } else {
        bubble.appendChild(captionNode(m));
      }
    } else if (cap) {
      cap.remove();
    }
  } else {
    bubble.textContent = m.text;
    bubble.classList.toggle('e2ee', !!m.e2eeText);
    if (m.edited && !m.e2eeText) bubble.textContent += ' (ред.)';
  }
  const box = $('.msg-reactions', el);
  if (box) box.remove();
  if (m.reactions && m.reactions.length) {
    const nb = document.createElement('div');
    nb.className = 'msg-reactions';
    m.reactions.forEach((r) => {
      const chip = document.createElement('button');
      chip.className = 'reaction-chip' + ((m.myEmoji || []).includes(r.emoji) ? ' mine' : '');
      chip.textContent = r.emoji + ' ' + r.count;
      chip.addEventListener('click', () => toggleReaction(m, r.emoji));
      nb.appendChild(chip);
    });
    el.appendChild(nb);
  }
}

async function editMessage(div, m) {
  const bubble = $('.msg-bubble', div);
  const current = bubble.dataset.rawText || m.text;
  const input = document.createElement('input');
  input.className = 'msg-edit-input';
  input.value = current;
  input.maxLength = 4000;
  bubble.replaceWith(input);
  input.focus();
  input.select();
  const commit = async () => {
    const val = input.value.trim();
    if (!val) { input.replaceWith(bubble); return; }
    try {
      let body = { text: val, e2ee: false };
      const chat = activeChat;
      const other = chat && chat.kind === 'dm' && chat.other ? chat.other : null;
      const pub = other ? await otherPubKey(other.uid) : null;
      if (pub) {
        try {
          const enc = await E2EE.encrypt(val, pub);
          body = { text: JSON.stringify(enc), e2ee: true };
        } catch (err) {}
      }
      const res = await api(`/chats/${activeChatUid}/messages/${m.id}`, { method: 'PATCH', body });
      const updated = await decryptMessage(res.message, activeChatUid);
      updateMessageEl(m.id, updated);
      refreshChatList();
    } catch (err) { toast(err.message, 'error'); input.replaceWith(bubble); }
  };
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); commit(); }
    if (e.key === 'Escape') input.replaceWith(bubble);
  });
  input.addEventListener('blur', commit);
}

async function deleteMessage(m) {
  if (!confirm('Удалить сообщение?')) return;
  try {
    await api(`/chats/${activeChatUid}/messages/${m.id}`, { method: 'DELETE' });
    removeMessageEl(m.id);
    refreshChatList();
  } catch (err) { toast(err.message, 'error'); }
}

async function toggleReaction(m, emoji) {
  try {
    const res = await api(`/chats/${activeChatUid}/messages/${m.id}/reaction`, { method: 'POST', body: { emoji } });
    const updated = await decryptMessage(res.message, activeChatUid);
    updateMessageEl(m.id, updated);
  } catch (err) { toast(err.message, 'error'); }
}

let typingTimer = null;
function sendTyping(chatUid) {
  api(`/chats/${chatUid}/typing`, { method: 'POST', silent: true }).catch(() => {});
  typingTimer = setTimeout(() => { typingTimer = null; }, 2000);
}

function showTyping() {
  const container = $('#chat-messages');
  if (!container) return;
  let ind = $('#typing-ind');
  if (!ind) {
    ind = document.createElement('div');
    ind.id = 'typing-ind';
    ind.className = 'typing-ind';
    ind.innerHTML = `<span class="dots"><i></i><i></i><i></i></span> печатает…`;
    container.appendChild(ind);
  }
  clearTimeout(ind._t);
  ind._t = setTimeout(() => ind.remove(), 2500);
  scrollChat();
}

function updateReadMarks() {
  const container = $('#chat-messages');
  if (!container) return;
  if (activeChat && activeChat.kind === 'group') return;
  container.querySelectorAll('.msg.mine .msg-read').forEach((m) => {
    m.textContent = '✓✓';
    m.classList.add('read');
    m.classList.remove('sent');
  });
}

function scrollChat() {
  const c = $('#chat-messages');
  if (c) c.scrollTop = c.scrollHeight;
}

async function markChatRead(chatUid) {
  try {
    await api(`/chats/${chatUid}/read`, { method: 'POST', silent: true });
    const c = chatsCache.find((x) => x.uid === chatUid);
    if (c) c.unread = 0;
    renderChatList();
  } catch (e) {}
}

async function openNewChatModal() {
  const data = await api('/users?exclude=me');
  const modal = document.createElement('div');
  modal.className = 'modal-backdrop';
  modal.innerHTML = `
    <div class="modal card">
      <button class="close-x">✕</button>
      <h2>Новый чат</h2>
      <input type="search" placeholder="Поиск по имени или логину..." id="chat-user-search" style="margin-bottom:12px">
      <div id="chat-user-list" style="max-height:340px;overflow-y:auto"></div>
    </div>`;
  $('#modal-root').appendChild(modal);
  modal.addEventListener('click', (e) => { if (e.target === modal || e.target.classList.contains('close-x')) modal.remove(); });

  const list = $('#chat-user-list', modal);
  function renderUsers(users) {
    list.innerHTML = users.length ? '' : `<div class="chat-placeholder">Никого не найдено</div>`;
    users.forEach((u) => {
      const row = document.createElement('div');
      row.className = 'user-row card';
      row.style.marginBottom = '6px';
      row.innerHTML = `
        <img class="avatar" src="${mediaUrl(u.avatar)}" alt="">
        <div style="flex:1">
          <div style="font-weight:700">${esc(displayName(u))}</div>
          <div class="muted" style="font-size:12px">@${esc(u.username)}</div>
        </div>
        <button class="btn btn-sm">Написать</button>`;
      row.querySelector('button').addEventListener('click', async () => {
        const res = await api('/chats', { method: 'POST', body: { user_id: u.id } });
        modal.remove();
        go('/messages/' + res.uid);
      });
      list.appendChild(row);
    });
  }
  renderUsers(data.users);

  $('#chat-user-search', modal).addEventListener('input', async (e) => {
    const q = e.target.value.trim();
    const res = await api('/users?exclude=me' + (q ? `&q=${encodeURIComponent(q)}` : ''));
    renderUsers(res.users);
  });
}

async function openNewGroupModal() {
  const data = await api('/users?exclude=me');
  const modal = document.createElement('div');
  modal.className = 'modal-backdrop';
  modal.innerHTML = `
    <div class="modal card">
      <button class="close-x">✕</button>
      <h2>👥 Новая группа</h2>
      <input type="text" id="g-name" placeholder="Название группы" maxlength="80" style="margin-bottom:8px">
      <input type="text" id="g-desc" placeholder="Описание (необязательно)" maxlength="2000" style="margin-bottom:10px">
      <div style="margin-bottom:6px;font-size:13px;color:var(--muted)">Выберите участников</div>
      <input type="search" placeholder="Поиск по имени или логину..." id="g-search" style="margin-bottom:12px">
      <div id="g-user-list" style="max-height:220px;overflow-y:auto"></div>
      <button class="btn btn-primary btn-block" id="g-create" style="margin-top:12px">Создать группу</button>
    </div>`;
  $('#modal-root').appendChild(modal);
  modal.addEventListener('click', (e) => { if (e.target === modal || e.target.classList.contains('close-x')) modal.remove(); });

  const selected = new Set();
  const list = $('#g-user-list', modal);
  function renderUsers(users) {
    list.innerHTML = users.length ? '' : `<div class="chat-placeholder">Никого не найдено</div>`;
    users.forEach((u) => {
      const row = document.createElement('div');
      row.className = 'user-row card';
      row.style.marginBottom = '6px';
      row.style.cursor = 'pointer';
      row.innerHTML = `
        <img class="avatar" src="${mediaUrl(u.avatar)}" alt="">
        <div style="flex:1">
          <div style="font-weight:700">${esc(displayName(u))}</div>
          <div class="muted" style="font-size:12px">@${esc(u.username)}</div>
        </div>
        <span class="pick-check">${selected.has(u.id) ? '✓' : ''}</span>`;
      row.addEventListener('click', () => {
        if (selected.has(u.id)) selected.delete(u.id); else selected.add(u.id);
        renderUsers(users);
      });
      list.appendChild(row);
    });
  }
  renderUsers(data.users);

  $('#g-search', modal).addEventListener('input', async (e) => {
    const q = e.target.value.trim();
    const res = await api('/users?exclude=me' + (q ? `&q=${encodeURIComponent(q)}` : ''));
    renderUsers(res.users);
  });

  $('#g-create', modal).addEventListener('click', async () => {
    const name = $('#g-name', modal).value.trim();
    if (!name) return toast('Укажите название группы', 'error');
    try {
      const res = await api('/library/groups', {
        method: 'POST',
        body: { name, description: $('#g-desc', modal).value.trim(), members: [...selected] }
      });
      modal.remove();
      go('/messages/' + res.group.chatUid);
    } catch (err) { toast(err.message, 'error'); }
  });
}

async function openGroupMembers(chat) {
  if (!chat || !chat.group_id) return;
  const data = await api(`/library/groups/${chat.group_id}/members`);
  const isOwner = !!chat.is_owner;
  const modal = document.createElement('div');
  modal.className = 'modal-backdrop';
  modal.innerHTML = `
    <div class="modal card">
      <button class="close-x">✕</button>
      <h2>👥 ${esc(chat.name)} — участники</h2>
      ${isOwner ? `<div style="margin-bottom:10px">
          <input type="search" placeholder="Добавить: имя или @логин" id="gm-search" style="margin-bottom:8px">
          <div id="gm-add-result"></div>
        </div>` : ''}
      <div id="gm-list" style="max-height:320px;overflow-y:auto"></div>
    </div>`;
  $('#modal-root').appendChild(modal);
  modal.addEventListener('click', (e) => { if (e.target === modal || e.target.classList.contains('close-x')) modal.remove(); });

  const list = $('#gm-list', modal);
  function render(rows) {
    list.innerHTML = '';
    if (!rows.length) { list.innerHTML = `<div class="chat-placeholder">Участников нет</div>`; return; }
    rows.forEach((u) => {
      const row = document.createElement('div');
      row.className = 'user-row card';
      row.style.marginBottom = '6px';
      row.innerHTML = `
        <img class="avatar" src="${mediaUrl(u.avatar)}" alt="">
        <div style="flex:1">
          <div style="font-weight:700">${esc(displayName(u))}${u.role === 'owner' ? ' <span class="role-badge admin">СОЗДАТЕЛЬ</span>' : ''}</div>
          <div class="muted" style="font-size:12px">@${esc(u.username)}</div>
        </div>
        ${isOwner && u.role !== 'owner' ? `<button class="btn btn-sm btn-ghost" data-id="${u.id}">Исключить</button>` : ''}`;
      const kick = row.querySelector('[data-id]');
      if (kick) {
        kick.addEventListener('click', async () => {
          if (!confirm(`Исключить ${displayName(u)} из группы?`)) return;
          try {
            await api(`/library/groups/${chat.group_id}/members/${u.id}`, { method: 'DELETE' });
            toast('Участник исключён');
            openGroupMembers(chat);
          } catch (err) { toast(err.message, 'error'); }
        });
      }
      list.appendChild(row);
    });
  }
  render(data.members);

  if (isOwner) {
    const s = $('#gm-search', modal);
    const result = $('#gm-add-result', modal);
    let timer = null;
    s.addEventListener('input', () => {
      clearTimeout(timer);
      timer = setTimeout(async () => {
        const q = s.value.trim();
        result.innerHTML = '';
        if (!q) return;
        const res = await api('/users?q=' + encodeURIComponent(q)).catch(() => ({ users: [] }));
        const existing = new Set(data.members.map((m) => m.id));
        res.users.filter((u) => !existing.has(u.id)).slice(0, 8).forEach((u) => {
          const b = document.createElement('button');
          b.className = 'btn btn-sm';
          b.style.marginRight = '6px';
          b.style.marginBottom = '6px';
          b.textContent = '＋ ' + u.name;
          b.addEventListener('click', async () => {
            try {
              await api(`/library/groups/${chat.group_id}/members`, { method: 'POST', body: { user_id: u.id } });
              toast('Добавлен: ' + u.name);
              openGroupMembers(chat);
            } catch (err) { toast(err.message, 'error'); }
          });
          result.appendChild(b);
        });
      }, 300);
    });
  }
}
/* =========================================================
   ПРОФИЛЬ
   ========================================================= */
async function viewProfile(id) {
  const data = await api(`/users/${id}`);
  const u = data.user;
  const isMe = u.id === me.id;
  const view = $('#view');
  const phoneHref = u.phone ? 'tel:' + u.phone.replace(/[^\+0-9]/g, '') : '';
  view.innerHTML = `
    <div class="profile">
      <div class="profile-head card">
        <span class="avatar-ring ${u.online ? '' : 'offline'}"><img class="avatar xl" src="${mediaUrl(u.avatar)}" alt=""></span>
        <div class="profile-info">
          <div class="profile-name">${esc(isMe ? u.name : displayName(u))}
            <span class="role-badge ${u.role}">${u.role === 'admin' ? 'АДМИН' : 'УЧАСТНИК'}</span>
          </div>
          ${!isMe && aliases.get(u.uid) ? `<div class="profile-status muted" style="font-size:13px">${esc(u.name)}</div>` : ''}
          <div class="profile-status">${u.online ? '<span class="online-dot"></span> онлайн' : ''} ${esc(u.status || '')}</div>
          <p class="profile-bio">${esc(u.bio || '')}</p>
          ${u.phone ? `<p class="profile-bio"><a class="phone-link" href="${esc(phoneHref)}">📞 ${esc(u.phone)}</a></p>` : ''}
          <div class="profile-stats">
            <div class="stat"><b>${data.stats.posts}</b><span>Постов</span></div>
            <div class="stat"><b>${data.stats.videos}</b><span>Видео</span></div>
            <div class="stat"><b id="f-count">${data.stats.followers}</b><span>Подписчиков</span></div>
            <div class="stat"><b>${data.stats.following}</b><span>Подписок</span></div>
          </div>
          <div style="margin-top:16px;display:flex;gap:10px;flex-wrap:wrap">
            ${isMe
              ? `<button class="btn btn-ghost" data-action="edit-profile">✏ Редактировать</button>
                 <button class="btn btn-ghost" data-action="logout" style="color:var(--danger);border-color:var(--danger)">🚪 Выйти</button>`
              : `<button class="btn ${data.isFollowing ? 'btn-ghost' : 'btn-primary'}" data-action="follow" data-state="${data.isFollowing ? '1' : '0'}">
                   ${data.isFollowing ? '✓ Вы подписаны' : '＋ Подписаться'}</button>
                 <button class="btn btn-ghost" data-action="friend" data-relation="${data.relation || 'none'}" style="color:var(--accent);border-color:var(--accent)">${friendBtnLabel(data.relation)}</button>
                 <button class="btn btn-ghost" data-action="alias">✏ Имя</button>`
            }
            <button class="btn btn-ghost" data-action="message" ${isMe ? 'disabled' : ''}>💬 Написать</button>
          </div>
        </div>
      </div>
      <div class="profile-tabs-nav">
        <button data-ptab="posts" class="active">📝 Посты</button>
        <button data-ptab="videos">▶ Видео</button>
      </div>
      <div id="profile-posts"></div>
      <div class="video-grid hidden" id="profile-videos"></div>
    </div>`;

  view.querySelector('.profile-tabs-nav').addEventListener('click', (e) => {
    const btn = e.target.closest('[data-ptab]');
    if (!btn) return;
    view.querySelectorAll('[data-ptab]').forEach((b) => b.classList.toggle('active', b === btn));
    const postsMode = btn.dataset.ptab === 'posts';
    $('#profile-posts', view).classList.toggle('hidden', !postsMode);
    $('#profile-videos', view).classList.toggle('hidden', postsMode);
  });

  const actions = view.querySelector('.profile-head');
  actions.addEventListener('click', async (e) => {
    const btn = e.target.closest('[data-action]');
    if (!btn) return;
    const act = btn.dataset.action;
    if (act === 'edit-profile') go('/edit-profile');
    if (act === 'logout') {
      if (confirm('Выйти из аккаунта?')) logout();
    }
    if (act === 'friend') {
      try {
        const rel = btn.dataset.relation;
        let res;
        if (rel === 'friends') res = await api(`/users/${u.uid}/friend`, { method: 'DELETE' });
        else if (rel === 'incoming') res = await api(`/users/${u.uid}/friend/accept`, { method: 'POST' });
        else if (rel === 'outgoing') res = await api(`/users/${u.uid}/friend`, { method: 'DELETE' });
        else res = await api(`/users/${u.uid}/friend`, { method: 'POST' });
        btn.dataset.relation = res.relation;
        btn.textContent = friendBtnLabel(res.relation);
        toast(rel === 'incoming' && res.relation === 'friends' ? 'Вы друзья!' : undefined);
      } catch (err) { toast(err.message, 'error'); }
    }
    if (act === 'message') {
      const res = await api('/chats', { method: 'POST', body: { user_id: u.id } });
      go('/messages/' + res.uid);
    }
    if (act === 'alias') {
      const current = aliases.get(u.uid) || '';
      const modal = document.createElement('div');
      modal.className = 'modal-backdrop';
      modal.innerHTML = `
        <div class="modal card">
          <button class="close-x">✕</button>
          <h2>✏ Личное имя</h2>
          <p class="muted" style="font-size:13px;margin-bottom:12px">Имя, под которым вы видите ${esc(u.name)} (видно только вам)</p>
          <form id="alias-form">
            <div class="form-row"><label>Имя</label><input name="alias" maxlength="40" value="${esc(current)}" placeholder="${esc(u.name)}"></div>
            <div style="display:flex;gap:8px;margin-top:14px">
              <button type="submit" class="btn btn-primary" style="flex:1">Сохранить</button>
              ${current ? `<button type="button" class="btn btn-ghost" id="alias-clear" style="color:var(--danger)">Сбросить</button>` : ''}
            </div>
          </form>
        </div>`;
      document.body.appendChild(modal);
      modal.querySelector('.close-x').addEventListener('click', () => modal.remove());
      modal.addEventListener('click', (e) => { if (e.target === modal) modal.remove(); });
      modal.querySelector('#alias-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        try {
          const alias = modal.querySelector('[name="alias"]').value.trim();
          const res = await api(`/users/${u.uid}/alias`, { method: 'PUT', body: { alias } });
          if (res.alias) aliases.set(u.uid, res.alias); else aliases.delete(u.uid);
          modal.remove();
          toast(res.alias ? 'Имя сохранено' : 'Имя удалено');
          viewProfile(u.uid);
        } catch (err) { toast(err.message, 'error'); }
      });
      const clearBtn = modal.querySelector('#alias-clear');
      if (clearBtn) clearBtn.addEventListener('click', async () => {
        try {
          await api(`/users/${u.uid}/alias`, { method: 'DELETE' });
          aliases.delete(u.uid);
          modal.remove();
          toast('Имя удалено');
          viewProfile(u.uid);
        } catch (err) { toast(err.message, 'error'); }
      });
    }
    if (act === 'follow') {
      try {
        const state = btn.dataset.state === '1';
        const res = state
          ? await api(`/users/${u.uid}/follow`, { method: 'DELETE' })
          : await api(`/users/${u.uid}/follow`, { method: 'POST' });
        btn.dataset.state = res.isFollowing ? '1' : '0';
        btn.classList.toggle('btn-ghost', res.isFollowing);
        btn.classList.toggle('btn-primary', !res.isFollowing);
        btn.textContent = res.isFollowing ? '✓ Вы подписаны' : '＋ Подписаться';
        $('#f-count').textContent = res.followers;
      } catch (err) { toast(err.message, 'error'); }
    }
  });

  const postsWrap = $('#profile-posts', view);
  if (data.posts.length) {
    data.posts.forEach((p) => {
      postsWrap.appendChild(buildPost({
        ...p, username: u.username, name: u.name, avatar: u.avatar,
        user_id: u.id, author_uid: u.uid, likes: 0, comments: 0, liked: false
      }));
    });
    wirePostEvents(postsWrap);
  } else {
    postsWrap.innerHTML = `<div class="empty">Пока нет постов</div>`;
  }

  const vgrid = $('#profile-videos', view);
  data.videos.forEach((v) => vgrid.appendChild(buildVideoCard({ ...v, name: u.name })));
  if (!data.videos.length) vgrid.innerHTML = `<div class="empty">Пока нет видео</div>`;
}

function viewEditProfile() {
  const view = $('#view');
  view.innerHTML = `
    <div class="form-card card">
      <h1 class="page-title">Редактировать профиль</h1>
      <div style="display:flex;align-items:center;gap:14px;margin-bottom:18px">
        <img class="avatar xl" id="edit-avatar" src="${mediaUrl(me.avatar)}" alt="">
        <div>
          <button class="btn btn-ghost btn-sm" id="edit-avatar-btn">Сменить аватар</button>
          <input type="file" accept="image/*" id="edit-avatar-file" class="hidden">
        </div>
      </div>
       <form id="profile-form">
        <div class="form-row"><label>Имя *</label><input name="name" required maxlength="60" value="${esc(me.name)}"></div>
        <div class="form-row"><label>Телефон</label><input name="phone" maxlength="30" inputmode="tel" value="${esc(me.phone || '')}" placeholder="+7 999 123-45-67"></div>
        <div class="form-row"><label>Статус</label><input name="status" maxlength="60" value="${esc(me.status || '')}" placeholder="Например: на сборах"></div>
        <div class="form-row"><label>О себе</label><textarea name="bio" maxlength="200" placeholder="Расскажите о себе...">${esc(me.bio || '')}</textarea></div>
        <div class="form-row checkbox-row">
          <input type="checkbox" name="incognito" ${me.incognito ? 'checked' : ''}> Режим инкогнито (мои просмотры видео не учитываются)
        </div>
        <button type="submit" class="btn btn-primary btn-block">Сохранить</button>
      </form>
    </div>`;

  $('#edit-avatar-btn').addEventListener('click', () => $('#edit-avatar-file').click());
  $('#edit-avatar-file').addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const fd = new FormData();
    fd.append('avatar', file);
    try {
      const res = await api(`/users/${me.uid}/avatar`, { method: 'POST', body: fd });
      me = res.user;
      $('#edit-avatar').src = mediaUrl(me.avatar);
      updateNavUser();
      toast('Аватар обновлён');
    } catch (err) { toast(err.message, 'error'); }
  });

  $('#profile-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    try {
      const res = await api(`/users/${me.uid}`, {
        method: 'PUT',
        body: {
          name: fd.get('name'),
          phone: fd.get('phone'),
          status: fd.get('status'),
          bio: fd.get('bio'),
          incognito: fd.get('incognito') ? true : false
        }
      });
      me = res.user;
      updateNavUser();
      toast('Профиль сохранён');
      go('/profile/me');
    } catch (err) { toast(err.message, 'error'); }
  });
}
async function viewSecurity() {
  const view = $('#view');
  let totp = false;
  try { totp = (await api('/auth/2fa/status')).enabled; } catch (e) {}
  view.innerHTML = `
    <div class="page-title">🔐 Безопасность</div>
    <div class="form-card card" id="sec-2fa">
      <h3>Двухфакторная аутентификация (2FA)</h3>
      <div id="sec-2fa-body"></div>
    </div>
    <div class="form-card card">
      <h3>Смена пароля</h3>
      <form id="sec-pass-form">
        <div class="form-row"><label>Текущий пароль</label><input type="password" name="current_password" required></div>
        <div class="form-row"><label>Новый пароль</label><input type="password" name="new_password" required minlength="6"></div>
        <button type="submit" class="btn btn-primary">Сменить пароль</button>
      </form>
    </div>
    <div class="form-card card">
      <h3>Устройства и сессии</h3>
      <div id="sec-sessions"></div>
      <button class="btn btn-ghost" id="sec-logout-all" style="margin-top:12px">Выйти со всех устройств</button>
    </div>`;
  renderSec2fa(totp);
  $('#sec-pass-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    try {
      await api('/auth/password', { method: 'POST', body: { current_password: fd.get('current_password'), new_password: fd.get('new_password') } });
      toast('Пароль изменён'); e.target.reset();
    } catch (err) { toast(err.message, 'error'); }
  });
  $('#sec-logout-all').addEventListener('click', async () => {
    if (!confirm('Выйти со всех устройств?')) return;
    try { await api('/auth/logout-all', { method: 'POST' }); sessionExpired(); } catch (err) { toast(err.message, 'error'); }
  });
  renderSessions();
}
function renderSec2fa(enabled) {
  const box = $('#sec-2fa-body');
  if (enabled) {
    box.innerHTML = `
      <p class="muted" style="margin-bottom:12px">2FA включена. При входе потребуется код из приложения-аутентификатора.</p>
      <form id="sec-2fa-disable">
        <div class="form-row"><label>Пароль</label><input type="password" name="password" required></div>
        <div class="form-row"><label>Код 2FA</label><input name="code" inputmode="numeric" required maxlength="6" placeholder="000000"></div>
        <button type="submit" class="btn btn-ghost">Отключить 2FA</button>
      </form>`;
    $('#sec-2fa-disable').addEventListener('submit', async (e) => {
      e.preventDefault();
      const fd = new FormData(e.target);
      try { await api('/auth/2fa/disable', { method: 'POST', body: { password: fd.get('password'), code: fd.get('code') } }); toast('2FA отключена'); viewSecurity(); }
      catch (err) { toast(err.message, 'error'); }
    });
    return;
  }
  box.innerHTML = `
    <p class="muted" style="margin-bottom:12px">Включите 2FA: понадобится приложение-аутентификатор (Google Authenticator, Aegis и т.п.).</p>
    <button class="btn btn-primary" id="sec-2fa-start">Включить 2FA</button>
    <div id="sec-2fa-setup" class="hidden" style="margin-top:14px"></div>`;
  $('#sec-2fa-start').addEventListener('click', async () => {
    try {
      const res = await api('/auth/2fa/setup', { method: 'POST' });
      const setup = $('#sec-2fa-setup');
      setup.classList.remove('hidden');
      setup.innerHTML = `
        <div class="form-row"><label>Секрет</label><code class="secret-code">${esc(res.secret)}</code></div>
        <div class="form-row"><label>Ссылка для приложения</label><code class="secret-code" style="font-size:11px;word-break:break-all">${esc(res.uri)}</code></div>
        <div class="form-row"><label>Код из приложения</label><input id="sec-2fa-code" inputmode="numeric" maxlength="6" placeholder="000000"></div>
        <div class="form-row"><label>Резервные коды (сохраните!)</label><code class="secret-code">${res.codes.map(esc).join('  ')}</code></div>
        <button class="btn btn-primary" id="sec-2fa-confirm">Подтвердить</button>`;
      $('#sec-2fa-confirm').addEventListener('click', async () => {
        const code = $('#sec-2fa-code').value.trim();
        try { await api('/auth/2fa/verify', { method: 'POST', body: { token: res.token, code } }); toast('2FA включена'); viewSecurity(); }
        catch (err) { toast(err.message, 'error'); }
      });
    } catch (err) { toast(err.message, 'error'); }
  });
}

async function renderSessions() {
  const box = $('#sec-sessions');
  try {
    const data = await api('/auth/sessions');
    box.innerHTML = data.sessions.length
      ? data.sessions.map((s) => `<div style="display:flex;align-items:center;justify-content:space-between;padding:10px 0;border-bottom:1px solid var(--border)"><div><b>${s.isCurrent ? 'Это устройство' : 'Другое устройство'}</b><div class="muted" style="font-size:12px">Создана: ${timeAgo(s.created_at)} · активна до ${new Date(s.expires_at).toLocaleDateString('ru-RU')}</div></div>${s.isCurrent ? '' : `<button class="btn btn-ghost btn-sm" data-device="${esc(s.device_id)}">Отозвать</button>`}</div>`).join('')
      : `<div class="muted">Нет активных сессий</div>`;
    box.querySelectorAll('[data-device]').forEach((b) => {
      b.addEventListener('click', async () => {
        try { await api(`/auth/sessions/${b.dataset.device}`, { method: 'DELETE' }); toast('Сессия отозвана'); renderSessions(); }
        catch (err) { toast(err.message, 'error'); }
      });
    });
  } catch (e) { box.innerHTML = `<div class="muted">Не удалось загрузить сессии</div>`; }
}
async function viewSearch(type) {
  const view = $('#view');
  const isPeople = type === 'all' || type === 'users';
  view.innerHTML = `
    <div class="page-title">🔍 Поиск: ${esc(currentSearch)}</div>
    <div class="search-tabs" style="display:flex;gap:8px;margin-bottom:18px">
      <button class="btn btn-sm ${type === 'all' ? '' : 'btn-ghost'}" data-t="all">Все</button>
      <button class="btn btn-sm ${type === 'users' ? '' : 'btn-ghost'}" data-t="users">Люди</button>
      <button class="btn btn-sm ${type === 'posts' ? '' : 'btn-ghost'}" data-t="posts">Посты</button>
      <button class="btn btn-sm ${type === 'videos' ? '' : 'btn-ghost'}" data-t="videos">Видео</button>
    </div>
    ${isPeople ? contactsBlockHtml() : ''}
    <div class="search-results" id="search-results"></div>`;

  $$('.search-tabs button', view).forEach((b) => {
    b.addEventListener('click', () => go('/search?type=' + b.dataset.t + '&q=' + encodeURIComponent(currentSearch)));
  });

  if (isPeople) initContacts(view);

  const results = $('#search-results', view);
  if (!currentSearch) { results.innerHTML = `<div class="empty">Введите запрос для поиска</div>`; return; }
  const data = await api(`/search?q=${encodeURIComponent(currentSearch)}&type=${type}`);
  let html = '';

  if ((type === 'all' || type === 'users') && data.users.length) {
    html += `<div class="search-block"><h2>👤 Люди (${data.users.length})</h2><div id="sr-users"></div></div>`;
  }
  if ((type === 'all' || type === 'posts') && data.posts.length) {
    html += `<div class="search-block"><h2>📝 Посты (${data.posts.length})</h2><div class="feed" id="sr-posts"></div></div>`;
  }
  if ((type === 'all' || type === 'videos') && data.videos.length) {
    html += `<div class="search-block"><h2>▶ Видео (${data.videos.length})</h2><div class="video-grid" id="sr-videos"></div></div>`;
  }
  results.innerHTML = html || `<div class="empty">Ничего не найдено по запросу «${esc(currentSearch)}»</div>`;

  const usersBox = $('#sr-users', results);
  if (usersBox) {
    data.users.forEach((u) => {
      const row = document.createElement('div');
      row.className = 'user-row card';
      row.style.marginBottom = '8px';
      row.innerHTML = `
        <a href="#/profile/${u.uid}"><img class="avatar" src="${mediaUrl(u.avatar)}" alt=""></a>
        <div style="flex:1"><a href="#/profile/${u.uid}" style="font-weight:700;color:var(--text)">${esc(displayName(u))}</a>
          <div class="muted" style="font-size:12px">@${esc(u.username)} · ${esc(u.status || '')}</div></div>
        <button class="btn btn-ghost btn-sm" data-act="msg-${u.id}">💬</button>`;
      row.querySelector('[data-act]').addEventListener('click', async (ev) => {
        ev.preventDefault();
        const res = await api('/chats', { method: 'POST', body: { user_id: u.id } });
        go('/messages/' + res.uid);
      });
      usersBox.appendChild(row);
    });
  }

  const postsBox = $('#sr-posts', results);
  if (postsBox) { data.posts.forEach((p) => postsBox.appendChild(buildPost({ ...p, likes: 0, comments: 0, liked: false }))); wirePostEvents(postsBox); }

  const vBox = $('#sr-videos', results);
  if (vBox) data.videos.forEach((v) => vBox.appendChild(buildVideoCard({ ...v, is_clip: v.is_clip })));
}

/* ---------- поиск по контактам телефонной книги ---------- */
function contactsBlockHtml() {
  return `
  <div class="search-block card" style="padding:16px;margin-bottom:18px">
    <h2 style="margin:0 0 4px">📇 Контакты из телефонной книги</h2>
    <div class="muted" style="font-size:13px;margin-bottom:12px">Найдите людей РЕСКИ по номеру из контактов устройства. Номера не сохраняются — на сервер уходит только хэш.</div>
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px">
      <button class="btn btn-primary btn-sm" id="ct-pick">📱 Выбрать контакты</button>
      <input id="ct-input" class="form-input" placeholder="+7 999 123-45-67" inputmode="tel" maxlength="30" style="flex:1;min-width:180px">
      <button class="btn btn-ghost btn-sm" id="ct-add">＋ Добавить</button>
    </div>
    <div id="ct-chips" style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:10px"></div>
    <button class="btn btn-primary btn-block" id="ct-find" disabled>Найти в контактах</button>
    <div id="ct-results" style="margin-top:12px"></div>
  </div>`;
}

function normalizePhone(raw) {
  let d = String(raw || '').replace(/\D/g, '');
  if (d.length === 11 && d[0] === '8') d = '7' + d.slice(1);
  else if (d.length === 10) d = '7' + d;
  return /^7\d{10}$/.test(d) ? d : '';
}

function initContacts(view) {
  const chips = new Set();
  const names = new Map(); /* нормализованный номер → имя контакта */
  const chipBox = $('#ct-chips', view);
  const results = $('#ct-results', view);
  const findBtn = $('#ct-find', view);

  function renderChips() {
    chipBox.innerHTML = '';
    [...chips].forEach((n) => {
      const c = document.createElement('span');
      c.className = 'chip';
      c.innerHTML = `${esc(n)} <b data-x="1" style="cursor:pointer">✕</b>`;
      c.querySelector('[data-x]').addEventListener('click', () => { chips.delete(n); renderChips(); });
      chipBox.appendChild(c);
    });
    findBtn.disabled = chips.size === 0;
  }

  function addNum(raw, name) {
    const n = normalizePhone(raw);
    if (!n) return false;
    chips.add(n);
    if (name && !names.has(n)) names.set(n, name);
    renderChips();
    return true;
  }

  $('#ct-add', view).addEventListener('click', () => {
    const inp = $('#ct-input', view);
    if (!addNum(inp.value, '')) toast('Неверный формат номера', 'error');
    inp.value = '';
  });

  $('#ct-pick', view).addEventListener('click', async () => {
    if (!('contacts' in navigator) || !navigator.contacts || typeof navigator.contacts.select !== 'function') {
      toast('Выбор контактов недоступен в этом браузере — введите номера вручную', 'error');
      return;
    }
    let contacts = null;
    try {
      contacts = await navigator.contacts.select(['name', 'tel'], { multiple: true });
    } catch (e) {
      try { contacts = await navigator.contacts.select(['tel'], { multiple: true }); }
      catch (e2) { toast('Доступ к контактам отклонён', 'error'); return; }
    }
    let added = 0;
    (contacts || []).forEach((c) => {
      (c.tel || []).forEach((t) => { if (addNum(t, c.name || '')) added++; });
    });
    toast(added ? `Добавлено номеров: ${added}` : 'В выбранных контактах нет номеров');
  });

  findBtn.addEventListener('click', async () => {
    findBtn.disabled = true;
    try {
      const data = await api('/search/contacts', { method: 'POST', body: { phones: [...chips] } });
      results.innerHTML = '';
      if (!data.matches.length) {
        results.innerHTML = `<div class="empty">Никто из контактов пока не зарегистрирован в РЕСКИ</div>`;
        return;
      }
      data.matches.forEach((m) => {
        const contactName = names.get(m.phone) || '';
        const row = document.createElement('div');
        row.className = 'user-row card';
        row.style.marginBottom = '8px';
        row.innerHTML = `
          <a href="#/profile/${esc(m.user.uid)}"><img class="avatar" src="${mediaUrl(m.user.avatar)}" alt=""></a>
          <div style="flex:1;min-width:0">
            ${contactName ? `<div class="muted" style="font-size:12px">${esc(contactName)}</div>` : ''}
            <a href="#/profile/${esc(m.user.uid)}" style="font-weight:700;color:var(--text)">${esc(displayName(m.user))}</a>
            <div class="muted" style="font-size:12px">@${esc(m.user.username)}</div>
          </div>
          <button class="btn btn-ghost btn-sm" data-act="msg">💬</button>`;
        row.querySelector('[data-act]').addEventListener('click', async () => {
          const res = await api('/chats', { method: 'POST', body: { user_id: m.user.id } });
          go('/messages/' + res.uid);
        });
        results.appendChild(row);
      });
    } catch (err) { toast(err.message, 'error'); }
    finally { findBtn.disabled = false; }
  });
}

function openNewPostModal() {
  const modal = document.createElement('div');
  modal.className = 'modal-backdrop';
  modal.innerHTML = `
    <div class="modal card">
      <button class="close-x">✕</button>
      <h2>Новый пост</h2>
      <form id="post-form">
        <div class="form-row">
          <textarea name="text" rows="4" placeholder="Что у вас нового?" maxlength="5000"></textarea>
        </div>
        <div class="file-zone" id="post-zone">
          <div>📎 Прикрепить фото или видео (необязательно)</div>
          <div class="fname hidden"></div>
        </div>
        <input type="file" name="media" accept="image/*,video/*" class="hidden" id="post-file">
        <button type="submit" class="btn btn-primary btn-block">Опубликовать</button>
      </form>
    </div>`;
  $('#modal-root').appendChild(modal);
  modal.addEventListener('click', (e) => { if (e.target === modal || e.target.classList.contains('close-x')) modal.remove(); });

  const zone = $('#post-zone', modal);
  const fileInput = $('#post-file', modal);
  zone.addEventListener('click', () => fileInput.click());
  fileInput.addEventListener('change', () => {
    if (fileInput.files[0]) { $('.fname', modal).classList.remove('hidden'); $('.fname', modal).textContent = '✓ ' + fileInput.files[0].name; }
  });

  $('#post-form', modal).addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    try {
      const res = await api('/posts', { method: 'POST', body: fd });
      modal.remove();
      toast('Пост опубликован');
      if (parseHash().segs[0] === 'feed') {
        const feed = $('#post-feed');
        feed.prepend(buildPost(res.post));
        wirePostEvents(feed);
      } else { go('/feed'); }
    } catch (err) { toast(err.message, 'error'); }
  });
}
const LS = {
  notesKey() { return 'reska_notes_' + (me ? me.uid : 'anon'); },
  favKey() { return 'reska_favs_' + (me ? me.uid : 'anon'); },
  groupsKey() { return 'reska_groups_' + (me ? me.uid : 'anon'); },
  load(k) { try { return JSON.parse(localStorage.getItem(k)) || []; } catch (e) { return []; } },
  save(k, v) { localStorage.setItem(k, JSON.stringify(v)); }
};
function luid() { return Date.now().toString(36) + Math.random().toString(36).slice(2, 8); }
/* ---------- КОНСПЕКТЫ ---------- */
async function viewNotes() {
  const view = $('#view');
  view.innerHTML = `
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:18px">
      <div class="page-title" style="margin:0">📝 Конспекты</div>
      <button class="btn btn-primary btn-sm" id="note-add">＋ Новый</button>
    </div>
    <div class="notes-grid" id="notes-grid"></div>`;
  $('#note-add').addEventListener('click', () => noteEditor(null));
  const grid = $('#notes-grid');
  let notes = [];
  try { notes = (await api('/library/notes')).notes; } catch (e) { toast(e.message, 'error'); }
  if (!notes.length) { grid.innerHTML = `<div class="empty">Пока пусто. Создайте первый конспект!</div>`; return; }
  notes.sort((a, b) => new Date(b.updated_at) - new Date(a.updated_at)).forEach((n) => grid.appendChild(noteCard(n)));
}

function noteCard(n) {
  const el = document.createElement('div');
  el.className = 'note-card card';
  el.innerHTML = `
    <h3>${esc(n.title)}</h3>
    <p>${esc(n.body)}</p>
    <div class="note-date muted">${timeAgo(n.updated_at)}</div>
    <div class="note-actions">
      <button class="btn btn-ghost btn-sm" data-act="edit">✏</button>
      <button class="btn btn-ghost btn-sm" data-act="del">🗑</button>
    </div>`;
  el.querySelector('[data-act="edit"]').addEventListener('click', () => noteEditor(n));
  el.querySelector('[data-act="del"]').addEventListener('click', async () => {
    if (!confirm('Удалить конспект?')) return;
    try { await api('/library/notes/' + n.id, { method: 'DELETE' }); viewNotes(); toast('Конспект удалён'); }
    catch (err) { toast(err.message, 'error'); }
  });
  return el;
}

function noteEditor(n) {
  const modal = document.createElement('div');
  modal.className = 'modal-backdrop';
  modal.innerHTML = `
    <div class="modal card">
      <button class="close-x">✕</button>
      <h2>${n ? 'Редактировать конспект' : 'Новый конспект'}</h2>
      <form id="note-form">
        <div class="form-row"><label>Заголовок</label><input name="title" required maxlength="120" value="${esc(n ? n.title : '')}"></div>
        <div class="form-row"><label>Текст</label><textarea name="body" rows="6" placeholder="Содержимое конспекта...">${esc(n ? n.body : '')}</textarea></div>
        <button type="submit" class="btn btn-primary btn-block">Сохранить</button>
      </form>
    </div>`;
  $('#modal-root').appendChild(modal);
  modal.addEventListener('click', (e) => { if (e.target === modal || e.target.classList.contains('close-x')) modal.remove(); });
  $('#note-form', modal).addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    try {
      if (n) await api('/library/notes/' + n.id, { method: 'PUT', body: { title: fd.get('title'), body: fd.get('body') } });
      else await api('/library/notes', { method: 'POST', body: { title: fd.get('title'), body: fd.get('body') } });
      modal.remove(); viewNotes(); toast('Конспект сохранён');
    } catch (err) { toast(err.message, 'error'); }
  });
}
/* ---------- ИЗБРАННОЕ ---------- */
function viewFavorites() {
  const view = $('#view');
  const favs = LS.load(LS.favKey());
  view.innerHTML = `
    <div class="page-title">⭐ Избранное</div>
    <div id="fav-list"></div>`;
  const list = $('#fav-list');
  if (!favs.length) { list.innerHTML = `<div class="empty">Пусто. Нажмите «⭐» на посте или видео, чтобы добавить.</div>`; return; }
  favs.sort((a, b) => b.saved_at - a.saved_at).forEach((f) => list.appendChild(favCard(f)));
}

function favCard(f) {
  const el = document.createElement('div');
  el.className = 'fav-post card';
  if (f.type === 'post') {
    el.innerHTML = `
      <div class="fav-post-text">${esc(f.text || '(без текста)')}</div>
      <div class="fav-post-meta muted">${f.author || ''} · ${timeAgo(f.saved_at)}</div>
      <div class="note-actions"><button class="btn btn-ghost btn-sm" data-act="go">Открыть</button><button class="btn btn-ghost btn-sm" data-act="del">Удалить</button></div>`;
    el.querySelector('[data-act="go"]').addEventListener('click', () => go('/profile/' + (f.author_uid || 'me')));
  } else {
    el.innerHTML = `
      <div style="display:flex;gap:12px;align-items:center">
        <img src="${mediaUrl(f.thumb)}" style="width:80px;border-radius:8px;object-fit:cover" alt="">
        <div style="flex:1">
          <div class="fav-post-text">${esc(f.title)}</div>
          <div class="fav-post-meta muted">${f.author || ''} · ${timeAgo(f.saved_at)}</div>
        </div>
      </div>
      <div class="note-actions"><button class="btn btn-ghost btn-sm" data-act="go">Смотреть</button><button class="btn btn-ghost btn-sm" data-act="del">Удалить</button></div>`;
    el.querySelector('[data-act="go"]').addEventListener('click', () => go('/watch/' + f.uid));
  }
  el.querySelector('[data-act="del"]').addEventListener('click', () => {
    LS.save(LS.favKey(), LS.load(LS.favKey()).filter((x) => x.id !== f.id));
    viewFavorites(); toast('Удалено из избранного');
  });
  return el;
}
/* ---------- ДРУЗЬЯ ---------- */
async function viewFriends() {
  const view = $('#view');
  view.innerHTML = `
    <div class="page-title" style="margin-bottom:18px">👥 Друзья</div>
    <div class="tabs" id="friend-tabs">
      <button class="tab active" data-tab="friends">Друзья</button>
      <button class="tab" data-tab="incoming">Входящие заявки</button>
      <button class="tab" data-tab="outgoing">Исходящие заявки</button>
    </div>
    <div id="friend-list"></div>`;

  const list = $('#friend-list', view);
  let tab = 'friends';

  function userRow(u, actions) {
    const el = document.createElement('div');
    el.className = 'user-row card';
    el.style.marginBottom = '6px';
    el.innerHTML = `
      <a href="#/profile/${esc(u.uid)}" style="display:flex;align-items:center;gap:12px;flex:1;color:var(--text)">
        <img class="avatar" src="${mediaUrl(u.avatar)}" alt="">
        <div>
          <div style="font-weight:700">${esc(displayName(u))}</div>
          <div class="muted" style="font-size:12px">@${esc(u.username)}</div>
        </div>
      </a>
      <div style="display:flex;gap:6px;flex-wrap:wrap">${actions}</div>`;
    return el;
  }

  function bind(el, u) {
    const msg = el.querySelector('[data-act="msg"]');
    if (msg) msg.addEventListener('click', async () => {
      const res = await api('/chats', { method: 'POST', body: { user_id: u.id } });
      go('/messages/' + res.uid);
    });
    const accept = el.querySelector('[data-act="accept"]');
    if (accept) accept.addEventListener('click', async () => {
      try { await api(`/users/${u.uid}/friend/accept`, { method: 'POST' }); toast('Вы друзья!'); load(); }
      catch (err) { toast(err.message, 'error'); }
    });
    const decline = el.querySelector('[data-act="decline"]');
    if (decline) decline.addEventListener('click', async () => {
      try { await api(`/users/${u.uid}/friend`, { method: 'DELETE' }); load(); }
      catch (err) { toast(err.message, 'error'); }
    });
    const unfriend = el.querySelector('[data-act="unfriend"]');
    if (unfriend) unfriend.addEventListener('click', async () => {
      if (!confirm('Убрать из друзей?')) return;
      try { await api(`/users/${u.uid}/friend`, { method: 'DELETE' }); load(); }
      catch (err) { toast(err.message, 'error'); }
    });
  }

  async function load() {
    try {
      const [fr, reqs] = await Promise.all([api('/users/list'), api('/users/requests')]);
      renderTab(fr.friends, reqs);
    } catch (err) { list.innerHTML = `<div class="empty">${esc(err.message)}</div>`; }
  }

  function renderTab(friends, reqs) {
    if (tab === 'friends') {
      if (!friends.length) { list.innerHTML = `<div class="empty">Пока нет друзей. Добавьте людей на их страницах!</div>`; return; }
      list.innerHTML = '';
      friends.forEach((u) => {
        const el = userRow(u, `<button class="btn btn-ghost btn-sm" data-act="msg">💬</button>
          <button class="btn btn-ghost btn-sm" data-act="unfriend" style="color:var(--danger)">Убрать</button>`);
        bind(el, u);
        list.appendChild(el);
      });
    } else if (tab === 'incoming') {
      if (!reqs.incoming.length) { list.innerHTML = `<div class="empty">Нет входящих заявок</div>`; return; }
      list.innerHTML = '';
      reqs.incoming.forEach((u) => {
        const el = userRow(u, `<button class="btn btn-primary btn-sm" data-act="accept">Принять</button>
          <button class="btn btn-ghost btn-sm" data-act="decline">Отклонить</button>`);
        bind(el, u);
        list.appendChild(el);
      });
    } else {
      if (!reqs.outgoing.length) { list.innerHTML = `<div class="empty">Нет исходящих заявок</div>`; return; }
      list.innerHTML = '';
      reqs.outgoing.forEach((u) => {
        const el = userRow(u, `<button class="btn btn-ghost btn-sm" data-act="decline">Отменить</button>`);
        bind(el, u);
        list.appendChild(el);
      });
    }
  }

  $('#friend-tabs', view).addEventListener('click', (e) => {
    const btn = e.target.closest('[data-tab]');
    if (!btn) return;
    tab = btn.dataset.tab;
    view.querySelectorAll('[data-tab]').forEach((b) => b.classList.toggle('active', b === btn));
    load();
  });

  load();
}

/* ---------- УВЕДОМЛЕНИЯ ---------- */
async function viewNotifications() {
  const view = $('#view');
  view.innerHTML = `
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:18px">
      <div class="page-title" style="margin:0">🔔 Уведомления</div>
      <button class="btn btn-ghost btn-sm" id="notif-read-all">Прочитать все</button>
    </div>
    <div id="notif-list"></div>`;

  const list = $('#notif-list', view);

  const TYPE_TEXT = {
    like: 'лайкнул(а) вашу запись',
    comment: 'оставил(а) комментарий',
    follow: 'подписался(ась) на вас',
    friend_request: 'хочет добавить вас в друзья',
    friend_accepted: 'принял(а) вашу заявку в друзья',
    message: 'отправил(а) сообщение'
  };
  const TYPE_ICO = { like: '❤️', comment: '💬', follow: '➕', friend_request: '🤝', friend_accepted: '🤝', message: '💬' };

  function row(n) {
    const el = document.createElement('a');
    const href = n.url && n.url !== 'feed' ? '#/' + n.url : '#/feed';
    el.className = 'user-row card' + (n.read ? '' : ' unread');
    el.style.marginBottom = '6px';
    el.style.textDecoration = 'none';
    el.href = href;
    el.innerHTML = `
      <img class="avatar" src="${mediaUrl(n.actor_avatar)}" alt="">
      <div style="flex:1;min-width:0">
        <div>
          <span style="font-weight:700">${esc(n.actor_name)}</span>
          <span class="muted">${esc(TYPE_TEXT[n.type] || n.body || n.type)}</span>
        </div>
        ${n.body ? `<div class="muted" style="font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(n.body)}</div>` : ''}
        <div class="muted" style="font-size:11px">${timeAgo(n.created_at)}${n.read ? '' : ' · новый'}</div>
      </div>
      <span style="font-size:18px">${TYPE_ICO[n.type] || '🔔'}</span>`;
    if (!n.read) el.addEventListener('click', () => {
      api('/notifications/read', { method: 'POST', body: { id: n.id } });
      const b = $('#notif-badge');
      if (b && !b.classList.contains('hidden')) {
        const v = Math.max(0, (Number(b.textContent) || 1) - 1);
        setNotifBadges(v);
      }
    });
    return el;
  }

  async function load() {
    try {
      const data = await api('/notifications');
      setNotifBadges(data.unread || 0);
      list.innerHTML = '';
      if (!data.notifications.length) {
        list.innerHTML = `<div class="empty">Пока нет уведомлений</div>`;
        return;
      }
      data.notifications.forEach((n) => list.appendChild(row(n)));
    } catch (err) { list.innerHTML = `<div class="empty">${esc(err.message)}</div>`; }
  }

  $('#notif-read-all', view).addEventListener('click', async () => {
    try { await api('/notifications/read-all', { method: 'POST' }); setNotifBadges(0); load(); }
    catch (err) { toast(err.message, 'error'); }
  });

  load();
}

/* ---------- ГРУППЫ ---------- */
async function viewGroups() {
  const view = $('#view');
  view.innerHTML = `
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:18px">
      <div class="page-title" style="margin:0">👥 Группы</div>
      <button class="btn btn-primary btn-sm" id="group-add">＋ Создать</button>
    </div>
    <div class="notes-grid" id="groups-grid"></div>`;
  $('#group-add').addEventListener('click', () => groupEditor(null));
  const grid = $('#groups-grid');
  let groups = [];
  try { groups = (await api('/library/groups')).groups; } catch (e) { toast(e.message, 'error'); }
  if (!groups.length) { grid.innerHTML = `<div class="empty">Пока нет групп. Создайте первую!</div>`; return; }
  groups.sort((a, b) => new Date(b.updated_at) - new Date(a.updated_at)).forEach((g) => grid.appendChild(groupCard(g)));
}

function groupCard(g) {
  const el = document.createElement('div');
  el.className = 'note-card card group-card';
  el.innerHTML = `
    <h3>${esc(g.name)}</h3>
    <p>${esc(g.description)}</p>
    <div class="note-date muted">👥 ${g.member_count || 1} участн. · ${timeAgo(g.updated_at)}</div>
    <div class="note-actions">
      <button class="btn btn-ghost btn-sm" data-act="go">Перейти в чат</button>
      <button class="btn btn-ghost btn-sm" data-act="edit">✏</button>
      <button class="btn btn-ghost btn-sm" data-act="del">🗑</button>
    </div>`;
  el.querySelector('[data-act="go"]').addEventListener('click', () => {
    if (g.chatUid) go('/messages/' + g.chatUid);
  });
  el.querySelector('[data-act="edit"]').addEventListener('click', () => groupEditor(g));
  el.querySelector('[data-act="del"]').addEventListener('click', async () => {
    if (!confirm('Удалить группу?')) return;
    try { await api('/library/groups/' + g.id, { method: 'DELETE' }); viewGroups(); toast('Группа удалена'); }
    catch (err) { toast(err.message, 'error'); }
  });
  return el;
}

function groupEditor(g) {
  const modal = document.createElement('div');
  modal.className = 'modal-backdrop';
  modal.innerHTML = `
    <div class="modal card">
      <button class="close-x">✕</button>
      <h2>${g ? 'Редактировать группу' : 'Новая группа'}</h2>
      <form id="group-form">
        <div class="form-row"><label>Название</label><input name="name" required maxlength="80" value="${esc(g ? g.name : '')}"></div>
        <div class="form-row"><label>Описание</label><textarea name="description" rows="4" placeholder="О чём эта группа...">${esc(g ? g.description : '')}</textarea></div>
        <button type="submit" class="btn btn-primary btn-block">Сохранить</button>
      </form>
    </div>`;
  $('#modal-root').appendChild(modal);
  modal.addEventListener('click', (e) => { if (e.target === modal || e.target.classList.contains('close-x')) modal.remove(); });
  $('#group-form', modal).addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    try {
      if (g) await api('/library/groups/' + g.id, { method: 'PUT', body: { name: fd.get('name'), description: fd.get('description') } });
      else {
        const res = await api('/library/groups', { method: 'POST', body: { name: fd.get('name'), description: fd.get('description') } });
        modal.remove();
        toast('Группа создана');
        if (res.group.chatUid) go('/messages/' + res.group.chatUid);
        return;
      }
      modal.remove(); viewGroups(); toast('Группа сохранена');
    } catch (err) { toast(err.message, 'error'); }
  });
}
function wireGlobal() {
  $$('.tab').forEach((tab) => {
    tab.addEventListener('click', () => {
      $$('.tab').forEach((t) => t.classList.remove('active'));
      tab.classList.add('active');
      const mode = tab.dataset.tab;
      $$('[data-role="register"]').forEach((el) => el.classList.toggle('hidden', mode !== 'register'));
      $('#auth-form button[type="submit"]').textContent = mode === 'register' ? 'Зарегистрироваться' : 'Войти';
      resetAuthState();
      if (mode === 'register') loadCaptcha();
    });
  });

  $('#auth-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    const mode = $('.tab.active').dataset.tab;
    if (authState.totpToken) {
      try { const res = await api('/auth/login/2fa', { method: 'POST', body: { totp_token: authState.totpToken, code: fd.get('totp_code') } }); me = res.user; afterLogin(); }
      catch (err) { toast(err.message, 'error'); }
      return;
    }
    const body = { username: fd.get('username'), password: fd.get('password') };
    if (mode === 'register') { body.name = fd.get('name'); body.captcha_token = authState.captchaToken; body.captcha_answer = fd.get('captcha_answer'); }
    else if (authState.needCaptcha) { body.captcha_token = authState.captchaToken; body.captcha_answer = fd.get('captcha_answer'); }
    try {
      const res = await api('/auth/' + (mode === 'register' ? 'register' : 'login'), { method: 'POST', body });
      if (res.step === 'totp') { authState.totpToken = res.totpToken; $('#totp-field').classList.remove('hidden'); $('#captcha-field').classList.add('hidden'); $('input[name="totp_code"]').focus(); toast('Введите код из приложения (2FA)'); return; }
      me = res.user; afterLogin();
    } catch (err) { if (err.data && err.data.needCaptcha) { authState.needCaptcha = true; await loadCaptcha(); } toast(err.message, 'error'); }
  });
  $('#search-form').addEventListener('submit', (e) => {
    e.preventDefault();
    const q = $('#search-input').value.trim();
    if (q) { currentSearch = q; go('/search?q=' + encodeURIComponent(q)); }
  });

  $('#user-menu-btn').addEventListener('click', (e) => { e.stopPropagation(); $('#user-menu').classList.toggle('hidden'); });
  document.addEventListener('click', () => $('#user-menu').classList.add('hidden'));
  $('#user-menu').addEventListener('click', (e) => { if (e.target.closest('[data-action="logout"]')) { e.preventDefault(); logout(); } });
  $('#new-post-btn').addEventListener('click', openNewPostModal);

  const fabMain = $('#fab-main');
  const fabMenu = $('#fab-menu');
  fabMain.addEventListener('click', (e) => { e.stopPropagation(); fabMenu.classList.toggle('hidden'); });
  document.addEventListener('click', (e) => {
    if (e.target.closest('#fab-menu') || e.target.closest('#fab-main')) return;
    fabMenu.classList.add('hidden');
  });
  fabMenu.addEventListener('click', (e) => {
    const item = e.target.closest('[data-fab]');
    if (!item) return;
    fabMenu.classList.add('hidden');
    if (item.dataset.fab === 'post') e.preventDefault(), openNewPostModal();
  });

  $('#menu-toggle').addEventListener('click', () => $('#sidebar').classList.toggle('open'));
  $('#sidebar-backdrop').addEventListener('click', () => $('#sidebar').classList.remove('open'));
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') $('#sidebar').classList.remove('open');
  });
  $('#sidebar').addEventListener('click', (e) => {
    if (e.target.classList.contains('slink') && window.innerWidth <= 860) $('#sidebar').classList.remove('open');
  });

  /* ---------- восстановление пароля ---------- */
  const resetModal = $('#reset-modal');
  const resetUser = { username: '' };
  function showResetMsg(text, isError) {
    const el = $('#reset-msg');
    el.textContent = text;
    el.style.color = isError ? 'var(--danger)' : 'var(--ok)';
    el.classList.remove('hidden');
  }
  function openResetModal() {
    resetUser.username = '';
    $('#reset-step-1').classList.remove('hidden');
    $('#reset-step-2').classList.add('hidden');
    $('#reset-done').classList.add('hidden');
    $('#reset-msg').classList.add('hidden');
    $('#reset-username').value = '';
    resetModal.classList.remove('hidden');
    setTimeout(() => $('#reset-username').focus(), 50);
  }
  function closeResetModal() { resetModal.classList.add('hidden'); }
  $('#forgot-link').addEventListener('click', (e) => { e.preventDefault(); openResetModal(); });
  $('#reset-close').addEventListener('click', closeResetModal);
  resetModal.addEventListener('click', (e) => { if (e.target === resetModal) closeResetModal(); });
  $('#reset-check').addEventListener('click', async () => {
    const username = $('#reset-username').value.trim();
    if (!username) return toast('Введите логин', 'error');
    try {
      const res = await api('/auth/reset-status', { method: 'POST', body: { username } });
      resetUser.username = username;
      if (res.twofa) {
        $('#reset-hint').textContent = 'Введите код из приложения (2FA) или один из резервных кодов.';
        $('#reset-step-1').classList.add('hidden');
        $('#reset-step-2').classList.remove('hidden');
      } else {
        showResetMsg('2FA не включена. Обратись к администратору для сброса пароля.', true);
      }
    } catch (err) {
      showResetMsg(err.message || 'Ошибка', true);
    }
  });
  $('#reset-do').addEventListener('click', async () => {
    const code = $('#reset-code').value.trim();
    const np = $('#reset-new').value;
    const np2 = $('#reset-new2').value;
    if (!code) return toast('Введите код 2FA', 'error');
    if (np.length < 6) return toast('Пароль: минимум 6 символов', 'error');
    if (np !== np2) return toast('Пароли не совпадают', 'error');
    try {
      await api('/auth/reset', { method: 'POST', body: { username: resetUser.username, code, new_password: np } });
      $('#reset-step-2').classList.add('hidden');
      $('#reset-done').classList.remove('hidden');
      setTimeout(() => { closeResetModal(); }, 2200);
    } catch (err) {
      showResetMsg(err.message || 'Ошибка', true);
    }
  });

  window.addEventListener('hashchange', render);
}

async function logout() {
  unregisterPushToken();
  try { await api('/auth/logout', { method: 'POST', silent: true }); } catch (e) {}
  if (socket) { socket.disconnect(); socket = null; }
  me = null; activeChatUid = null; activeChat = null; chatsCache = [];
  $('#view').innerHTML = '';
  showAuth();
}

document.addEventListener('DOMContentLoaded', () => { wireGlobal(); boot(); });
