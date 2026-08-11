
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

function fmtViews(n) {
  n = Number(n) || 0;
  if (n >= 1e6) return (n / 1e6).toFixed(1).replace('.0', '') + 'M';
  if (n >= 1e3) return (n / 1e3).toFixed(1).replace('.0', '') + 'K';
  return String(n);
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
let chatsCache = [];
let currentSearch = '';

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
  'notes', 'favorites', 'groups'
]);

async function render() {
  if (!me) return;
  const { segs, query } = parseHash();
  const route = segs[0] || 'feed';
  setActiveNav(route);

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
      default: await viewFeed();
    }
    window.scrollTo(0, 0);
  } catch (e) {
    if (e.status === 401) return showAuth();
    $('#view').innerHTML = `<div class="empty">Ошибка: ${esc(e.message)}</div>`;
  }
}

function setActiveNav(route) {
  const map = {
    feed: 'feed', videos: 'videos', clips: 'clips', watch: 'videos',
    messages: 'messages', notes: 'notes', favorites: 'favorites', groups: 'groups',
    search: 'search'
  };
  const key = map[route] || (route === 'profile' ? 'profile' : 'feed');
  $$('.slink, .mobilenav a').forEach((a) => a.classList.toggle('active', a.dataset.nav === key));
}

/* ---------- авторизация ---------- */
function showAuth() {
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
  try {
    const data = await api('/auth/me', { silent: true });
    me = data.user;
    afterLogin();
  } catch (e) {
    showAuth();
  }
}

async function afterLogin() {
  showApp();
  updateNavUser();
  E2EE.pushPubKey(me.uid);
  connectSocket();
  render();
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

  socket.on('chat:message', async (payload) => {
    const mine = payload.message.sender_id === me.id;
    if (!mine && activeChatUid === payload.chatUid) {
      const m = await decryptMessage(payload.message, payload.chatUid);
      appendMessage(m);
      markChatRead(payload.chatUid);
    } else if (!mine) {
      bumpBadge();
    }
    if (!mine) refreshChatList();
  });

  socket.on('chat:read', () => { loadChatBadges(); });
}

function bumpBadge() {
  const badge = $('#msg-badge');
  badge.textContent = (Number(badge.textContent) || 0) + 1;
  badge.classList.remove('hidden');
}

async function loadChatBadges() {
  try {
    const data = await api('/chats', { silent: true });
    chatsCache = data.chats;
    const total = chatsCache.reduce((s, c) => s + (c.unread || 0), 0);
    const badge = $('#msg-badge');
    if (total > 0) { badge.textContent = total > 99 ? '99+' : total; badge.classList.remove('hidden'); }
    else badge.classList.add('hidden');
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
  authorEl.textContent = post.name;
  $('.post-time', node).textContent = timeAgo(post.created_at);
  $('.post-text', node).textContent = post.text;

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

  if (post.user_id === me.id || me.role === 'admin') $('.post-del', node).classList.remove('hidden');

  return node;
}

async function viewFeed() {
  const data = await api('/posts');
  const view = $('#view');
  view.innerHTML = `<div class="feed" id="post-feed"></div>`;
  const feed = $('#post-feed');
  if (!data.posts.length) feed.innerHTML = `<div class="empty">Пока нет постов. Напишите первый!</div>`;
  data.posts.forEach((p) => feed.appendChild(buildPost(p)));
  wirePostEvents(feed);
}

function wirePostEvents(feed) {
  feed.addEventListener('click', async (e) => {
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
  a.textContent = c.name;
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
  $('.video-title', node).textContent = v.title;
  $('.video-author', node).textContent = `${v.name} · ${fmtViews(v.views)} просмотров`;
  if (v.is_clip) $('.clip-badge', node).classList.remove('hidden');
  card.addEventListener('click', () => openVideoOverlay(v.id));
  return node;
}

async function viewVideos(isClips) {
  const data = await api('/videos?clip=' + (isClips ? '1' : '0'));
  if (isClips) return viewClipsReel(data.videos);
  const view = $('#view');
  view.innerHTML = `
    <div class="page-title">🎬 Видео</div>
    <div class="video-grid" id="video-grid"></div>`;
  const g = $('#video-grid');
  if (!data.videos.length) g.innerHTML = `<div class="empty">Нет видео. Загрузите первым!</div>`;
  data.videos.forEach((v) => g.appendChild(buildVideoCard(v)));
}

async function viewClipsReel(videos) {
  const view = $('#view');
  view.innerHTML = '';
  if (!videos.length) {
    view.innerHTML = `<div class="clips-empty"><div class="empty">Нет клипов. Добавьте видео как клип!</div></div>`;
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
  $('.clip-author-name', node).textContent = v.name || '';
  $('.clip-author-block', node).href = '#/profile/' + v.uid;
  $('.clip-like-count', node).textContent = v.likes || '0';
  $('.clip-comment-count', node).textContent = v.comments != null ? v.comments : '0';
  $('.clip-title', node).textContent = v.title || '';
  const soundEl = $('.clip-sound-text', node);
  soundEl.textContent = '♫ ' + (v.title || 'Оригинальный звук') + '     ♫ ' + (v.title || 'Оригинальный звук') + '     ';

  $('[data-action="like"]', node).addEventListener('click', (e) => {
    const btn = e.currentTarget;
    const clipEl = btn.closest('.clip');
    const vid = $('video', clipEl);
    toggleLikeGlobal(clipEl, vid);
  });

  $('[data-action="share"]', node).addEventListener('click', () => shareLink('#/watch/' + v.uid, v.title));

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
  $('.video-title', node).textContent = v.title;
  $('.video-author', node).textContent = `${v.name} · ${fmtViews(v.views)} просмотров`;
  if (v.is_clip) $('.clip-badge', node).classList.remove('hidden');
  card.addEventListener('click', () => openVideoOverlay(v.id));
  return node;
}

async function viewVideos(isClips) {
  const data = await api('/videos?clip=' + (isClips ? '1' : '0'));
  if (isClips) return viewClipsReel(data.videos);
  const view = $('#view');
  view.innerHTML = `
    <div class="page-title">🎬 Видео</div>
    <div class="video-grid" id="video-grid"></div>`;
  const g = $('#video-grid');
  if (!data.videos.length) g.innerHTML = `<div class="empty">Нет видео. Загрузите первым!</div>`;
  data.videos.forEach((v) => g.appendChild(buildVideoCard(v)));
}

async function viewClipsReel(videos) {
  const view = $('#view');
  view.innerHTML = `
    <div class="page-title">🎬 Клипы</div>
    <div class="clips-feed" id="clips-feed"></div>
    <div class="clips-nav">
      <button data-dir="up" title="Назад">^</button>
      <button data-dir="down" title="Вперёд">▼</button>
    </div>`;
  const feed = $('#clips-feed');
  if (!videos.length) {
    feed.innerHTML = `<div class="empty">Нет клипов. Добавьте видео как клип!</div>`;
    $('.clips-nav', view).style.display = 'none';
    return;
  }

  videos.forEach((v) => feed.appendChild(buildClipCard(v)));

  const clips = $$('.clip', feed);
  const observers = [];

  const playObserver = new IntersectionObserver((entries) => {
    entries.forEach((entry) => {
      const vid = $('video', entry.target);
      if (!vid) return;
      if (entry.isIntersecting && entry.intersectionRatio >= 0.6) {
        vid.play().catch(() => {});
        entry.target.dataset.playing = '1';
      } else {
        vid.pause();
        delete entry.target.dataset.playing;
      }
    });
  }, { threshold: [0, 0.6, 1] });

  clips.forEach((c) => playObserver.observe(c));

  const navObserver = new IntersectionObserver((entries) => {
    entries.forEach((entry) => {
      const idx = Number(entry.target.dataset.idx);
      if (entry.isIntersecting && entry.intersectionRatio >= 0.6) {
        clips.forEach((c, i) => c.classList.toggle('active', i === idx));
      }
    });
  }, { threshold: 0.6 });
  clips.forEach((c, i) => { c.dataset.idx = String(i); navObserver.observe(c); });

  function scrollToClip(dir) {
    const active = $('.clip.active', feed) || clips[0];
    const idx = clips.indexOf(active);
    const next = dir === 'down' ? Math.min(idx + 1, clips.length - 1) : Math.max(idx - 1, 0);
    if (next >= 0 && next < clips.length) clips[next].scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
  $$('.clips-nav button', view).forEach((b) => b.addEventListener('click', () => scrollToClip(b.dataset.dir)));
  view._clipCleanup = () => { playObserver.disconnect(); navObserver.disconnect(); };
}

function buildClipCard(v) {
  const node = $('#tpl-clip').content.cloneNode(true);
  const clip = $('[data-role="clip"]', node);
  clip.dataset.id = v.id;
  clip.dataset.uid = v.uid;
  const video = $('video', node);
  video.src = mediaUrl(v.file);
  video.poster = mediaUrl(v.thumb);
  $('.clip-like-count', node).textContent = v.likes || '0';
  $('.clip-comment-count', node).textContent = v.comments != null ? v.comments : '0';
  $('.clip-author', node).textContent = v.name || '';
  $('.clip-title', node).textContent = v.title || '';

  $('[data-action="like"]', node).addEventListener('click', async (e) => {
    const btn = e.currentTarget;
    try {
      const res = btn.classList.contains('liked')
        ? await api(`/videos/${v.uid}/like`, { method: 'DELETE' })
        : await api(`/videos/${v.uid}/like`, { method: 'POST' });
      btn.classList.toggle('liked', res.liked);
      btn.querySelector('.clip-act-ico').textContent = res.liked ? '❤️' : '🤍';
      btn.querySelector('.clip-like-count').textContent = res.likes || '0';
    } catch (err) { toast(err.message, 'error'); }
  });

  $('[data-action="toggle-comments"]', node).addEventListener('click', () => openVideoOverlay(v.uid));
  $('[data-action="share"]', node).addEventListener('click', () => shareLink('#/watch/' + v.uid, v.title));

  return node;
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
      <h1 class="watch-title">${esc(v.title)}</h1>
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
          <button class="pact" data-action="share"><span class="pact-ico">🔗</span><span>Поделиться</span></button>
        </div>
      </div>
      ${v.description ? `<div class="watch-desc card">${esc(v.description)}</div>` : ''}
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
  const badge = $('#msg-badge');
  if (total > 0) { badge.textContent = total > 99 ? '99+' : total; badge.classList.remove('hidden'); }
  else badge.classList.add('hidden');

  const view = $('#view');
  view.innerHTML = `
    <div class="messenger">
      <aside class="chat-sidebar card" id="chat-sidebar">
        <button class="btn btn-primary btn-block" data-action="new-chat" style="margin-bottom:12px">＋ Новый чат</button>
        <div id="chat-list"></div>
      </aside>
      <section class="chat-window card" id="chat-window">
        <div class="chat-placeholder">Выберите чат или создайте новый</div>
      </section>
    </div>`;

  renderChatList();
  $('#chat-list').addEventListener('click', (e) => {
    const item = e.target.closest('[data-chat-uid]');
    if (item) go('/messages/' + item.dataset.chatUid);
  });
  $('[data-action="new-chat"]').addEventListener('click', openNewChatModal);
  if (openChatUid) await openChat(openChatUid);
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
    const el = document.createElement('div');
    el.className = 'chat-item' + (c.uid === activeChatUid ? ' active' : '');
    el.dataset.chatUid = c.uid;
    el.innerHTML = `
      <img class="avatar sm" src="${mediaUrl(c.other.avatar)}" alt="">
      <div class="chat-item-info">
        <div class="chat-item-name">
          <span>${esc(c.other.name)}</span>
          <span class="muted" style="font-weight:400;font-size:11px">${c.last_at ? timeAgo(c.last_at) : ''}</span>
        </div>
        <div class="chat-item-last">${esc(c.last_text || 'Нет сообщений')}</div>
      </div>
      ${c.unread ? `<span class="badge">${c.unread}</span>` : ''}`;
    list.appendChild(el);
  });
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
  renderChatList();
  const data = await api(`/chats/${chatUid}/messages`);
  const chat = chatsCache.find((c) => c.uid === chatUid);
  const win = $('#chat-window');
  win.innerHTML = `
    <div class="chat-head">
      ${chat ? `<a href="#/profile/${esc(chat.other.uid)}"><img class="avatar sm" src="${mediaUrl(chat.other.avatar)}" alt=""></a>
      <b>${esc(chat.other.name)}</b>
      <span class="e2ee-tag" title="Сообщения шифруются на вашем устройстве (E2EE)">🔒 E2EE</span>` : ''}
    </div>
    <div class="chat-messages" id="chat-messages"></div>
    <form class="chat-input" id="chat-input">
      <input type="text" placeholder="Сообщение..." autocomplete="off" maxlength="4000">
      <button type="submit" class="btn btn-primary">➤</button>
    </form>`;

  const msgs = [];
  for (const m of data.messages) msgs.push(await decryptMessage(m, chatUid));
  msgs.forEach((m) => appendMessage(m));
  scrollChat();

  $('#chat-input').addEventListener('submit', async (e) => {
    e.preventDefault();
    const input = $('input', e.target);
    const text = input.value.trim();
    if (!text) return;
    input.value = '';
    try {
      const other = chat && chat.other ? chat.other : null;
      let body = { text, e2ee: false };
      const pub = other ? await otherPubKey(other.uid) : null;
      if (pub) {
        try {
          const enc = await E2EE.encrypt(text, pub);
          body = { text: JSON.stringify(enc), e2ee: true };
        } catch (err) {
          toast('Шифрование недоступно, отправлено открытым текстом', 'error');
        }
      }
      const res = await api(`/chats/${chatUid}/messages`, { method: 'POST', body });
      const m = await decryptMessage(res.message, chatUid);
      appendMessage(m);
      scrollChat();
      refreshChatList();
    } catch (err) { toast(err.message, 'error'); }
  });

  markChatRead(chatUid);
}

function appendMessage(m) {
  const container = $('#chat-messages');
  if (!container) return;
  const node = $('#tpl-message').content.cloneNode(true);
  const div = $('.msg', node);
  div.classList.toggle('mine', m.sender_id === me.id);
  $('.msg-bubble', node).textContent = m.text;
  if (m.e2eeText) $('.msg-bubble', node).classList.add('e2ee');
  $('.msg-time', node).textContent = timeAgo(m.created_at);
  container.appendChild(node);
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
          <div style="font-weight:700">${esc(u.name)}</div>
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
/* =========================================================
   ПРОФИЛЬ
   ========================================================= */
async function viewProfile(id) {
  const data = await api(`/users/${id}`);
  const u = data.user;
  const isMe = u.id === me.id;
  const view = $('#view');
  view.innerHTML = `
    <div class="profile">
      <div class="profile-head card">
        <img class="avatar xl" src="${mediaUrl(u.avatar)}" alt="">
        <div class="profile-info">
          <div class="profile-name">${esc(u.name)}
            <span class="role-badge ${u.role}">${u.role === 'admin' ? 'АДМИН' : 'УЧАСТНИК'}</span>
          </div>
          <div class="profile-status">${esc(u.status || '')}</div>
          <p class="profile-bio">${esc(u.bio || '')}</p>
          <div class="profile-stats">
            <div class="stat"><b>${data.stats.posts}</b><span>Постов</span></div>
            <div class="stat"><b>${data.stats.videos}</b><span>Видео</span></div>
            <div class="stat"><b id="f-count">${data.stats.followers}</b><span>Подписчиков</span></div>
            <div class="stat"><b>${data.stats.following}</b><span>Подписок</span></div>
          </div>
          <div style="margin-top:16px;display:flex;gap:10px;flex-wrap:wrap">
            ${isMe
              ? `<button class="btn btn-ghost" data-action="edit-profile">✏ Редактировать</button>`
              : `<button class="btn ${data.isFollowing ? 'btn-ghost' : 'btn-primary'}" data-action="follow" data-state="${data.isFollowing ? '1' : '0'}">
                   ${data.isFollowing ? '✓ Вы подписаны' : '＋ Подписаться'}</button>`
            }
            <button class="btn btn-ghost" data-action="message" ${isMe ? 'disabled' : ''}>💬 Написать</button>
          </div>
        </div>
      </div>
      <div class="profile-tabs">
        <div class="page-title" style="font-size:17px">📝 Последние посты</div>
        <div id="profile-posts"></div>
        <div class="page-title" style="font-size:17px;margin-top:10px">▶ Последние видео</div>
        <div class="video-grid" id="profile-videos"></div>
      </div>
    </div>`;

  const actions = view.querySelector('.profile-head');
  actions.addEventListener('click', async (e) => {
    const btn = e.target.closest('[data-action]');
    if (!btn) return;
    const act = btn.dataset.action;
    if (act === 'edit-profile') go('/edit-profile');
    if (act === 'message') {
      const res = await api('/chats', { method: 'POST', body: { user_id: u.id } });
      go('/messages/' + res.uid);
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
  view.innerHTML = `
    <div class="page-title">🔍 Поиск: ${esc(currentSearch)}</div>
    <div class="search-tabs" style="display:flex;gap:8px;margin-bottom:18px">
      <button class="btn btn-sm ${type === 'all' ? '' : 'btn-ghost'}" data-t="all">Все</button>
      <button class="btn btn-sm ${type === 'users' ? '' : 'btn-ghost'}" data-t="users">Люди</button>
      <button class="btn btn-sm ${type === 'posts' ? '' : 'btn-ghost'}" data-t="posts">Посты</button>
      <button class="btn btn-sm ${type === 'videos' ? '' : 'btn-ghost'}" data-t="videos">Видео</button>
    </div>
    <div class="search-results" id="search-results"></div>`;

  $$('.search-tabs button', view).forEach((b) => {
    b.addEventListener('click', () => go('/search?type=' + b.dataset.t + '&q=' + encodeURIComponent(currentSearch)));
  });

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
        <div style="flex:1"><a href="#/profile/${u.uid}" style="font-weight:700;color:var(--text)">${esc(u.name)}</a>
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
function viewNotes() {
  const view = $('#view');
  const notes = LS.load(LS.notesKey());
  view.innerHTML = `
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:18px">
      <div class="page-title" style="margin:0">📝 Конспекты</div>
      <button class="btn btn-primary btn-sm" id="note-add">＋ Новый</button>
    </div>
    <div class="notes-grid" id="notes-grid"></div>`;
  $('#note-add').addEventListener('click', () => noteEditor(null));
  const grid = $('#notes-grid');
  if (!notes.length) { grid.innerHTML = `<div class="empty">Пока пусто. Создайте первый конспект!</div>`; return; }
  notes.sort((a, b) => b.updated_at - a.updated_at).forEach((n) => grid.appendChild(noteCard(n)));
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
  el.querySelector('[data-act="del"]').addEventListener('click', () => {
    if (!confirm('Удалить конспект?')) return;
    LS.save(LS.notesKey(), LS.load(LS.notesKey()).filter((x) => x.id !== n.id));
    viewNotes(); toast('Конспект удалён');
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
  $('#note-form', modal).addEventListener('submit', (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    let notes = LS.load(LS.notesKey());
    if (n) {
      const idx = notes.findIndex((x) => x.id === n.id);
      if (idx >= 0) notes[idx] = { ...notes[idx], title: fd.get('title'), body: fd.get('body'), updated_at: Date.now() };
    } else {
      notes.unshift({ id: luid(), title: fd.get('title'), body: fd.get('body'), updated_at: Date.now() });
    }
    LS.save(LS.notesKey(), notes);
    modal.remove(); viewNotes(); toast('Конспект сохранён');
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
/* ---------- ГРУППЫ ---------- */
function viewGroups() {
  const view = $('#view');
  const groups = LS.load(LS.groupsKey());
  view.innerHTML = `
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:18px">
      <div class="page-title" style="margin:0">👥 Группы</div>
      <button class="btn btn-primary btn-sm" id="group-add">＋ Создать</button>
    </div>
    <div class="notes-grid" id="groups-grid"></div>`;
  $('#group-add').addEventListener('click', () => groupEditor(null));
  const grid = $('#groups-grid');
  if (!groups.length) { grid.innerHTML = `<div class="empty">Пока нет групп. Создайте первую!</div>`; return; }
  groups.sort((a, b) => b.updated_at - a.updated_at).forEach((g) => grid.appendChild(groupCard(g)));
}

function groupCard(g) {
  const el = document.createElement('div');
  el.className = 'note-card card';
  el.innerHTML = `
    <h3>${esc(g.name)}</h3>
    <p>${esc(g.description)}</p>
    <div class="note-date muted">${timeAgo(g.updated_at)}</div>
    <div class="note-actions">
      <button class="btn btn-ghost btn-sm" data-act="edit">✏</button>
      <button class="btn btn-ghost btn-sm" data-act="del">🗑</button>
    </div>`;
  el.querySelector('[data-act="edit"]').addEventListener('click', () => groupEditor(g));
  el.querySelector('[data-act="del"]').addEventListener('click', () => {
    if (!confirm('Удалить группу?')) return;
    LS.save(LS.groupsKey(), LS.load(LS.groupsKey()).filter((x) => x.id !== g.id));
    viewGroups(); toast('Группа удалена');
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
  $('#group-form', modal).addEventListener('submit', (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    let groups = LS.load(LS.groupsKey());
    if (g) {
      const idx = groups.findIndex((x) => x.id === g.id);
      if (idx >= 0) groups[idx] = { ...groups[idx], name: fd.get('name'), description: fd.get('description'), updated_at: Date.now() };
    } else {
      groups.unshift({ id: luid(), name: fd.get('name'), description: fd.get('description'), updated_at: Date.now() });
    }
    LS.save(LS.groupsKey(), groups);
    modal.remove(); viewGroups(); toast('Группа сохранена');
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

  $('#menu-toggle').addEventListener('click', () => $('#sidebar').classList.toggle('open'));
  $('#sidebar').addEventListener('click', (e) => {
    if (e.target.classList.contains('slink') && window.innerWidth <= 860) $('#sidebar').classList.remove('open');
  });

  window.addEventListener('hashchange', render);
}

async function logout() {
  try { await api('/auth/logout', { method: 'POST', silent: true }); } catch (e) {}
  if (socket) { socket.disconnect(); socket = null; }
  me = null; activeChatUid = null; chatsCache = [];
  $('#view').innerHTML = '';
  showAuth();
}

document.addEventListener('DOMContentLoaded', () => { wireGlobal(); boot(); });
