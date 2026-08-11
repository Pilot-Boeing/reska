const express = require('express');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { db } = require('../db');
const {
  auth,
  publicUser,
  createSession,
  destroySession,
  parseCookies
} = require('../helpers');
const {
  getClientIp,
  signToken,
  verifyToken,
  generateTotpSecret,
  totpUri,
  verifyTotp,
  captchaGenerate,
  captchaVerify,
  randomUid
} = require('../security');
const { encryptString, decryptString } = require('../encryption');
const { bruteKey, bruteCheck, bruteFail, bruteSuccess, bruteNeedsCaptcha } = require('../rateLimit');
const { log, alert } = require('../logger');
const { validUsername, validPassword, validName } = require('../validate');

const router = express.Router();

const BCRYPT_COST = 12;

/* ---------- утилиты 2FA ---------- */
function makeBackupCodes() {
  const codes = [];
  for (let i = 0; i < 5; i++) {
    const a = crypto.randomBytes(3).toString('hex').toUpperCase();
    const b = crypto.randomBytes(3).toString('hex').toUpperCase();
    codes.push(`${a.slice(0, 5)}-${b.slice(0, 5)}`);
  }
  return codes;
}

function totpSecretOf(row) {
  if (!row) return null;
  try {
    const data = JSON.parse(decryptString(row.secret));
    return data.s || null;
  } catch (e) {
    return null;
  }
}

function verifyBackupCode(row, code) {
  if (!row) return false;
  try {
    const data = JSON.parse(decryptString(row.secret));
    const given = String(code || '').replace(/\s+/g, '').toUpperCase();
    if (!data.codes || !data.codes.length) return false;
    const hit = data.codes.findIndex((c) => c === given);
    if (hit === -1) return false;
    data.codes.splice(hit, 1);
    db.prepare('UPDATE totp SET secret = ? WHERE user_id = ?').run(encryptString(JSON.stringify(data)), row.user_id);
    return true;
  } catch (e) {
    return false;
  }
}

function totpEnabled(userId) {
  return !!db.prepare('SELECT 1 FROM totp WHERE user_id = ? AND enabled = 1').get(userId);
}

/* ---------- публичные ---------- */
router.get('/captcha', (req, res) => {
  res.json(captchaGenerate());
});

router.get('/health', (req, res) => res.json({ ok: true }));

/* ---------- регистрация (первый пользователь — администратор) ---------- */
router.post('/register', (req, res) => {
  const ip = getClientIp(req);
  const key = bruteKey(ip, 'register');
  const { captcha_token: ct, captcha_answer: ca } = req.body || {};
  if (!captchaVerify(ct, ca)) {
    bruteFail(key);
    return res.status(400).json({ error: 'Проверка «человечности» не пройдена', needCaptcha: true });
  }

  const { username, password, name } = req.body || {};
  const bad = !validUsername(username) ? 'Логин: 3–24 символа, только буквы, цифры, _ и .'
    : !validPassword(password) ? 'Пароль должен быть 6–128 символов'
    : !validName(name) ? 'Имя: от 2 до 60 символов'
    : null;
  if (bad) return res.status(400).json({ error: bad, needCaptcha: true });

  const exists = db.prepare('SELECT id FROM users WHERE username = ?').get(String(username));
  if (exists) return res.status(409).json({ error: 'Логин уже занят' });

  const hash = bcrypt.hashSync(String(password), BCRYPT_COST);
  const userCount = db.prepare('SELECT COUNT(*) AS n FROM users').get().n;
  const role = userCount === 0 ? 'admin' : 'user';
  const r = db
    .prepare('INSERT INTO users (uid, username, password_hash, name, role) VALUES (?, ?, ?, ?, ?)')
    .run(randomUid(), String(username), hash, String(name), role);
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(Number(r.lastInsertRowid));
  createSession(req, res, user.id);
  log('register', { req, userId: user.id, meta: { username: user.username, role } });
  res.status(201).json({ user: publicUser(user) });
});

/* ---------- вход: 1-й шаг (пароль) ---------- */
router.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  const key = bruteKey(getClientIp(req), username);

  const check = bruteCheck(key);
  if (!check.ok) {
    return res.status(429).json({
      error: `Слишком много попыток. Подождите ${check.wait} сек.`,
      retryAfter: check.wait,
      locked: true
    });
  }

  const needCaptcha = bruteNeedsCaptcha(key);
  const { captcha_token: ct, captcha_answer: ca } = req.body || {};
  if (needCaptcha && !captchaVerify(ct, ca)) {
    return res.status(400).json({ error: 'Введите ответ на капчу', needCaptcha: true });
  }

  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(String(username || ''));
  if (!user || !bcrypt.compareSync(String(password || ''), user.password_hash)) {
    bruteFail(key);
    log('login_fail', { req, meta: { username: String(username || '') } });
    return res.status(401).json({
      error: 'Неверный логин или пароль',
      needCaptcha: bruteNeedsCaptcha(key)
    });
  }

  // при успешном пароле — если включена 2FA, просим код
  if (totpEnabled(user.id)) {
    const token = signToken({ uid: user.id, purpose: 'totp-login' }, 300);
    log('login_2fa_pending', { req, userId: user.id });
    return res.json({ step: 'totp', totpToken: token });
  }

  bruteSuccess(key);
  createSession(req, res, user.id);
  log('login', { req, userId: user.id });
  res.json({ user: publicUser(user) });
});

/* ---------- вход: 2-й шаг (код 2FA) ---------- */
router.post('/login/2fa', (req, res) => {
  const { totp_token: t, code } = req.body || {};
  const payload = verifyToken(t);
  if (!payload || payload.purpose !== 'totp-login') {
    return res.status(400).json({ error: 'Сессия 2FA истекла, войдите заново' });
  }
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(Number(payload.uid));
  const trow = user ? db.prepare('SELECT * FROM totp WHERE user_id = ?').get(user.id) : null;
  if (!trow || !trow.enabled) return res.status(400).json({ error: '2FA не включена' });

  const key = bruteKey(getClientIp(req), user.username);
  const check = bruteCheck(key);
  if (!check.ok) {
    return res.status(429).json({ error: `Слишком много попыток. Подождите ${check.wait} сек.`, locked: true });
  }

  const secret = totpSecretOf(trow);
  if (secret && verifyTotp(secret, code)) {
    bruteSuccess(key);
    createSession(req, res, user.id);
    log('login', { req, userId: user.id, meta: { via2fa: true } });
    return res.json({ user: publicUser(user) });
  }
  if (verifyBackupCode(trow, code)) {
    bruteSuccess(key);
    createSession(req, res, user.id);
    log('login', { req, userId: user.id, meta: { viaBackupCode: true } });
    return res.json({ user: publicUser(user) });
  }
  bruteFail(key);
  log('login_fail', { req, userId: user.id, meta: { reason: '2fa_code' } });
  return res.status(401).json({ error: 'Неверный код', needCaptcha: bruteNeedsCaptcha(key) });
});

/* ---------- текущий пользователь ---------- */
router.get('/me', auth, (req, res) => {
  res.json({
    user: publicUser(req.user),
    totp: totpEnabled(req.userId),
    csrf: parseCookies(req).reska_csrf || ''
  });
});

router.get('/token', auth, (req, res) => {
  res.json({ token: parseCookies(req).reska_session || '' });
});

/* ---------- выход ---------- */
router.post('/logout', auth, (req, res) => {
  log('logout', { req, userId: req.userId });
  destroySession(req, res);
  res.json({ ok: true });
});

router.post('/logout-all', auth, (req, res) => {
  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(req.userId);
  db.prepare('DELETE FROM refresh_tokens WHERE user_id = ?').run(req.userId);
  log('logout_all', { req, userId: req.userId });
  destroySession(req, res);
  res.json({ ok: true });
});

/* ---------- смена пароля ---------- */
router.post('/password', auth, (req, res) => {
  const { current_password: cur, new_password: next } = req.body || {};
  if (!bcrypt.compareSync(String(cur || ''), req.user.password_hash)) {
    return res.status(403).json({ error: 'Неверный текущий пароль' });
  }
  if (!validPassword(next)) return res.status(400).json({ error: 'Новый пароль: 6–128 символов' });
  if (String(next) === String(cur)) return res.status(400).json({ error: 'Новый пароль совпадает со старым' });
  db.prepare('UPDATE users SET password_hash = ?, password_changed_at = ? WHERE id = ?')
    .run(bcrypt.hashSync(String(next), BCRYPT_COST), new Date().toISOString(), req.userId);
  // инвалидируем остальные устройства, но сохраняем текущую сессию
  db.prepare('DELETE FROM sessions WHERE user_id = ? AND device_id != ?').run(req.userId, parseCookies(req).reska_device || '');
  db.prepare('DELETE FROM refresh_tokens WHERE user_id = ? AND device_id != ?').run(req.userId, parseCookies(req).reska_device || '');
  log('password_change', { req, userId: req.userId });
  res.json({ ok: true });
});

/* ---------- 2FA: статус / включение / выключение ---------- */
router.get('/2fa/status', auth, (req, res) => {
  res.json({ enabled: totpEnabled(req.userId) });
});

router.post('/2fa/setup', auth, (req, res) => {
  if (totpEnabled(req.userId)) return res.status(409).json({ error: '2FA уже включена' });
  const secret = generateTotpSecret();
  const codes = makeBackupCodes();
  const token = signToken({ uid: req.userId, purpose: '2fa-setup', secret, codes }, 300);
  log('totp_setup_start', { req, userId: req.userId });
  res.json({ token, secret, uri: totpUri(secret, req.user.username), codes });
});

router.post('/2fa/verify', auth, (req, res) => {
  const { token, code } = req.body || {};
  const payload = verifyToken(token);
  if (!payload || payload.purpose !== '2fa-setup' || Number(payload.uid) !== req.userId) {
    return res.status(400).json({ error: 'Ссылка подтверждения истекла' });
  }
  if (!verifyTotp(payload.secret, code)) {
    return res.status(401).json({ error: 'Неверный код, проверьте время устройства' });
  }
  db.prepare('INSERT OR REPLACE INTO totp (user_id, secret, enabled, created_at) VALUES (?, ?, 1, ?)')
    .run(req.userId, encryptString(JSON.stringify({ s: payload.secret, codes: payload.codes })), new Date().toISOString());
  log('totp_enable', { req, userId: req.userId });
  res.json({ ok: true, codes: payload.codes });
});

router.post('/2fa/disable', auth, (req, res) => {
  const { password, code } = req.body || {};
  if (!bcrypt.compareSync(String(password || ''), req.user.password_hash)) {
    return res.status(403).json({ error: 'Неверный пароль' });
  }
  const trow = db.prepare('SELECT * FROM totp WHERE user_id = ?').get(req.userId);
  const secret = totpSecretOf(trow);
  if (secret && !verifyTotp(secret, code) && !verifyBackupCode(trow, code)) {
    return res.status(401).json({ error: 'Неверный код 2FA' });
  }
  db.prepare('DELETE FROM totp WHERE user_id = ?').run(req.userId);
  log('totp_disable', { req, userId: req.userId });
  res.json({ ok: true });
});

/* ---------- управление сессиями ---------- */
router.get('/sessions', auth, (req, res) => {
  const deviceId = parseCookies(req).reska_device || '';
  const sessions = db
    .prepare('SELECT token, device_id, ip_hash, ua_hash, created_at, expires_at FROM sessions WHERE user_id = ? ORDER BY created_at DESC')
    .all(req.userId);
  const refs = db.prepare('SELECT COUNT(*) AS n FROM refresh_tokens WHERE user_id = ?').get(req.userId).n;
  res.json({
    currentDevice: deviceId,
    sessions: sessions.map((s) => ({ ...s, token: undefined, isCurrent: s.device_id === deviceId })),
    refreshCount: refs
  });
});

router.delete('/sessions/:deviceId', auth, (req, res) => {
  const deviceId = String(req.params.deviceId);
  if (!/^[a-f0-9]{24}$/.test(deviceId)) return res.status(400).json({ error: 'Некорректный device' });
  db.prepare('DELETE FROM sessions WHERE user_id = ? AND device_id = ?').run(req.userId, deviceId);
  db.prepare('DELETE FROM refresh_tokens WHERE user_id = ? AND device_id = ?').run(req.userId, deviceId);
  log('session_revoked', { req, userId: req.userId, meta: { deviceId } });
  res.json({ ok: true });
});

module.exports = router;
