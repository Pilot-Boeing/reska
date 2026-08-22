/**
 * notif.js — внутриприложенные уведомления + push (FCM).
 * Сохраняет запись в notifications, шлёт socket-событие notify:new
 * (для живого счётчика) и дублирует push-уведомлением, если пользователь офлайн.
 */

const { db } = require('./db');
const { notifyUser, notifyFollowers } = require('./fcm');

function unreadCount(userId) {
  const row = db.prepare('SELECT COUNT(*) AS n FROM notifications WHERE user_id = ? AND read = 0').get(userId);
  return row ? row.n : 0;
}

function emitSocket(app, userId, payload) {
  const io = app && app.get ? app.get('io') : null;
  if (io) io.to(`user:${userId}`).emit('notify:new', payload);
}

const TYPE_MAP = {
  like: 'likes',
  comment: 'comments',
  follow: 'follows',
  friend_request: 'friend_requests',
  friend_accepted: 'friend_requests',
  message: 'messages',
  react: 'reactions'
};

function getSettings(userId) {
  let s = db.prepare('SELECT * FROM notification_settings WHERE user_id = ?').get(userId);
  if (!s) {
    db.prepare('INSERT OR IGNORE INTO notification_settings (user_id) VALUES (?)').run(userId);
    s = db.prepare('SELECT * FROM notification_settings WHERE user_id = ?').get(userId);
  }
  return s;
}

function isMuted(userId, chatId) {
  if (!chatId) return false;
  return !!db.prepare('SELECT 1 FROM muted_chats WHERE user_id = ? AND chat_id = ?').get(userId, chatId);
}

/**
 * Создать уведомление.
 * @param app — express app (для io/onlineUsers)
 * @param userId — кому
 * @param actor — кто (объект юзера: id, uid, name, avatar)
 * @param type — like | comment | follow | friend_request | friend_accepted | message
 * @param opts — { title, body, url }
 */
function notify(app, userId, actor, type, opts = {}) {
  if (!userId || !actor || userId === actor.id) return;
  const settings = getSettings(userId);
  const col = TYPE_MAP[type];
  if (col && settings && settings[col] === 0) return;
  if (isMuted(userId, opts.chatId)) return;
  db.prepare(
    'INSERT INTO notifications (user_id, actor_id, type, title, body, url) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(userId, actor.id, type, opts.title || actor.name || '', opts.body || '', opts.url || '');
  emitSocket(app, userId, {
    type,
    actor: { id: actor.id, uid: actor.uid, name: actor.name, avatar: actor.avatar },
    title: opts.title || actor.name || '',
    body: opts.body || '',
    url: opts.url || '',
    unread: unreadCount(userId)
  });
  const onlineUsers = app && app.get ? app.get('onlineUsers') : null;
  notifyUser(userId, { title: opts.title || actor.name, body: opts.body, data: { url: opts.url } }, onlineUsers);
}

function markRead(userId, id) {
  db.prepare('UPDATE notifications SET read = 1 WHERE id = ? AND user_id = ?').run(Number(id), userId);
}

function markAllRead(userId) {
  db.prepare('UPDATE notifications SET read = 1 WHERE user_id = ?').run(userId);
}

module.exports = { notify, notifyFollowers, unreadCount, markRead, markAllRead, getSettings, isMuted };
