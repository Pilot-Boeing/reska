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

module.exports = { notify, notifyFollowers, unreadCount, markRead, markAllRead };
