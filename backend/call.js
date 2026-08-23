/**
 * call.js — сигналинг WebRTC-звонков поверх существующего socket.io.
 * Сам медиа-трафик идёт peer-to-peer через TURN-relay (см. docker-compose:
 * coturn на 443/TLS), чтобы работать в условиях ограничений РКН.
 * Сервер только пересылает SDP/ICE между участниками + шлёт уведомления о звонках.
 */
const { randomUid } = require('./security');
const { db } = require('./db');
const { notify } = require('./notif');

const activeCalls = new Map(); // callId -> { from, to, type, accepted }

function setupCalls(io, app) {
  io.on('connection', (socket) => {
    const me = socket.userId;

    // A звонит B
    socket.on('call:start', ({ to, type }) => {
      if (!to) return;
      const callId = randomUid();
      activeCalls.set(callId, { from: me, to, type: type === 'audio' ? 'audio' : 'video', accepted: false });
      io.to(`user:${to}`).emit('call:incoming', { callId, from: me, type: activeCalls.get(callId).type });
      const fromUser = db.prepare('SELECT id, uid, name, avatar FROM users WHERE id = ?').get(me);
      notify(app, to, fromUser, 'call', { body: 'звонит вам', url: 'feed' });
    });

    // B принимает
    socket.on('call:accept', ({ callId }) => {
      const call = activeCalls.get(callId);
      if (!call) return;
      call.accepted = true;
      io.to(`user:${call.from}`).emit('call:accepted', { callId });
    });

    // B отклоняет
    socket.on('call:decline', ({ callId }) => {
      const call = activeCalls.get(callId);
      if (!call) return;
      io.to(`user:${call.from}`).emit('call:declined', { callId });
      activeCalls.delete(callId);
    });

    // SDP offer/answer
    socket.on('call:signal', ({ callId, to, data }) => {
      io.to(`user:${to}`).emit('call:signal', { callId, from: me, data });
    });

    // ICE candidates
    socket.on('call:ice', ({ callId, to, candidate }) => {
      io.to(`user:${to}`).emit('call:ice', { callId, from: me, candidate });
    });

    // Завершение
    socket.on('call:end', ({ callId }) => {
      const call = activeCalls.get(callId);
      if (call) {
        if (!call.accepted) {
          const fromUser = db.prepare('SELECT id, uid, name, avatar FROM users WHERE id = ?').get(call.from);
          notify(app, call.to, fromUser, 'call', { body: 'пропущенный звонок', url: 'feed' });
        }
        io.to(`user:${call.from}`).emit('call:end', { callId });
        io.to(`user:${call.to}`).emit('call:end', { callId });
        activeCalls.delete(callId);
      }
    });

    socket.on('disconnect', () => {
      for (const [cid, call] of activeCalls) {
        if (call.from === me || call.to === me) {
          if (!call.accepted && call.to === me) {
            const fromUser = db.prepare('SELECT id, uid, name, avatar FROM users WHERE id = ?').get(call.from);
            notify(app, call.to, fromUser, 'call', { body: 'пропущенный звонок', url: 'feed' });
          }
          io.to(`user:${call.from}`).emit('call:end', { callId: cid });
          io.to(`user:${call.to}`).emit('call:end', { callId: cid });
          activeCalls.delete(cid);
        }
      }
    });
  });
}

module.exports = { setupCalls };
