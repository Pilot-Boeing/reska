/**
 * encryption.js — шифрование на диске AES-256-GCM.
 *
 * 1) Поля БД:    encryptString/decryptString  ("1:<iv>:<tag>:<ct>")
 * 2) Файлы:      чанковое шифрование по 16 КБ, поддержка случайного доступа
 *                (HTTP Range для перемотки видео):
 *                [8B magic][16B fileId][chunk0 ct+tag][chunk1 ct+tag]...
 *                nonce каждого чанка выводится из fileId + индекса (HMAC).
 * 3) Бэкапы:     encryptBuffer/decryptBuffer (целиком AES-256-GCM + MAC).
 */
const crypto = require('crypto');
const fs = require('fs');
const { getMasterKey } = require('./security');

const MAGIC = Buffer.from('SPCEFL01');
const HEADER_SIZE = MAGIC.length + 16; // 24
const CHUNK = 16384;                    // размер открытого чанка
const TAG = 16;                         // размер GCM tag
const ON_DISK_CHUNK = CHUNK + TAG;      // 16400

const isEncryptedPayload = (s) => typeof s === 'string' && s.startsWith('1:');

/* ---------- поля БД ---------- */
function encryptString(plain) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', getMasterKey(), iv);
  const ct = Buffer.concat([cipher.update(String(plain ?? ''), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `1:${iv.toString('base64')}:${tag.toString('base64')}:${ct.toString('base64')}`;
}

function decryptString(payload) {
  if (!isEncryptedPayload(payload)) return payload ?? '';
  const parts = payload.split(':');
  if (parts.length !== 4) return '';
  try {
    const iv = Buffer.from(parts[1], 'base64');
    const tag = Buffer.from(parts[2], 'base64');
    const ct = Buffer.from(parts[3], 'base64');
    const decipher = crypto.createDecipheriv('aes-256-gcm', getMasterKey(), iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
  } catch (e) {
    return '';
  }
}

/* ---------- файлы: производный nonce для чанка ---------- */
function chunkNonce(fileId, index) {
  const h = crypto.createHmac('sha256', getMasterKey());
  h.update(Buffer.from('filechunk'));
  h.update(fileId);
  const ib = Buffer.alloc(4);
  ib.writeUInt32BE(index >>> 0);
  h.update(ib);
  return h.digest().slice(0, 12);
}

/**
 * Потоковое шифрование файла (мультер пишет напрямую в зашифрованный файл).
 */
function encryptFileStream(targetPath, sourceStream, cb) {
  const fileId = crypto.randomBytes(16);
  const out = fs.createWriteStream(targetPath);
  let index = 0;
  let pending = Buffer.alloc(0);

  out.write(Buffer.concat([MAGIC, fileId]));

  function flush(buf) {
    const cipher = crypto.createCipheriv('aes-256-gcm', getMasterKey(), chunkNonce(fileId, index++));
    const ct = Buffer.concat([cipher.update(buf), cipher.final()]);
    out.write(Buffer.concat([ct, cipher.getAuthTag()]));
  }

  sourceStream.on('data', (d) => {
    pending = Buffer.concat([pending, d]);
    while (pending.length >= CHUNK) {
      flush(pending.slice(0, CHUNK));
      pending = pending.slice(CHUNK);
    }
  });
  sourceStream.on('end', () => {
    if (pending.length) flush(pending);
    out.end(() => cb(null, { fileId, size: filePlainSize(targetPath) }));
  });
  sourceStream.on('error', (err) => cb(err));
  out.on('error', (err) => cb(err));
}

function fileHeader(filePath) {
  const fd = fs.openSync(filePath, 'r');
  try {
    const h = Buffer.alloc(HEADER_SIZE);
    fs.readSync(fd, h, 0, HEADER_SIZE, 0);
    if (h.subarray(0, MAGIC.length).toString('ascii') !== MAGIC.toString('ascii')) {
      throw new Error('Файл не в зашифрованном формате');
    }
    return { fileId: h.subarray(MAGIC.length, HEADER_SIZE) };
  } finally {
    fs.closeSync(fd);
  }
}

/** Общий размер открытых данных файла. */
function filePlainSize(filePath) {
  const total = fs.statSync(filePath).size;
  const dataLen = total - HEADER_SIZE;
  if (dataLen < 0) return 0;
  const full = Math.floor(dataLen / ON_DISK_CHUNK);
  const rem = dataLen % ON_DISK_CHUNK;
  return full * CHUNK + (rem > 0 ? rem - TAG : 0);
}

function decryptChunk(fileId, index, encBuf) {
  if (encBuf.length < TAG) throw new Error('Повреждённый чанк файла');
  const decipher = crypto.createDecipheriv('aes-256-gcm', getMasterKey(), chunkNonce(fileId, index));
  decipher.setAuthTag(encBuf.subarray(encBuf.length - TAG));
  return Buffer.concat([decipher.update(encBuf.subarray(0, encBuf.length - TAG)), decipher.final()]);
}

/**
 * Чтение открытого диапазона [offset, offset+length). Безопасно для Range.
 */
function readPlainRange(filePath, offset, length) {
  const { fileId } = fileHeader(filePath);
  const total = filePlainSize(filePath);
  if (offset >= total) return { buffer: Buffer.alloc(0), total, start: offset };
  const end = Math.min(total, offset + length);
  const startChunk = Math.floor(offset / CHUNK);
  const endChunk = Math.floor((end - 1) / CHUNK);

  const fd = fs.openSync(filePath, 'r');
  try {
    const parts = [];
    for (let i = startChunk; i <= endChunk; i++) {
      const onDiskPos = HEADER_SIZE + i * ON_DISK_CHUNK;
      const chunkSize = Math.min(ON_DISK_CHUNK, fs.fstatSync(fd).size - onDiskPos);
      const enc = Buffer.alloc(chunkSize);
      fs.readSync(fd, enc, 0, chunkSize, onDiskPos);
      parts.push(decryptChunk(fileId, i, enc));
    }
    let plain = Buffer.concat(parts);
    const relStart = offset - startChunk * CHUNK;
    plain = plain.subarray(relStart, relStart + (end - offset));
    return { buffer: plain, total, start: offset };
  } finally {
    fs.closeSync(fd);
  }
}

function readPlainWhole(filePath) {
  const total = filePlainSize(filePath);
  return readPlainRange(filePath, 0, total).buffer;
}

/* ---------- бэкапы: файл целиком ---------- */
function encryptBuffer(buf) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', getMasterKey(), iv);
  const ct = Buffer.concat([cipher.update(buf), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, ct]);
}

function decryptBuffer(buf) {
  try {
    const iv = buf.subarray(0, 12);
    const tag = buf.subarray(12, 28);
    const ct = buf.subarray(28);
    const decipher = crypto.createDecipheriv('aes-256-gcm', getMasterKey(), iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]);
  } catch (e) {
    throw new Error('Не удалось расшифровать бэкап (неверный ключ или повреждение): ' + e.message);
  }
}

module.exports = {
  MAGIC,
  HEADER_SIZE,
  CHUNK,
  ON_DISK_CHUNK,
  isEncryptedPayload,
  encryptString,
  decryptString,
  encryptFileStream,
  fileHeader,
  filePlainSize,
  readPlainRange,
  readPlainWhole,
  encryptBuffer,
  decryptBuffer
};
