const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { AVATAR_DIR, COVER_DIR, POST_DIR, VIDEO_DIR, CHAT_DIR } = require('./db');
const { encryptFileStream } = require('./encryption');

const IMAGE_MIME = ['image/jpeg', 'image/png', 'image/webp', 'image/gif', 'image/svg+xml'];
const VIDEO_MIME = ['video/mp4', 'video/webm', 'video/quicktime', 'video/x-matroska', 'video/ogg'];
const AUDIO_MIME = ['audio/webm', 'audio/mp4', 'audio/mpeg', 'audio/ogg', 'audio/opus', 'audio/wav', 'audio/x-wav', 'audio/aac', 'audio/x-m4a'];

function makeUpload(dir, mimes, maxMb) {
  const upload = multer({
    storage: multer.diskStorage({
      destination(req, file, cb) {
        cb(null, dir);
      },
      filename(req, file, cb) {
        cb(null, 'tmp_' + crypto.randomBytes(12).toString('hex'));
      }
    }),
    limits: { fileSize: maxMb * 1024 * 1024 },
    fileFilter(req, file, cb) {
      if (!mimes || mimes.includes(file.mimetype)) cb(null, true);
      else cb(new Error(`Недопустимый тип файла: ${file.mimetype}`));
    }
  });

  /**
   * Возвращает middleware для поля field:
   * временный файл → шифруется потоком → остаётся только <имя>.enc.
   */
  return (field) => (req, res, next) => {
    upload.single(field)(req, res, (err) => {
      if (err) {
        if (req.file) fs.unlink(req.file.path, () => {});
        err.status = err.code === 'LIMIT_FILE_SIZE' ? 413 : 400;
        return next(err);
      }
      const f = req.file;
      if (!f) return next();
      const ext = path.extname(f.originalname).toLowerCase() || '.bin';
      const finalName = Date.now().toString(36) + '_' + crypto.randomBytes(8).toString('hex') + ext + '.enc';
      const target = path.join(dir, finalName);
      const src = fs.createReadStream(f.path);

      encryptFileStream(target, src, (encErr) => {
        fs.unlink(f.path, () => {});
        if (encErr) {
          encErr.status = 500;
          return next(encErr);
        }
        f.filename = finalName;
        f.path = target;
        f.encrypted = true;
        next();
      });
    });
  };
}

const uploadAvatar = makeUpload(AVATAR_DIR, IMAGE_MIME, 8);
const uploadCover = makeUpload(COVER_DIR, IMAGE_MIME, 8);
const uploadPostMedia = makeUpload(POST_DIR, [...IMAGE_MIME, ...VIDEO_MIME], 200);
const uploadVideo = makeUpload(VIDEO_DIR, VIDEO_MIME, 500);

/** Загрузка вложений чата в подпапку <chatId> — файл относится к конкретному чату. */
function uploadChatMedia(field) {
  const multer = require('multer');
  const upload = multer({
    storage: multer.diskStorage({
      destination(req, file, cb) {
        const chatId = req.chat ? req.chat.id : 0;
        const dir = path.join(CHAT_DIR, String(chatId));
        fs.mkdirSync(dir, { recursive: true });
        cb(null, dir);
      },
      filename(req, file, cb) {
        cb(null, 'tmp_' + crypto.randomBytes(12).toString('hex'));
      }
    }),
    limits: { fileSize: 500 * 1024 * 1024 }
  });
  return (req, res, next) => {
    upload.single(field)(req, res, (err) => {
      if (err) {
        if (req.file) fs.unlink(req.file.path, () => {});
        err.status = err.code === 'LIMIT_FILE_SIZE' ? 413 : 400;
        return next(err);
      }
      const f = req.file;
      if (!f) return next();
      const ext = path.extname(f.originalname).toLowerCase() || '.bin';
      const finalName = Date.now().toString(36) + '_' + crypto.randomBytes(8).toString('hex') + ext + '.enc';
      const target = path.join(path.dirname(f.path), finalName);
      const src = fs.createReadStream(f.path);
      encryptFileStream(target, src, (encErr) => {
        fs.unlink(f.path, () => {});
        if (encErr) {
          encErr.status = 500;
          return next(encErr);
        }
        f.filename = finalName;
        f.path = target;
        f.encrypted = true;
        next();
      });
    });
  };
}

module.exports = { uploadAvatar, uploadCover, uploadPostMedia, uploadVideo, uploadChatMedia, AUDIO_MIME, VIDEO_MIME, IMAGE_MIME };
