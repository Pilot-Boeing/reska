const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { AVATAR_DIR, POST_DIR, VIDEO_DIR } = require('./db');
const { encryptFileStream } = require('./encryption');

const IMAGE_MIME = ['image/jpeg', 'image/png', 'image/webp', 'image/gif', 'image/svg+xml'];
const VIDEO_MIME = ['video/mp4', 'video/webm', 'video/quicktime', 'video/x-matroska', 'video/ogg'];

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
      if (mimes.includes(file.mimetype)) cb(null, true);
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
const uploadPostMedia = makeUpload(POST_DIR, [...IMAGE_MIME, ...VIDEO_MIME], 200);
const uploadVideo = makeUpload(VIDEO_DIR, VIDEO_MIME, 500);

module.exports = { uploadAvatar, uploadPostMedia, uploadVideo };
