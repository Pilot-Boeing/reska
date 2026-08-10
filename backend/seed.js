const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const {
  db,
  AVATAR_DIR,
  POST_DIR,
  VIDEO_DIR,
  THUMB_DIR
} = require('./db');
const { avatarSVG, postImageSVG, thumbSVG } = require('./demo-assets');
const { encryptBuffer } = require('./encryption');
const { randomUid } = require('./security');

const DEMO_VIDEO = path.join(__dirname, 'demo', 'demo1.mp4');

const DEMO_USERS = [
  { username: 'admin', password: 'admin123', name: 'Администратор РЕСК', bio: 'Создатель платформы. Организатор сборов.', status: 'Онлайн', role: 'admin' },
  { username: 'alex', password: 'user123', name: 'Алексей Соколов', bio: 'Курсант, 2 курс. Готовлю конспекты по тактике.', status: 'На сборах', role: 'user' },
  { username: 'maria', password: 'user123', name: 'Мария Волкова', bio: 'Курсантка 3 курса. Организатор мероприятий.', status: 'Готовлю к экзамену', role: 'user' },
  { username: 'dima', password: 'user123', name: 'Дмитрий Орлов', bio: 'Студент, фанат выживания и первой помощи.', status: 'В походе', role: 'user' },
  { username: 'katya', password: 'user123', name: 'Екатерина Лебедева', bio: 'Новенькая. Хочу попасть на сборы!', status: 'Новичок', role: 'user' }
];

const POSTS = [
  { by: 'alex', text: 'Всем привет! Выложил полный конспект по тактике на 2 курс. Кто идёт на сборы в выходные?' },
  { by: 'maria', text: 'Открыта запись на сборы «Рассвет-2026»! 50 мест, подробности в комментариях.\n\nНе забудьте паспорт и форму.', media: 'maria_promo', type: 'image' },
  { by: 'dima', text: 'Разобрали сегодня аптечку первой помощи. Список того, что обязательно должно быть — в картинке.' },
  { by: 'katya', text: 'Привет! Вчера подала заявку на вступление в сообщество. Что посоветуете почитать новичку?' },
  { by: 'admin', text: 'Правила сообщества обновлены. Просьба всем ознакомиться в закреплённом посте.' },
  { by: 'alex', text: 'Ночные учения прошли отлично. Топ-3 ошибки новичков:\n1. Слишком яркий фонарь\n2. Громкие разговоры в строю\n3. Неправильная маскировка' },
  { by: 'maria', text: 'Завтра общее собрание в 18:00. Явка обязательна!' },
  { by: 'dima', text: 'Собрал свои первые маршрутные точки для ориентирования. Делитесь своими!' },
  { by: 'katya', text: 'Спасибо всем за советы в комментариях! Уже начала готовиться. Скоро увидимся на сборах 🙌' },
  { by: 'admin', text: 'Напоминание: заявки на статус организатора принимаются до конца месяца. Пишите в личные сообщения.' }
];

const VIDEOS = [
  { by: 'admin', title: 'Как устроена платформа РЕСК', desc: 'Краткий обзор: лента, видео, мессенджер и профиль.', clip: 0 },
  { by: 'alex', title: 'Тактика: база для новичков', desc: 'Базовые принципы перемещения и сигналы.', clip: 0 },
  { by: 'maria', title: 'Клип: физподготовка', desc: 'Утренняя разминка, 30 секунд.', clip: 1 },
  { by: 'dima', title: 'Клип: первая помощь', desc: 'Наложение жгута за 20 секунд.', clip: 1 },
  { by: 'katya', title: 'Клип: мой первый сбор', desc: 'Впечатления новичка.', clip: 1 }
];

function writeEncrypted(dir, filename, content) {
  fs.writeFileSync(path.join(dir, filename), encryptBuffer(Buffer.from(content, 'utf8')));
  return filename;
}

function reset() {
  db.exec(`
    DELETE FROM messages;
    DELETE FROM chats;
    DELETE FROM comments;
    DELETE FROM video_likes;
    DELETE FROM videos;
    DELETE FROM post_likes;
    DELETE FROM posts;
    DELETE FROM follows;
    DELETE FROM sessions;
    DELETE FROM refresh_tokens;
    DELETE FROM totp;
    DELETE FROM users;
    DELETE FROM sqlite_sequence;
  `);
  for (const dir of [AVATAR_DIR, POST_DIR, VIDEO_DIR, THUMB_DIR]) {
    for (const f of fs.readdirSync(dir)) fs.unlinkSync(path.join(dir, f));
  }
}

function seed() {
  const row = db.prepare('SELECT COUNT(*) AS n FROM users').get();
  if (row.n > 0) {
    console.log('Данные уже существуют, скип seeding (для пересоздания: node backend/seed.js --force).');
    return;
  }
  reset();

  const insUser = db.prepare(
    'INSERT INTO users (uid, username, password_hash, name, bio, status, avatar, role) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
  );
  const userIds = {};
  for (const u of DEMO_USERS) {
    const hash = bcrypt.hashSync(u.password, 12);
    const avatar = `avatars/${u.username}.svg.enc`;
    writeEncrypted(AVATAR_DIR, `${u.username}.svg.enc`, avatarSVG(u.name, u.username));
    const r = insUser.run(randomUid(), u.username, hash, u.name, u.bio, u.status, avatar, u.role);
    userIds[u.username] = Number(r.lastInsertRowid);
  }
  console.log('Созданы пользователи:', DEMO_USERS.map((u) => u.username).join(', '));

  const insFollow = db.prepare('INSERT INTO follows (user_id, following_id) VALUES (?, ?)');
  const followPairs = [
    ['katya', 'alex'], ['katya', 'maria'], ['katya', 'admin'],
    ['alex', 'maria'], ['alex', 'admin'], ['alex', 'dima'],
    ['maria', 'alex'], ['maria', 'dima'], ['maria', 'admin'],
    ['dima', 'alex'], ['dima', 'maria'], ['dima', 'admin'],
    ['admin', 'alex'], ['admin', 'maria']
  ];
  for (const [a, b] of followPairs) {
    if (a !== b) insFollow.run(userIds[a], userIds[b]);
  }
  console.log(`Создано подписок: ${followPairs.length}`);

  const insPost = db.prepare('INSERT INTO posts (uid, user_id, text, media, media_type) VALUES (?, ?, ?, ?, ?)');
  const insLike = db.prepare('INSERT INTO post_likes (post_id, user_id) VALUES (?, ?)');
  const postIds = [];
  POSTS.forEach((p, i) => {
    let media = '';
    let type = '';
    if (p.media) {
      const fname = `post_${i + 1}.svg.enc`;
      writeEncrypted(POST_DIR, fname, postImageSVG(p.text, `${p.by}_${i}`, 640, 480));
      media = `posts/${fname}`;
      type = 'image';
    }
    const r = insPost.run(randomUid(), userIds[p.by], p.text, media, type);
    postIds.push(Number(r.lastInsertRowid));
  });
  console.log(`Создано постов: ${postIds.length}`);

  const likeMatrix = [
    [1, 'maria'], [1, 'dima'], [1, 'admin'], [1, 'katya'],
    [2, 'alex'], [2, 'dima'], [2, 'admin'], [2, 'katya'],
    [3, 'alex'], [3, 'maria'], [3, 'admin'],
    [4, 'alex'], [4, 'maria'], [4, 'dima'],
    [5, 'alex'], [5, 'maria'], [5, 'dima'], [5, 'katya'],
    [6, 'maria'], [6, 'katya'],
    [7, 'alex'], [7, 'dima'], [7, 'katya'],
    [8, 'alex'], [8, 'maria'],
    [9, 'alex'], [9, 'maria'], [9, 'dima'], [9, 'admin'],
    [10, 'maria'], [10, 'dima']
  ];
  for (const [pi, uname] of likeMatrix) {
    insLike.run(postIds[pi - 1], userIds[uname]);
  }
  console.log(`Создано лайков постов: ${likeMatrix.length}`);

  const insComment = db.prepare(
    'INSERT INTO comments (uid, post_id, user_id, text, parent_id) VALUES (?, ?, ?, ?, ?)'
  );
  const comments = [
    [1, 'dima', 'Иду! Жду конспект по картам.', null],
    [1, 'alex', 'Уже выложил в раздел «Конспекты», лови.', 1],
    [2, 'katya', 'Подскажите, форма обязательна?', null],
    [2, 'maria', 'Да, с эмблемой сообщества.', 3],
    [4, 'alex', 'Начни с раздела «Тактика для новичков».', null],
    [4, 'maria', 'И обязательно посмотри клипы с физподготовкой!', null],
    [6, 'dima', 'По фонарю согласен, нас учили в первую очередь.', null],
    [7, 'admin', 'Тема собрания — распределение по взводам.', null],
    [7, 'katya', 'Буду!', 7],
    [9, 'alex', 'Добро пожаловать в семью!)', null]
  ];
  for (const [pi, uname, text, parent] of comments) {
    insComment.run(randomUid(), postIds[pi - 1], userIds[uname], text, parent);
  }
  console.log(`Создано комментариев: ${comments.length}`);

  const insVideo = db.prepare(
    'INSERT INTO videos (uid, user_id, title, description, file, thumb, is_clip, views) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
  );
  const videoIds = [];
  VIDEOS.forEach((v, i) => {
    const fname = `demo_${i + 1}.mp4.enc`;
    const fpath = path.join(VIDEO_DIR, fname);
    if (!fs.existsSync(fpath)) {
      const plain = fs.readFileSync(DEMO_VIDEO);
      fs.writeFileSync(fpath, encryptBuffer(plain));
    }
    const thumbName = writeEncrypted(THUMB_DIR, `thumb_${i + 1}.svg.enc`, thumbSVG(v.title, `${v.by}_${i}`));
    const views = 80 + i * 137 + (v.clip ? 220 : 150);
    const r = insVideo.run(
      randomUid(), userIds[v.by], v.title, v.desc, `videos/${fname}`, `thumbs/${thumbName}`, v.clip, views
    );
    videoIds.push(Number(r.lastInsertRowid));
  });
  console.log(`Создано видео: ${videoIds.length} (${VIDEOS.filter((v) => !v.clip).length} ролика, ${VIDEOS.filter((v) => v.clip).length} клипа)`);

  const insVLike = db.prepare('INSERT INTO video_likes (video_id, user_id) VALUES (?, ?)');
  const vLikeMatrix = [
    [1, 'alex'], [1, 'maria'], [1, 'dima'], [1, 'katya'],
    [2, 'maria'], [2, 'dima'], [2, 'katya'], [2, 'admin'],
    [3, 'alex'], [3, 'katya'], [3, 'admin'],
    [4, 'alex'], [4, 'maria'], [4, 'katya'],
    [5, 'alex'], [5, 'maria'], [5, 'dima'], [5, 'admin']
  ];
  for (const [vi, uname] of vLikeMatrix) {
    insVLike.run(videoIds[vi - 1], userIds[uname]);
  }
  console.log(`Создано лайков видео: ${vLikeMatrix.length}`);

  const insChat = db.prepare('INSERT INTO chats (uid, user_a, user_b) VALUES (?, ?, ?)');
  const insMessage = db.prepare(
    'INSERT INTO messages (chat_id, sender_id, text, read) VALUES (?, ?, ?, ?)'
  );
  const chat1 = Number(insChat.run(randomUid(), userIds.alex, userIds.maria).lastInsertRowid);
  const chat2 = Number(insChat.run(randomUid(), userIds.alex, userIds.katya).lastInsertRowid);

  const chatMessages = [
    [chat1, 'maria', 'Привет! Скинь, пожалуйста, конспект по тактике.', 1],
    [chat1, 'alex', 'Привет! Держи, ссылка на раздел «Конспекты».', 1],
    [chat1, 'maria', 'Спасибо! Ты на собрание завтра придёшь?', 1],
    [chat1, 'alex', 'Да, конечно. Напомни тему?', 1],
    [chat1, 'maria', 'Распределение по взводам.', 1],
    [chat2, 'katya', 'Здравствуйте! Подскажите, как записаться на сборы?', 1],
    [chat2, 'alex', 'Привет! Заполни анкету в разделе «Сборы», я потом проверю.', 0],
    [chat2, 'katya', 'Сделала, отправила. Спасибо!', 0]
  ];
  for (const [chat, from, text, read] of chatMessages) {
    insMessage.run(chat, userIds[from], text, read);
  }
  console.log(`Создано сообщений: ${chatMessages.length}`);

  console.log('Seeding завершён. Демо-аккаунты: admin/admin123, alex|maria|dima|katya / user123');
}

const FORCE = process.argv.includes('--force');
if (FORCE) reset();
seed();
