# AGENTS.md

Сайт/соцсеть «РЕСКА» (стиль МЧС). Backend: Express + `node:sqlite` (`DatabaseSync`, WAL) + socket.io. Frontend: **vanilla JS, без сборщика/фреймворка** — один `frontend/app.js` (~4к строк) + `frontend/index.html` + CSS. Мобильное приложение — Capacitor (`android/`, `ios/`). Прод: Render, `https://reska-z7h0.onrender.com`.

## Команды (это всё, что есть — lint/typecheck/unit нет)
- `npm start` — сервер (backend/server.js)
- `npm run smoke` — интеграционный вариант (temp DB, не трогает реальные данные): 144 проверки API. **Основной способ проверки изменений.**
- `npm run seed`, `npm run backup`, `npm run restore` — локальные (backup-cli.js/restore.js; НЕ то же, что GitHub-бэкап ниже).

## Критично для каждого изменения
- **`git push origin main` часто зависает** — всегда давай `timeout: 240000` в bash-вызове. Не открывай новый терминал, просто жди.
- Коммит-сообщения — на русском, стиль как в `git log` (краткое описание сути).
- НЕ коммитить: `server.err`, `space.db*`, `uploads/`, `certs/`, `backend/fcm-service-account.json`, `.env`.
- После правок всегда `node --check` на изменённых `.js` + `npm run smoke`.

## Медиа-файлы (частый источник багов)
- Загрузки шифруются в `.enc` и раздаются расшифрованными через `/api/media/*`.
- **Allowlist** в `backend/server.js` (~стр. 94): `chats/\d+/` или `/(avatars|covers|posts|videos|thumbs)/`. Любую новую папку загрузок (напр. `covers`, `stories`) обязательно добавить туда, иначе файлы отдаются с 403. Проверяй при добавлении нового типа медиа.
- На фронте URL строится функцией `mediaUrl()` (app.js:28). Пути пишутся как `covers/<file>`, `chats/<chatId>/<file>` и т.п.

## Деплой (Render) — НЕ автоматический
- Авто-деплой НЕ работает. После каждого push нужен **Manual Deploy вручную** в дашборде Render.
- **Эфемерный диск**: `space.db` и `uploads/` стираются при перезапуске. Данные не теряются только благодаря GitHub-бэкапу.
- GitHub-бэкап: `backend/db-github-backup.js` — `restoreDbSync()` вызывается ДО открытия БД (db.js), `uploadDbFrom()` по таймеру/при старте/SIGTERM (server.js). Использует env: `GITHUB_TOKEN`, `GITHUB_REPO` (`Pilot-Boeing/reska-db`, приватный), `GITHUB_DB_PATH`, `GITHUB_BACKUP_MIN`. Код-репозиторий `Pilot-Boeing/reska` публичный (иначе Render не соберёт).
- `notify`/уведомления пишутся в БД → при потере БД теряются. Код уже пишет уведомления во внутреннюю таблицу; push (FCM) отдельно.

## Push-уведомления (FCM)
- Push отправляются только при наличии `FCM_SERVICE_ACCOUNT` (env, JSON service account) ИЛИ файла `backend/fcm-service-account.json`. Для нативного Android обязательно `google-services.json` в `android/app` и регистрация токена через `POST /api/push/token` (app.js `initPush`).
- `notifyUser` в `fcm.js` пропускает отправку, если получатель онлайн в socket (рассчитано на realtime).

## Архитектурные заметки
- Сессии — cookie + IP/UA-привязка (auth middleware в `helpers.js`). Socket.io-комнаты `user:<id>`; новое сообщение шлётся и отправителю, и получателю (`chat:message`), обработчик в app.js.
- Темы: `html[data-theme="dark|light"]`, токены в `frontend/css/redesign.css` (`:root` + `[data-theme="light"]`). Хардкоды цветов поверх `var(--...)` надо переопределять в `[data-theme="light"]`, иначе портят светлую тему.
- Устройство: `html[data-device="desktop|mobile"]` (определяется по `pointer: coarse` + ширине) — мобильная навигация/сайдбар зависят от него.
- Иконки: `data-ico="<name>"` + функция `window.icon(name)` (`frontend/icons.js`); автоотрисовка через MutationObserver → если в разметке `data-ico` указан неизвестный ключ, иконка пустая.
- Взаимодействие на тач-экранах: на сообщениях чата панель действий показывается тапом (класс `.actions-open`), не через `:hover` — учитывать, когда добавляешь кнопки в `.msg-actions`.

## Запуск вручную (необязательно)
- `docker-compose.yml`/`Dockerfile` для контейнера; `start.bat` — локальный запуск на Windows.
