FROM node:22-slim

WORKDIR /app

COPY package*.json ./
RUN npm install --omit=dev

COPY . .

ENV PORT=3000
ENV NODE_ENV=production
ENV SPACE_DB_PATH=/data/space.db
ENV SPACE_UPLOAD_DIR=/data/uploads

RUN mkdir -p /data/uploads/avatars /data/uploads/posts /data/uploads/videos \
             /data/uploads/thumbs /data/uploads/chats /data/uploads/covers /data/uploads/stories

EXPOSE 3000

CMD ["node", "backend/server.js"]
