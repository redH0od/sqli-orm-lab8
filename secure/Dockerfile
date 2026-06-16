FROM node:20-alpine

WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev

COPY src ./src

# Директория для sqlite БД
RUN mkdir -p /data

EXPOSE 3000

CMD ["node", "src/server.js"]
