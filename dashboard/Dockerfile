FROM node:20-alpine
RUN apk add --no-cache docker-cli docker-cli-compose python3 make g++
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev
RUN apk del python3 make g++
COPY . .
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1:3000/api/health || exit 1
CMD ["node", "server.js"]
