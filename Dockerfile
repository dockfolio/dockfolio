FROM node:20-alpine AS builder

RUN apk add --no-cache python3 make g++
WORKDIR /app
COPY dashboard/package.json ./
RUN npm install --omit=dev
RUN apk del python3 make g++

FROM node:20-alpine

RUN apk add --no-cache docker-cli docker-cli-compose \
    && addgroup -S dockfolio && adduser -S dockfolio -G dockfolio

WORKDIR /app
COPY --from=builder /app/node_modules ./node_modules
COPY dashboard/package.json ./
COPY dashboard/server.js ./
COPY dashboard/public ./public

# Default empty config (user mounts their own or uses Settings UI)
RUN echo 'apps: []' > config.yml \
    && mkdir -p /data && chown dockfolio:dockfolio /data

ENV NODE_ENV=production
ENV AUTH_DB_PATH=/data/auth.db
ENV MARKETING_DB_PATH=/data/marketing.db

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD wget -qO- http://127.0.0.1:3000/api/health || exit 1

USER dockfolio
CMD ["node", "server.js"]
