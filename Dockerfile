FROM node:24-alpine AS build
WORKDIR /app
COPY package*.json tsconfig.json ./
RUN npm ci
COPY src ./src
RUN npm run build && npm prune --omit=dev

FROM node:24-alpine
RUN apk add --no-cache tini && addgroup -S sentinel && adduser -S -G sentinel sentinel
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build --chown=sentinel:sentinel /app/node_modules ./node_modules
COPY --from=build --chown=sentinel:sentinel /app/dist ./dist
COPY --chown=sentinel:sentinel public ./public
RUN chmod -R a=rX /app/dist /app/node_modules /app/public && mkdir -p /data
# Runs as container-root only to read root-owned host audit logs. All Linux
# capabilities are still dropped by Compose and the filesystem is read-only.
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "dist/index.js"]
