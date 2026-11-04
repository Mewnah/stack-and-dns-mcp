# syntax=docker/dockerfile:1
FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
RUN npm run build && npm prune --omit=dev

FROM node:22-alpine AS runtime
ENV NODE_ENV=production \
    STACKDNS_TRANSPORT=http \
    STACKDNS_HOST=0.0.0.0 \
    STACKDNS_PORT=3333 \
    STACKDNS_USAGE_FILE=/data/usage.json \
    STACKDNS_DB_FILE=/data/stackdns.db \
    STACKDNS_LOG_LEVEL=info
WORKDIR /app
RUN addgroup -S mcp && adduser -S mcp -G mcp && mkdir -p /data && chown mcp:mcp /data
COPY --from=build --chown=mcp:mcp /app/node_modules ./node_modules
COPY --from=build --chown=mcp:mcp /app/dist ./dist
COPY --chown=mcp:mcp package.json README.md LICENSE server.json ./
USER mcp
EXPOSE 3333
VOLUME ["/data"]
# Probes the port the server actually listens on (PORT wins over STACKDNS_PORT, as in config.ts),
# and passes in stdio mode (Smithery runs this image with STACKDNS_TRANSPORT=stdio), which has no
# HTTP listener. Docker does not expand variables here; the shell does, at run time.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD test "${STACKDNS_TRANSPORT:-http}" = "stdio" || wget -qO- "http://127.0.0.1:${PORT:-${STACKDNS_PORT:-3333}}/healthz" >/dev/null || exit 1
ENTRYPOINT ["node", "dist/index.js"]
CMD ["--http"]
