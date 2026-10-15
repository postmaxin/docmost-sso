# syntax=docker/dockerfile:1.7
# docmost-sso: multi-stage build, runs as the unprivileged `node` user.

ARG NODE_IMAGE=node:22-alpine@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402

FROM ${NODE_IMAGE} AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY tsconfig.json ./
COPY src ./src
COPY test/unit ./test/unit
RUN npm run build && node --test 'dist/test/unit/**/*.test.js' \
 && npm prune --omit=dev --ignore-scripts

FROM ${NODE_IMAGE}
LABEL org.opencontainers.image.source="https://github.com/postmaxin/docmost-sso" \
      org.opencontainers.image.description="OIDC sign-in shim for self-hosted Docmost community edition" \
      org.opencontainers.image.licenses="MIT"
ENV NODE_ENV=production PORT=8080
WORKDIR /app
COPY --from=build /app/package.json ./
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist/src ./dist/src
USER node
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- "http://127.0.0.1:${PORT}/sso/healthz" >/dev/null || exit 1
CMD ["node", "dist/src/main.js"]
