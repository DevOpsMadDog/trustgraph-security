# ──────────────────────────────────────────────────────────────
# tg-ui — React/Vite frontend served by nginx
# ──────────────────────────────────────────────────────────────
FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json* ./
# Use `npm ci` when lockfile present, fall back to `npm install`
RUN if [ -f package-lock.json ]; then npm ci --no-audit --no-fund; \
    else npm install --no-audit --no-fund; fi
COPY . .
# Point API client at the gateway path; nginx in tg-ui proxies /api to tg-api
ENV VITE_API_BASE=/api/v1
# vite.config.ts pins outDir to dist/public/ (root=client, base=./)
RUN npx vite build

FROM nginx:1.27-alpine
# Build output lives at /app/dist/public/ (set in vite.config.ts)
COPY --from=build /app/dist/public /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 8080
