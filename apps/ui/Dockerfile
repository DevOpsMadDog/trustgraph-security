# ──────────────────────────────────────────────────────────────
# tg-ui — React/Vite frontend served by nginx
# ──────────────────────────────────────────────────────────────
FROM node:22-alpine AS build
WORKDIR /app
COPY package.json ./
RUN npm install --no-audit --no-fund
COPY . .
# Point API client at the gateway path; nginx in tg-ui proxies /api to tg-api
ENV VITE_API_BASE=/api/v1
RUN npx vite build --outDir dist

FROM nginx:1.27-alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 8080
