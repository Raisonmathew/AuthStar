# ============================================================================
# Multi-stage build for IDaaS Frontend (React SPA)
#
# Stages:
#   1. deps    — install npm dependencies (cached until package-lock changes)
#   2. builder — compile TypeScript and build Vite production bundle
#   3. runtime — serve static assets via nginx with security headers
#
# Build context: repo root (docker build -f frontend/Dockerfile .)
# ============================================================================

# ── Stage 1: Dependencies ──────────────────────────────────────────────────
FROM node:20-alpine AS deps

WORKDIR /app

# Copy only package files first — npm ci is cached until these change
COPY frontend/package.json frontend/package-lock.json ./

RUN npm ci --ignore-scripts

# ── Stage 2: Builder ──────────────────────────────────────────────────────
FROM deps AS builder

WORKDIR /app

# Copy source
COPY frontend/ ./

# Build for production
RUN npm run build

# ── Stage 3: Runtime (nginx) ─────────────────────────────────────────────
FROM nginx:1.27-alpine AS runtime

# Copy custom nginx config
COPY infrastructure/nginx/nginx.conf /etc/nginx/nginx.conf

# Copy built assets
COPY --from=builder /app/dist /usr/share/nginx/html

# Non-root user with writable dirs for nginx pid/cache/logs
RUN chown -R nginx:nginx /usr/share/nginx/html && \
    chown -R nginx:nginx /var/cache/nginx && \
    chown -R nginx:nginx /var/log/nginx && \
    chown -R nginx:nginx /etc/nginx/conf.d && \
    touch /var/run/nginx.pid && \
    chown nginx:nginx /var/run/nginx.pid

USER nginx

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -qO- http://localhost/healthz || exit 1

CMD ["nginx", "-g", "daemon off;"]
