# ── Stage 1: Frontend build ───────────────────────────────────────────────────
FROM node:22-alpine AS frontend-builder

WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm ci --silent
COPY frontend/ ./
RUN npm run build
# Output: /app/frontend/dist/

# ── Stage 2: Go build ─────────────────────────────────────────────────────────
FROM golang:1.25-alpine AS go-builder

WORKDIR /app/backend
COPY backend/go.mod backend/go.sum ./
RUN go mod download
COPY backend/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /modulab-core ./cmd/core

# ── Stage 3: Final image ──────────────────────────────────────────────────────
FROM debian:bookworm-slim

# Install Deno (required for Tier 2/3 module handlers).
# Pinned to a specific version for reproducible builds.
ENV DENO_VERSION=2.3.6
# Detect CPU arch at build time so the image works on both x86_64 and arm64
# (Apple Silicon via `docker buildx build --platform linux/arm64` or plain
# `docker build` on an M-series Mac with the default linux/arm64 platform).
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        unzip \
    && ARCH="$(dpkg --print-architecture)" \
    && case "$ARCH" in \
         amd64) DENO_ARCH="x86_64-unknown-linux-gnu" ;; \
         arm64) DENO_ARCH="aarch64-unknown-linux-gnu" ;; \
         *) echo "Unsupported arch: $ARCH" && exit 1 ;; \
       esac \
    && curl -fsSL "https://github.com/denoland/deno/releases/download/v${DENO_VERSION}/deno-${DENO_ARCH}.zip" \
        -o /tmp/deno.zip \
    && unzip /tmp/deno.zip -d /usr/local/bin \
    && rm /tmp/deno.zip \
    && chmod +x /usr/local/bin/deno \
    && deno --version \
    && apt-get remove -y curl unzip \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# Copy Go binary
COPY --from=go-builder /modulab-core /usr/local/bin/modulab-core

# Copy built frontend into the directory Core serves as static files.
# Core serves frontend/dist/ at the path configured via MODULAB_FRONTEND_DIR
# (default: /app/frontend/dist).
COPY --from=frontend-builder /app/frontend/dist/ /app/frontend/dist/

# Module data directory — override with MODULAB_MODULE_DATA_DIR if needed.
# Mount a persistent volume here in production (see deploy/docker-compose.yml).
RUN mkdir -p /var/lib/modulab/modules
ENV MODULAB_MODULE_DATA_DIR=/var/lib/modulab/modules

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/modulab-core"]
