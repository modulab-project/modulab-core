# ── Stage 1: Frontend build ───────────────────────────────────────────────────
# Pinned to a digest, not just the node:26-alpine tag (2026-07-23 security
# pass): a tag is a mutable pointer, so a rebuild weeks later can silently
# pull a different (and potentially compromised or behaviorally-changed)
# image under the same name. Bump this deliberately via Renovate/Dependabot
# rather than letting `docker build` resolve it implicitly.
FROM node:26-alpine@sha256:e88a35be04478413b7c71c455cd9865de9b9360e1f43456be5951032d7ac1a66 AS frontend-builder

WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm ci --silent
COPY frontend/ ./
RUN npm run build
# Output: /app/frontend/dist/

# ── Stage 2: Go build ─────────────────────────────────────────────────────────
# Same digest-pinning reasoning as the frontend-builder stage above.
FROM golang:1.26-alpine@sha256:f23e8b227fb4493eabe03bede4d5a32d04092da71962f1fb79b5f7d1e6c2a17f AS go-builder

WORKDIR /app/backend
COPY backend/go.mod backend/go.sum ./
RUN go mod download
COPY backend/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /modulab-core ./cmd/core

# ── Stage 3: Final image ──────────────────────────────────────────────────────
# Same digest-pinning reasoning as the frontend-builder stage above - this
# is the base of the image that actually ships, so it matters most here.
FROM debian:bookworm-slim@sha256:0104b334637a5f19aa9c983a91b54c89887c0984081f2068983107a6f6c21eeb

# Install Deno (required for Tier 2/3 module handlers) and cosign (required by
# VerifyCosign, backend/internal/modules/verifier.go, to check official/community
# module signatures on install/update). Both pinned to a specific version for
# reproducible builds, and both verified against the official SHA256 checksum
# published alongside each release before being made executable - a corrupted
# or MITM'd binary at build time would otherwise become the module-signature
# verifier / Tier 2-3 runtime itself, so its own integrity is checked the same
# way modules.downloadFile + VerifySHA256 already check module ZIPs.
ENV DENO_VERSION=2.9.0
ENV COSIGN_VERSION=3.0.6
# Detect CPU arch at build time so the image works on both x86_64 and arm64
# (Apple Silicon via `docker buildx build --platform linux/arm64` or plain
# `docker build` on an M-series Mac with the default linux/arm64 platform).
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        unzip \
        passwd \
        gosu \
    && ARCH="$(dpkg --print-architecture)" \
    && case "$ARCH" in \
         amd64) DENO_ARCH="x86_64-unknown-linux-gnu"; COSIGN_ARCH="amd64" ;; \
         arm64) DENO_ARCH="aarch64-unknown-linux-gnu"; COSIGN_ARCH="arm64" ;; \
         *) echo "Unsupported arch: $ARCH" && exit 1 ;; \
       esac \
    && curl -fsSL "https://github.com/denoland/deno/releases/download/v${DENO_VERSION}/deno-${DENO_ARCH}.zip" \
        -o "/tmp/deno-${DENO_ARCH}.zip" \
    && curl -fsSL "https://github.com/denoland/deno/releases/download/v${DENO_VERSION}/deno-${DENO_ARCH}.zip.sha256sum" \
        -o /tmp/deno.zip.sha256sum \
    && (cd /tmp && sha256sum -c deno.zip.sha256sum) \
    && unzip "/tmp/deno-${DENO_ARCH}.zip" -d /usr/local/bin \
    && rm "/tmp/deno-${DENO_ARCH}.zip" /tmp/deno.zip.sha256sum \
    && chmod +x /usr/local/bin/deno \
    && deno --version \
    && curl -fsSL "https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-linux-${COSIGN_ARCH}" \
        -o "/tmp/cosign-linux-${COSIGN_ARCH}" \
    && curl -fsSL "https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign_checksums.txt" \
        -o /tmp/cosign_checksums.txt \
    && (cd /tmp && grep -E "  cosign-linux-${COSIGN_ARCH}\$" cosign_checksums.txt | sha256sum -c -) \
    && mv "/tmp/cosign-linux-${COSIGN_ARCH}" /usr/local/bin/cosign \
    && rm /tmp/cosign_checksums.txt \
    && chmod +x /usr/local/bin/cosign \
    && cosign version \
    && apt-get remove -y unzip \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*
# curl is deliberately kept (not removed like unzip above): the HEALTHCHECK
# below needs an HTTP client, and Core's own /healthz endpoint has no CLI
# equivalent to shell out to instead.

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

# Unprivileged, non-login user the process actually runs as (the default
# for every FROM debian:... image is root unless overridden). -r makes it a
# system account (no password, no aging policy); -d sets its home to the
# same path Core writes module data under, so the two stay consistent.
#
# Note there is deliberately no `USER modulab` here: MODULAB_MODULE_DATA_DIR
# is normally a persistent named volume (docker-compose.yml's
# modulab-modules-data) that, on any deployment that existed before this
# non-root migration, was created and populated while Core still ran as
# root. Docker only seeds a *brand-new* volume's ownership from the image -
# an existing volume keeps whatever ownership its files already have,
# unaffected by anything set at build time. So a build-time chown here would
# be correct for a fresh install and silently wrong (unreadable module
# files, exactly the "Permission denied" failure seen in practice) for every
# upgrade of an existing deployment. entrypoint.sh below runs as root at
# container start, chowns the actual mounted volume once it's in place, and
# only then drops to this user via gosu - see its comment for the full
# reasoning.
RUN groupadd -r modulab \
    && useradd -r -g modulab -d /var/lib/modulab -s /usr/sbin/nologin modulab

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 8080

# /healthz (main.go) is unauthenticated by design (see its handler's doc
# comment) specifically so Docker/Traefik healthchecks like this one can hit
# it without credentials. start-period gives Postgres/Valkey/module-worker
# startup (main.go connects to both before serving) room to finish before
# failed checks start counting toward retries.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -fsS http://localhost:8080/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["/usr/local/bin/modulab-core"]
