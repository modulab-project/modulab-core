# modulab-core

Core backend (Go) and frontend (React/Vite) for ModuLab (https://modulab.app), the self-hosted, secure, modular intranet nexus for Docker-based homelabs.

## Features

- **OIDC-only authentication** against your own identity provider, with a group-claim prefix that maps IdP groups to ModuLab roles. New accounts land in a pending state until an admin approves, locks, or removes them.
- **Module Store** — browse, install, update, and uninstall modules from the official registry and community submissions, with searchable/filterable listings (name, description, and category localized into the user's language), Cosign signature verification, and per-module logos.
- **Sandboxed module execution** — Tier 2/3 modules run as isolated Deno subprocess Workers with a per-module PostgreSQL schema and role, and an outbound network allowlist that's re-scoped automatically whenever the module's configuration changes.
- **AI chat assistant** — admin-configured providers (Anthropic, or any OpenAI-compatible endpoint: OpenAI, Gemini, DeepSeek, Ollama, Groq, ...), with optional per-user API key overrides that take priority over the shared admin key.
- **Tamper-evident audit log** — every security-relevant admin action (user approve/lock/unlock/delete, SMTP/OIDC changes, ...) is written to an append-only log: a PostgreSQL trigger blocks UPDATE/DELETE outright, and an HMAC-SHA256 hash chain over the entries makes any retroactive edit cryptographically detectable. PII in the log is encrypted at rest.
- **News & feeds** — admin-curated RSS/Atom feed catalog with OPML import, per-user subscriptions.
- **Quick Links** — admin-curated and personal shortcut tiles on the home dashboard.
- **Weather widget** and **web search** (self-hosted via SearXNG) on the home dashboard.
- **Live updates** over Server-Sent Events (`/v1/events`) for admin notifications (new signups, module updates available, ...).
- Encryption at rest (AES-256-GCM under a single master key) for every credential, secret, and piece of PII the app stores - OIDC client secret, SMTP credentials, AI provider keys, module gateway credentials, audit log PII, and so on.

## Architecture at a glance

The backend is written in Go. It serves the REST API under `/v1/`, runs the Setup Wizard, owns auth via OIDC, manages PostgreSQL and Valkey, and supervises a long-lived Deno subprocess that runs Tier 2/3 module handlers as isolated Workers (their own outbound-network allowlist, own DB role/schema). The frontend is React and Vite; each module ships its own independently-built UI bundle (`ui/bundle.js`), which the frontend loads via a dynamic `import()` over a Blob URL and renders directly in the host app - there is no iframe or postMessage boundary between Core and module UI, so the isolation module code gets is on the backend (the sandboxed Deno Worker and its scoped DB role), not in the browser.

Data lives in PostgreSQL (Core's own tables, plus one schema per installed module) and Valkey (sessions, cache, pub/sub, SSE fan-out, job scheduling), with nginx serving the built frontend and proxying `/v1/` to Core so both share one origin. SearXNG powers the search widget. At the edge, Traefik handles TLS termination behind a docker-socket-proxy (so Traefik never touches the real Docker socket directly) and is the only externally exposed component.

## Repository layout

The `backend/` directory holds the Go module: API, auth, module orchestrator, and Deno-subprocess supervisor. The `frontend/` directory holds the React/Vite SPA. The `deploy/` directory holds `docker-compose.yml` (the production stack: Core, Postgres, Valkey, nginx, SearXNG, Traefik, and the docker-socket-proxy in front of it) and `docker-compose.dev.yml` (the local dev stack: Postgres, Valkey, and SearXNG only, with Core and the frontend running on the host). There is also a `.env.example` at the repository root.

## Schema changes

Core's own PostgreSQL schema (as opposed to a module's own per-schema tables) has no separate migration tool or SQL files - it is created and evolved directly in Go, via the `Ensure*Schema` methods on `*db.Pool` in `backend/internal/db/db.go` (`EnsureCoreSchema`, `EnsureAuditSchema`, `EnsureModuleStoreSchema`, `EnsureNewsSchema`, `EnsureAISchema`, `EnsureQuickLinksSchema`, and so on). These run on every boot and are fully idempotent (`CREATE TABLE IF NOT EXISTS`, `ADD COLUMN IF NOT EXISTS`), so a running instance picks up any additive change automatically on its next restart.

- **Additive change** (new column, new table, new index): add another idempotent statement to the relevant `Ensure*Schema` function, or a new `EnsureXSchema` function called from `EnsureCoreSchema` in the correct dependency order if it's a new feature area.
- **Non-additive change** (rename/retype a column, backfill or transform existing data): `IF NOT EXISTS` can't express this. Follow the pattern in `MigrateToEncryptedStorage` (`backend/internal/db/db.go`, called once at boot from `main.go`): a one-time function guarded by a version flag in `core_settings`, so it runs exactly once per instance and is a no-op afterward.

## Local development

Copy `.env.example` to `.env`, then run `docker compose -f deploy/docker-compose.dev.yml up -d` to start Postgres, Valkey, and SearXNG. Run the backend with `cd backend && go run ./cmd/core`, and the frontend with `cd frontend && npm install && npm run dev`.

Core connects to Postgres directly, both in dev and in production - there is no connection pooler in front of it. After copying `.env.example`, override three values in your local `.env`: set `MODULAB_DB_PORT=5432` (the dev stack exposes Postgres directly on 5432), `MODULAB_DB_PASSWORD=modulab-dev` (matching `docker-compose.dev.yml`'s `POSTGRES_PASSWORD`), and `MODULAB_VALKEY_PASSWORD=modulab-dev` (matching that file's `--requirepass`). Without these overrides, the backend cannot reach Postgres or Valkey locally - a missing Valkey password surfaces as `NOAUTH Authentication required` on the first request that touches a session.

On first start, the backend prints a one-time bootstrap token to its log. The entire Setup Wizard API under `/v1/setup/` is locked until that token is supplied via the `X-ModuLab-Bootstrap-Token` header on every request; `/healthz` remains unauthenticated for monitoring. The wizard is fully implemented: `/v1/setup/init` (generates and persists the master key), `/v1/setup/oidc/configure` (stores the OIDC provider's issuer URL, client ID, and an encrypted client secret), `/v1/setup/group-prefix/configure` (defines the OIDC groups-claim prefix), the super-admin's own OIDC login (the same `/v1/auth/login` / `/v1/auth/callback` end users use), and finally `/v1/setup/complete`, which only unlocks the app once every prior step - including a bound super-admin account, not just an attempted login - actually checks out. Each configuration step has a matching `/status` endpoint.

See `.env.example` for required environment variables (`MODULAB_MASTER_KEY`, DB/Valkey connection strings, and so on).

## License

AGPLv3, see LICENSE. Modules retain their own license; this Core repository is AGPLv3.
