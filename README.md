# modulab-core

Core backend (Go) and frontend (React/Vite) for ModuLab (https://modulab.app), the self-hosted, secure, modular intranet nexus for Docker-based homelabs.

Full specification: modulab-docs (https://github.com/modulab-project/modulab-docs).

## Architecture at a glance

The backend is written in Go. It serves the REST API under /v1/, runs the Setup Wizard, owns auth via OIDC, manages PostgreSQL and Valkey, and supervises a long-lived Deno subprocess that runs module handlers as isolated Workers (spec section 4.7). The frontend is React and Vite, and the @modulab/ui Component Library (spec section 6.7) lives here too. Module UI is rendered through a sandboxed iframe with postMessage RPC (spec section 6.8). Data lives in PostgreSQL (Core tables plus one schema per installed module) and Valkey (sessions, cache, pub/sub, job scheduler), with PgBouncer in front of Postgres. At the edge, Traefik handles TLS termination and is the only externally exposed component.

## Repository layout

The backend/ directory holds the Go module: API, auth, module orchestrator, and Deno-subprocess supervisor. The frontend/ directory holds the React/Vite app and the @modulab/ui component library. The migrations/ directory holds Core's own PostgreSQL schema migrations (golang-migrate). The deploy/ directory holds docker-compose.yml, the production stack (Core, Postgres, PgBouncer, Valkey, Traefik), and docker-compose.dev.yml, the local dev stack (Postgres and Valkey only, with Core running on the host). There is also a .env.example at the repository root.

## First module to build

Per the specification's MVP guidance, build a Tier 1 module first (for example a simple recipe manager) to validate the full pipeline: per-module PostgreSQL role, migration execution, generated CRUD UI, and iframe rendering, before attempting a Tier 3 module (external egress, for example UniFi) which exercises the Deno-subprocess IPC and credential handling on top of that.

## Local development

Copy .env.example to .env, then run docker compose -f deploy/docker-compose.dev.yml up -d to start Postgres and Valkey only. Run the backend with cd backend && go run ./cmd/core, and the frontend with cd frontend && npm install && npm run dev.

The dev stack runs Postgres directly, without PgBouncer, unlike production. After copying .env.example, override two values in your local .env: set MODULAB_DB_PORT=5432 (the dev stack exposes Postgres directly on 5432, not the PgBouncer port 6432 assumed by .env.example) and MODULAB_DB_PASSWORD=modulab-dev (matching docker-compose.dev.yml's POSTGRES_PASSWORD). Without this override, the backend cannot reach Postgres locally.

See .env.example for required environment variables (MODULAB_MASTER_KEY, DB/Valkey connection strings, and so on, spec section 2.4).

## License

AGPLv3, see LICENSE. Modules retain their own license (spec section 4.1); this Core repository is AGPLv3.
