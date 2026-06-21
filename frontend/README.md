# modulab-core frontend

Minimal React + Vite + TypeScript + Tailwind SPA implementing the Setup
Wizard (spec section 6.5). Scope is deliberately limited to the wizard for
now - the login screen, dashboard, and module UI (spec section 6.4) land in
later Phase 2 work, at which point TanStack Query / i18next / dnd-kit (spec
section 6.1) get introduced as they're actually needed.

## Setup

```
npm install
cp .env.example .env   # adjust VITE_API_BASE_URL if the backend isn't on :8080
npm run dev
```

Requires the backend running with `MODULAB_FRONTEND_BASE_URL` matching this
dev server's origin (`http://localhost:5173` by default on both sides - no
`.env` edits needed for a default local setup).

## Routes

- `/setup` - the 6-step Setup Wizard (spec section 6.5 defines 7 steps, but
  step 2 - "choose your OIDC provider" - is dropped here: it was purely
  informational, since Core talks to every standard OIDC provider
  identically, so the wizard goes straight from the bootstrap token into
  entering OIDC credentials).
- `/auth/complete` - landing point for the OIDC redirect back from
  `backend/internal/auth`'s `CallbackHandler`; reads the result out of the
  URL fragment and hands off to `/setup` step 5 (Super-Admin login).

## Build

```
npm run build
```

Runs `tsc -b` then `vite build`; output goes to `dist/`.
