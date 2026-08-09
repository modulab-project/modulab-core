# modulab-core frontend

React 19 + Vite + TypeScript + Tailwind v4 SPA for ModuLab Core. It is the
full app - dashboard, login, Setup Wizard, user pages, admin pages, and the
runtime host for installed modules' own UI bundles - not just the Setup
Wizard. TanStack Query (data fetching/caching) and i18next/react-i18next
(lazy-loaded per-language translation catalogs, see `src/lib/i18n.ts`) are
both in active use throughout, not planned additions.

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

All routes are lazily code-split (`src/App.tsx`) so the initial bundle only
ships the app shell and router.

- `/` - the home dashboard (`Home.tsx`): quick links, weather, search, news.
- `/profile`, `/user/feeds`, `/user/search-prefs`, `/user/ai-keys` - per-user
  settings pages.
- `/modules/:moduleName` - runtime host for an installed module's own UI
  bundle (loaded via a dynamic `import()` over a Blob URL, no iframe).
- `/admin/users` - user approve/lock/unlock/delete management.
- `/admin/modules/store`, `/admin/modules/installed` - the Module Store and
  installed-modules views.
- `/admin/feeds`, `/admin/quick-links`, `/admin/audit` - admin content and
  audit-log management.
- `/admin/system/general`, `/admin/system/limits`, `/admin/system/oidc`,
  `/admin/system/smtp`, `/admin/system/geoip`, `/admin/system/search`,
  `/admin/system/ai`, `/admin/system/info` - admin system configuration
  pages (a few legacy paths such as `/admin/smtp`, `/admin/ai`, and
  `/admin/system/searxng` redirect to their current `/admin/system/...`
  location for backward compatibility).
- `/admin/security/info` - security-relevant instance info (TLS, sessions,
  encryption status).
- `/setup` - the Setup Wizard: bootstrap token, OIDC provider configuration,
  group prefix, the first admin's own OIDC login, an SMTP step, and finally
  completion. Redirects to `/login` automatically once setup is done
  (`SetupWizard` checks `/healthz`'s `setup_completed` on mount).
- `/auth/complete` - landing point for the OIDC redirect back from
  `backend/internal/auth`'s `CallbackHandler`; reads the result out of the
  URL fragment and hands off to `/setup` or `/login` depending on state.
- `/login`, `/pending` - the ordinary end-user login screen and the
  "awaiting admin approval" screen.
- any other path redirects to `/setup`, which itself redirects onward to
  `/login` once setup is complete.

## Build

```
npm run build
```

Runs `tsc -b` then `vite build`; output goes to `dist/`.
