// Best-effort pre-paint dark-mode guess, before React mounts. There is no
// localStorage cache of the user's actual theme choice (that lives in
// users.theme, DB-only, applied by AppShell's getUserPrefs effect after a
// session is confirmed) - so this can only go by the OS/browser's
// prefers-color-scheme, same source AppShell.tsx's own "system" handling
// reads at runtime. A user who explicitly picked "dark" while their OS is in
// light mode (or vice versa) will see a brief flash of the wrong mode on
// /login, /setup and /pending, and on first paint of the main app before the
// DB fetch resolves - an accepted trade-off of not persisting theme
// client-side at all. Wrapped in try/catch because matchMedia can be
// unavailable in some locked-down contexts and a theme flash is not worth a
// blank page over.
//
// This lives as its own file under `script-src 'self'` rather than an
// inline <script> in index.html: Core's CSP (deploy/nginx.conf) is
// deliberately strict (no 'unsafe-inline', no nonce), so an inline script
// here is silently blocked by the browser and never runs - the theme-flash
// mitigation it exists for then just doesn't happen. Reported by the user
// 2026-07-14 (CSP console error on every page load).
(function () {
  try {
    if (
      window.matchMedia &&
      window.matchMedia("(prefers-color-scheme: dark)").matches
    ) {
      document.documentElement.classList.add("dark");
    }
  } catch (e) {}
})();
