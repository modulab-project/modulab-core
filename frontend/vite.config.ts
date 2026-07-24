import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { VitePWA } from "vite-plugin-pwa";

// Port 5173 is Vite's own default - made explicit here because
// backend/internal/config's MODULAB_FRONTEND_BASE_URL default
// ("http://localhost:5173") and the Go backend's CORS middleware both
// assume the frontend dev server runs on exactly this port.
//
// host: true binds to 0.0.0.0 so the dev server is reachable from other
// devices on the local network (e.g. a phone via the Mac's LAN IP) without
// any env changes.
//
// The proxy entries forward /v1/* and /healthz to the local Go backend so
// the browser (regardless of which IP it used to reach Vite) never needs to
// know the backend's address directly - all API traffic travels over the
// same origin as the frontend, which also eliminates CORS preflight issues
// when accessing from a non-localhost device.
export default defineConfig({
  plugins: [
    react(),
    tailwindcss(),
    // "Add to Home Screen" support (Android install prompt + iOS standalone
    // mode). Generates manifest.webmanifest + a minimal precaching service
    // worker from the icons in public/ - see AppShell.tsx's useInstallPrompt
    // hook for the actual install-button logic (Android triggers the real
    // browser prompt; iOS has no such API and gets a manual instructions
    // overlay instead, see AppShell.tsx). navigateFallbackDenylist keeps the
    // SW's SPA fallback from ever intercepting backend routes - only the
    // static frontend shell is precached, /v1 and /healthz always hit the
    // network exactly like without a service worker at all.
    VitePWA({
      registerType: "autoUpdate",
      injectRegister: "auto",
      includeAssets: ["logo.svg"],
      manifest: {
        id: "/",
        name: "ModuLab",
        short_name: "ModuLab",
        description: "ModuLab - self-hosted module platform",
        start_url: "/",
        scope: "/",
        display: "standalone",
        background_color: "#ffffff",
        theme_color: "#1f2d3d",
        icons: [
          { src: "/pwa-192x192.png", sizes: "192x192", type: "image/png", purpose: "any" },
          { src: "/pwa-512x512.png", sizes: "512x512", type: "image/png", purpose: "any" },
          { src: "/maskable-512x512.png", sizes: "512x512", type: "image/png", purpose: "maskable" },
        ],
      },
      workbox: {
        navigateFallbackDenylist: [/^\/v1\//, /^\/healthz$/],
      },
    }),
  ],
  server: {
    port: 5173,
    host: true,
    proxy: {
      "/v1": "http://localhost:8080",
      "/healthz": "http://localhost:8080",
    },
  },
  build: {
    rollupOptions: {
      output: {
        // Split stable, rarely-changing vendor code out of the app chunk so
        // browsers can cache it across ModuLab releases even when app code
        // changes on every deploy. Paired with the React.lazy route
        // splitting in App.tsx - this only covers what's shared across all
        // routes (react/router/query-client/i18n bootstrapped in main.tsx),
        // page-level code already lives in its own per-route chunk.
        //
        // This is Rolldown-Vite (vite 8), whose manualChunks only accepts
        // the function form - the plain object-of-arrays form from classic
        // Rollup/Vite is not supported by its types.
        manualChunks(id) {
          if (!id.includes("node_modules")) return;
          if (/node_modules\/(react|react-dom)\//.test(id)) return "vendor-react";
          if (id.includes("node_modules/react-router")) return "vendor-router";
          if (id.includes("node_modules/@tanstack")) return "vendor-query";
          if (/node_modules\/(i18next|react-i18next|i18next-browser-languagedetector)\//.test(id))
            return "vendor-i18n";
        },
      },
    },
  },
});
