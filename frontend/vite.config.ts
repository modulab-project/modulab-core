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
});
