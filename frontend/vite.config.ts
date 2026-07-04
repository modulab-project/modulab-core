import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

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
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    host: true,
    proxy: {
      "/v1": "http://localhost:8080",
      "/healthz": "http://localhost:8080",
    },
  },
});
