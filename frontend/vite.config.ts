import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Port 5173 is Vite's own default - made explicit here because
// backend/internal/config's MODULAB_FRONTEND_BASE_URL default
// ("http://localhost:5173") and the Go backend's CORS middleware both
// assume the frontend dev server runs on exactly this port.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
  },
});
