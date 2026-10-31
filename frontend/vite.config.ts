import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The FastAPI service runs separately in development; the dev server proxies
// /api/* to it (rewriting the prefix) so the browser stays on one origin.
// In a production build the SPA is served by FastAPI itself, so VITE_API_BASE
// is empty and requests go straight to /health, /tool-calls, ...
const backend = process.env.AGENTSHIELD_API ?? "http://127.0.0.1:8000";

export default defineConfig({
  plugins: [react()],
  server: {
    host: "0.0.0.0",
    port: 3000,
    strictPort: true,
    proxy: {
      "/api": {
        target: backend,
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ""),
      },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: false,
  },
});
