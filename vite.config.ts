import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 9007,
    proxy: {
      // Match errata.research.atomicorp.com: /api/v2 → Apollo /v2, /api/v3 → /api/v3
      "/api/v2": {
        target: "http://127.0.0.1:18000",
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api\/v2/, "/v2"),
      },
      "/api/v3": {
        target: "http://127.0.0.1:18000",
        changeOrigin: true,
      },
      "/mcp": {
        target: "http://127.0.0.1:18000",
        changeOrigin: true,
      },
      "/v2": {
        target: "http://127.0.0.1:18000",
        changeOrigin: true,
      },
    },
  },
});
