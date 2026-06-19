import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "node:path";

// The console is served by the Go BFF in production and talks to it on the same
// origin. In dev we proxy /api to the BFF so EventSource (SSE) and fetch both
// hit a single origin without CORS. Override the target with VITE_BFF_TARGET.
const BFF_TARGET = process.env.VITE_BFF_TARGET ?? "http://localhost:8080";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: BFF_TARGET,
        changeOrigin: true,
        // SSE: keep the connection open and unbuffered.
        ws: false,
      },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: false,
    chunkSizeWarningLimit: 900,
    rollupOptions: {
      output: {
        // Split heavy, independently-cacheable vendors out of the app chunk so
        // a code change doesn't bust the whole bundle.
        manualChunks(id) {
          if (!id.includes("node_modules")) return undefined;
          if (/[\\/]react(-dom)?[\\/]/.test(id) || id.includes("scheduler"))
            return "react";
          if (id.includes("@tanstack/react-router")) return "router";
          if (id.includes("@tanstack/react-query")) return "query";
          if (
            id.includes("@tanstack/react-table") ||
            id.includes("@tanstack/react-virtual")
          )
            return "table";
          // rjsf + its ajv8 validator are the largest single dependency.
          if (id.includes("@rjsf") || id.includes("ajv")) return "forms";
          if (id.includes("@radix-ui")) return "radix";
          return undefined;
        },
      },
    },
  },
});
