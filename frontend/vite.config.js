import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Every UI action goes through the API. Nothing here talks to a cloud, holds a
// credential, or runs Terraform. See 0001 and architecture.md.
export default defineConfig({
  plugins: [react()],
  // The pure logic suites run under plain node and need no browser. These are
  // the ones that do: losing a topology on refresh is a rendering and wiring
  // failure, not a data one, and nothing that runs without a DOM can see it.
  test: {
    environment: "jsdom",
    setupFiles: ["./vitest.setup.js"],
    include: ["src/**/*.test.jsx"],
    restoreMocks: true,
  },
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: process.env.REDSTACKPRO_API || "http://127.0.0.1:8000",
        changeOrigin: true,
      },
    },
  },
});
