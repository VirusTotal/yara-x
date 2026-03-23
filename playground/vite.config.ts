import { defineConfig } from "vite";
import os from "node:os";
import path from "node:path";

export default defineConfig({
  base: process.env.GITHUB_ACTIONS ? "/playground/" : "/",
  worker: {
    format: "es",
  },
  optimizeDeps: {
    include: ["@codingame/monaco-vscode-editor-api"],
  },
  build: {
    rollupOptions: {
      output: {
        format: "es",
      },
    },
  },
  server: {
    fs: {
      allow: [
        path.resolve(__dirname, ".."),
        path.resolve(__dirname, "node_modules"),
        path.resolve(os.homedir(), "node_modules"),
      ],
    },
  },
});
