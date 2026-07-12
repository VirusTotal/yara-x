import { defineConfig } from "vite";
import { readFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";

const yaraXPackage = JSON.parse(
  readFileSync(
    new URL("./node_modules/@virustotal/yara-x/package.json", import.meta.url),
    "utf-8",
  ),
) as { version: string };

export default defineConfig({
  base: process.env.GITHUB_ACTIONS ? "/yara-x/playground/" : "/",
  define: {
    __YARA_X_VERSION__: JSON.stringify(yaraXPackage.version),
  },
  worker: {
    format: "es",
  },
  optimizeDeps: {
    include: ["@codingame/monaco-vscode-editor-api"],
    exclude: ["@virustotal/yara-x"],
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
