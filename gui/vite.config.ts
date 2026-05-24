import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));

const pkg = JSON.parse(
  readFileSync(resolve(__dirname, "package.json"), "utf8"),
) as { version?: string };
const APP_VERSION = pkg.version ?? "dev";

export default defineConfig({
  plugins: [svelte()],
  clearScreen: false,
  // Force the browser export of `svelte` so production builds get
  // client-side `mount()` rather than the SSR stub.
  resolve: {
    conditions: ["browser", "module", "import", "default"],
  },
  server: {
    port: 1421,
    strictPort: true,
    watch: { ignored: ["**/src-tauri/**"] },
  },
  envPrefix: ["VITE_", "TAURI_ENV_*"],
  define: {
    __APP_VERSION__: JSON.stringify(APP_VERSION),
  },
  build: {
    target: "chrome105",
    minify: !process.env.TAURI_ENV_DEBUG ? "esbuild" : false,
    sourcemap: !!process.env.TAURI_ENV_DEBUG,
  },
});
