// SPDX-License-Identifier: Apache-2.0
import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";

const local = (name: string) =>
  fileURLToPath(new URL(`.browser/pkg/${name}`, import.meta.url));
export default defineConfig({
  resolve: {
    alias: [
      {
        find: /^@scoplen\/browser\/scoplen_browser_bg\.wasm(\?url)?$/,
        replacement: `${local("scoplen_browser_bg.wasm")}$1`,
      },
      { find: /^@scoplen\/browser$/, replacement: local("scoplen_browser.js") },
    ],
  },
  worker: { format: "es" },
});
