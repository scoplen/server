// SPDX-License-Identifier: Apache-2.0
import { mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";

const root = new URL("../dist/", import.meta.url);
const entries = [
  "index.html",
  ...(await readdir(new URL("assets/", root))).map((name) => `assets/${name}`),
];
const assets = [];
let total = 0;
if (entries.length > 256) throw new Error("too many console assets");
for (const name of entries) {
  if (!/^(index\.html|assets\/[A-Za-z0-9_.-]+\.(js|css|woff2))$/.test(name))
    throw new Error("unsupported console asset");
  const data = await readFile(new URL(name, root));
  total += data.length;
  if (
    data.length === 0 ||
    data.length > 2 * 1024 * 1024 ||
    total > 16 * 1024 * 1024
  )
    throw new Error("console asset exceeds runtime limits");
  assets.push({
    path: name,
    bytes: data.length,
    sha256: createHash("sha256").update(data).digest("hex"),
  });
}
await mkdir(new URL("licenses/", root));
for (const name of [
  "react",
  "react-dom",
  "@fontsource-variable/inter",
  "@fontsource-variable/lora",
  "@fontsource-variable/jetbrains-mono",
]) {
  await writeFile(
    new URL(`licenses/${name.replaceAll("/", "-")}.txt`, root),
    await readFile(new URL(`../node_modules/${name}/LICENSE`, import.meta.url)),
  );
}
await writeFile(
  new URL("manifest.json", root),
  JSON.stringify({ version: 1, assets }, null, 2) + "\n",
);
console.log(`validated ${assets.length} same-origin console assets`);
