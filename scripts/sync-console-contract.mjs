// SPDX-License-Identifier: Apache-2.0
import { readFile, mkdir, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

export const revision = "cb4f2488ae1847ede2534a8585ba1907c8978f21";
const source = `https://raw.githubusercontent.com/scoplen/proto/${revision}/crates/scoplen-api/openapi/types.ts`;
const destination = new URL("../web/console/src/generated/api.ts", import.meta.url);
const result = await fetch(source, { redirect: "error" });
if (!result.ok) throw new Error("could not read the pinned public OpenAPI types");
const content = `// Source: ${source}\n${await result.text()}`;
if (process.argv.includes("--check")) {
  if ((await readFile(destination, "utf8")) !== content) throw new Error("console API types differ from the pinned proto artifact");
  console.log("console API types match the pinned proto artifact");
} else {
  await mkdir(new URL("../web/console/src/generated/", import.meta.url), { recursive: true });
  await writeFile(destination, content);
  console.log(`updated ${fileURLToPath(destination)}`);
}
