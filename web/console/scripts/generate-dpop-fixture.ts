// SPDX-License-Identifier: Apache-2.0
import { writeFile } from "node:fs/promises";
import { BrowserProofKey } from "../src/operator.ts";

const origin = "https://operator.example";
const path = "/api/v1/auth/operator/logout";
const access_token = "public-fixture-access-token";
const now = Math.floor(Date.now() / 1000);
const key = await BrowserProofKey.create();
const authentication = await key.proof(
  origin,
  "/api/v1/auth/operator/login/options",
);
const protected_request = await key.proof(origin, path, access_token);
await writeFile(
  new URL(
    "../../../crates/scoplen-server/src/console/dpop-webcrypto.json",
    import.meta.url,
  ),
  JSON.stringify(
    { origin, path, access_token, now, authentication, protected_request },
    null,
    2,
  ) + "\n",
);
