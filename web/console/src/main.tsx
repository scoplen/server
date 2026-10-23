// SPDX-License-Identifier: AGPL-3.0-only
import { createRoot } from "react-dom/client";
import { App } from "./view.tsx";
import { OperatorClient, takeSetupFragment } from "./operator.ts";
import "@fontsource-variable/inter";
import "@fontsource-variable/lora";
import "@fontsource-variable/jetbrains-mono";
import "./style.css";

let setupToken: string | undefined;
let invalidLink = false;
try {
  setupToken = takeSetupFragment(new URL(location.href), (path) =>
    history.replaceState(null, "", path),
  );
} catch {
  invalidLink = true;
}
const client = new OperatorClient(location.origin, setupToken);
setupToken = undefined;
const unavailable =
  location.protocol !== "https:"
    ? "Open this console at its configured HTTPS address. Passkeys and session credentials require HTTPS."
    : !window.isSecureContext ||
        !window.PublicKeyCredential ||
        !crypto.subtle ||
        !navigator.locks
      ? "This browser does not support the passkey and browser-key features required by this console. Use a current browser over HTTPS."
      : undefined;
const root = document.getElementById("root");
if (!root) throw new Error("Console root is missing.");
createRoot(root).render(
  <App client={client} invalidLink={invalidLink} unavailable={unavailable} />,
);
