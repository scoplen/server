// SPDX-License-Identifier: AGPL-3.0-only
import { createRoot } from "react-dom/client";
import { App } from "./view.tsx";
import { OperatorClient } from "./operator.ts";
import { AccountClient } from "./account.ts";
import { AccountApp } from "./account-view.tsx";
import { PasswordWorkerLogin } from "./password-worker-client.ts";
import { passwordWorkerFactory } from "./password-worker-factory.ts";
import workerUrl from "./password-worker.ts?worker&url";
import { sharedBrowser } from "./browser-shared.ts";
import { consoleEntry } from "./entry.ts";
import { LocaleProvider } from "./locale.tsx";
import "@fontsource-variable/inter";
import "@fontsource-variable/lora";
import "@fontsource-variable/jetbrains-mono";
import "./style.css";

const entry = consoleEntry(new URL(location.href), (path) =>
  history.replaceState(null, "", path),
);
const root = document.getElementById("root");
if (!root) throw new Error("Console root is missing.");
const renderer = createRoot(root);
if (entry.kind === "operator") {
  document.title = "Scoplen · Operator console";
  const client = new OperatorClient(location.origin, entry.setupToken);
  entry.setupToken = undefined;
  const unavailable =
    location.protocol !== "https:"
      ? "Open this console at its configured HTTPS address. Passkeys and session credentials require HTTPS."
      : !window.isSecureContext ||
          !window.PublicKeyCredential ||
          !crypto.subtle ||
          !navigator.locks
        ? "This browser does not support the passkey and browser-key features required by this console. Use a current browser over HTTPS."
        : undefined;
  renderer.render(
    <App
      client={client}
      invalidLink={entry.invalidLink}
      unavailable={unavailable}
    />,
  );
} else {
  document.title = "Scoplen · Team console";
  const unavailable =
    location.protocol !== "https:"
      ? "https"
      : !window.isSecureContext ||
          !crypto.subtle ||
          !navigator.locks ||
          !window.Worker ||
          !window.WebAssembly ||
          !window.structuredClone ||
          !String.prototype.isWellFormed
        ? "browser"
        : undefined;
  const client = unavailable
    ? undefined
    : new AccountClient(
        location.origin,
        new PasswordWorkerLogin(
          passwordWorkerFactory(workerUrl, location.origin),
        ),
      );
  renderer.render(
    <LocaleProvider>
      <AccountApp
        client={client}
        origin={location.origin}
        shared={sharedBrowser}
        initialTarget={entry.target}
        invalidLink={entry.invalidLink}
        unavailable={unavailable}
      />
    </LocaleProvider>,
  );
}
