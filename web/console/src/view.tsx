// SPDX-License-Identifier: AGPL-3.0-only
import { useRef, useState } from "react";
import type { PersonalInvitationResponse } from "./generated/api.ts";
import { ConsoleFailure, type OperatorClient } from "./operator.ts";

function failureText(error: unknown): string {
  if (
    error instanceof DOMException &&
    ["NotAllowedError", "AbortError"].includes(error.name)
  )
    return "The passkey request was cancelled or expired. Try again to start a fresh request.";
  if (!(error instanceof ConsoleFailure))
    return "The request could not be completed. Check your connection and try a fresh passkey request.";
  if (error.uncertain && error.operation === "setup")
    return "Registration may have completed. Keep the passkey you created and sign in with it. Do not create another passkey automatically.";
  if (error.uncertain && error.operation === "invitation")
    return "An invitation may have been created, but its link cannot be recovered. Choose Create another invitation to issue a different link.";
  if (error.uncertain)
    return "The session response could not be confirmed. Sign in again with a fresh passkey request; the previous request will not be repeated.";
  switch (error.code) {
    case "auth.rate_limited":
      return `Too many attempts. Wait ${error.retryAfter || 60} seconds before starting a fresh request.`;
    case "auth.authentication_required":
    case "sign_in_required":
      return "Your sign-in could not be verified. Sign in again with a fresh passkey request.";
    case "policy.denied":
      return "This deployment did not allow the request. Check that you opened its configured console address and have Operator access.";
    case "auth.storage_unavailable":
      return "The deployment is temporarily unavailable. No change was confirmed. Try a fresh request when it is available.";
    case "auth.invalid_dpop_proof":
      return "This tab's browser key could not be verified. Check your device clock, then sign in again.";
    case "ceremony_expired":
      return "The passkey request expired. Try again to start a fresh request.";
    case "passkey_unavailable":
      return "No compatible passkey was returned. Try again with a discoverable passkey that supports user verification.";
    default:
      return "The server response could not be verified. Check the deployment and start a fresh request.";
  }
}

export function App({
  client,
  invalidLink,
  unavailable,
}: {
  client: OperatorClient;
  invalidLink: boolean;
  unavailable?: string;
}) {
  const [step, setStep] = useState<"setup" | "login" | "invitation">(
    client.canSetup ? "setup" : "login",
  );
  const [busy, setBusy] = useState(false);
  const running = useRef(false);
  const [message, setMessage] = useState(
    invalidLink
      ? "This setup link is invalid. Open the complete setup link from the server's local bootstrap output, or sign in if setup is already complete."
      : "",
  );
  const [error, setError] = useState(invalidLink);
  const [invitation, setInvitation] = useState<PersonalInvitationResponse>();
  const [another, setAnother] = useState(false);
  const [copied, setCopied] = useState(false);

  async function act() {
    if (running.current || unavailable) return;
    running.current = true;
    setBusy(true);
    setMessage("");
    setError(false);
    try {
      if (step === "setup") {
        await client.register();
        setStep("login");
        setMessage(
          "Your passkey was created. Sign in with it to open the Personal console.",
        );
      } else if (step === "login") {
        await client.signIn();
        setStep("invitation");
        setMessage("Signed in as a deployment Operator.");
      } else {
        setInvitation(undefined);
        setCopied(false);
        setInvitation(await client.invite());
        setAnother(true);
        setMessage(
          "Invitation created. Copy the link before closing this tab.",
        );
      }
    } catch (failure) {
      setError(true);
      setMessage(failureText(failure));
      if (failure instanceof ConsoleFailure) {
        if (step === "setup" && failure.uncertain) setStep("login");
        if (
          step === "invitation" &&
          failure.uncertain &&
          failure.operation === "invitation"
        )
          setAnother(true);
        if (
          step === "invitation" &&
          (failure.operation === "refresh" ||
            [
              "auth.authentication_required",
              "sign_in_required",
              "auth.invalid_dpop_proof",
            ].includes(failure.code))
        ) {
          client.lock();
          setStep("login");
        }
      }
    } finally {
      running.current = false;
      setBusy(false);
    }
  }

  function lock() {
    client.lock();
    setInvitation(undefined);
    setStep("login");
    setError(false);
    setMessage("This tab is locked. Sign in again to continue.");
  }
  const title =
    step === "setup"
      ? "Create your Operator passkey"
      : step === "login"
        ? "Sign in to your deployment"
        : "Connect your Personal account";
  const action =
    step === "setup"
      ? "Create passkey"
      : step === "login"
        ? "Sign in with passkey"
        : another
          ? "Create another invitation"
          : "Create Personal invitation";
  return (
    <div className="console-shell">
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <header className="console-header">
        <span className="wordmark">Scoplen</span>
        <span className="context">Personal console</span>
        {step === "invitation" && (
          <button className="quiet" onClick={lock} disabled={busy}>
            Lock this tab
          </button>
        )}
      </header>
      <main id="main" className="workspace" tabIndex={-1}>
        <section className="primary" aria-labelledby="title">
          <p className="eyebrow">
            {step === "setup"
              ? "First Operator"
              : step === "login"
                ? "Operator access"
                : "Personal invitation"}
          </p>
          <h1 id="title">{title}</h1>
          <p className="intro">
            {step === "setup"
              ? "Use a passkey to administer this Scoplen deployment. Your device will ask you to verify and save it."
              : step === "login"
                ? "Use the passkey registered for this deployment. Your device will ask you to verify."
                : "Create a one-use invitation to set up a Personal account in the Scoplen desktop app."}
          </p>
          {unavailable && (
            <div className="notice error" role="alert">
              <h2>HTTPS and a compatible browser are required</h2>
              <p>{unavailable}</p>
            </div>
          )}
          <div
            className={`notice${error ? " error" : ""}`}
            role={error ? "alert" : "status"}
            aria-live="polite"
            aria-atomic="true"
            hidden={!message}
          >
            {message}
          </div>
          {invitation && (
            <section className="invitation" aria-labelledby="invitation-label">
              <h2 id="invitation-label">Your invitation link</h2>
              <p>
                Anyone with this link can create one Personal account and enroll
                its first device. Share it only with the intended person.
              </p>
              <label htmlFor="invitation-link">Invitation URL</label>
              <textarea
                id="invitation-link"
                readOnly
                value={invitation.invitation_url}
                rows={3}
                spellCheck={false}
              />
              <div className="link-actions">
                <button
                  className="secondary"
                  onClick={() => {
                    void navigator.clipboard
                      .writeText(invitation.invitation_url)
                      .then(
                        () => setCopied(true),
                        () => {
                          setError(true);
                          setMessage(
                            "Clipboard access was unavailable. Select and copy the invitation link above.",
                          );
                        },
                      );
                  }}
                >
                  {copied ? "Copied" : "Copy invitation link"}
                </button>
                <span>
                  Expires{" "}
                  <time dateTime={invitation.expires_at}>
                    {new Intl.DateTimeFormat(undefined, {
                      dateStyle: "medium",
                      timeStyle: "short",
                    }).format(new Date(invitation.expires_at))}
                  </time>
                </span>
              </div>
              <p className="caption">
                The link is shown once. Keep it until it has been opened in the
                desktop app.
              </p>
            </section>
          )}
          <div className="actions">
            <button
              className="primary-button"
              onClick={() => {
                void act();
              }}
              disabled={busy || Boolean(unavailable)}
              aria-busy={busy}
            >
              {busy
                ? step === "invitation"
                  ? "Creating invitation…"
                  : "Waiting for your passkey…"
                : action}
            </button>
            {step === "login" && client.canReturnToSetup && (
              <button
                className="quiet"
                disabled={busy}
                onClick={() => {
                  setStep("setup");
                  setMessage(
                    "Use the original setup link only if the passkey could not sign in and setup is still pending.",
                  );
                  setError(false);
                }}
              >
                Return to pending setup
              </button>
            )}
            {step === "setup" && (
              <button
                className="quiet"
                disabled={busy}
                onClick={() => {
                  setStep("login");
                  setMessage("");
                }}
              >
                Already created a passkey? Sign in
              </button>
            )}
          </div>
          <p className="caption">
            {step === "invitation"
              ? "Creating another invitation issues a new one. It does not replace or recover an earlier link."
              : "A passkey authenticates the deployment Operator. Your Personal account is created separately in the desktop app."}
          </p>
        </section>
        <aside className="guide" aria-labelledby="guide-title">
          <h2 id="guide-title">A short path to your devices</h2>
          <ol className="steps">
            <li aria-current={step === "setup" ? "step" : undefined}>
              <span className="step-number">01</span>
              <div>
                <h3>Create an Operator passkey</h3>
                <p>Register once using the server's setup link.</p>
              </div>
            </li>
            <li aria-current={step === "login" ? "step" : undefined}>
              <span className="step-number">02</span>
              <div>
                <h3>Sign in to this deployment</h3>
                <p>Verify with your saved passkey.</p>
              </div>
            </li>
            <li aria-current={step === "invitation" ? "step" : undefined}>
              <span className="step-number">03</span>
              <div>
                <h3>Create a Personal invitation</h3>
                <p>Open the one-use link in the Scoplen desktop app.</p>
              </div>
            </li>
          </ol>
          <div className="boundary">
            <h2>Keys stay with you</h2>
            <p>
              Your browser holds its own signing key. The console keeps sign-in
              information in memory and requires a fresh sign-in after a reload.
            </p>
          </div>
        </aside>
      </main>
      <footer>
        <span>Self-hosted by your deployment</span>
        <span className="deployment">{new URL(client.origin).host}</span>
      </footer>
    </div>
  );
}
