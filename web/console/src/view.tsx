// SPDX-License-Identifier: AGPL-3.0-only
import { useEffect, useRef, useState } from "react";
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
  if (error.operation === "logout") {
    if (error.code === "logout_expired")
      return "This session can no longer confirm sign out. Lock this tab to remove its local access. Signing in again cannot confirm whether the earlier sign out completed.";
    if (error.uncertain)
      return "Sign out has not been confirmed. This session may already have ended. Keep this tab open and choose Retry sign out, or lock this tab locally. No retry runs automatically.";
    if (error.code === "auth.rate_limited")
      return (
        "Sign out was limited. This request revoked no session. Wait " +
        (error.retryAfter || 60) +
        " seconds before choosing Retry sign out."
      );
    if (error.code === "auth.authentication_required")
      return "This session could not be verified. An earlier sign out remains unconfirmed. Choose Retry sign out while it is available, or lock this tab locally.";
    return "Sign out was not confirmed. This request ended no session. Choose Retry sign out when the deployment is available, or lock this tab locally.";
  }
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
  const [step, setStep] = useState<"setup" | "login" | "invitation" | "logout">(
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
  const [logoutExpired, setLogoutExpired] = useState(false);
  const titleRef = useRef<HTMLHeadingElement>(null);

  useEffect(() => {
    if (step !== "logout" || busy) return;
    const remaining = client.logoutExpiresAt - Date.now();
    if (remaining <= 0) return;
    const timer = setTimeout(() => setLogoutExpired(true), remaining);
    return () => clearTimeout(timer);
  }, [step, busy, client]);

  async function signOut() {
    if (running.current || unavailable) return;
    running.current = true;
    setBusy(true);
    setStep("logout");
    setInvitation(undefined);
    setCopied(false);
    setError(false);
    setLogoutExpired(false);
    setMessage("Signing out of this session…");
    try {
      await client.signOut();
      setStep("login");
      setMessage(
        "This session is signed out. Its server credentials have been revoked.",
      );
    } catch (failure) {
      setError(true);
      setMessage(failureText(failure));
      if (client.logoutState === "idle") {
        setStep("login");
      } else {
        setLogoutExpired(
          client.logoutState === "expired" ||
            client.logoutExpiresAt <= Date.now(),
        );
      }
    } finally {
      running.current = false;
      setBusy(false);
      titleRef.current?.focus();
    }
  }

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
    setMessage(
      "This tab is locked locally. This does not confirm server sign out. Sign in again to continue.",
    );
    titleRef.current?.focus();
  }
  const title =
    step === "setup"
      ? "Create your Operator passkey"
      : step === "login"
        ? "Sign in to your deployment"
        : step === "logout"
          ? "Sign out of this session"
          : "Connect your Personal account";
  const action =
    step === "setup"
      ? "Create passkey"
      : step === "login"
        ? "Sign in with passkey"
        : step === "logout"
          ? "Retry sign out"
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
        {(step === "invitation" || step === "logout") && (
          <div className="session-actions">
            {step === "invitation" && (
              <button
                className="secondary"
                onClick={() => {
                  void signOut();
                }}
                disabled={busy}
              >
                Sign out
              </button>
            )}
            <button className="quiet" onClick={lock} disabled={busy}>
              Lock this tab
            </button>
          </div>
        )}
      </header>
      <main id="main" className="workspace" tabIndex={-1}>
        <section className="primary" aria-labelledby="title">
          <p className="eyebrow">
            {step === "setup"
              ? "First Operator"
              : step === "login"
                ? "Operator access"
                : step === "logout"
                  ? "Operator session"
                  : "Personal invitation"}
          </p>
          <h1 id="title" ref={titleRef} tabIndex={-1}>
            {title}
          </h1>
          <p className="intro">
            {step === "setup"
              ? "Use a passkey to administer this Scoplen deployment. Your device will ask you to verify and save it."
              : step === "login"
                ? "Use the passkey registered for this deployment. Your device will ask you to verify."
                : step === "logout"
                  ? "Sign out ends this browser session. Other browser sessions stay signed in. Lock this tab only removes access from this tab."
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
          {step === "logout" && logoutExpired && (
            <p className="notice error" role="alert">
              The retry window has expired. Server sign out remains
              unconfirmed. Use Lock this tab to remove local access.
            </p>
          )}
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
                if (step === "logout") void signOut();
                else void act();
              }}
              disabled={
                busy ||
                Boolean(unavailable) ||
                (step === "logout" && logoutExpired)
              }
              aria-busy={busy}
            >
              {busy
                ? step === "logout"
                  ? "Signing out…"
                  : step === "invitation"
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
            {step === "logout"
              ? "Wait for the server to confirm sign out. No retry runs automatically. Other browser sessions are unaffected."
              : step === "invitation"
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
