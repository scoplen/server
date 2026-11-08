// SPDX-License-Identifier: AGPL-3.0-only
import { useEffect, useReducer, useRef, useState } from "react";
import type { AccountClient } from "./account.ts";
import { AccountFailure } from "./account-http.ts";
import { TeamApi } from "./team.ts";
import { TeamWorkspace } from "./team-view.tsx";
import { Field } from "./editors.tsx";
import { LanguageControl, useLocale } from "./locale.tsx";
import type { InvitationCrypto, JoinTarget } from "./invitation.ts";
import type { RuleGenerator } from "./rule-editor.tsx";

type Translate = (en: string, zh: string) => string;
function authFeedback(failure: unknown, t: Translate) {
  if (!(failure instanceof AccountFailure))
    return t(
      "Sign-in could not be completed. Start a fresh sign-in; the previous request is never repeated automatically.",
      "无法完成登录。请重新登录，之前的请求不会自动重放。",
    );
  let message: string;
  if (failure.code === "session_changed") {
    message = t(
      "This tab was cleared. Sign in again to start a fresh session.",
      "此标签页已清除。请重新登录以开始新的会话。",
    );
  } else if (failure.operation === "logout") {
    message =
      failure.code === "logout_expired"
        ? t(
            "The sign-out retry window has expired. Server sign out remains unconfirmed. Lock this tab to clear its local credentials.",
            "退出确认期限已过，服务器退出仍未确认。请锁定此标签页以清除本地凭据。",
          )
        : failure.changed
          ? t(
              "Sign out remains unconfirmed. Keep this tab open and choose Retry sign out, or lock this tab locally. Protected actions are blocked and no retry runs automatically.",
              "退出登录尚未确认。请保留此标签页并选择重试退出，或在本地锁定标签页。受保护操作已阻止，不会自动重试。",
            )
          : t(
              "Sign out was not confirmed. Keep the original session for an explicit retry, or lock this tab locally. Other browser sessions are unaffected.",
              "退出登录未获确认。可保留原会话并明确重试，或在本地锁定此标签页。其他浏览器会话不受影响。",
            );
  } else if (failure.code.endsWith("rate_limited")) {
    message = t(
      `Too many attempts. Wait ${failure.retryAfter || 60} seconds, then start a fresh sign-in.`,
      `尝试次数过多。请等待 ${failure.retryAfter || 60} 秒后重新登录。`,
    );
  } else if (
    ["invalid_password_input", "password_derivation_failed"].includes(
      failure.code,
    )
  ) {
    message = t(
      "The password could not be checked. Use the exact username and existing Account password in a current browser. Close memory-heavy tabs before trying again; the password check is never weakened.",
      "无法检查密码。请在当前版本的浏览器中输入精确用户名及现有账号密码。重试前可关闭占用大量内存的标签页；密码检查不会降低强度。",
    );
  } else if (failure.code === "password_worker_unavailable") {
    message = t(
      "This browser could not start the password check. Reload the console and use a current browser. Contact the deployment owner if the problem continues.",
      "浏览器无法启动密码检查。请重新加载控制台并使用当前版本的浏览器。若问题持续，请联系部署所有者。",
    );
  } else if (failure.code === "password_attempt_expired") {
    message = t(
      "The password attempt expired before sign-in. Submit the form again to start a fresh attempt.",
      "密码验证尝试在登录前已过期。请重新提交表单以开始新的尝试。",
    );
  } else if (failure.code === "auth.authentication_required") {
    message = t(
      "Sign-in could not be verified. Check the exact username and existing Account password, then start a fresh attempt.",
      "无法验证登录。请检查精确用户名及现有账号密码，再开始新的尝试。",
    );
  } else if (failure.code === "policy.denied") {
    message = t(
      "This deployment did not allow the sign-in request. Check its console address and contact the deployment owner.",
      "此部署不允许该登录请求。请检查控制台地址并联系部署所有者。",
    );
  } else if (failure.code.endsWith("storage_unavailable")) {
    message = t(
      "The deployment is temporarily unavailable. No session was confirmed. Start a fresh sign-in when it is available.",
      "部署暂时不可用，未确认建立会话。请在服务恢复后重新登录。",
    );
  } else {
    message = t(
      "The sign-in result could not be confirmed. Start a fresh sign-in; no password-login request is replayed automatically.",
      "无法确认登录结果。请重新登录；密码登录请求不会自动重放。",
    );
    if (/^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$/.test(failure.code))
      message += ` ${t("Code", "代码")}: ${failure.code}`;
  }
  return failure.requestId
    ? `${message} ${t("Reference", "参考编号")}: ${failure.requestId}`
    : message;
}

export function AccountApp({
  client,
  origin,
  shared,
  initialTarget,
  invalidLink,
  unavailable,
}: {
  client?: AccountClient;
  origin: string;
  shared: { invitations: InvitationCrypto; rules: RuleGenerator };
  initialTarget?: JoinTarget;
  invalidLink: boolean;
  unavailable?: "https" | "browser";
}) {
  const { t } = useLocale();
  const [, redraw] = useReducer((value: number) => value + 1, 0);
  const [api, setApi] = useState<TeamApi | undefined>(undefined);
  const [username, setUsername] = useState("");
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<unknown>(undefined);
  const running = useRef(false);
  const title = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    document.title = `Scoplen · ${t("Team console", "团队控制台")}`;
  }, [t]);
  useEffect(() => client?.subscribe(redraw), [client]);
  useEffect(() => {
    if (!client?.blocked) return;
    const delay = client.logoutExpiresAt - Date.now();
    if (delay <= 0) return;
    const timer = setTimeout(redraw, delay);
    return () => clearTimeout(timer);
  }, [client, client?.blocked, client?.logoutExpiresAt]);

  async function signIn(form: HTMLFormElement) {
    if (!client || running.current || unavailable) return;
    running.current = true;
    setBusy(true);
    setFailure(undefined);
    const passwordInput = form.elements.namedItem(
      "password",
    ) as HTMLInputElement;
    const usernameInput = form.elements.namedItem(
      "username",
    ) as HTMLInputElement;
    const name = usernameInput.value;
    let raw = passwordInput.value;
    passwordInput.value = "";
    let owned: Uint8Array | undefined;
    try {
      if (!raw.isWellFormed())
        throw new AccountFailure("login", "invalid_password_input");
      owned = new TextEncoder().encode(raw);
      raw = "";
      await client.signIn(name, owned);
      if (client.authenticated) {
        setUsername(name);
        setApi(new TeamApi(client));
      }
    } catch (error) {
      setFailure(error);
    } finally {
      raw = "";
      owned?.fill(0);
      running.current = false;
      setBusy(false);
      title.current?.focus();
    }
  }
  async function signOut() {
    if (!client || running.current) return;
    running.current = true;
    setBusy(true);
    setFailure(undefined);
    try {
      await client.signOut();
    } catch (error) {
      setFailure(error);
    } finally {
      running.current = false;
      setBusy(false);
      if (!client.authenticated) setApi(undefined);
    }
  }
  if (client?.authenticated && api)
    return (
      <TeamWorkspace
        api={api}
        username={username}
        shared={shared}
        initialTarget={initialTarget}
        session={{
          busy,
          blocked: client.blocked,
          message: failure
            ? authFeedback(failure, t)
            : client.logoutState === "expired"
              ? t(
                  "Sign out remains unconfirmed and its retry window has expired. Lock this tab to remove local access.",
                  "退出登录仍未确认，且重试期限已过。请锁定此标签页以清除本地访问。",
                )
              : "",
          expired: client.logoutState === "expired",
        }}
        onLock={() => {
          client.lock();
          setApi(undefined);
          setFailure(undefined);
        }}
        onSignOut={signOut}
      />
    );
  const unavailableText =
    unavailable === "https"
      ? t(
          "Open this console at its configured HTTPS address. Account passwords and browser sessions require HTTPS.",
          "请使用配置的 HTTPS 地址打开控制台。账号密码及浏览器会话需要 HTTPS。",
        )
      : unavailable === "browser"
        ? t(
            "This browser does not support the required browser-key, Worker and WebAssembly features. Use a current browser over HTTPS.",
            "此浏览器不支持所需的浏览器密钥、Worker 及 WebAssembly 功能。请通过 HTTPS 使用当前版本的浏览器。",
          )
        : undefined;
  return (
    <div className="console-shell account-shell">
      <a className="skip-link" href="#account-main">
        {t("Skip to content", "跳至内容")}
      </a>
      <header className="console-header">
        <span className="wordmark">Scoplen</span>
        <span className="context">{t("Team console", "团队控制台")}</span>
        <div className="session-actions">
          <LanguageControl />
          <a className="operator-link" href="/operator">
            {t("Operator access", "Operator 入口")}
          </a>
        </div>
      </header>
      <main id="account-main" className="workspace">
        <section className="primary" aria-labelledby="account-title">
          <p className="eyebrow">
            {initialTarget
              ? t("Team invitation", "团队邀请")
              : t("Existing Account", "现有账号")}
          </p>
          <h1 id="account-title" ref={title} tabIndex={-1}>
            {t("Sign in to your teams", "登录您的团队")}
          </h1>
          <p className="intro">
            {t(
              "Manage your teams, members and shared access with your existing Account. Use this deployment's exact username and password.",
              "使用现有账号管理团队、成员及共享访问。请输入此部署的精确用户名及密码。",
            )}
          </p>
          {unavailableText && (
            <p className="notice error" role="alert">
              {unavailableText}
            </p>
          )}
          {invalidLink && (
            <p className="notice error" role="alert">
              {t(
                "This invitation link is invalid. Ask for the original link and its separate invitation password. You can still sign in to your teams.",
                "邀请链接无效。请索取原始链接及单独的邀请密码。您仍可登录自己的团队。",
              )}
            </p>
          )}
          {client?.reason === "signed_out" && (
            <p className="notice" role="status">
              {t(
                "This browser session was signed out. Other sessions are unaffected.",
                "此浏览器会话已退出，其他会话不受影响。",
              )}
            </p>
          )}
          {client?.reason === "refresh_sign_in_required" && (
            <p className="notice error" role="alert">
              {t(
                "The session could not be refreshed. Sign in again with a fresh password attempt. Any earlier unconfirmed team operation still needs review; a new session cannot confirm its original receipt.",
                "无法刷新会话。请使用新的密码验证尝试重新登录。之前未确认的团队操作仍需审阅，新会话不能确认其原回执。",
              )}
            </p>
          )}
          {failure !== undefined && (
            <p className="notice error" role="alert">
              {authFeedback(failure, t)}
            </p>
          )}
          <form
            className="account-sign-in"
            onSubmit={(event) => {
              event.preventDefault();
              void signIn(event.currentTarget);
            }}
          >
            <fieldset
              className="form-fields"
              disabled={busy || Boolean(unavailable)}
            >
              <Field
                label={t("Username", "用户名")}
                help={t(
                  "Use the exact deployment username. An email address is not a username alias.",
                  "请使用此部署的精确用户名。电子邮件地址不是用户名别名。",
                )}
              >
                <input
                  name="username"
                  autoComplete="username"
                  autoCapitalize="none"
                  autoCorrect="off"
                  spellCheck={false}
                  minLength={3}
                  maxLength={64}
                  required
                  defaultValue={username}
                />
              </Field>
              <Field label={t("Account password", "账号密码")}>
                <input
                  name="password"
                  type="password"
                  autoComplete="current-password"
                  maxLength={2_048}
                  required
                />
              </Field>
              <button className="primary-button" aria-busy={busy}>
                {busy
                  ? t("Checking your password…", "正在检查密码…")
                  : t("Sign in", "登录")}
              </button>
            </fieldset>
          </form>
          {busy && (
            <button
              className="quiet"
              onClick={() => {
                client?.lock();
                setApi(undefined);
              }}
            >
              {t("Cancel and clear this tab", "取消并清除此标签页")}
            </button>
          )}
          <p className="caption">
            {t(
              "Create an Account, recover a password and open a Personal vault in the desktop app. This console does not open SSH sessions.",
              "请在桌面端创建账号、恢复密码及打开个人保险库。本控制台不会发起 SSH 会话。",
            )}
          </p>
        </section>
        <aside className="guide" aria-labelledby="account-guide-title">
          <h2 id="account-guide-title">
            {t("Your team workspace", "您的团队空间")}
          </h2>
          <ol className="steps">
            <li>
              <span className="step-number">01</span>
              <div>
                <h3>{t("Choose a team", "选择团队")}</h3>
                <p>
                  {t(
                    "Use a current membership, create a permitted team or accept an invitation addressed to your Account.",
                    "使用当前成员资格、创建获准的团队，或接受发给您账号的邀请。",
                  )}
                </p>
              </div>
            </li>
            <li>
              <span className="step-number">02</span>
              <div>
                <h3>{t("Configure shared access", "配置共享访问")}</h3>
                <p>
                  {t(
                    "Manage inventory and members. Grant asset visibility and connection permission separately.",
                    "管理资产及成员，分别授予资产可见与连接权限。",
                  )}
                </p>
              </div>
            </li>
            <li>
              <span className="step-number">03</span>
              <div>
                <h3>{t("Sign out when finished", "完成后退出登录")}</h3>
                <p>
                  {t(
                    "Confirm server sign out, or lock this tab locally. Reloading always requires a fresh sign-in.",
                    "确认服务器退出，或在本地锁定此标签页。重新加载后始终需要重新登录。",
                  )}
                </p>
              </div>
            </li>
          </ol>
          <div className="boundary">
            <h2>
              {t("Personal keys stay in the app", "个人密钥保留在桌面端")}
            </h2>
            <p>
              {t(
                "Team data is visible to this deployment. This browser session opens no Personal vault, Account roots or enrolled Device credentials.",
                "团队数据可由此部署读取。此浏览器会话不会打开个人保险库、账号根密钥或已注册设备的凭据。",
              )}
            </p>
          </div>
        </aside>
      </main>
      <footer>
        <span>{t("Self-hosted by your deployment", "由您的部署自行托管")}</span>
        <span className="deployment">{new URL(origin).host}</span>
      </footer>
    </div>
  );
}
