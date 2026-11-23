// SPDX-License-Identifier: AGPL-3.0-only
import { useEffect, useRef, useState, type RefObject } from "react";
import { Field } from "./editors.tsx";
import { requestFeedback } from "./feedback.ts";
import type {
  AuthConnectionDraftResource,
  DraftLoginCredentials,
} from "./generated/api.ts";
import {
  draftRegistrationSettings,
  IssuerDraftActions,
} from "./issuer-draft.ts";
import { useLocale } from "./locale.tsx";
import { RequestFailure, type TeamApi } from "./team.ts";

export interface IssuerDraftHandle {
  hasLocalWork(): boolean;
}

export function DraftDetail({ draft }: { draft: AuthConnectionDraftResource }) {
  const { t } = useLocale();
  return (
    <div className="draft-detail">
      <h3>{t("Issuer draft", "签发方草案")}</h3>
      <p className="mono identifier" dir="ltr">
        {draft.data.issuer}
      </p>
      <p className="caption">
        {t("Generation", "草案版本")}{" "}
        <span className="mono identifier">{draft.id}</span>
      </p>
    </div>
  );
}

export function DraftRegistration({
  origin,
  issuer,
}: {
  origin: string;
  issuer: string;
}) {
  const { t } = useLocale();
  const [settings, setSettings] =
    useState<Awaited<ReturnType<typeof draftRegistrationSettings>>>();
  const [failed, setFailed] = useState(false);
  const [copy, setCopy] = useState<"copied" | "failed">();

  useEffect(() => {
    let active = true;
    void draftRegistrationSettings(origin, issuer).then(
      (value) => {
        if (active) setSettings(value);
      },
      () => {
        if (active) setFailed(true);
      },
    );
    return () => {
      active = false;
    };
  }, [origin, issuer]);

  return (
    <details className="draft-registration">
      <summary>{t("Application registration details", "应用注册参数")}</summary>
      <p>
        {t(
          "Give these settings to your Auth administrator to register a private, confidential application for human sign-in.",
          "将这些参数交给 Auth 管理员，登记一个私有机密应用并启用人类登录。",
        )}
      </p>
      {failed && (
        <p role="alert">
          {t(
            "Registration details could not be generated. Reload this page or use the server CLI worksheet.",
            "无法生成注册参数。请刷新页面或使用服务器 CLI 获取参数。",
          )}
        </p>
      )}
      {settings && (
        <>
          <dl className="draft-registration-fields">
            {Object.entries(settings).map(([field, value]) => (
              <div key={field}>
                <dt>
                  <code>{field}</code>
                </dt>
                <dd className="mono identifier" dir="ltr">
                  {value}
                </dd>
              </div>
            ))}
          </dl>
          <div className="inline-actions">
            <button
              className="secondary"
              type="button"
              onClick={async () => {
                try {
                  await navigator.clipboard.writeText(
                    JSON.stringify(settings, null, 2),
                  );
                  setCopy("copied");
                } catch {
                  setCopy("failed");
                }
              }}
            >
              {t("Copy registration settings", "复制注册参数")}
            </button>
          </div>
          {copy && (
            <p role="status">
              {copy === "copied"
                ? t("Registration settings copied.", "已复制注册参数。")
                : t(
                    "Clipboard unavailable. You can select and copy the values above.",
                    "无法访问剪贴板。可选中并复制上方参数。",
                  )}
            </p>
          )}
        </>
      )}
    </details>
  );
}

function DraftLoginPanel({
  login,
  busy,
  disabled,
  onStart,
  onRead,
}: {
  login: IssuerDraftActions["login"];
  busy: boolean;
  disabled: boolean;
  onStart: (credentials: DraftLoginCredentials) => void;
  onRead: () => void;
}) {
  const { t } = useLocale();
  const pending =
    login?.kind === "attempt" && login.attempt.status === "pending";
  return (
    <section aria-labelledby="issuer-test-heading" className="form-fields">
      <h3 id="issuer-test-heading">{t("Test sign-in", "测试登录")}</h3>
      {login?.kind === "wait" && (
        <p className="notice" role="status">
          {t(
            "A test may still be active. Wait up to five minutes for it to expire, then start a new test here.",
            "可能仍有测试在进行。请等待最多五分钟，待其过期后在此开始新测试。",
          )}
        </p>
      )}
      {login?.kind === "unavailable" && (
        <p className="notice" role="status">
          {t(
            "This test is no longer available. Read the current draft before starting a new test.",
            "此次测试已不可用。请先查看当前草案，再开始新测试。",
          )}
        </p>
      )}
      {login?.kind === "expired" && (
        <p className="notice" role="status">
          {t(
            "The test window has ended. Start a fresh test.",
            "测试时段已结束。请开始新测试。",
          )}
        </p>
      )}
      {login?.kind === "attempt" && (
        <p className="notice" role="status">
          {login.attempt.status === "verified"
            ? t(
                "Sign-in verified. This test leaves team access as it was. Review the test in the Audit timeline.",
                "登录已验证。团队访问保持原状。可在审计时间线中查看此次测试。",
              )
            : login.attempt.status === "failed"
              ? t(
                  "Sign-in failed. Check the application registration and review the Audit timeline before starting a new test.",
                  "登录失败。请核对应用注册参数并查看审计时间线，再开始新测试。",
                )
              : t(
                  "Complete sign-in in the new tab, then return here and check the result. Keep this team tab open.",
                  "在新标签页登录，然后返回此处查看结果。请保持此团队标签页打开。",
                )}
        </p>
      )}
      {pending && (
        <div className="inline-actions">
          {login.url && !disabled && !busy && (
            <a href={login.url} target="_blank" rel="noopener noreferrer">
              {t("Open Auth sign-in in a new tab", "在新标签页打开 Auth 登录")}
            </a>
          )}
          <button
            type="button"
            className="secondary"
            disabled={disabled || busy}
            onClick={onRead}
          >
            {busy
              ? t("Checking result…", "正在查看结果…")
              : t("Check test result", "查看测试结果")}
          </button>
        </div>
      )}
      {!pending && login?.kind !== "wait" && login?.kind !== "unavailable" && (
        <form
          className="form-fields"
          autoComplete="off"
          onSubmit={(event) => {
            event.preventDefault();
            if (disabled || busy) return;
            const form = new FormData(event.currentTarget);
            event.currentTarget.reset();
            onStart({
              client_id: String(form.get("client_id")),
              client_secret: String(form.get("client_secret")),
            });
          }}
        >
          <Field label={t("Client ID", "客户端 ID")}>
            <input
              name="client_id"
              dir="ltr"
              required
              maxLength={512}
              autoCapitalize="none"
              spellCheck={false}
              disabled={disabled || busy}
            />
          </Field>
          <Field
            label={t("Client secret", "客户端密钥")}
            help={t(
              "Use the secret from your application registration. You will enter it again for each test.",
              "请使用应用注册时获得的密钥。每次测试都需要重新输入。",
            )}
          >
            <input
              name="client_secret"
              type="password"
              dir="ltr"
              autoComplete="off"
              required
              maxLength={512}
              disabled={disabled || busy}
            />
          </Field>
          <div className="inline-actions">
            <button className="secondary" disabled={disabled || busy}>
              {busy
                ? t("Starting test…", "正在开始测试…")
                : t("Start sign-in test", "开始登录测试")}
            </button>
          </div>
        </form>
      )}
    </section>
  );
}

export function IssuerDraftPanel({
  api,
  organization,
  teamName,
  disabled,
  handle,
  onBusy,
}: {
  api: TeamApi;
  organization: string;
  teamName: string;
  disabled: boolean;
  handle: RefObject<IssuerDraftHandle | null>;
  onBusy: (busy: boolean) => void;
}) {
  const { t } = useLocale();
  const workflow = useRef<IssuerDraftActions | null>(null),
    running = useRef(false);
  const typed = useRef(false);
  const [issuer, setIssuer] = useState(""),
    [busy, setBusy] = useState(true);
  const [receipt, setReceipt] = useState<"POST" | "DELETE">();
  const [review, setReview] = useState<
    { cancel: string } | { discard: true }
  >();
  const [failure, setFailure] = useState<unknown>();
  const [testFailure, setTestFailure] = useState<{
    error: unknown;
    start: boolean;
  }>();
  const [, tick] = useState(0);
  const current = workflow.current?.current,
    pending = workflow.current?.pending,
    login = workflow.current?.login;
  const blocked = disabled || busy;
  useEffect(() => {
    const actions = new IssuerDraftActions(api, organization);
    workflow.current = actions;
    handle.current = {
      hasLocalWork: () =>
        typed.current ||
        Boolean(actions.pending) ||
        (actions.login?.kind === "attempt" &&
          actions.login.attempt.status === "pending"),
    };
    running.current = true;
    setBusy(true);
    onBusy(true);
    void actions
      .read()
      .catch((error: unknown) => {
        if (workflow.current === actions) setFailure(error);
      })
      .finally(() => {
        if (workflow.current === actions) {
          running.current = false;
          setBusy(false);
          onBusy(false);
        }
      });
    return () => {
      workflow.current = null;
      actions.dispose();
      handle.current = null;
      onBusy(false);
    };
  }, [api, organization, handle, onBusy]);
  useEffect(() => {
    if (!pending) return;
    const timer = window.setInterval(() => tick((value) => value + 1), 30_000);
    return () => window.clearInterval(timer);
  }, [pending]);
  useEffect(() => {
    const delay = workflow.current?.loginRemaining;
    if (!delay) return;
    const timer = window.setTimeout(
      () => tick((value) => value + 1),
      Math.ceil(delay),
    );
    return () => window.clearTimeout(timer);
  }, [login]);

  function updateIssuer(value: string) {
    typed.current = Boolean(value);
    setIssuer(value);
  }
  async function run(
    operation: "read" | "create" | "cancel" | "confirm" | "discard",
  ) {
    const actions = workflow.current;
    if (!actions || running.current || disabled) return;
    if (
      operation === "cancel" &&
      (!review ||
        !("cancel" in review) ||
        actions.current?.etag !== review.cancel)
    )
      return;
    if (operation === "discard" && !(review && "discard" in review)) return;
    running.current = true;
    setBusy(true);
    onBusy(true);
    setFailure(undefined);
    setTestFailure(undefined);
    setReview(undefined);
    if (operation !== "read") setReceipt(undefined);
    try {
      if (operation === "discard") actions.discard();
      else if (operation !== "read") {
        const method =
          operation === "confirm"
            ? actions.pending?.method
            : operation === "cancel"
              ? "DELETE"
              : "POST";
        if (operation === "create") await actions.create(issuer);
        else if (operation === "cancel") await actions.cancel();
        else await actions.confirm();
        if (workflow.current !== actions) return;
        setReceipt(method);
      }
      if (operation !== "read") updateIssuer("");
      const result = await actions.read();
      if (workflow.current === actions && result) updateIssuer("");
    } catch (error) {
      if (workflow.current === actions) {
        setFailure(error);
        if (actions.pending || actions.current === undefined) updateIssuer("");
      }
    } finally {
      if (workflow.current === actions) {
        running.current = false;
        setBusy(false);
        onBusy(false);
      }
    }
  }

  async function runTest(credentials?: DraftLoginCredentials) {
    const actions = workflow.current;
    if (!actions || running.current || disabled || !actions.current || review)
      return;
    running.current = true;
    setBusy(true);
    onBusy(true);
    setTestFailure(undefined);
    try {
      if (credentials) await actions.startLogin(credentials);
      else await actions.readLogin();
    } catch (error) {
      if (workflow.current === actions && actions.login?.kind !== "wait")
        setTestFailure({ error, start: Boolean(credentials) });
    } finally {
      if (workflow.current === actions) {
        running.current = false;
        setBusy(false);
        onBusy(false);
      }
    }
  }

  function testFeedback({ error, start }: { error: unknown; start: boolean }) {
    if (error instanceof RequestFailure) {
      switch (error.code) {
        case "invalid_draft_client":
          return t(
            "Enter a Client ID and secret of at most 512 UTF-8 bytes each, without control characters.",
            "请输入客户端 ID 和密钥，每项最多 512 个 UTF-8 字节，且不能包含控制字符。",
          );
        case "organization.auth_provider_unavailable":
          return t(
            "Scoplen could not use this issuer’s discovery document. Check that the issuer is reachable and the application supports confidential OIDC sign-in.",
            "Scoplen 无法使用此签发方的发现文档。请检查签发方是否可达，以及应用是否支持机密 OIDC 登录。",
          );
        case "policy.denied":
          return t(
            "This session or issuer cannot run the test. Ask your deployment operator to check issuer trust and sign in again to obtain current permissions.",
            "当前会话或签发方无法运行测试。请联系部署运营人员检查签发方信任设置，并重新登录以取得当前权限。",
          );
        case "invalid_response":
        case "response_lost":
          if (!start)
            return t(
              "Could not verify the test result. Check it again from this tab.",
              "无法验证测试结果。请在此标签页重新查看。",
            );
      }
    }
    return requestFeedback(error, t);
  }
  const failureMessage =
    failure instanceof RequestFailure && failure.code === "invalid_draft_issuer"
      ? t(
          "Enter an HTTPS issuer with its exact path. Remove any credentials, query or fragment and keep it within 2,048 UTF-8 bytes.",
          "请输入带有精确路径的 HTTPS 签发方地址。请移除凭据、查询参数及片段，并将长度限制在 2,048 个 UTF-8 字节内。",
        )
      : failure instanceof RequestFailure && failure.status === 403
        ? t(
            "Access denied. Ask a team owner to check your role and the team policy. If your access has changed, lock this tab and sign in again.",
            "访问被拒绝。请联系团队所有者检查您的角色和团队策略。若权限已变更，请锁定此标签页并重新登录。",
          )
        : failure instanceof RequestFailure &&
            failure.code === "invalid_response" &&
            !failure.changed
          ? t(
              "The server's current draft response could not be verified. Read it again before making a change.",
              "无法验证服务器返回的当前草案。请重新读取后再进行更改。",
            )
          : requestFeedback(failure, t);
  return (
    <section
      className="issuer-draft"
      aria-labelledby="issuer-draft-heading"
      aria-busy={busy}
    >
      <h2 id="issuer-draft-heading">
        {t("Connect Plystra Auth", "连接 Plystra Auth")}
      </h2>
      <p>
        {t(
          "Use your existing Auth instance to prepare and test an enterprise sign-in connection. Teams can keep using Scoplen accounts during setup.",
          "使用已有的 Auth 实例准备并测试企业登录连接。设置期间，团队可以继续使用 Scoplen 账号。",
        )}
      </p>
      {receipt && (
        <p className="notice" role="status">
          {receipt === "POST"
            ? t("The original save was confirmed.", "原保存操作已确认。")
            : t(
                "The original cancellation was confirmed.",
                "原取消操作已确认。",
              )}
        </p>
      )}
      {failure !== undefined && (
        <p role="alert" className="notice error">
          {failureMessage}
        </p>
      )}
      {!busy && current && <DraftDetail draft={current} />}
      {!busy && current && !pending && !review && !disabled && (
        <DraftRegistration
          key={`${organization}:${current.id}:${api.transport.origin}`}
          origin={api.transport.origin}
          issuer={current.data.issuer}
        />
      )}
      {current && !pending && !review && (
        <>
          {testFailure && (
            <p role="alert" className="notice error">
              {testFeedback(testFailure)}
            </p>
          )}
          <DraftLoginPanel
            key={current.id}
            login={login}
            busy={busy}
            disabled={disabled}
            onStart={(credentials) => void runTest(credentials)}
            onRead={() => void runTest()}
          />
        </>
      )}
      {!busy && current === null && (
        <p>
          {t(
            "No draft is visible to this session in the selected team.",
            "本会话在所选团队中没有可见的草案。",
          )}
        </p>
      )}
      {!busy && current === undefined && (
        <p>{t("Current draft status is unknown.", "当前草案状态未知。")}</p>
      )}
      {!busy && current === null && !pending && (
        <form
          className="form-fields"
          onSubmit={(event) => {
            event.preventDefault();
            void run("create");
          }}
        >
          <Field
            label={t("Auth instance issuer URL", "Auth 实例地址（issuer）")}
            help={t(
              "Include the tenant path and trailing slash exactly as supplied.",
              "请按提供的原样包含租户路径及末尾斜杠。",
            )}
          >
            <input
              type="text"
              inputMode="url"
              spellCheck={false}
              autoCapitalize="none"
              autoComplete="off"
              dir="ltr"
              required
              maxLength={2048}
              disabled={blocked}
              value={issuer}
              onChange={(event) => updateIssuer(event.target.value)}
            />
          </Field>
          <div className="inline-actions">
            <button className="primary-button" disabled={blocked || !issuer}>
              {t("Save draft", "保存草案")}
            </button>
          </div>
        </form>
      )}
      {pending && (
        <div className="notice pending-operation">
          <h3>
            {t("Original operation awaiting confirmation", "原操作待确认")}
          </h3>
          <p>
            {t(
              "Only this sign-in can confirm the original request within 24 hours. Reading the current draft cannot establish the earlier outcome.",
              "原请求只能在 24 小时内用本次登录确认。查看当前草案无法证明此前操作的结果。",
            )}
          </p>
          <div className="inline-actions">
            <button
              className="secondary"
              disabled={blocked || !workflow.current?.canConfirm}
              onClick={() => void run("confirm")}
            >
              {t("Confirm original operation", "确认原操作")}
            </button>
            <button
              className="quiet"
              disabled={blocked}
              onClick={() => setReview({ discard: true })}
            >
              {t("Discard confirmation data", "丢弃确认数据")}
            </button>
          </div>
          {!workflow.current?.canConfirm && (
            <p>
              {t(
                "The original confirmation window has closed. Discard the confirmation data to review the current draft.",
                "原操作的确认期限已结束。请丢弃确认数据并审阅当前草案。",
              )}
            </p>
          )}
        </div>
      )}
      <div className="inline-actions">
        <button
          className="secondary"
          disabled={blocked}
          onClick={() => void run("read")}
        >
          {t("Read current draft", "查看当前草案")}
        </button>
        {current && !pending && !review && (
          <button
            className="danger"
            disabled={blocked}
            onClick={() => setReview({ cancel: current.etag })}
          >
            {t("Review cancellation", "审阅取消操作")}
          </button>
        )}
      </div>
      {review && (
        <div className="notice">
          {"cancel" in review && current?.etag === review.cancel ? (
            <>
              <h3>{t("Cancel this issuer draft?", "取消此签发方草案？")}</h3>
              <p>
                {t(
                  `Review the issuer and generation above for ${teamName} before cancelling.`,
                  `取消前，请核对上方显示的团队“${teamName}”的签发方及草案版本。`,
                )}
              </p>
              <div className="inline-actions">
                <button
                  className="secondary"
                  autoFocus
                  disabled={blocked}
                  onClick={() => setReview(undefined)}
                >
                  {t("Keep draft", "保留草案")}
                </button>
                <button
                  className="danger"
                  disabled={blocked}
                  onClick={() => void run("cancel")}
                >
                  {t("Cancel this draft", "取消此草案")}
                </button>
              </div>
            </>
          ) : (
            "discard" in review && (
              <>
                <h3>
                  {t(
                    "Discard the original confirmation?",
                    "丢弃原操作的确认数据？",
                  )}
                </h3>
                <p>
                  {t(
                    "The operation may already have completed. Discarding loses the original request and reads the current draft again.",
                    "操作可能已经完成。丢弃后将失去原请求，并重新读取当前草案。",
                  )}
                </p>
                <div className="inline-actions">
                  <button
                    className="secondary"
                    autoFocus
                    disabled={blocked}
                    onClick={() => setReview(undefined)}
                  >
                    {t("Keep confirmation", "保留确认数据")}
                  </button>
                  <button
                    className="danger"
                    disabled={blocked}
                    onClick={() => void run("discard")}
                  >
                    {t("Discard and read draft", "丢弃并读取草案")}
                  </button>
                </div>
              </>
            )
          )}
        </div>
      )}
    </section>
  );
}
