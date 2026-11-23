// SPDX-License-Identifier: AGPL-3.0-only
import { useEffect, useRef, useState, type RefObject } from "react";
import { AuthConnectionActions } from "./auth-connection.ts";
import { Field } from "./editors.tsx";
import { requestFeedback } from "./feedback.ts";
import type {
  AuthConnectionDraftResource,
  AuthConnectionResource,
} from "./generated/api.ts";
import { useLocale } from "./locale.tsx";
import { RequestFailure, type TeamApi } from "./team.ts";

export interface AuthConnectionHandle {
  hasLocalWork(): boolean;
}

export function ConnectionTarget({
  data,
}: {
  data: Pick<
    AuthConnectionResource["data"],
    "issuer" | "client_id" | "space_id"
  >;
}) {
  const { t } = useLocale();
  return (
    <dl className="draft-registration-fields">
      <div>
        <dt>{t("Issuer", "签发方")}</dt>
        <dd className="mono identifier" dir="ltr">
          {data.issuer}
        </dd>
      </div>
      <div>
        <dt>{t("Client ID", "客户端 ID")}</dt>
        <dd className="mono identifier" dir="ltr">
          {data.client_id}
        </dd>
      </div>
      <div>
        <dt>{t("Auth Space ID", "Auth Space ID")}</dt>
        <dd className="mono identifier" dir="ltr">
          {data.space_id}
        </dd>
      </div>
    </dl>
  );
}

type Action =
  | "read"
  | "start"
  | "status"
  | "abandon"
  | "confirm"
  | "suspend"
  | "recover"
  | "discard";

export function AuthConnectionPanel({
  api,
  organization,
  draft,
  disabled,
  handle,
  onBusy,
}: {
  api: TeamApi;
  organization: string;
  draft?: AuthConnectionDraftResource;
  disabled: boolean;
  handle: RefObject<AuthConnectionHandle | null>;
  onBusy: (busy: boolean) => void;
}) {
  const { t } = useLocale();
  const controller = useRef<AuthConnectionActions | null>(null);
  const running = useRef(false);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<{ error: unknown; action: Action }>();
  const [suspension, setSuspension] = useState<string>();
  const [discarding, setDiscarding] = useState(false);
  const [, refresh] = useState(0);
  const actions = controller.current;
  const current = actions?.current;
  const candidate = actions?.candidate;
  const pending = actions?.hasPendingReceipt;
  const waiting = (actions?.waitRemaining ?? 0) > 0;
  const blocked = busy || disabled;
  const awaitingRecovery =
    pending &&
    failure?.error instanceof RequestFailure &&
    failure.error.changed &&
    failure.action !== "recover";

  useEffect(() => {
    const workflow = new AuthConnectionActions(api, organization);
    controller.current = workflow;
    handle.current = { hasLocalWork: () => workflow.hasLocalWork };
    refresh((value) => value + 1);
    return () => {
      workflow.dispose();
      controller.current = null;
      handle.current = null;
      running.current = false;
      onBusy(false);
    };
  }, [api, organization, handle, onBusy]);
  useEffect(() => {
    const remaining = Math.max(
      actions?.candidateRemaining ?? 0,
      actions?.waitRemaining ?? 0,
    );
    if (!remaining) return;
    const timer = window.setTimeout(
      () => refresh((value) => value + 1),
      Math.ceil(remaining),
    );
    return () => window.clearTimeout(timer);
  }, [actions, candidate, waiting]);

  async function run(
    action: Action,
    execute: (workflow: AuthConnectionActions) => void | Promise<void>,
  ) {
    const workflow = controller.current;
    if (!workflow || disabled || running.current) return;
    running.current = true;
    setBusy(true);
    onBusy(true);
    setFailure(undefined);
    setSuspension(undefined);
    setDiscarding(false);
    try {
      await execute(workflow);
    } catch (error) {
      if (controller.current === workflow) setFailure({ error, action });
    } finally {
      if (controller.current === workflow) {
        running.current = false;
        setBusy(false);
        onBusy(false);
      }
    }
  }

  function failureMessage({
    action,
    error,
  }: {
    action: Action;
    error: unknown;
  }) {
    if (error instanceof RequestFailure) {
      if (error.code === "invalid_connection_candidate")
        return t(
          "Check the Space ID. The client ID and secret must each fit in 512 UTF-8 bytes and contain no control characters.",
          "请核对 Space ID。客户端 ID 和密钥各自不得超过 512 个 UTF-8 字节，也不能含控制字符。",
        );
      if (
        error.code === "policy.denied" &&
        (action === "start" || action === "confirm")
      )
        return t(
          "You need current Owner permission and a Scoplen password sign-in within five minutes. Sign in again and start a new verification if this session is too old.",
          "需要当前所有者权限，并且须在五分钟内使用 Scoplen 密码登录。如果会话过旧，请重新登录并开始验证。",
        );
      if (error.code === "connection_review_required")
        return t(
          "Review the current connection and draft before continuing.",
          "继续之前请核对当前连接和草案。",
        );
    }
    return requestFeedback(error, t);
  }

  return (
    <section
      className="form-fields"
      aria-labelledby="auth-connection-heading"
      aria-busy={busy}
    >
      <h3 id="auth-connection-heading">
        {t("Organization connection", "组织连接")}
      </h3>
      {current ? (
        <div className="draft-detail">
          <p>
            {current.data.status === "active"
              ? t("Active connection", "连接已激活")
              : t("Suspended connection", "连接已暂停")}
          </p>
          <ConnectionTarget data={current.data} />
        </div>
      ) : (
        !pending &&
        !actions?.receipt && (
          <p>
            {current === null
              ? t(
                  "No connection is visible for this team.",
                  "此团队没有可见的连接。",
                )
              : t(
                  "Read the connection status before making changes.",
                  "更改前请查看连接状态。",
                )}
          </p>
        )
      )}
      {failure && !waiting && !awaitingRecovery && (
        <p className="notice error" role="alert">
          {failureMessage(failure)}
        </p>
      )}
      {waiting && (
        <p className="notice" role="status">
          {t(
            "A verification may still be active in this browser session. Wait up to five minutes before starting again.",
            "此浏览器会话可能仍在验证中。请等待最多五分钟后再开始。",
          )}
        </p>
      )}
      {actions?.receipt && (
        <div className="notice" role="status">
          <p>
            {actions.receipt.data.status === "active"
              ? t("The original activation is confirmed.", "原激活操作已确认。")
              : t(
                  "The original suspension is confirmed.",
                  "原暂停操作已确认。",
                )}
          </p>
          <p>
            {t(
              "Read the connection to see its current status.",
              "查看连接可获取当前状态。",
            )}
          </p>
        </div>
      )}
      <div className="inline-actions">
        <button
          type="button"
          className="secondary"
          disabled={blocked}
          onClick={() => void run("read", (workflow) => workflow.readCurrent())}
        >
          {t("Read connection status", "查看连接状态")}
        </button>
        {current?.data.status === "active" && !pending && !suspension && (
          <button
            type="button"
            className="danger"
            disabled={blocked}
            onClick={() => setSuspension(current.id)}
          >
            {t("Review suspension", "查看暂停操作")}
          </button>
        )}
      </div>
      {suspension && current?.id === suspension && (
        <div className="notice">
          <p>
            {t(
              "This pauses sign-in through the current connection. Any team action that requires this connection stays blocked until the requirement is resolved.",
              "这会暂停通过当前连接登录。依赖此连接的团队操作会继续受限，直到该要求得到处理。",
            )}
          </p>
          <div className="inline-actions">
            <button
              type="button"
              className="secondary"
              disabled={blocked}
              onClick={() => setSuspension(undefined)}
            >
              {t("Keep connection", "保留连接")}
            </button>
            <button
              type="button"
              className="danger"
              disabled={blocked}
              onClick={() =>
                void run("suspend", (workflow) => workflow.suspend(suspension))
              }
            >
              {t("Suspend connection", "暂停连接")}
            </button>
          </div>
        </div>
      )}
      {pending && (
        <div className="notice">
          <p>
            {t(
              "The result is unconfirmed. You can recover the original result from this session while it is eligible.",
              "操作结果尚未确认。当前会话仍符合条件时，可恢复原操作的结果。",
            )}
          </p>
          {discarding && (
            <p>
              {t(
                "Clearing recovery information will leave only the current connection status available.",
                "清除恢复信息后，只能查看当前连接状态。",
              )}
            </p>
          )}
          <div className="inline-actions">
            <button
              type="button"
              className="primary-button"
              disabled={blocked || !actions?.canRecover || discarding}
              onClick={() =>
                void run("recover", (workflow) => workflow.recover())
              }
            >
              {t("Recover original result", "恢复原操作结果")}
            </button>
            <button
              type="button"
              className="secondary"
              disabled={blocked}
              onClick={() =>
                discarding
                  ? void run("discard", (workflow) => workflow.discardReceipt())
                  : setDiscarding(true)
              }
            >
              {discarding
                ? t("Clear recovery information", "清除恢复信息")
                : t("Review clearing recovery", "查看清除恢复信息的影响")}
            </button>
            {discarding && (
              <button
                type="button"
                className="secondary"
                disabled={blocked}
                onClick={() => setDiscarding(false)}
              >
                {t("Keep recovery information", "保留恢复信息")}
              </button>
            )}
          </div>
        </div>
      )}
      {candidate && !pending && (
        <div
          className="draft-detail"
          aria-label={t("Candidate connection", "候选连接")}
        >
          <ConnectionTarget data={candidate.attempt} />
          <p role="status">
            {candidate.attempt.status === "verified"
              ? t(
                  "Sign-in verified. Review these settings before installing the connection.",
                  "登录已验证。请在启用连接前核对这些设置。",
                )
              : candidate.attempt.status === "failed"
                ? t(
                    "Verification failed. Abandon this candidate before starting again.",
                    "验证失败。请先放弃此候选连接，再重新开始。",
                  )
                : t(
                    "Complete sign-in in the new tab, then return here to check verification.",
                    "请在新标签页完成登录，然后返回此处查看验证结果。",
                  )}
          </p>
          <div className="inline-actions">
            {candidate.url && !blocked && (
              <a href={candidate.url} target="_blank" rel="noopener noreferrer">
                {t(
                  "Open Auth sign-in in a new tab",
                  "在新标签页打开 Auth 登录",
                )}
              </a>
            )}
            {candidate.attempt.status === "pending" && (
              <button
                type="button"
                className="secondary"
                disabled={blocked}
                onClick={() =>
                  void run("status", (workflow) => workflow.checkCandidate())
                }
              >
                {t("Check verification", "查看验证结果")}
              </button>
            )}
            {draft &&
              candidate.attempt.status === "verified" &&
              draft.id === candidate.attempt.draft_generation &&
              current !== undefined &&
              (current?.id ?? null) === candidate.attempt.expected_revision && (
                <button
                  type="button"
                  className="primary-button"
                  disabled={blocked}
                  onClick={() =>
                    void run("confirm", (workflow) =>
                      workflow.confirm(draft.id),
                    )
                  }
                >
                  {current?.data.status === "active"
                    ? t("Replace connection", "替换连接")
                    : t("Activate connection", "激活连接")}
                </button>
              )}
            <button
              type="button"
              className="secondary"
              disabled={blocked}
              onClick={() =>
                void run("abandon", (workflow) => workflow.abandon())
              }
            >
              {t("Abandon candidate", "放弃候选连接")}
            </button>
          </div>
        </div>
      )}
      {draft &&
        current !== undefined &&
        !candidate &&
        !pending &&
        !waiting &&
        !suspension && (
          <form
            className="form-fields"
            autoComplete="off"
            onSubmit={(event) => {
              event.preventDefault();
              if (blocked) return;
              const data = new FormData(event.currentTarget);
              event.currentTarget.reset();
              void run("start", (workflow) =>
                workflow.start(draft, {
                  client_id: String(data.get("client_id")),
                  client_secret: String(data.get("client_secret")),
                  space_id: String(data.get("space_id")),
                }),
              );
              data.delete("client_secret");
            }}
          >
            <Field label={t("Candidate issuer", "候选签发方")}>
              <output className="mono identifier" dir="ltr">
                {draft.data.issuer}
              </output>
            </Field>
            <Field label={t("Client ID", "客户端 ID")}>
              <input
                name="client_id"
                dir="ltr"
                required
                maxLength={512}
                disabled={blocked}
                autoCapitalize="none"
                spellCheck={false}
              />
            </Field>
            <Field label={t("Client secret", "客户端密钥")}>
              <input
                name="client_secret"
                type="password"
                dir="ltr"
                autoComplete="off"
                required
                maxLength={512}
                disabled={blocked}
              />
            </Field>
            <Field label={t("Auth Space ID", "Auth Space ID")}>
              <input
                name="space_id"
                dir="ltr"
                required
                maxLength={96}
                pattern="spc_[A-Za-z0-9_\\-]{1,92}"
                disabled={blocked}
                autoCapitalize="none"
                spellCheck={false}
              />
            </Field>
            <div className="inline-actions">
              <button className="primary-button" disabled={blocked}>
                {t("Start candidate verification", "开始验证候选连接")}
              </button>
            </div>
          </form>
        )}
    </section>
  );
}
