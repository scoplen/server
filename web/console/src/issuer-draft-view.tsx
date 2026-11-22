// SPDX-License-Identifier: AGPL-3.0-only
import { useEffect, useRef, useState, type RefObject } from "react";
import { Field } from "./editors.tsx";
import { requestFeedback } from "./feedback.ts";
import type { AuthConnectionDraftResource } from "./generated/api.ts";
import { IssuerDraftActions } from "./issuer-draft.ts";
import { useLocale } from "./locale.tsx";
import { RequestFailure, type TeamApi } from "./team.ts";

export interface IssuerDraftHandle {
  hasLocalWork(): boolean;
}

export function DraftDetail({ draft }: { draft: AuthConnectionDraftResource }) {
  const { t } = useLocale();
  return (
    <div className="draft-detail">
      <h3>{t("Untested issuer draft", "尚未验证的签发方草案")}</h3>
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
  const [, tick] = useState(0);
  const current = workflow.current?.current,
    pending = workflow.current?.pending;
  const blocked = disabled || busy;
  useEffect(() => {
    const actions = new IssuerDraftActions(api, organization);
    workflow.current = actions;
    handle.current = {
      hasLocalWork: () => typed.current || Boolean(actions.pending),
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
          "Save your Auth instance’s issuer URL as an untested draft. Enterprise sign-in requires separate setup.",
          "将 Auth 实例的 issuer 地址保存为待验证的草案。启用企业登录需要另行配置。",
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
