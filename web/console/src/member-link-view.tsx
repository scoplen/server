// SPDX-License-Identifier: AGPL-3.0-only
import { useEffect, useId, useRef, useState, type RefObject } from "react";
import { ConnectionTarget } from "./auth-connection-view.tsx";
import { requestFeedback } from "./feedback.ts";
import { useLocale } from "./locale.tsx";
import { MemberLinkActions } from "./member-link.ts";
import { RequestFailure, type TeamApi } from "./team.ts";

export function MemberLinkPanel({
  api,
  organization,
  membership,
  teamName,
  username,
  named = false,
  disabled,
  handle,
  onBusy,
}: {
  api: TeamApi;
  organization: string;
  membership: string;
  teamName: string;
  username: string;
  named?: boolean;
  disabled: boolean;
  handle: RefObject<{ hasLocalWork(): boolean } | null>;
  onBusy: (busy: boolean) => void;
}) {
  const { t } = useLocale();
  const heading = useId();
  const controller = useRef<MemberLinkActions | null>(null);
  const running = useRef(false);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<unknown>();
  const [notice, setNotice] = useState("");
  const [review, setReview] = useState<{ linkId: string } | "discard">();
  const [, refresh] = useState(0);
  const workflow = controller.current;
  const status = workflow?.current,
    candidate = workflow?.candidate,
    link = status?.link;
  const blocked = disabled || busy;
  const revision = status?.connection;
  const wait = workflow?.waitRemaining ?? 0;
  const remaining = workflow?.remaining ?? 0;
  const recover = workflow?.recoveryRemaining ?? 0;
  const generation = api.transport.sessionGeneration;
  useEffect(() => {
    const actions = new MemberLinkActions(api, organization, membership, named);
    controller.current = actions;
    handle.current = { hasLocalWork: () => actions.hasLocalWork };
    setBusy(false);
    setFailure(undefined);
    setNotice("");
    setReview(undefined);
    refresh((v) => v + 1);
    return () => {
      actions.dispose();
      controller.current = null;
      handle.current = null;
      running.current = false;
      onBusy(false);
    };
  }, [api, organization, membership, named, handle, onBusy, generation]);
  useEffect(() => {
    const next = Math.min(...[remaining, wait, recover].filter((v) => v > 0));
    if (!Number.isFinite(next)) return;
    const timer = window.setTimeout(
      () => refresh((v) => v + 1),
      Math.ceil(next),
    );
    return () => window.clearTimeout(timer);
  }, [remaining, wait, recover]);
  async function run(
    action: (w: MemberLinkActions) => void | Promise<void>,
    message = "",
  ) {
    const actions = controller.current;
    if (!actions || disabled || running.current) return;
    running.current = true;
    setBusy(true);
    onBusy(true);
    setFailure(undefined);
    setReview(undefined);
    setNotice("");
    try {
      await action(actions);
      if (controller.current === actions) setNotice(message);
    } catch (error) {
      if (controller.current === actions) setFailure(error);
    } finally {
      if (controller.current === actions) {
        running.current = false;
        setBusy(false);
        onBusy(false);
      }
    }
  }
  return (
    <section
      className="editor form-fields"
      aria-labelledby={heading}
      aria-busy={busy}
    >
      <h2 id={heading}>
        {named
          ? t(`Identity link for ${username}`, `成员 ${username} 的身份关联`)
          : t("Your team identity link", "你的团队身份关联")}
      </h2>
      <p className="caption">
        {t(
          `Scoplen account ${username} · Team ${teamName}`,
          `Scoplen 账号 ${username} · 团队 ${teamName}`,
        )}
      </p>
      <div className="inline-actions">
        <button
          type="button"
          className="secondary"
          disabled={blocked}
          onClick={() => void run((w) => w.read())}
        >
          {t("Check current link", "查看当前关联")}
        </button>
      </div>
      {failure !== undefined && (
        <p className="notice error" role="alert">
          {failure instanceof RequestFailure &&
          failure.code === "policy.denied" &&
          !named
            ? t(
                "This action requires a current membership. To start or confirm a link, sign in with your Scoplen password within five minutes.",
                "此操作需要有效的团队成员资格。开始或确认关联前，请在五分钟内使用 Scoplen 密码登录。",
              )
            : requestFeedback(failure, t)}
        </p>
      )}
      {notice && <p role="status">{notice}</p>}
      {workflow?.receipt && (
        <p role="status">
          {t("Link confirmed for this membership.", "已确认此成员的身份关联。")}{" "}
          <span className="mono identifier">{workflow.receipt.id}</span>
        </p>
      )}
      {status && (
        <div className="form-fields">
          <p>
            {link
              ? t(
                  "This membership has a linked identity.",
                  "此成员已关联外部身份。",
                )
              : t(
                  "This membership has no linked identity.",
                  "此成员尚未关联外部身份。",
                )}
          </p>
          {link && (
            <p className="caption">
              {t("Link ID", "关联 ID")}{" "}
              <span className="mono identifier">{link.id}</span> ·{" "}
              <time dateTime={link.created_at}>{link.created_at}</time>
            </p>
          )}
          {revision && <ConnectionTarget data={revision} />}
          {!named && !revision && (
            <p className="caption">
              {t(
                "This team has no active identity provider.",
                "此团队没有启用的身份提供方。",
              )}
            </p>
          )}
          {revision && !link && !candidate && !wait && !workflow?.pending && (
            <>
              <p className="caption">
                {t(
                  "Use a Scoplen password sign-in from the last five minutes. After signing in with the provider, return here to confirm your link.",
                  "请在使用 Scoplen 密码登录后五分钟内开始。登录身份提供方后，返回此处确认关联。",
                )}
              </p>
              <div className="inline-actions">
                <button
                  type="button"
                  className="primary-button"
                  disabled={blocked}
                  onClick={() => void run((w) => w.start())}
                >
                  {t("Start identity verification", "开始身份验证")}
                </button>
              </div>
            </>
          )}
          {link && !workflow?.pending && (
            <div className="inline-actions">
              <button
                type="button"
                className="danger"
                disabled={blocked}
                onClick={() => setReview({ linkId: link.id })}
              >
                {named
                  ? t("Withdraw member link", "撤回成员关联")
                  : t("Unlink identity", "解除身份关联")}
              </button>
            </div>
          )}
        </div>
      )}
      {wait > 0 && (
        <p role="status">
          {t(
            "A sign-in attempt may already be open. Wait up to five minutes before starting another.",
            "可能已有登录验证正在进行。请最多等待五分钟后再开始。",
          )}
        </p>
      )}
      {candidate && (
        <div className="form-fields">
          <p role="status">
            {candidate.data.status === "verified"
              ? t(
                  "Provider verified. Review your account, team and provider before confirming.",
                  "身份提供方已验证。确认前，请核对账号、团队和身份提供方。",
                )
              : candidate.data.status === "failed"
                ? t(
                    "Verification failed. Abandon this attempt to start again.",
                    "验证失败。请放弃本次验证后重试。",
                  )
                : t(
                    "Complete sign-in in the second tab, then return here to check verification.",
                    "请在第二个标签页完成登录，随后返回此处查看验证结果。",
                  )}
          </p>
          <div className="inline-actions">
            {candidate.url &&
              revision?.id === candidate.connection.id &&
              !blocked && (
                <a
                  href={candidate.url}
                  className="provider-sign-in"
                  target="_blank"
                  rel="noopener noreferrer"
                  referrerPolicy="no-referrer"
                >
                  {t("Open provider in a new tab", "在新标签页打开身份提供方")}
                </a>
              )}
            {candidate.data.status === "pending" && (
              <button
                type="button"
                className="secondary"
                disabled={blocked}
                onClick={() => void run((w) => w.checkAttempt())}
              >
                {t("Check verification", "查看验证结果")}
              </button>
            )}
            {candidate.data.status === "verified" &&
              revision?.id === candidate.connection.id &&
              !link && (
                <button
                  type="button"
                  className="primary-button"
                  disabled={blocked}
                  onClick={() => void run((w) => w.confirm())}
                >
                  {t("Confirm identity link", "确认身份关联")}
                </button>
              )}
            <button
              type="button"
              className="secondary"
              disabled={blocked}
              onClick={() =>
                void run(
                  (w) => w.abandon(),
                  t("Verification abandoned.", "已放弃验证。"),
                )
              }
            >
              {t("Abandon verification", "放弃验证")}
            </button>
          </div>
        </div>
      )}
      {workflow?.pending && (
        <div className="form-fields">
          <p role="status">
            {recover
              ? t(
                  "The original confirmation is unresolved. Current link status only describes the membership now. Recover the original response in this tab while your password sign-in is fresh.",
                  "原确认操作的结果待核实。当前关联状态仅反映此刻的成员情况。请在密码登录仍有效时，在此标签页恢复原操作结果。",
                )
              : t(
                  "The original confirmation can no longer be recovered in this tab. Check the current link before taking another action.",
                  "此标签页已无法恢复原确认结果。继续操作前，请查看当前关联。",
                )}
          </p>
          <div className="inline-actions">
            <button
              type="button"
              className="secondary"
              disabled={blocked || !recover}
              onClick={() => void run((w) => w.recover())}
            >
              {t("Recover original confirmation", "恢复原确认结果")}
            </button>
            <button
              type="button"
              className="secondary"
              disabled={blocked}
              onClick={() => setReview("discard")}
            >
              {t("Discard recovery data", "丢弃恢复数据")}
            </button>
          </div>
        </div>
      )}
      {review && (
        <div className="form-fields">
          <p>
            {review === "discard"
              ? t(
                  "Discarding the original request ends recovery in this tab.",
                  "丢弃原请求后，此标签页将无法恢复原结果。",
                )
              : t(
                  `Remove the reviewed identity link for ${username} in ${teamName}? The Scoplen account and team membership remain active.`,
                  `移除 ${username} 在 ${teamName} 中的此项身份关联？Scoplen 账号及团队成员资格会保留。`,
                )}
          </p>
          <div className="inline-actions">
            <button
              type="button"
              className="secondary"
              disabled={blocked}
              onClick={() => setReview(undefined)}
            >
              {t("Cancel", "取消")}
            </button>
            <button
              type="button"
              className="danger"
              disabled={blocked}
              onClick={() =>
                review === "discard"
                  ? void run((w) => w.discardReceipt())
                  : void run(
                      (w) => w.withdraw(review.linkId),
                      t("Identity link removed.", "已移除身份关联。"),
                    )
              }
            >
              {review === "discard"
                ? t("Confirm discard", "确认丢弃")
                : t("Confirm removal", "确认移除")}
            </button>
          </div>
        </div>
      )}
    </section>
  );
}
