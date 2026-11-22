// SPDX-License-Identifier: AGPL-3.0-only
import { useEffect, useRef, useState } from "react";
import type {
  AccessRequestResource,
  AccessRequestView,
} from "./generated/api.ts";
import {
  AccessRequestActions,
  AccessRequestApi,
  requestPending,
  type RequestDecision,
} from "./access-requests.ts";
import { RequestFailure, type TeamApi } from "./team.ts";
import { useLocale } from "./locale.tsx";
import { useConfirmation } from "./confirm.tsx";
import { requestFeedback } from "./feedback.ts";

export function RequestPreview({ item }: { item: AccessRequestResource }) {
  const { t } = useLocale();
  return (
    <dl className="grant-preview request-preview">
      <div>
        <dt>{t("Requester Account", "申请者账号")}</dt>
        <dd className="mono identifier">{item.data.requester_account_id}</dd>
      </div>
      <div>
        <dt>{t("Host", "主机")}</dt>
        <dd className="mono identifier">{item.data.host}</dd>
      </div>
      <div>
        <dt>{t("Exact remote username", "精确远程用户名")}</dt>
        <dd className="mono grant-remote-user">{item.data.remote_user}</dd>
      </div>
      <div>
        <dt>{t("Duration (seconds)", "时长（秒）")}</dt>
        <dd>{item.data.duration_seconds.toLocaleString()}</dd>
      </div>
      <div>
        <dt>{t("Reason", "申请理由")}</dt>
        <dd className="request-reason">{item.data.reason}</dd>
      </div>
      <div>
        <dt>{t("Pending deadline (UTC)", "待审批截止时间（UTC）")}</dt>
        <dd>
          <time dateTime={item.data.expires_at}>{item.data.expires_at}</time>
        </dd>
      </div>
      {item.data.decision && (
        <>
          <div>
            <dt>{t("Decided by", "审批者")}</dt>
            <dd className="mono identifier">
              {item.data.decision.actor_account_id}
            </dd>
          </div>
          <div>
            <dt>{t("Decision time (UTC)", "审批时间（UTC）")}</dt>
            <dd>
              <time dateTime={item.data.decision.decided_at}>
                {item.data.decision.decided_at}
              </time>
            </dd>
          </div>
        </>
      )}
      {item.data.grant && (
        <>
          <div>
            <dt>{t("Approved start (UTC)", "批准开始时间（UTC）")}</dt>
            <dd>
              <time dateTime={item.data.grant.valid_from}>
                {item.data.grant.valid_from}
              </time>
            </dd>
          </div>
          <div>
            <dt>{t("Approved end (UTC)", "批准结束时间（UTC）")}</dt>
            <dd>
              <time dateTime={item.data.grant.valid_until}>
                {item.data.grant.valid_until}
              </time>
            </dd>
          </div>
        </>
      )}
    </dl>
  );
}

export function AccessRequestPanel({
  teamApi,
  organization,
  account,
  disabled,
}: {
  teamApi: TeamApi;
  organization: string;
  account: string;
  disabled: boolean;
}) {
  const { t } = useLocale(),
    { confirm, dialog } = useConfirmation();
  const [view, setView] = useState<AccessRequestView>("mine");
  const [items, setItems] = useState<AccessRequestResource[]>([]),
    [next, setNext] = useState<string | null>(null);
  const [review, setReview] = useState<AccessRequestResource>(),
    [failure, setFailure] = useState<unknown>();
  const [busy, setBusy] = useState(true),
    [notice, setNotice] = useState("");
  const [now, setNow] = useState(Date.now()),
    [, renderPending] = useState(0);
  const workflow = useRef<AccessRequestActions | null>(null),
    generation = useRef(0),
    running = useRef(false);
  const disabledRef = useRef(disabled);
  disabledRef.current = disabled;
  const heading = useRef<HTMLHeadingElement>(null);
  const pending = workflow.current?.pending,
    reviewRequired = workflow.current?.reviewRequired ?? false;
  const blocked = disabled || busy,
    actionable = !blocked && !pending && !reviewRequired;
  const selected = pending?.original ?? review;
  useEffect(() => {
    if (selected) heading.current?.focus();
  }, [selected]);
  const decisionName = (decision: RequestDecision) =>
    ({
      approve: t("Approve", "批准"),
      deny: t("Deny", "拒绝"),
      cancel: t("Cancel request", "取消申请"),
    })[decision];
  function statusName(item: AccessRequestResource) {
    if (item.data.status === "pending" && !requestPending(item, now))
      return t("Deadline passed", "已过截止时间");
    const names: Record<string, string> = {
      pending: t("Pending", "待审批"),
      approved: t("Approved", "已批准"),
      denied: t("Denied", "已拒绝"),
      expired: t("Expired", "已过期"),
      cancelled: t("Cancelled", "已取消"),
    };
    return names[item.data.status] ?? t("Unrecognized status", "未知状态");
  }
  async function read(
    actions: AccessRequestActions,
    epoch: number,
    cursor?: string,
  ) {
    const page = await actions.api.list(view, cursor);
    if (generation.current !== epoch) return;
    setItems((current) => (cursor ? [...current, ...page.items] : page.items));
    setNext(page.next_cursor);
    setReview(undefined);
    actions.reviewed();
  }
  async function run(
    action: (actions: AccessRequestActions, epoch: number) => Promise<void>,
  ) {
    const actions = workflow.current,
      epoch = generation.current;
    if (!actions || running.current || disabledRef.current) return;
    running.current = true;
    setBusy(true);
    setFailure(undefined);
    try {
      await action(actions, epoch);
    } catch (error) {
      if (generation.current === epoch) {
        setFailure(error);
        setReview(undefined);
        if (
          error instanceof RequestFailure &&
          [401, 403, 404].includes(error.status)
        ) {
          setItems([]);
          setNext(null);
        }
      }
    } finally {
      if (generation.current === epoch) {
        running.current = false;
        setBusy(false);
        renderPending((value) => value + 1);
      }
    }
  }
  useEffect(() => {
    const actions = new AccessRequestActions(
      new AccessRequestApi(teamApi.transport, organization, account),
    );
    const epoch = ++generation.current;
    workflow.current = actions;
    running.current = true;
    setBusy(true);
    setItems([]);
    setNext(null);
    setReview(undefined);
    setFailure(undefined);
    setNotice("");
    void read(actions, epoch)
      .catch((error: unknown) => {
        if (generation.current === epoch) setFailure(error);
      })
      .finally(() => {
        if (generation.current === epoch) {
          running.current = false;
          setBusy(false);
        }
      });
    const refresh = window.setInterval(() => {
      void run((current, currentEpoch) => read(current, currentEpoch));
    }, 60_000);
    const clock = window.setInterval(() => setNow(Date.now()), 1_000);
    return () => {
      ++generation.current;
      actions.dispose();
      running.current = false;
      window.clearInterval(refresh);
      window.clearInterval(clock);
    };
  }, [teamApi, organization, account, view]);
  async function open(
    actions: AccessRequestActions,
    epoch: number,
    item: AccessRequestResource,
  ) {
    const current = await actions.api.get(item.id);
    if (generation.current !== epoch) return;
    actions.reviewed();
    setReview(current);
    setNotice("");
  }
  async function decide(decision: RequestDecision) {
    if (!review) return;
    await run(async (actions, epoch) => {
      await actions.decide(review, decision);
      if (generation.current !== epoch) return;
      setNotice(t("Request action confirmed.", "申请操作已确认。"));
      setReview(undefined);
      await read(actions, epoch);
    });
  }
  return (
    <section aria-label={t("Access requests", "访问申请")} aria-busy={busy}>
      {dialog}
      <p className="section-intro">
        {t(
          "Review requests for temporary access to one Host. Approval records a finite permission; current policy still decides new SSH connections. Use the desktop app to request access and connect.",
          "查看单台主机的临时访问申请。批准会记录限时权限；新的 SSH 连接仍由当前策略决定。请在桌面端申请访问并连接。",
        )}
      </p>
      <div
        className="inline-actions request-toolbar"
        role="group"
        aria-label={t("Request views", "申请列表")}
      >
        <button
          type="button"
          className="secondary"
          aria-pressed={view === "mine"}
          disabled={blocked || Boolean(pending)}
          onClick={() => setView("mine")}
        >
          {t("My requests", "我的申请")}
        </button>
        <button
          type="button"
          className="secondary"
          aria-pressed={view === "approvals"}
          disabled={blocked || Boolean(pending)}
          onClick={() => setView("approvals")}
        >
          {t("Approvals", "待我审批")}
        </button>
        <button
          type="button"
          className="secondary"
          disabled={blocked}
          onClick={() => void run((actions, epoch) => read(actions, epoch))}
        >
          {busy ? t("Loading…", "加载中…") : t("Refresh requests", "刷新申请")}
        </button>
      </div>
      <p className="caption">
        {t(
          "Refreshes every 60 seconds while open, including an empty inbox. Requester and Host IDs are shown without looking up hidden directory details.",
          "打开期间每 60 秒刷新一次，包括空列表。申请者与主机显示 ID，不会查询隐藏的目录详情。",
        )}
      </p>
      {failure !== undefined && (
        <p className="notice error" role="alert">
          {requestFeedback(failure, t)}
        </p>
      )}
      {notice && (
        <p className="notice" role="status">
          {notice}
        </p>
      )}
      {reviewRequired && !pending && (
        <p className="notice">
          {t(
            "Refresh and review the current request before another action.",
            "请刷新并查看当前申请后，再执行操作。",
          )}
        </p>
      )}
      {pending && (
        <div className="notice">
          <p>
            {t(
              "The original action is unconfirmed. Confirmation sends only its original operation; it never creates a new decision. Leaving this workspace loses this confirmation context.",
              "原操作尚未确认。确认只会发送原操作，不会创建新的审批。离开此工作区将丢失此确认上下文。",
            )}
          </p>
          <p>
            {t("Original action", "原操作")}: {decisionName(pending.decision)}
          </p>
          <div className="inline-actions">
            <button
              type="button"
              className="secondary"
              disabled={blocked || now >= pending.deadline}
              onClick={() =>
                void run(async (actions, epoch) => {
                  await actions.confirm();
                  if (generation.current !== epoch) return;
                  setNotice(
                    t(
                      "Original action confirmed. Approval history does not prove current access.",
                      "原操作已确认。批准历史不代表当前仍有访问权限。",
                    ),
                  );
                  await read(actions, epoch);
                })
              }
            >
              {t("Confirm original action", "确认原操作")}
            </button>
            <button
              type="button"
              className="secondary"
              disabled={blocked}
              onClick={() =>
                void (async () => {
                  const actions = workflow.current,
                    epoch = generation.current;
                  if (
                    (await confirm(
                      t(
                        "Discard this local confirmation? This does not cancel or undo the server operation. Refresh and review current state afterwards.",
                        "放弃本地确认上下文吗？这不会取消或撤销服务端操作。之后请刷新并查看当前状态。",
                      ),
                    )) &&
                    generation.current === epoch &&
                    !running.current &&
                    !disabledRef.current
                  ) {
                    actions?.discard();
                    setReview(undefined);
                    renderPending((value) => value + 1);
                  }
                })()
              }
            >
              {t("Discard local confirmation", "放弃本地确认")}
            </button>
          </div>
          {now >= pending.deadline && (
            <p>
              {t(
                "The confirmation window has ended. Discard the local context, then refresh and review.",
                "确认期限已结束。请放弃本地上下文，再刷新并查看当前状态。",
              )}
            </p>
          )}
        </div>
      )}
      {selected && (
        <section
          className="request-review"
          aria-labelledby="request-review-title"
        >
          <h2 id="request-review-title" ref={heading} tabIndex={-1}>
            {t("Review request", "查看申请")}
          </h2>
          <p className="caption mono identifier">
            {selected.id} · {statusName(selected)}
          </p>
          <RequestPreview item={selected} />
          {selected.data.grant && (
            <p className="notice">
              {t(
                "This interval records the original approval. It does not show whether the Grant is still active or permit a connection by itself.",
                "此时间段记录原始批准，不代表授权目前仍有效，也不能单独用于连接。",
              )}
            </p>
          )}
          {!pending && (
            <div className="inline-actions">
              {requestPending(selected, now) &&
                (selected.data.requester_account_id === account ? (
                  <button
                    type="button"
                    className="secondary"
                    disabled={!actionable}
                    onClick={() => void decide("cancel")}
                  >
                    {t("Cancel request", "取消申请")}
                  </button>
                ) : (
                  <>
                    <button
                      type="button"
                      className="primary-button"
                      disabled={!actionable}
                      onClick={() => void decide("approve")}
                    >
                      {t("Approve", "批准")}
                    </button>
                    <button
                      type="button"
                      className="secondary"
                      disabled={!actionable}
                      onClick={() => void decide("deny")}
                    >
                      {t("Deny", "拒绝")}
                    </button>
                  </>
                ))}
              <button
                type="button"
                className="secondary"
                disabled={blocked}
                onClick={() => setReview(undefined)}
              >
                {t("Close review", "关闭详情")}
              </button>
            </div>
          )}
        </section>
      )}
      <div className="resource-list">
        {items.map((item) => (
          <article className="resource-row" key={item.id}>
            <div>
              <h2 className="mono identifier">{item.data.host}</h2>
              <p className="grant-remote-user mono">{item.data.remote_user}</p>
              <p>
                {statusName(item)} ·{" "}
                <time dateTime={item.data.expires_at}>
                  {item.data.expires_at}
                </time>
              </p>
            </div>
            <div className="inline-actions">
              <button
                type="button"
                className="secondary"
                disabled={blocked || Boolean(pending)}
                onClick={() =>
                  void run((actions, epoch) => open(actions, epoch, item))
                }
              >
                {t("Review request", "查看申请")}
              </button>
            </div>
          </article>
        ))}
      </div>
      {!busy && !failure && items.length === 0 && (
        <div className="empty-state">
          <h2>
            {view === "mine"
              ? t("No requests yet", "暂无申请")
              : t("No requests awaiting your approval", "暂无待您审批的申请")}
          </h2>
          <p>
            {view === "mine"
              ? t(
                  "Request access from the desktop app after a team connection is denied.",
                  "团队连接被拒绝后，可在桌面端申请访问。",
                )
              : t(
                  "Only pending requests you can currently approve appear here. Refresh to check for new requests.",
                  "此处仅显示您当前可以审批的待处理申请。可刷新查看新申请。",
                )}
          </p>
        </div>
      )}
      {next && (
        <button
          type="button"
          className="secondary load-more"
          disabled={blocked || Boolean(pending)}
          onClick={() =>
            void run((actions, epoch) => read(actions, epoch, next))
          }
        >
          {t("Load more requests", "加载更多申请")}
        </button>
      )}
    </section>
  );
}
