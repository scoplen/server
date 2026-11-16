// SPDX-License-Identifier: AGPL-3.0-only
import { useEffect, useMemo, useRef, useState } from "react";
import type { AuditEvent, AuditVerification } from "./generated/api.ts";
import {
  AuditApi,
  AuditInputError,
  auditRange,
  emptyAuditFilters,
  type AuditFilters,
} from "./audit.ts";
import { Field } from "./editors.tsx";
import { useLocale } from "./locale.tsx";
import { RequestFailure, type AccountTransport } from "./team.ts";

export function AuditPanel({
  transport,
  organization,
  disabled,
}: {
  transport: AccountTransport;
  organization: string;
  disabled: boolean;
}) {
  const { t } = useLocale();
  const api = useMemo(() => new AuditApi(transport), [transport]);
  const [filters, setFilters] = useState(emptyAuditFilters);
  const [applied, setApplied] = useState(emptyAuditFilters);
  const [items, setItems] = useState<AuditEvent[]>([]);
  const [next, setNext] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<unknown>();
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [verified, setVerified] = useState<AuditVerification>();
  const generation = useRef(0);
  const running = useRef(false);
  const locked = disabled || busy;
  const unknown = t("Unknown / not recorded", "未知／未记录");
  const outcomeNames = {
    success: t("Success", "成功"),
    failure: t("Failure", "失败"),
    unknown: t("Unknown", "未知"),
  };
  const categoryNames = {
    authentication: t("Authentication", "身份认证"),
    authorization: t("Authorization", "权限授权"),
    account_change: t("Account change", "账号变更"),
    scoplen: t("Inventory", "资产"),
    unknown: t("Unknown", "未知"),
  };

  async function read(action: () => Promise<void>, clear: () => void) {
    if (running.current) return;
    running.current = true;
    setBusy(true);
    setFailure(undefined);
    const ticket = ++generation.current;
    try {
      await action();
    } catch (error) {
      if (ticket === generation.current) {
        setFailure(error);
        clear();
        if (
          error instanceof RequestFailure &&
          [401, 403, 404].includes(error.status)
        ) {
          setItems([]);
          setNext(null);
          setLoaded(false);
          setVerified(undefined);
        }
      }
    } finally {
      if (ticket === generation.current) {
        running.current = false;
        setBusy(false);
      }
    }
  }

  async function load(selected: AuditFilters, cursor?: string) {
    await read(
      async () => {
        const ticket = generation.current;
        if (!cursor) {
          setItems([]);
          setNext(null);
          setLoaded(false);
          setVerified(undefined);
        }
        const page = await api.list(organization, selected, cursor);
        if (ticket !== generation.current) return;
        setItems((previous) =>
          cursor ? [...previous, ...page.items] : page.items,
        );
        setNext(page.next_cursor);
        setApplied(selected);
        setLoaded(true);
      },
      () => {
        if (!cursor) setLoaded(false);
      },
    );
  }

  useEffect(() => {
    void load(emptyAuditFilters());
    return () => {
      generation.current++;
      running.current = false;
    };
    // The parent keys this view by Organization and unmounts it when the session ends.
    // Transient transport busy notifications must not restart its own reads.
  }, [api, organization]);

  function feedback(error: unknown): string {
    if (error instanceof AuditInputError) {
      const fields: Record<AuditInputError["field"], string> = {
        fromTime: t(
          "Use a UTC time such as 2026-11-01T00:00:00Z, with at most three normalized fractional digits.",
          "起始时间请使用 UTC 格式，例如 2026-11-01T00:00:00Z；小数部分最多三位并省略末尾的零。",
        ),
        beforeTime: t(
          "Use a normalized UTC end time later than the start time.",
          "结束时间请使用规范 UTC 格式，并晚于起始时间。",
        ),
        actor: t(
          "Enter the recorded Account UUID shown in an event's details.",
          "请输入事件详情中记录的账号 UUID。",
        ),
        resource: t(
          "Enter a resource kind and UUID, for example host: followed by its UUID.",
          "请输入资源类型和 UUID，例如 host: 后接主机 UUID。",
        ),
        eventClass: t(
          "Enter an exact event class, for example organization.inventory_created.",
          "请输入完整事件类别，例如 organization.inventory_created。",
        ),
        outcome: t(
          "Choose one of the available outcomes.",
          "请选择一个可用结果。",
        ),
        range: t(
          "Choose positive sequence numbers in ascending order, covering at most 4,096 events.",
          "请选择递增的正整数序号，每次最多验证 4,096 条事件。",
        ),
      };
      return fields[error.field];
    }
    if (error instanceof RequestFailure) {
      const reference = error.requestId ? ` (${error.requestId})` : "";
      if (
        error.status === 401 ||
        [
          "sign_in_required",
          "session_ended",
          "refresh_sign_in_required",
        ].includes(error.code)
      )
        return (
          t(
            "Your session has ended. Sign in again to read this team's audit.",
            "会话已结束，请重新登录以读取团队审计。",
          ) + reference
        );
      if (error.status === 403)
        return (
          t(
            "Your current session or team permissions do not allow audit reads. Ask an Owner to review access; a session created before audit access was added needs a fresh sign-in.",
            "当前会话或团队权限不允许读取审计。请联系所有者检查权限；审计权限加入前创建的会话需要重新登录。",
          ) + reference
        );
      if (error.status === 404)
        return (
          t(
            "This team is no longer available to your Account. Refresh your teams or choose another team.",
            "此团队已不可用。请刷新团队列表或选择其他团队。",
          ) + reference
        );
      if (error.status === 400 || error.status === 413)
        return (
          t(
            "This selection cannot be read within the audit limits. Reduce the range or review the filters, then try again.",
            "当前选择超出审计读取范围。请缩小区间或检查筛选条件后重试。",
          ) + reference
        );
      if (error.status === 429)
        return (
          t(
            "Audit reads are temporarily rate limited. Wait before refreshing.",
            "审计读取暂时受到限流，请稍后刷新。",
          ) + reference
        );
      if (error.status === 503)
        return (
          t(
            "Audit storage is unavailable. Refresh later; no verification result was obtained.",
            "审计存储暂不可用，请稍后重试；此次未取得验证结果。",
          ) + reference
        );
      if (error.code === "invalid_response")
        return (
          t(
            "The audit response could not be validated. Refresh to request it again.",
            "审计响应未通过校验，请刷新以重新读取。",
          ) + reference
        );
    }
    return t(
      "The audit read could not finish. Check the connection and try again.",
      "审计读取未完成，请检查连接后重试。",
    );
  }

  function setFilter(field: keyof AuditFilters, value: string) {
    setFilters((previous) => ({ ...previous, [field]: value }));
  }

  return (
    <div className="audit-workspace" aria-busy={busy}>
      <p className="section-intro">
        {t(
          "Read the team's recorded activity and verify original event intervals. Unknown attribution stays unknown; event details do not resolve historical actors to current usernames.",
          "查看团队已记录的活动，并验证原始事件区间。未知归属会明确保留；历史操作者不会被替换为当前用户名。",
        )}
      </p>
      <form
        onSubmit={(event) => {
          event.preventDefault();
          if (!locked) void load({ ...filters });
        }}
      >
        <fieldset className="audit-filters" disabled={locked}>
          <legend className="sr-only">{t("Audit filters", "审计筛选")}</legend>
          <Field label={t("From (UTC, inclusive)", "起始时间（UTC，包含）")}>
            <input
              value={filters.fromTime}
              onChange={(event) => setFilter("fromTime", event.target.value)}
              placeholder="2026-11-01T00:00:00Z"
              spellCheck={false}
            />
          </Field>
          <Field
            label={t("Before (UTC, exclusive)", "结束时间（UTC，不包含）")}
          >
            <input
              value={filters.beforeTime}
              onChange={(event) => setFilter("beforeTime", event.target.value)}
              placeholder="2026-11-02T00:00:00Z"
              spellCheck={false}
            />
          </Field>
          <Field
            label={t("Recorded actor Account ID", "已记录的操作者账号 ID")}
          >
            <input
              value={filters.actor}
              onChange={(event) => setFilter("actor", event.target.value)}
              spellCheck={false}
            />
          </Field>
          <Field label={t("Resource (kind:UUID)", "资源（类型:UUID）")}>
            <input
              value={filters.resource}
              onChange={(event) => setFilter("resource", event.target.value)}
              spellCheck={false}
            />
          </Field>
          <Field label={t("Exact event class", "完整事件类别")}>
            <input
              value={filters.eventClass}
              onChange={(event) => setFilter("eventClass", event.target.value)}
              spellCheck={false}
            />
          </Field>
          <fieldset className="audit-outcomes">
            <legend>{t("Outcome", "结果")}</legend>
            {(["", "success", "failure", "unknown"] as const).map((outcome) => (
              <label key={outcome}>
                <input
                  type="radio"
                  name="audit-outcome"
                  checked={filters.outcome === outcome}
                  onChange={() => setFilter("outcome", outcome)}
                />
                {outcome ? outcomeNames[outcome] : t("All", "全部")}
              </label>
            ))}
          </fieldset>
        </fieldset>
        <div className="form-actions">
          <button className="primary-button" disabled={locked}>
            {t("Search audit", "查询审计")}
          </button>
          <button
            type="button"
            className="secondary"
            disabled={locked}
            onClick={() => void load({ ...applied })}
          >
            {t("Refresh results", "刷新结果")}
          </button>
          <button
            type="button"
            className="quiet"
            disabled={locked}
            onClick={() => {
              const empty = emptyAuditFilters();
              setFilters(empty);
              void load(empty);
            }}
          >
            {t("Clear filters", "清除筛选")}
          </button>
        </div>
      </form>
      {failure !== undefined && (
        <p className="notice error" role="alert">
          {feedback(failure)}
        </p>
      )}
      {busy && (
        <p className="loading-status" role="status">
          {t("Reading audit…", "正在读取审计…")}
        </p>
      )}
      {loaded && items.length === 0 && (
        <div className="empty-state" role="status">
          <h2>{t("No matching events", "没有匹配事件")}</h2>
          <p>
            {t(
              "Clear or adjust the filters, or refresh after new team activity.",
              "可清除或调整筛选条件，或在团队产生新活动后刷新。",
            )}
          </p>
        </div>
      )}
      <ol
        className="audit-events"
        aria-label={t("Audit timeline, newest first", "审计时间线，由新到旧")}
      >
        {items.map((item) => (
          <li key={item.sequence}>
            <details>
              <summary>
                <span className="audit-event-title">
                  <span className="mono">#{item.sequence}</span>{" "}
                  {item.event_class ?? t("Unclassified event", "未分类事件")}
                </span>
                <time dateTime={item.occurred_at}>{item.occurred_at}</time>
                <span className={`audit-outcome audit-outcome-${item.outcome}`}>
                  {outcomeNames[item.outcome]}
                </span>
              </summary>
              <dl className="audit-details">
                {[
                  [t("Category", "分类"), categoryNames[item.category]],
                  [
                    t("Recorded actor Account ID", "已记录的操作者账号 ID"),
                    item.actor_account_id ?? unknown,
                  ],
                  [
                    t("Recorded Device ID", "已记录的设备 ID"),
                    item.actor_device_id ?? unknown,
                  ],
                  [
                    t("Recorded browser family ID", "已记录的浏览器会话族 ID"),
                    item.actor_browser_family_id ?? unknown,
                  ],
                  [
                    t("Resource", "资源"),
                    item.resource
                      ? `${item.resource.kind}:${item.resource.id}`
                      : unknown,
                  ],
                  [t("Organization ID", "组织 ID"), item.organization_id],
                  [t("Previous hash", "前序哈希"), item.previous_hash],
                  [t("Event hash", "事件哈希"), item.event_hash],
                ].map(([label, value]) => (
                  <div key={label}>
                    <dt>{label}</dt>
                    <dd className="mono">{value}</dd>
                  </div>
                ))}
              </dl>
            </details>
          </li>
        ))}
      </ol>
      {next && (
        <button
          type="button"
          className="secondary load-more"
          disabled={locked}
          onClick={() => void load({ ...applied }, next)}
        >
          {t("Load earlier events", "加载更早事件")}
        </button>
      )}
      <section
        className="audit-verification"
        aria-labelledby="audit-verify-heading"
      >
        <h2 id="audit-verify-heading">
          {t("Verify a sequence range", "验证序号区间")}
        </h2>
        <p className="section-intro">
          {t(
            "Verification includes every event between these sequence numbers, even when search filters hide some rows. Read up to 4,096 events per interval; verify adjacent intervals separately for larger ranges.",
            "验证会包含两端序号之间的全部事件，包括被查询条件隐藏的记录。每个区间最多 4,096 条事件；更大的范围请分为相邻区间验证。",
          )}
        </p>
        <form
          onSubmit={(event) => {
            event.preventDefault();
            if (locked) return;
            void read(
              async () => {
                setVerified(undefined);
                const selected = auditRange(from.trim(), to.trim());
                const ticket = generation.current;
                const result = await api.verify(organization, selected);
                if (ticket === generation.current) setVerified(result);
              },
              () => setVerified(undefined),
            );
          }}
        >
          <fieldset className="form-row" disabled={locked}>
            <legend className="sr-only">
              {t("Inclusive sequence interval", "包含两端的序号区间")}
            </legend>
            <Field label={t("From sequence", "起始序号")}>
              <input
                inputMode="numeric"
                value={from}
                onChange={(event) => {
                  setFrom(event.target.value);
                  setVerified(undefined);
                }}
                required
                spellCheck={false}
              />
            </Field>
            <Field label={t("Through sequence", "结束序号")}>
              <input
                inputMode="numeric"
                value={to}
                onChange={(event) => {
                  setTo(event.target.value);
                  setVerified(undefined);
                }}
                required
                spellCheck={false}
              />
            </Field>
          </fieldset>
          <div className="form-actions">
            <button
              className="secondary"
              disabled={locked || !from.trim() || !to.trim()}
            >
              {t("Verify range", "验证区间")}
            </button>
          </div>
        </form>
        {verified && (
          <div className="audit-result" role="status">
            <h3>
              {verified.valid
                ? t("Hash chain verified", "哈希链验证通过")
                : t("Hash chain verification failed", "哈希链验证失败")}
            </h3>
            <p>
              {t("Sequence interval", "序号区间")}:{" "}
              <span className="mono">
                {verified.from_sequence}–{verified.to_sequence}
              </span>{" "}
              · {t("Verified events", "已验证事件")}: {verified.checked_events}
            </p>
            {!verified.valid ? (
              <p className="attention-text">
                {t("First failed sequence", "首个失败序号")}:{" "}
                {verified.failure_sequence}.{" "}
                {t(
                  "This result makes no signature-coverage claim. Contact the deployment operator to investigate.",
                  "此结果不声明任何签名覆盖范围。请联系部署运维人员排查。",
                )}
              </p>
            ) : (
              <>
                {verified.checkpoint ? (
                  <>
                    <p>
                      {t(
                        "Included signed checkpoint through sequence",
                        "本区间内已签名检查点覆盖至序号",
                      )}
                      :{" "}
                      <span className="mono">
                        {verified.checkpoint.sequence}
                      </span>
                    </p>
                    <p>
                      {t("Signed at", "签名时间")}:{" "}
                      <time dateTime={verified.checkpoint.signed_at}>
                        {verified.checkpoint.signed_at}
                      </time>
                    </p>
                  </>
                ) : (
                  <p className="attention-text">
                    {t(
                      "No checkpoint is included in this interval. Extend the selection or verify adjacent intervals to examine further signature evidence.",
                      "本区间内没有检查点。可扩大选择或验证相邻区间以查看进一步的签名证据。",
                    )}
                  </p>
                )}
                {verified.uncheckpointed_from_sequence && (
                  <p className="attention-text">
                    {t(
                      "Not covered by a checkpoint in this interval",
                      "未被本区间内检查点覆盖",
                    )}
                    :{" "}
                    <span className="mono">
                      {verified.uncheckpointed_from_sequence}–
                      {verified.to_sequence}
                    </span>
                    .{" "}
                    {t(
                      "This can be the newest tail awaiting its checkpoint; an older interval may be covered by a later checkpoint.",
                      "这可能是等待生成检查点的最新尾部；历史区间也可能由更晚的检查点覆盖。",
                    )}
                  </p>
                )}
                <p className="caption">
                  {t(
                    "The deployment checked original event bytes and included checkpoint signatures using its configured audit key. This is not an independent external archive verification.",
                    "部署使用原始事件字节及其配置的审计密钥检查链和区间内的签名。这不代表经过独立外部归档验证。",
                  )}
                </p>
                <details>
                  <summary>{t("Verification evidence", "验证证据")}</summary>
                  <dl className="audit-details">
                    <div>
                      <dt>{t("Previous hash", "前序哈希")}</dt>
                      <dd className="mono">{verified.previous_hash}</dd>
                    </div>
                    <div>
                      <dt>{t("Head hash", "末端哈希")}</dt>
                      <dd className="mono">{verified.head_hash}</dd>
                    </div>
                    {verified.checkpoint && (
                      <>
                        <div>
                          <dt>{t("Checkpoint hash", "检查点哈希")}</dt>
                          <dd className="mono">
                            {verified.checkpoint.head_hash}
                          </dd>
                        </div>
                        <div>
                          <dt>{t("Checkpoint signature", "检查点签名")}</dt>
                          <dd className="mono">
                            {verified.checkpoint.signature}
                          </dd>
                        </div>
                      </>
                    )}
                  </dl>
                </details>
              </>
            )}
          </div>
        )}
      </section>
    </div>
  );
}
