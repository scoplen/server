// SPDX-License-Identifier: AGPL-3.0-only
import { useEffect, useRef, useState } from "react";
import type {
  GrantFields,
  GrantResource,
  InventoryHostResource,
  TeamMemberResource,
} from "./generated/api.ts";
import { GrantActions, GrantApi, grantFields, grantStatus } from "./grants.ts";
import { GrantChoice } from "./grant-choice.tsx";
import { TeamApi, RequestFailure } from "./team.ts";
import { Field } from "./editors.tsx";
import { useLocale } from "./locale.tsx";
import { useConfirmation } from "./confirm.tsx";
import { requestFeedback } from "./feedback.ts";

interface Draft {
  fields: GrantFields;
  original?: GrantResource;
  preview: boolean;
}
export function GrantPreview({
  fields,
  member,
  host,
}: {
  fields: GrantFields;
  member: string;
  host: string;
}) {
  const { t } = useLocale();
  return (
    <dl className="grant-preview">
      <div>
        <dt>{t("Member", "成员")}</dt>
        <dd>{member}</dd>
      </div>
      <div>
        <dt>{t("Host", "主机")}</dt>
        <dd>{host}</dd>
      </div>
      <div>
        <dt>{t("Remote user", "远程用户名")}</dt>
        <dd className="mono grant-remote-user">{fields.remote_user}</dd>
      </div>
      <div>
        <dt>{t("Starts (UTC)", "开始时间（UTC）")}</dt>
        <dd>
          <time dateTime={fields.valid_from}>{fields.valid_from}</time>
        </dd>
      </div>
      <div>
        <dt>{t("Ends (UTC)", "结束时间（UTC）")}</dt>
        <dd>
          {fields.valid_until === null ? (
            t("No expiry", "无到期时间")
          ) : (
            <time dateTime={fields.valid_until}>{fields.valid_until}</time>
          )}
        </dd>
      </div>
    </dl>
  );
}

export function GrantPanel({
  teamApi,
  organization,
  disabled,
}: {
  teamApi: TeamApi;
  organization: string;
  disabled: boolean;
}) {
  const { t } = useLocale(),
    { confirm, dialog } = useConfirmation();
  const workflow = useRef<GrantActions | null>(null),
    generation = useRef(0),
    running = useRef(false);
  const [items, setItems] = useState<GrantResource[]>([]),
    [next, setNext] = useState<string | null>(null);
  const [members, setMembers] = useState<TeamMemberResource[]>([]),
    [hosts, setHosts] = useState<InventoryHostResource[]>([]);
  const [memberNext, setMemberNext] = useState<string | null>(null),
    [hostNext, setHostNext] = useState<string | null>(null);
  const [choiceFailure, setChoiceFailure] = useState(false),
    [busy, setBusy] = useState(true);
  const [draft, setDraft] = useState<Draft | undefined>(),
    [failure, setFailure] = useState<unknown>();
  const [notice, setNotice] = useState(""),
    [, renderPending] = useState(0),
    [now, setNow] = useState(Date.now());
  const blocked = disabled || busy;
  const pending = workflow.current?.pending;
  const reviewRequired = workflow.current?.reviewRequired ?? false;
  const editable = !blocked && !pending && !reviewRequired;
  const memberName = (id: string) =>
    members.find((item) => item.id === id)?.data.username ?? id;
  const hostName = (id: string) =>
    hosts.find((item) => item.id === id)?.data.fields.name ?? id;
  const statusName = (item: GrantResource) =>
    ({
      active: t("Active", "有效"),
      future: t("Scheduled", "未开始"),
      expired: t("Expired", "已过期"),
    })[grantStatus(item.data, now)];

  async function read(actions: GrantActions, epoch: number, cursor?: string) {
    const page = await actions.api.list(cursor);
    if (generation.current !== epoch) return;
    setItems((current) => (cursor ? [...current, ...page.items] : page.items));
    setNext(page.next_cursor);
  }
  useEffect(() => {
    const actions = new GrantActions(
      new GrantApi(teamApi.transport, organization),
    );
    workflow.current = actions;
    const epoch = ++generation.current;
    running.current = true;
    setBusy(true);
    setItems([]);
    setNext(null);
    setMembers([]);
    setHosts([]);
    setMemberNext(null);
    setHostNext(null);
    setDraft(undefined);
    setFailure(undefined);
    setNotice("");
    void read(actions, epoch)
      .then(() => (generation.current === epoch ? choices(epoch) : undefined))
      .catch((error: unknown) => {
        if (generation.current === epoch) {
          setItems([]);
          setFailure(error);
        }
      })
      .finally(() => {
        if (generation.current === epoch) {
          running.current = false;
          setBusy(false);
        }
      });
    const timer = window.setInterval(() => setNow(Date.now()), 30_000);
    const warn = (event: BeforeUnloadEvent) => {
      if (actions.pending) {
        event.preventDefault();
        event.returnValue = "";
      }
    };
    window.addEventListener("beforeunload", warn);
    return () => {
      ++generation.current;
      actions.dispose();
      running.current = false;
      window.clearInterval(timer);
      window.removeEventListener("beforeunload", warn);
    };
  }, [teamApi, organization]);

  async function run(
    action: (actions: GrantActions, epoch: number) => Promise<void>,
  ) {
    const actions = workflow.current,
      epoch = generation.current;
    if (!actions || running.current || disabled) return;
    running.current = true;
    setBusy(true);
    setFailure(undefined);
    setNotice("");
    try {
      await action(actions, epoch);
    } catch (error) {
      if (generation.current === epoch) {
        setFailure(error);
        if (
          error instanceof RequestFailure &&
          [401, 403, 404].includes(error.status)
        ) {
          setItems([]);
          setNext(null);
          setMembers([]);
          setHosts([]);
          setDraft(undefined);
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
  async function choices(epoch: number, append = false) {
    const results = await Promise.allSettled([
      append && !memberNext
        ? Promise.resolve(undefined)
        : teamApi.members(
            organization,
            append ? (memberNext ?? undefined) : undefined,
          ),
      append && !hostNext
        ? Promise.resolve(undefined)
        : teamApi.list(
            organization,
            "hosts",
            append ? (hostNext ?? undefined) : undefined,
          ),
    ]);
    if (generation.current !== epoch) return;
    const [memberResult, hostResult] = results;
    setChoiceFailure(results.some((result) => result.status === "rejected"));
    if (memberResult.status === "fulfilled") {
      const page = memberResult.value;
      if (page) {
        setMembers((current) =>
          append && memberNext ? [...current, ...page.items] : page.items,
        );
        setMemberNext(page.next_cursor);
      }
    } else {
      setMembers([]);
      setMemberNext(null);
    }
    if (hostResult.status === "fulfilled") {
      const page = hostResult.value;
      if (page) {
        setHosts((current) =>
          append && hostNext ? [...current, ...page.items] : page.items,
        );
        setHostNext(page.next_cursor);
      }
    } else {
      setHosts([]);
      setHostNext(null);
    }
  }
  async function open(
    actions: GrantActions,
    epoch: number,
    original?: GrantResource,
  ) {
    const current = original ? await actions.api.get(original.id) : undefined;
    if (generation.current !== epoch) return;
    await choices(epoch);
    if (generation.current !== epoch) return;
    const fields = current
      ? grantFields(current.data)
      : {
          membership: "",
          host: "",
          remote_user: "",
          valid_from: new Date().toISOString().replace(/\.\d+Z$/, "Z"),
          valid_until: new Date(Date.now() + 3_600_000)
            .toISOString()
            .replace(/\.\d+Z$/, "Z"),
        };
    setDraft({ fields, original: current, preview: false });
  }
  function update(patch: Partial<GrantFields>) {
    setDraft((current) =>
      current
        ? {
            ...current,
            preview: false,
            fields: { ...current.fields, ...patch },
          }
        : current,
    );
  }
  function preview() {
    if (!draft) return;
    try {
      const fields = grantFields(draft.fields);
      if (
        !members.some(
          (item) =>
            item.id === fields.membership && item.data.status === "active",
        ) ||
        !hosts.some((item) => item.id === fields.host)
      )
        throw new Error("Unavailable Grant reference.");
      setFailure(undefined);
      setDraft({ ...draft, fields, preview: true });
    } catch {
      setFailure(new RequestFailure("invalid_grant_input"));
    }
  }
  async function saved(
    actions: GrantActions,
    epoch: number,
    confirmation = false,
  ) {
    if (confirmation) await actions.confirm();
    else if (draft?.original)
      await actions.replace(draft.original, draft.fields);
    else if (draft) await actions.create(draft.fields);
    if (generation.current !== epoch) return;
    setDraft(undefined);
    setNotice(
      confirmation
        ? t(
            "Original creation confirmed. The list shows current Grants.",
            "已确认原创建操作。列表显示当前授权。",
          )
        : t("Grant saved.", "授权已保存。"),
    );
    await read(actions, epoch);
  }

  return (
    <section aria-label={t("Host Grants", "主机连接授权")} aria-busy={busy}>
      {dialog}
      <p className="section-intro">
        {t(
          "Give a member permission to connect to one Host as a specific remote user. Host visibility is managed separately. Withdrawing a Grant stops new certificates; certificates already issued expire normally and existing SSH sessions continue.",
          "允许成员以指定远程用户名连接一台主机。主机可见权限单独管理。撤回授权会停止签发新证书；已签发的证书正常到期，现有 SSH 会话继续运行。",
        )}
      </p>
      <div className="inline-actions">
        <button
          type="button"
          className="secondary"
          disabled={blocked}
          onClick={() =>
            void run(async (actions, epoch) => {
              await read(actions, epoch);
              if (generation.current === epoch) {
                actions.reviewed();
                setDraft(undefined);
                setNotice(
                  t(
                    "Current Grants loaded. Review a Grant before editing.",
                    "已加载当前授权。请查看授权后再编辑。",
                  ),
                );
              }
            })
          }
        >
          {busy && !draft
            ? t("Loading…", "加载中…")
            : t("Refresh Grants", "刷新授权")}
        </button>
        <button
          type="button"
          className="primary-button"
          disabled={!editable}
          onClick={() => void run(open)}
        >
          {t("Create Grant", "创建授权")}
        </button>
      </div>
      {notice && (
        <p className="notice" role="status">
          {notice}
        </p>
      )}
      {failure !== undefined && (
        <p className="notice error" role="alert">
          {failure instanceof RequestFailure &&
          failure.code === "invalid_grant_input"
            ? t(
                "Choose a current member and Host, enter a short remote username without control characters, and use UTC times such as 2030-01-01T09:00:00Z. The end must follow the start, or choose No expiry.",
                "请选择当前成员与主机，输入不含控制字符的简短远程用户名，并按 2030-01-01T09:00:00Z 格式填写 UTC 时间。结束必须晚于开始，或选择无到期时间。",
              )
            : requestFeedback(failure, t)}
        </p>
      )}
      {pending && (
        <section
          className="notice pending-operation"
          aria-label={t("Unconfirmed creation", "待确认的创建操作")}
        >
          <h2>{t("Creation is unconfirmed", "创建结果尚未确认")}</h2>
          <p>
            {t(
              "Keep this tab open to confirm this exact creation. Nothing retries automatically. Leaving this view or signing out loses its confirmation data; review current Grants before creating a replacement.",
              "请保留此标签页以确认这次原创建操作。不会自动重试。离开此页面或退出会丢失确认数据；创建替代授权前，请先查看当前授权。",
            )}
          </p>
          <GrantPreview
            fields={pending.body.data}
            member={memberName(pending.body.data.membership)}
            host={hostName(pending.body.data.host)}
          />
          <div className="inline-actions">
            <button
              type="button"
              className="secondary"
              disabled={blocked || Date.now() >= pending.deadline}
              onClick={() =>
                void run((actions, epoch) => saved(actions, epoch, true))
              }
            >
              {t("Confirm original creation", "确认原创建操作")}
            </button>
            <button
              type="button"
              className="quiet"
              disabled={blocked}
              onClick={() =>
                void (async () => {
                  const epoch = generation.current;
                  if (
                    (await confirm(
                      t(
                        "Discard the confirmation data? Creation may have completed. Refresh and review the current Grants before making a replacement.",
                        "要丢弃确认数据吗？创建可能已完成。请刷新并查看当前授权，再创建替代授权。",
                      ),
                    )) &&
                    epoch === generation.current
                  ) {
                    workflow.current?.discard();
                    setDraft(undefined);
                    renderPending((value) => value + 1);
                  }
                })()
              }
            >
              {t("Discard confirmation", "丢弃确认数据")}
            </button>
          </div>
          {Date.now() >= pending.deadline && (
            <p>
              {t(
                "The confirmation window has expired. Review current Grants before continuing.",
                "确认期限已过。请查看当前授权后再继续。",
              )}
            </p>
          )}
        </section>
      )}
      {reviewRequired && (
        <p className="notice" role="status">
          {t(
            "Refresh Grants and review the current values before another edit. Your previous edit will not be resent.",
            "请刷新授权并查看当前值后再编辑。不会重新发送之前的编辑。",
          )}
        </p>
      )}
      {draft && !pending && !reviewRequired && (
        <form
          className="editor"
          onSubmit={(event) => {
            event.preventDefault();
            preview();
          }}
        >
          <h2>
            {draft.original
              ? t("Replace Grant", "替换授权")
              : t("New Grant", "新授权")}
          </h2>
          {choiceFailure && (
            <p className="notice">
              {t(
                "Some choices could not be loaded with your current permissions. Only loaded current choices can be selected.",
                "当前权限下未能加载部分选项。仅可选择已加载的当前选项。",
              )}
            </p>
          )}
          <div className="form-fields">
            <GrantChoice
              label={t("Member", "成员")}
              placeholder={t("Choose a current member", "选择当前成员")}
              value={draft.fields.membership}
              disabled={blocked || draft.preview}
              onChange={(membership) => update({ membership })}
              options={members
                .filter((item) => item.data.status === "active")
                .map((item) => ({
                  id: item.id,
                  label: item.data.username,
                  detail: item.id,
                }))}
            />
            <GrantChoice
              label={t("Host", "主机")}
              placeholder={t("Choose a Host", "选择主机")}
              value={draft.fields.host}
              disabled={blocked || draft.preview}
              onChange={(host) => update({ host })}
              options={hosts.map((item) => ({
                id: item.id,
                label: item.data.fields.name,
                detail: item.data.fields.address,
              }))}
            />
            {(memberNext || hostNext) && (
              <button
                type="button"
                className="secondary"
                disabled={blocked || draft.preview}
                onClick={() =>
                  void run((_actions, epoch) => choices(epoch, true))
                }
              >
                {t("Load more choices", "加载更多选项")}
              </button>
            )}
            <Field
              label={t("Remote user", "远程用户名")}
              help={t(
                "Used exactly as entered, including spaces and letter case.",
                "按输入原样使用，包括空格和字母大小写。",
              )}
            >
              {" "}
              <input
                value={draft.fields.remote_user}
                disabled={blocked || draft.preview}
                required
                onChange={(event) =>
                  update({ remote_user: event.target.value })
                }
                autoComplete="off"
                spellCheck={false}
              />
            </Field>
            <div className="form-row">
              <Field label={t("Starts (UTC)", "开始时间（UTC）")}>
                <input
                  value={draft.fields.valid_from}
                  disabled={blocked || draft.preview}
                  required
                  placeholder="2030-01-01T09:00:00Z"
                  onChange={(event) =>
                    update({ valid_from: event.target.value })
                  }
                  autoComplete="off"
                />
              </Field>
              <Field label={t("Ends (UTC)", "结束时间（UTC）")}>
                <input
                  value={draft.fields.valid_until ?? ""}
                  disabled={
                    blocked ||
                    draft.preview ||
                    draft.fields.valid_until === null
                  }
                  required={draft.fields.valid_until !== null}
                  placeholder="2030-01-01T10:00:00Z"
                  onChange={(event) =>
                    update({ valid_until: event.target.value })
                  }
                  autoComplete="off"
                />
              </Field>
            </div>
            <label className="check">
              <input
                type="checkbox"
                checked={draft.fields.valid_until === null}
                disabled={blocked || draft.preview}
                onChange={(event) =>
                  update({ valid_until: event.target.checked ? null : "" })
                }
              />
              {t("No expiry", "无到期时间")}
            </label>
          </div>
          {draft.preview && (
            <>
              <h3 className="grant-review-heading">
                {t("Review connection permission", "确认连接权限")}
              </h3>
              <GrantPreview
                fields={draft.fields}
                member={memberName(draft.fields.membership)}
                host={hostName(draft.fields.host)}
              />
            </>
          )}
          <div className="form-actions">
            {draft.preview ? (
              <>
                <button
                  type="button"
                  className="primary-button"
                  disabled={blocked}
                  onClick={() => void run(saved)}
                >
                  {busy
                    ? t("Saving…", "保存中…")
                    : draft.original
                      ? t("Replace Grant", "替换授权")
                      : t("Create Grant", "创建授权")}
                </button>
                <button
                  type="button"
                  className="secondary"
                  disabled={blocked}
                  onClick={() => setDraft({ ...draft, preview: false })}
                >
                  {t("Back to edit", "返回编辑")}
                </button>
              </>
            ) : (
              <button className="primary-button" disabled={blocked}>
                {t("Review Grant", "预览授权")}
              </button>
            )}
            <button
              type="button"
              className="quiet"
              disabled={blocked}
              onClick={() => setDraft(undefined)}
            >
              {t("Cancel", "取消")}
            </button>
          </div>
        </form>
      )}
      <div className="resource-list grant-list">
        {!busy && !items.length && failure === undefined && (
          <div className="empty-state">
            <h2>{t("No Host Grants", "暂无主机连接授权")}</h2>
            <p>
              {t(
                "Create a Grant to give a member connection access. Existing access rules remain in effect.",
                "创建授权可授予成员连接权限。现有访问规则仍然有效。",
              )}
            </p>
          </div>
        )}
        {items.map((item) => (
          <article className="resource-row" key={item.id}>
            <div>
              <h2>
                {memberName(item.data.membership)}{" "}
                <span className="grant-status">{statusName(item)}</span>
              </h2>
              <GrantPreview
                fields={item.data}
                member={memberName(item.data.membership)}
                host={hostName(item.data.host)}
              />
              <p className="mono identifier">{item.id}</p>
            </div>
            <div className="row-actions">
              <button
                type="button"
                className="secondary"
                disabled={!editable}
                onClick={() =>
                  void run((actions, epoch) => open(actions, epoch, item))
                }
              >
                {t("View / edit", "查看／编辑")}
              </button>
              <button
                type="button"
                className="danger"
                disabled={!editable}
                onClick={() =>
                  void run(async (actions, epoch) => {
                    if (
                      !(await confirm(
                        t(
                          `Withdraw this Grant for ${memberName(item.data.membership)} on ${hostName(item.data.host)} as “${item.data.remote_user}”? New certificates will no longer use it. Already issued certificates expire normally.`,
                          `撤回成员 ${memberName(item.data.membership)} 以“${item.data.remote_user}”连接 ${hostName(item.data.host)} 的授权吗？此后不再使用它签发新证书。已签发的证书正常到期。`,
                        ),
                      )) ||
                      epoch !== generation.current
                    )
                      return;
                    await actions.withdraw(item);
                    if (epoch === generation.current) {
                      setDraft(undefined);
                      setNotice(t("Grant withdrawn.", "授权已撤回。"));
                      await read(actions, epoch);
                    }
                  })
                }
              >
                {t("Withdraw", "撤回")}
              </button>
            </div>
          </article>
        ))}
      </div>
      {next && (
        <button
          type="button"
          className="secondary load-more"
          disabled={blocked}
          onClick={() =>
            void run((actions, epoch) => read(actions, epoch, next))
          }
        >
          {t("Load more Grants", "加载更多授权")}
        </button>
      )}
    </section>
  );
}
