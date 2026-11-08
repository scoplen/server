// SPDX-License-Identifier: AGPL-3.0-only
import { useEffect, useRef, useState } from "react";
import type {
  AccountProfile,
  OrganizationResource,
  TeamInvitationResource,
  TeamMemberResource,
  TeamRole,
  GroupResource,
} from "./generated/api.ts";
import {
  TeamApi,
  operationId,
  type AnyResource,
  type AnyFields,
  type CollectionKind,
  type ResourcesByKind,
} from "./team.ts";
import { Field, ResourceEditor, RoleOptions } from "./editors.tsx";
import { LanguageControl, useLocale } from "./locale.tsx";
import { useConfirmation } from "./confirm.tsx";
import { InvitationPanel, type InvitationHandle } from "./invitation-view.tsx";
import type { InvitationCrypto, JoinTarget } from "./invitation.ts";
import { SimpleRuleEditor, type RuleGenerator } from "./rule-editor.tsx";
import { requestFeedback } from "./feedback.ts";

type Section = CollectionKind | "members" | "invitations" | "settings" | "join";
type Catalog = { [K in CollectionKind]: ResourcesByKind[K][] };
const emptyCatalog = (): Catalog => ({
  hosts: [],
  "access-profiles": [],
  routes: [],
  "host-groups": [],
  groups: [],
  policies: [],
});
const kinds: CollectionKind[] = [
  "hosts",
  "host-groups",
  "access-profiles",
  "routes",
  "groups",
  "policies",
];
interface PendingReceipt {
  label: string;
  id: string;
  deadline: number;
  run: () => Promise<void>;
}

function resourceName(item: AnyResource): string {
  if ("fields" in item.data) {
    const fields = item.data.fields as { name?: string; username?: string };
    return fields.name ?? fields.username ?? item.id;
  }
  return String(item.data.name);
}

export function TeamWorkspace({
  api,
  username,
  shared,
  initialTarget,
  session,
  onLock,
  onSignOut,
}: {
  api: TeamApi;
  username: string;
  shared: { invitations: InvitationCrypto; rules: RuleGenerator };
  initialTarget?: JoinTarget;
  session: {
    busy: boolean;
    blocked: boolean;
    message: string;
    expired: boolean;
  };
  onLock: () => void;
  onSignOut: () => Promise<void>;
}) {
  const { t, language } = useLocale();
  const { confirm, dialog } = useConfirmation();
  const [profile, setProfile] = useState<AccountProfile | undefined>(undefined);
  const [teams, setTeams] = useState<OrganizationResource[]>([]);
  const [teamNext, setTeamNext] = useState<string | null>(null);
  const [team, setTeam] = useState<OrganizationResource | undefined>(undefined);
  const [section, setSection] = useState<Section>(
    initialTarget ? "join" : "hosts",
  );
  const [catalog, setCatalog] = useState<Catalog>(emptyCatalog);
  const [next, setNext] = useState<string | null>(null);
  const [members, setMembers] = useState<TeamMemberResource[]>([]);
  const [invitations, setInvitations] = useState<TeamInvitationResource[]>([]);
  const [busy, setBusy] = useState(true);
  const [notice, setNotice] = useState("");
  const [failure, setFailure] = useState<unknown>(undefined);
  const [editor, setEditor] = useState<
    | { kind: CollectionKind; original?: AnyResource; simple?: boolean }
    | undefined
  >(undefined);
  const [memberEdit, setMemberEdit] = useState<TeamMemberResource | undefined>(
    undefined,
  );
  const [memberRoles, setMemberRoles] = useState<TeamRole[]>([]);
  const [memberStatus, setMemberStatus] = useState<"active" | "suspended">(
    "active",
  );
  const [createTeam, setCreateTeam] = useState(false);
  const [inviteForm, setInviteForm] = useState(false);
  const [pendingVersion, setPendingVersion] = useState(0);
  const [dependencyWarning, setDependencyWarning] = useState(false);
  const [dependencyNext, setDependencyNext] = useState<
    Partial<Record<CollectionKind | "members", string>>
  >({});
  const invitationHandle = useRef<InvitationHandle | null>(null);
  const pending = useRef<PendingReceipt | undefined>(undefined);
  const mounted = useRef(true);
  const running = useRef(false);
  const heading = useRef<HTMLHeadingElement>(null);
  const disabled = busy || session.busy || session.blocked;
  const labels: Record<Section, string> = {
    hosts: t("Hosts", "主机"),
    "host-groups": t("Host groups", "主机分组"),
    "access-profiles": t("Access profiles", "访问配置"),
    routes: t("Routes", "路由"),
    groups: t("Member groups", "成员组"),
    policies: t("Access rules", "访问规则"),
    members: t("Members", "成员"),
    invitations: t("Invitations", "邀请"),
    settings: t("Team settings", "团队设置"),
    join: t("Join a team", "加入团队"),
  };
  const roleNames: Record<string, string> = {
    administrator: t("Administrator", "管理员"),
    approver: t("Approver", "审批者"),
    member: t("Member", "成员"),
    owner: t("Owner", "所有者"),
    security_auditor: t("Security auditor", "安全审计员"),
  };
  const statusNames: Record<string, string> = {
    active: t("Active", "有效"),
    suspended: t("Suspended", "已停用"),
    removed: t("Removed", "已移除"),
    pending: t("Pending", "待接受"),
    accepted: t("Accepted", "已接受"),
    revoked: t("Revoked", "已撤销"),
    expired: t("Expired", "已过期"),
    locked: t("Locked", "已锁定"),
  };
  const displayRoles = (roles: string[]) =>
    roles
      .map((role) => roleNames[role] ?? role)
      .join(language === "zh" ? "、" : ", ");

  useEffect(() => {
    if (editor || memberEdit || createTeam || inviteForm)
      heading.current?.focus();
  }, [editor, memberEdit, createTeam, inviteForm]);

  useEffect(() => {
    mounted.current = true;
    void (async () => {
      try {
        const account = await api.profile();
        const page = await api.organizations();
        if (!mounted.current) return;
        setProfile(account);
        setTeams(page.items);
        setTeamNext(page.next_cursor);
      } catch (error) {
        if (mounted.current) setFailure(error);
      } finally {
        if (mounted.current) setBusy(false);
      }
    })();
    return () => {
      mounted.current = false;
      invitationHandle.current?.dispose();
    };
  }, [api]);
  useEffect(() => {
    const warn = (event: BeforeUnloadEvent) => {
      if (pending.current) {
        event.preventDefault();
        event.returnValue = "";
      }
    };
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, []);

  async function run(action: () => Promise<void>, success = "") {
    if (running.current || session.blocked || session.busy) return;
    running.current = true;
    setBusy(true);
    setFailure(undefined);
    setNotice("");
    try {
      await action();
      if (mounted.current && success) setNotice(success);
    } catch (error) {
      if (mounted.current) setFailure(error);
    } finally {
      running.current = false;
      if (mounted.current) {
        setBusy(false);
        heading.current?.focus();
      }
    }
  }
  async function guardLeave(): Promise<boolean> {
    if (!invitationHandle.current?.hasSecret()) return true;
    if (
      !(await confirm(
        t(
          "Leaving this view clears its separate invitation password and original confirmation payload. An unresolved outcome cannot be recovered after dismissal. Continue?",
          "离开此页面将清除单独的邀请密码及原确认请求。丢弃后无法恢复尚未确认的原操作。要继续吗？",
        ),
      ))
    )
      return false;
    invitationHandle.current.dispose();
    return true;
  }
  async function sessionAction(action: () => void | Promise<void>) {
    if (!(await guardLeave())) return;
    if (
      pending.current &&
      !(await confirm(
        t(
          "This tab holds an unresolved original operation. Leaving the session loses its in-memory confirmation data. Review current state after signing in again; a new session cannot prove the old operation's outcome. Continue?",
          "本标签页保留了一项尚未确认的原操作。离开会话将丢失其内存中的确认数据。重新登录后请查看当前状态；新会话不能证明原操作结果。要继续吗？",
        ),
      ))
    )
      return;
    await action();
  }
  async function discover(append = false) {
    const page = await api.organizations(
      append ? (teamNext ?? undefined) : undefined,
    );
    if (!mounted.current) return;
    setTeams((items) => (append ? [...items, ...page.items] : page.items));
    setTeamNext(page.next_cursor);
  }
  async function load(target: Section, selected = team, append = false) {
    if (target === "join" || !selected) return;
    const cursor = append ? (next ?? undefined) : undefined;
    if (target === "settings") {
      const current = await api.organization(selected.id);
      if (mounted.current) setTeam(current);
    } else if (target === "members") {
      if (!append) setMembers([]);
      const page = await api.members(selected.id, cursor);
      if (mounted.current) {
        setMembers((items) =>
          append ? [...items, ...page.items] : page.items,
        );
        setNext(page.next_cursor);
      }
    } else if (target === "invitations") {
      if (!append) setInvitations([]);
      const page = await api.invitations(selected.id, cursor);
      if (mounted.current) {
        setInvitations((items) =>
          append ? [...items, ...page.items] : page.items,
        );
        setNext(page.next_cursor);
      }
    } else {
      if (!append) setCatalog((items) => ({ ...items, [target]: [] }));
      const page = await api.list(selected.id, target, cursor);
      if (mounted.current) {
        setCatalog((items) => ({
          ...items,
          [target]: append ? [...items[target], ...page.items] : page.items,
        }));
        setNext(page.next_cursor);
      }
    }
  }
  async function navigate(target: Section) {
    if (!(await guardLeave())) return;
    setSection(target);
    setEditor(undefined);
    setMemberEdit(undefined);
    setInviteForm(false);
    setNext(null);
    setFailure(undefined);
    setNotice("");
    await run(() => load(target));
  }
  async function selectTeam(id: string) {
    if (pending.current) return;
    if (!(await guardLeave())) return;
    const selected = teams.find((value) => value.id === id);
    setTeam(selected);
    setCatalog(emptyCatalog());
    setMembers([]);
    setInvitations([]);
    setEditor(undefined);
    setMemberEdit(undefined);
    setSection("hosts");
    setInviteForm(false);
    setNext(null);
    if (selected) await run(() => load("hosts", selected));
  }
  async function prepareEditor(
    kind: CollectionKind,
    original?: AnyResource,
    simple = false,
  ) {
    if (!team) return;
    await run(async () => {
      let denied = false;
      const cursors: Partial<Record<CollectionKind | "members", string>> = {};
      const keys = simple
        ? kinds.filter((key) => key !== "policies")
        : kind === "hosts" ||
            kind === "access-profiles" ||
            kind === "host-groups" ||
            kind === "routes"
          ? ([
              "hosts",
              "host-groups",
              "access-profiles",
              "routes",
            ] as CollectionKind[])
          : [];
      const results = await Promise.allSettled(
        keys.map(async (key) => {
          if (mounted.current) setCatalog((items) => ({ ...items, [key]: [] }));
          const page = await api.list(team.id, key);
          if (mounted.current)
            setCatalog((items) => ({ ...items, [key]: page.items }));
          if (page.next_cursor) cursors[key] = page.next_cursor;
        }),
      );
      if (results.some((result) => result.status === "rejected")) denied = true;
      if (simple || kind === "groups") {
        try {
          setMembers([]);
          const page = await api.members(team.id);
          if (mounted.current) setMembers(page.items);
          if (page.next_cursor) cursors.members = page.next_cursor;
        } catch {
          denied = true;
        }
      }
      if (mounted.current) {
        setDependencyWarning(denied);
        setDependencyNext(cursors);
        setEditor({ kind, original, simple });
      }
    });
  }
  async function loadMoreDependencies() {
    if (!team) return;
    await run(async () => {
      const cursors = { ...dependencyNext };
      const results = await Promise.allSettled(
        Object.entries(dependencyNext).map(async ([name, cursor]) => {
          const key = name as CollectionKind | "members";
          try {
            const page =
              key === "members"
                ? await api.members(team.id, cursor)
                : await api.list(team.id, key, cursor);
            if (mounted.current) {
              if (key === "members")
                setMembers((items) => [
                  ...items,
                  ...(page.items as TeamMemberResource[]),
                ]);
              else
                setCatalog((items) => ({
                  ...items,
                  [key]: [...items[key], ...page.items],
                }));
            }
            if (page.next_cursor) cursors[key] = page.next_cursor;
            else delete cursors[key];
          } catch (error) {
            delete cursors[key];
            if (mounted.current) {
              if (key === "members") setMembers([]);
              else setCatalog((items) => ({ ...items, [key]: [] }));
            }
            throw error;
          }
        }),
      );
      if (mounted.current) {
        setDependencyNext(cursors);
        if (results.some((result) => result.status === "rejected"))
          setDependencyWarning(true);
      }
    });
  }
  async function attemptPending() {
    const operation = pending.current;
    if (!operation || operation.deadline <= Date.now())
      throw new Error("original_receipt_expired");
    await operation.run();
    if (mounted.current && pending.current === operation) {
      pending.current = undefined;
      setPendingVersion((value) => value + 1);
    }
  }
  function confirmReceipt() {
    pending.current = undefined;
    if (mounted.current) setPendingVersion((value) => value + 1);
  }
  async function receipt(
    label: string,
    id: string,
    action: () => Promise<void>,
  ) {
    if (pending.current) throw new Error("original_operation_pending");
    pending.current = {
      label,
      id,
      deadline: Date.now() + 86_400_000,
      run: action,
    };
    setPendingVersion((value) => value + 1);
    await attemptPending();
  }
  async function save(fields: AnyFields) {
    if (!team || !editor) return;
    const selected = team,
      edit = editor,
      desired = structuredClone(fields);
    await run(
      async () => {
        const save = async () => {
          await api.save(
            selected.id,
            edit.kind,
            desired,
            edit.original,
            creation,
          );
          if (creation) confirmReceipt();
          if (mounted.current) setEditor(undefined);
          await load(edit.kind, selected);
        };
        const creation = edit.original
          ? undefined
          : { id: operationId(), key: operationId() };
        if (creation)
          await receipt(t("Create resource", "创建资源"), creation.id, save);
        else await save();
      },
      t(
        "Resource saved. Current server permissions still apply to every use.",
        "资源已保存。每次使用仍需通过服务器的当前权限检查。",
      ),
    );
  }
  const sectionItems: AnyResource[] = kinds.includes(section as CollectionKind)
    ? catalog[section as CollectionKind]
    : [];
  const owner = Boolean(team?.data.membership.roles.includes("owner"));
  const catalogAssets = kinds
    .filter((kind) => !["groups", "policies"].includes(kind))
    .flatMap((kind) =>
      catalog[kind].map((resource) => ({
        type: (
          {
            hosts: 1,
            "access-profiles": 2,
            routes: 4,
            "host-groups": 5,
            groups: 5,
            policies: 5,
          } as const
        )[kind],
        id: resource.id,
        label: resourceName(resource),
        kind,
        resource,
      })),
    );
  const date = (value: string) =>
    new Intl.DateTimeFormat(language === "zh" ? "zh-CN" : "en", {
      dateStyle: "medium",
      timeStyle: "short",
    }).format(new Date(value));

  return (
    <div className="console-shell team-shell">
      <a className="skip-link" href="#team-main">
        {t("Skip to content", "跳至内容")}
      </a>
      <header className="console-header">
        <span className="wordmark">Scoplen</span>
        <span className="context">{t("Team console", "团队控制台")}</span>
        <div className="session-actions">
          <span className="account-label">{username}</span>
          <LanguageControl />
          <button
            className="quiet"
            onClick={() => void sessionAction(onLock)}
            disabled={session.busy}
          >
            {t("Lock this tab", "锁定此标签页")}
          </button>
          <button
            className="secondary"
            onClick={() => void sessionAction(onSignOut)}
            disabled={busy || session.busy || session.expired}
          >
            {session.blocked
              ? t("Retry sign out", "重试退出登录")
              : t("Sign out", "退出登录")}
          </button>
        </div>
      </header>
      {session.message && (
        <div className="notice error" role="alert">
          {session.message}
        </div>
      )}
      <div className="team-layout">
        <aside className="team-sidebar">
          <Field label={t("Current team", "当前团队")}>
            <select
              value={team?.id ?? ""}
              disabled={disabled || Boolean(pending.current)}
              onChange={(event) => void selectTeam(event.target.value)}
            >
              <option value="">{t("Select a team…", "选择团队…")}</option>
              {teams.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.data.name}
                </option>
              ))}
            </select>
          </Field>
          {teamNext && (
            <button
              className="quiet"
              disabled={disabled}
              onClick={() => void run(() => discover(true))}
            >
              {t("Load more teams", "加载更多团队")}
            </button>
          )}
          <div className="sidebar-actions">
            <button
              className="quiet"
              disabled={disabled || Boolean(pending.current)}
              onClick={() =>
                void (async () => {
                  if (await guardLeave()) setCreateTeam(true);
                })()
              }
            >
              {t("Create team", "创建团队")}
            </button>
            <button
              className="quiet"
              disabled={disabled}
              onClick={() => void navigate("join")}
            >
              {t("Join a team", "加入团队")}
            </button>
            <button
              className="quiet"
              disabled={disabled}
              onClick={() => void run(() => discover())}
            >
              {t("Refresh teams", "刷新团队")}
            </button>
          </div>
          {team && (
            <>
              <p className="sidebar-membership">
                {t("Your current roles", "当前角色")}:{" "}
                {displayRoles(team.data.membership.roles)}
              </p>
              <nav aria-label={t("Team areas", "团队功能")}>
                {(
                  [
                    "hosts",
                    "host-groups",
                    "access-profiles",
                    "routes",
                    "members",
                    "invitations",
                    "groups",
                    "policies",
                    "settings",
                  ] as Section[]
                ).map((item) => (
                  <button
                    key={item}
                    aria-current={section === item ? "page" : undefined}
                    disabled={disabled}
                    onClick={() => void navigate(item)}
                  >
                    {labels[item]}
                  </button>
                ))}
              </nav>
            </>
          )}
          <p className="caption">
            {t(
              "Team data is visible to this deployment. Personal vaults and device keys are opened only in the desktop app.",
              "团队数据可由此部署读取。个人保险库及设备密钥仅在桌面端打开。",
            )}
          </p>
        </aside>
        <main
          id="team-main"
          className="team-main"
          tabIndex={-1}
          aria-busy={busy}
        >
          <div className="page-heading">
            <div>
              <p className="eyebrow">
                {team?.data.name ?? t("Your Account", "您的账号")}
              </p>
              <h1 ref={heading} tabIndex={-1}>
                {createTeam ? t("Create a team", "创建团队") : labels[section]}
              </h1>
            </div>
            <div className="inline-actions">
              {team && section !== "join" && !editor && !createTeam && (
                <button
                  className="secondary"
                  disabled={disabled}
                  onClick={() => void run(() => load(section))}
                >
                  {t("Refresh view", "刷新当前列表")}
                </button>
              )}
              {team &&
                kinds.includes(section as CollectionKind) &&
                !editor &&
                !createTeam && (
                  <button
                    className="primary-button"
                    disabled={disabled || Boolean(pending.current)}
                    onClick={() =>
                      void prepareEditor(section as CollectionKind)
                    }
                  >
                    {t("Create", "创建")}
                  </button>
                )}
              {team && section === "policies" && !editor && !createTeam && (
                <button
                  className="secondary"
                  disabled={disabled || Boolean(pending.current)}
                  onClick={() =>
                    void prepareEditor("policies", undefined, true)
                  }
                >
                  {t("Create simple rule", "创建简单规则")}
                </button>
              )}
              {team &&
                section === "invitations" &&
                !inviteForm &&
                !createTeam && (
                  <button
                    className="primary-button"
                    disabled={disabled || Boolean(pending.current)}
                    onClick={() => setInviteForm(true)}
                  >
                    {t("Invite by username", "通过用户名邀请")}
                  </button>
                )}
            </div>
          </div>
          {notice && (
            <p className="notice" role="status">
              {notice}
            </p>
          )}
          {failure !== undefined && (
            <p className="notice error" role="alert">
              {requestFeedback(failure, t)}
            </p>
          )}
          {pending.current && (
            <section
              className="notice error pending-operation"
              data-version={pendingVersion}
            >
              <h2>{t("Original operation retained", "原操作已保留")}</h2>
              <p>{pending.current.label}</p>
              <p className="mono identifier">{pending.current.id}</p>
              <p>
                {t(
                  "Confirm only the original key and payload within its original 24-hour window. No retry runs automatically. Refreshing a list cannot prove this operation's outcome.",
                  "请在原 24 小时期限内，仅使用原操作键及请求确认。不会自动重试，刷新列表也无法证明此操作的结果。",
                )}
              </p>
              <div className="inline-actions">
                <button
                  className="secondary"
                  disabled={disabled || pending.current.deadline <= Date.now()}
                  onClick={() =>
                    void run(
                      attemptPending,
                      t("Original operation confirmed.", "原操作已确认。"),
                    )
                  }
                >
                  {t("Confirm original operation", "确认原操作")}
                </button>
                <button
                  className="quiet"
                  disabled={disabled}
                  onClick={() =>
                    void (async () => {
                      if (
                        await confirm(
                          t(
                            "Discard this original confirmation data? Its outcome remains unresolved. Review current state before creating a replacement.",
                            "要丢弃原确认数据吗？其结果仍未确认。创建替代操作前，请先检查当前状态。",
                          ),
                        )
                      ) {
                        pending.current = undefined;
                        setPendingVersion((value) => value + 1);
                      }
                    })()
                  }
                >
                  {t("Discard after review", "审阅后丢弃")}
                </button>
              </div>
            </section>
          )}
          {createTeam ? (
            <form
              className="editor"
              onSubmit={(event) => {
                event.preventDefault();
                const name = String(
                  new FormData(event.currentTarget).get("name"),
                );
                const key = operationId();
                void run(
                  () =>
                    receipt(t("Create team", "创建团队"), key, async () => {
                      const result = await api.createTeam(name, key);
                      confirmReceipt();
                      if (!mounted.current) return;
                      setCreateTeam(false);
                      setTeam(result);
                      setSection("hosts");
                      await discover();
                      await load("hosts", result);
                    }),
                  t(
                    "Team created. You are its initial Owner.",
                    "团队已创建，您是初始所有者。",
                  ),
                );
              }}
            >
              <Field label={t("Team name", "团队名称")}>
                <input
                  name="name"
                  required
                  maxLength={128}
                  disabled={disabled || Boolean(pending.current)}
                />
              </Field>
              <p className="caption">
                {t(
                  "The deployment controls who may create teams. Creation does not move or expose Personal inventory.",
                  "部署控制谁可以创建团队。创建团队不会移动或公开个人资产。",
                )}
              </p>
              <div className="form-actions">
                <button
                  className="primary-button"
                  disabled={disabled || Boolean(pending.current)}
                >
                  {t("Create team", "创建团队")}
                </button>
                <button
                  type="button"
                  className="secondary"
                  disabled={disabled}
                  onClick={() => setCreateTeam(false)}
                >
                  {t("Cancel", "取消")}
                </button>
              </div>
            </form>
          ) : section === "join" ? (
            <InvitationPanel
              key="join"
              disabled={session.blocked || session.busy}
              api={api}
              shared={shared.invitations}
              ownerAllowed={false}
              initialTarget={initialTarget}
              handle={invitationHandle}
              confirm={confirm}
              onBusy={setBusy}
              onFailure={setFailure}
              onChanged={async () => {
                await discover();
              }}
            />
          ) : !team ? (
            <div className="empty-state">
              <h2>
                {teams.length
                  ? t("Choose a team to continue", "请选择团队以继续")
                  : t("No teams loaded", "尚无团队")}
              </h2>
              <p>
                {t(
                  "Select a current membership, create a team if your deployment permits it, or join an addressed invitation. Team discovery does not require asset visibility.",
                  "可选择当前团队、在部署许可时创建团队，或接受指定接收者的邀请。发现自己的团队不需要资产可见权限。",
                )}
              </p>
              {profile && (
                <p className="caption mono identifier">
                  {t("Current Account", "当前账号")}: {profile.id}
                </p>
              )}
            </div>
          ) : editor ? (
            <>
              <h2>
                {editor.original
                  ? t("Edit resource", "编辑资源")
                  : editor.simple
                    ? t("New access rule", "新访问规则")
                    : t("New resource", "新资源")}
              </h2>
              {(dependencyWarning ||
                Object.keys(dependencyNext).length > 0) && (
                <p className="notice">
                  {t(
                    "Some choices are not visible or more pages are available. Existing opaque IDs are preserved. Load more choices below; missing visibility is never granted automatically.",
                    "部分选项不可见，或仍有后续页面。现有不透明 ID 会保留。可在下方加载更多选项；不会自动授予缺少的可见权限。",
                  )}
                </p>
              )}
              {Object.keys(dependencyNext).length > 0 && (
                <button
                  className="secondary"
                  disabled={disabled || Boolean(pending.current)}
                  onClick={() => void loadMoreDependencies()}
                >
                  {t("Load more choices", "加载更多选项")}
                </button>
              )}
              {editor.simple ? (
                <SimpleRuleEditor
                  organization={team.id}
                  members={members}
                  groups={catalog.groups as GroupResource[]}
                  assets={catalogAssets}
                  shared={shared.rules}
                  disabled={disabled || Boolean(pending.current)}
                  saving={busy}
                  onSave={save}
                  onCancel={() => setEditor(undefined)}
                />
              ) : (
                <ResourceEditor
                  key={`${editor.kind}:${editor.original?.id ?? "new"}`}
                  kind={editor.kind}
                  original={editor.original}
                  inventory={catalog}
                  members={members}
                  disabled={disabled || Boolean(pending.current)}
                  saving={busy}
                  onSave={save}
                  onCancel={() => setEditor(undefined)}
                />
              )}
            </>
          ) : section === "members" ? (
            <>
              {memberEdit ? (
                <form
                  className="editor"
                  onSubmit={(event) => {
                    event.preventDefault();
                    if (pending.current) return;
                    const current = memberEdit;
                    void run(
                      async () => {
                        await api.updateMember(team.id, current, {
                          roles: memberRoles,
                          status: memberStatus,
                        });
                        setMemberEdit(undefined);
                        await load("members");
                      },
                      t("Membership updated.", "成员资格已更新。"),
                    );
                  }}
                >
                  <h2>{memberEdit.data.username}</h2>
                  <RoleOptions
                    roles={memberRoles}
                    onChange={setMemberRoles}
                    ownerAllowed={owner}
                    disabled={disabled}
                  />
                  <Field label={t("Status", "状态")}>
                    <select
                      value={memberStatus}
                      onChange={(event) =>
                        setMemberStatus(
                          event.target.value as "active" | "suspended",
                        )
                      }
                      disabled={disabled}
                    >
                      <option value="active">{t("Active", "有效")}</option>
                      <option value="suspended">
                        {t("Suspended", "已停用")}
                      </option>
                    </select>
                  </Field>
                  <p className="caption">
                    {t(
                      "Only an Owner may change an Owner. At least one active Owner must remain. A removed membership requires a new invitation.",
                      "仅所有者可以更改所有者。必须保留至少一名有效所有者。已移除的成员需要新邀请。",
                    )}
                  </p>
                  <div className="form-actions">
                    <button
                      className="primary-button"
                      disabled={
                        disabled ||
                        Boolean(pending.current) ||
                        memberRoles.length === 0
                      }
                    >
                      {t("Save membership", "保存成员资格")}
                    </button>
                    <button
                      type="button"
                      className="secondary"
                      disabled={disabled}
                      onClick={() => setMemberEdit(undefined)}
                    >
                      {t("Cancel", "取消")}
                    </button>
                  </div>
                </form>
              ) : (
                <>
                  <p className="section-intro">
                    {t(
                      "Membership and local groups govern this team only. Current server authorization is checked for every change.",
                      "成员资格与本地成员组仅影响此团队。每次更改都将检查服务器的当前授权。",
                    )}
                  </p>
                  <div className="resource-list">
                    {members.map((item) => (
                      <article className="resource-row" key={item.id}>
                        <div>
                          <h2>{item.data.username}</h2>
                          <p>
                            {displayRoles(item.data.roles)} ·{" "}
                            {statusNames[item.data.status]}
                          </p>
                          <p className="mono identifier">{item.id}</p>
                        </div>
                        <div className="row-actions">
                          <button
                            className="secondary"
                            disabled={
                              disabled ||
                              Boolean(pending.current) ||
                              item.data.status === "removed"
                            }
                            onClick={() => {
                              setMemberEdit(item);
                              setMemberRoles(item.data.roles);
                              setMemberStatus(
                                item.data.status === "suspended"
                                  ? "suspended"
                                  : "active",
                              );
                            }}
                          >
                            {t("Edit", "编辑")}
                          </button>
                          <button
                            className="danger"
                            disabled={
                              disabled ||
                              Boolean(pending.current) ||
                              item.data.status === "removed"
                            }
                            onClick={() =>
                              void (async () => {
                                if (pending.current) return;
                                if (
                                  await confirm(
                                    t(
                                      "Remove this member from this team? Personal data, other teams and existing plaintext copies remain. Already issued direct certificates retain their actual validity.",
                                      "要将此成员移出团队吗？个人数据、其他团队及已有明文副本将保留。已颁发的直连证书在实际有效期内仍有效。",
                                    ),
                                  )
                                )
                                  await run(
                                    async () => {
                                      await api.removeMember(team.id, item);
                                      if (
                                        item.data.account_id === api.accountId
                                      ) {
                                        setTeam(undefined);
                                        setCatalog(emptyCatalog());
                                        setMembers([]);
                                      } else await load("members");
                                      await discover();
                                    },
                                    t(
                                      "Member removed from this team.",
                                      "成员已从此团队移除。",
                                    ),
                                  );
                              })()
                            }
                          >
                            {t("Remove", "移除")}
                          </button>
                        </div>
                      </article>
                    ))}
                  </div>
                  {members.length === 0 && !busy && (
                    <p className="empty-state">
                      {t(
                        "No members are loaded. Refresh this view; your current permissions may restrict the directory.",
                        "尚未加载成员。请刷新此列表；当前权限可能限制了成员目录访问。",
                      )}
                    </p>
                  )}
                </>
              )}
            </>
          ) : section === "invitations" ? (
            <>
              {inviteForm && (
                <InvitationPanel
                  key={`create:${team.id}`}
                  disabled={session.blocked || session.busy}
                  api={api}
                  shared={shared.invitations}
                  organization={team.id}
                  ownerAllowed={owner}
                  handle={invitationHandle}
                  confirm={confirm}
                  onBusy={setBusy}
                  onFailure={setFailure}
                  onChanged={async () => {
                    await load("invitations");
                  }}
                />
              )}
              <div className="resource-list">
                {invitations.map((item) => (
                  <article className="resource-row" key={item.id}>
                    <div>
                      <h2>{item.data.recipient_username}</h2>
                      <p>
                        {displayRoles(item.data.roles)} ·{" "}
                        {statusNames[item.data.status]}
                      </p>
                      <p className="caption">
                        {t("Expires", "到期")}: {date(item.data.expires_at)}
                      </p>
                      <p className="mono identifier">{item.id}</p>
                    </div>
                    <div className="row-actions">
                      <button
                        className="danger"
                        disabled={
                          disabled ||
                          !["pending", "locked", "revoked"].includes(
                            item.data.status,
                          )
                        }
                        onClick={() =>
                          void (async () => {
                            if (
                              await confirm(
                                t(
                                  "Revoke this selected invitation? It will no longer allow joining. This does not remove an accepted member. A lost or unconfirmed reply requires refresh and review.",
                                  "要撤销所选邀请吗？撤销后将无法用它加入团队，但不会移除已接受邀请的成员。响应丢失或未确认时需要刷新并审阅。",
                                ),
                              )
                            )
                              await run(
                                async () => {
                                  await api.revoke(team.id, item);
                                  await load("invitations");
                                },
                                t(
                                  "Invitation revocation confirmed.",
                                  "邀请撤销已确认。",
                                ),
                              );
                          })()
                        }
                      >
                        {t("Revoke", "撤销")}
                      </button>
                    </div>
                  </article>
                ))}
              </div>
              {invitations.length === 0 && !busy && (
                <p className="empty-state">
                  {t(
                    "No invitations are loaded. Invite an existing Account by its exact username. The list never contains invitation passwords.",
                    "尚未加载邀请。可通过精确用户名邀请现有账号。列表不会包含邀请密码。",
                  )}
                </p>
              )}
            </>
          ) : section === "settings" ? (
            <>
              <form
                className="editor"
                key={team.etag}
                onSubmit={(event) => {
                  event.preventDefault();
                  const name = String(
                    new FormData(event.currentTarget).get("name"),
                  );
                  void run(
                    async () => {
                      const current = await api.rename(team, name);
                      setTeam(current);
                      await discover();
                    },
                    t("Team name saved.", "团队名称已保存。"),
                  );
                }}
              >
                <Field label={t("Team name", "团队名称")}>
                  <input
                    name="name"
                    defaultValue={team.data.name}
                    required
                    maxLength={128}
                    disabled={disabled}
                  />
                </Field>
                <p className="caption">
                  {t(
                    "A stale edit is rejected. Refresh and review before applying another edit; no ETag is substituted automatically.",
                    "过期编辑会被拒绝。再次编辑前请刷新并审阅，不会自动替换 ETag。",
                  )}
                </p>
                <div className="form-actions">
                  <button className="primary-button" disabled={disabled}>
                    {t("Save name", "保存名称")}
                  </button>
                </div>
              </form>
              <section className="danger-zone">
                <h2>{t("Leave this team", "离开此团队")}</h2>
                <p>
                  {t(
                    "Your Personal data and other teams are retained. The final active Owner cannot leave.",
                    "个人数据及其他团队将保留。最后一名有效所有者不能离开。",
                  )}
                </p>
                <button
                  className="danger"
                  disabled={disabled || Boolean(pending.current)}
                  onClick={() =>
                    void (async () => {
                      if (pending.current) return;
                      if (
                        await confirm(
                          t(
                            "Leave this team? Team access will end. Personal data and other teams remain; already obtained plaintext cannot be recalled.",
                            "要离开此团队吗？团队访问将结束，个人数据及其他团队将保留，已经获得的明文无法撤回。",
                          ),
                        )
                      )
                        await run(
                          async () => {
                            await api.removeMember(team.id, {
                              id: team.data.membership.id,
                              etag: team.etag,
                            });
                            setTeam(undefined);
                            setCatalog(emptyCatalog());
                            await discover();
                          },
                          t("You left this team.", "您已离开此团队。"),
                        );
                    })()
                  }
                >
                  {t("Leave team", "离开团队")}
                </button>
              </section>
              <section className="danger-zone">
                <h2>{t("Dissolve this team", "解散此团队")}</h2>
                <p>
                  {t(
                    "Owner only. Team memberships, invitations and team access end. Accounts, Personal data, other teams and required audit evidence remain. Remove installed host trust separately.",
                    "仅所有者可以操作。团队成员资格、邀请及团队访问将结束。账号、个人数据、其他团队及必要审计证据将保留。已安装的主机信任需要单独移除。",
                  )}
                </p>
                <button
                  className="danger"
                  disabled={disabled || !owner || Boolean(pending.current)}
                  onClick={() =>
                    void (async () => {
                      if (
                        !(await confirm(
                          t(
                            "Dissolve this team and end all of its memberships and access? Personal data and other teams are retained. Installed host trust must be removed separately.",
                            "要解散此团队并结束所有成员资格及访问吗？个人数据及其他团队将保留，已安装的主机信任必须单独移除。",
                          ),
                        ))
                      )
                        return;
                      const original = team,
                        key = operationId();
                      await run(
                        () =>
                          receipt(
                            t("Dissolve team", "解散团队"),
                            original.id,
                            async () => {
                              await api.dissolve(original, key);
                              confirmReceipt();
                              setTeam(undefined);
                              setCatalog(emptyCatalog());
                              await discover();
                            },
                          ),
                        t(
                          "Team dissolution confirmed. Personal data and other teams were retained.",
                          "团队解散已确认。个人数据及其他团队已保留。",
                        ),
                      );
                    })()
                  }
                >
                  {t("Dissolve team", "解散团队")}
                </button>
              </section>
            </>
          ) : (
            <>
              <p className="section-intro">
                {section === "hosts"
                  ? t(
                      "Create a Host, add an access profile with a remote username and direct route 0, then set that profile as the Host default. Grant asset visibility and connection permission separately in Access rules.",
                      "创建主机后，添加包含远程用户名及直连路由 0 的访问配置，再将其设为主机默认配置。请在访问规则中分别授予资产可见及连接权限。",
                    )
                  : section === "policies"
                    ? t(
                        "Visibility and connection are separate. Simple rules use the shared Rust generator; Advanced source uses the same server schema and authorization. Cached roles never grant access.",
                        "可见与连接权限彼此独立。简单规则由共享 Rust 生成器生成，高级源码使用相同的服务器模式及授权。缓存角色不会授予访问权限。",
                      )
                    : t(
                        "Each resource and dependency is checked against the current team and its own visibility permission. References do not grant access to a hidden dependency.",
                        "每个资源及依赖对象都会单独检查所属团队与当前可见权限。引用不会授予隐藏依赖对象的访问权限。",
                      )}
              </p>
              <div className="resource-list">
                {sectionItems.map((item) => (
                  <article className="resource-row" key={item.id}>
                    <div>
                      <h2>{resourceName(item)}</h2>
                      {"fields" in item.data && section === "hosts" && (
                        <p className="mono">
                          {String(
                            (
                              item.data
                                .fields as ResourcesByKind["hosts"]["data"]["fields"]
                            ).address,
                          )}
                          :
                          {(
                            item.data
                              .fields as ResourcesByKind["hosts"]["data"]["fields"]
                          ).port ?? 22}
                        </p>
                      )}
                      {section === "access-profiles" && (
                        <p className="mono">
                          {String(
                            (
                              item.data as ResourcesByKind["access-profiles"]["data"]
                            ).fields.username,
                          )}{" "}
                          · {t("Route", "路由")}:{" "}
                          {String(
                            (
                              item.data as ResourcesByKind["access-profiles"]["data"]
                            ).fields.route ?? 0,
                          )}
                        </p>
                      )}
                      {section === "policies" && (
                        <p>
                          {(item.data as ResourcesByKind["policies"]["data"])
                            .enabled
                            ? t("Enabled", "已启用")
                            : t("Disabled", "已禁用")}
                        </p>
                      )}
                      {section === "groups" && (
                        <p>
                          {(item.data as ResourcesByKind["groups"]["data"])
                            .source === "local"
                            ? t("Local group", "本地成员组")
                            : t("Identity provider group", "身份提供商成员组")}
                        </p>
                      )}
                      <p className="mono identifier">{item.id}</p>
                      {section === "hosts" &&
                        !(item.data as ResourcesByKind["hosts"]["data"]).fields
                          .default_profile && (
                          <p className="attention-text">
                            {t(
                              "No default access profile. Add a profile, then edit this Host to link it.",
                              "尚无默认访问配置。请先添加访问配置，再编辑此主机以关联。",
                            )}
                          </p>
                        )}
                    </div>
                    <div className="row-actions">
                      <button
                        className="secondary"
                        disabled={
                          disabled ||
                          Boolean(pending.current) ||
                          (section === "groups" &&
                            (item.data as ResourcesByKind["groups"]["data"])
                              .source === "IdP")
                        }
                        onClick={() =>
                          void prepareEditor(section as CollectionKind, item)
                        }
                      >
                        {section === "policies"
                          ? t("Advanced editor", "高级编辑器")
                          : t("Edit", "编辑")}
                      </button>
                      <button
                        className="danger"
                        disabled={
                          disabled ||
                          (section === "groups" &&
                            (item.data as ResourcesByKind["groups"]["data"])
                              .source === "IdP")
                        }
                        onClick={() =>
                          void (async () => {
                            if (
                              await confirm(
                                t(
                                  "Delete this selected resource? Active references prevent deletion. An unconfirmed reply requires refresh and review; it is never retried automatically.",
                                  "要删除所选资源吗？有效引用会阻止删除。响应未确认时需要刷新并审阅，不会自动重试。",
                                ),
                              )
                            )
                              await run(
                                async () => {
                                  await api.remove(
                                    team.id,
                                    section as CollectionKind,
                                    item,
                                  );
                                  await load(section);
                                },
                                t(
                                  "Resource deletion confirmed.",
                                  "资源删除已确认。",
                                ),
                              );
                          })()
                        }
                      >
                        {t("Delete", "删除")}
                      </button>
                    </div>
                  </article>
                ))}
              </div>
              {sectionItems.length === 0 && !busy && (
                <div className="empty-state">
                  <h2>{t("No resources loaded", "尚未加载资源")}</h2>
                  <p>
                    {t(
                      "Refresh the permitted view or create a resource when you have management permission. An empty list does not reveal hidden resources or confirm a lost mutation.",
                      "可刷新已获许可的列表，或在拥有管理权限时创建资源。空列表不会披露隐藏资源，也不能确认丢失的修改结果。",
                    )}
                  </p>
                </div>
              )}
            </>
          )}
          {next &&
            !editor &&
            !createTeam &&
            section !== "join" &&
            section !== "settings" && (
              <button
                className="secondary load-more"
                disabled={disabled}
                onClick={() => void run(() => load(section, team, true))}
              >
                {t("Load more", "加载更多")}
              </button>
            )}
          {busy && (
            <p className="loading-status" role="status">
              {t("Waiting for the deployment…", "正在等待部署响应…")}
            </p>
          )}
        </main>
      </div>
      <footer>
        <span>{t("Self-hosted by your deployment", "由您的部署自行托管")}</span>
        <span className="deployment">{new URL(api.transport.origin).host}</span>
      </footer>
      {dialog}
    </div>
  );
}
