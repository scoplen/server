// SPDX-License-Identifier: AGPL-3.0-only
import { useState, type ReactNode } from "react";
import type { TeamMemberResource, TeamRole } from "./generated/api.ts";
import {
  parseFields,
  teamRoles,
  type AnyFields,
  type AnyResource,
  type CollectionKind,
  type ResourcesByKind,
} from "./team.ts";
import { object, strictJson, uuid } from "./wire.ts";
import { useLocale } from "./locale.tsx";

export function Field({
  label,
  children,
  help,
}: {
  label: string;
  children: ReactNode;
  help?: string;
}) {
  return (
    <label className="field">
      <span>{label}</span>
      {children}
      {help && <span className="field-help">{help}</span>}
    </label>
  );
}

export function RoleOptions({
  roles,
  onChange,
  ownerAllowed = true,
  disabled = false,
}: {
  roles: TeamRole[];
  onChange: (roles: TeamRole[]) => void;
  ownerAllowed?: boolean;
  disabled?: boolean;
}) {
  const { t } = useLocale();
  const labels = [
    t("Administrator", "管理员"),
    t("Approver", "审批者"),
    t("Member", "成员"),
    t("Owner", "所有者"),
    t("Security auditor", "安全审计员"),
  ];
  return (
    <fieldset className="check-list" disabled={disabled}>
      <legend>{t("Roles", "角色")}</legend>
      {teamRoles.map((role, index) => (
        <label key={role}>
          <input
            type="checkbox"
            checked={roles.includes(role)}
            disabled={role === "owner" && !ownerAllowed}
            onChange={(event) =>
              onChange(
                event.target.checked
                  ? [...roles, role].sort()
                  : roles.filter((value) => value !== role),
              )
            }
          />
          {labels[index]}
        </label>
      ))}
    </fieldset>
  );
}

type Inventory = {
  hosts: ResourcesByKind["hosts"][];
  "access-profiles": ResourcesByKind["access-profiles"][];
  "host-groups": ResourcesByKind["host-groups"][];
  routes: ResourcesByKind["routes"][];
};

function RefSelect({
  name,
  value,
  resources,
  optional,
  label,
  disabled,
  exclude,
}: {
  name: string;
  value?: string;
  resources: { id: string; label: string }[];
  optional?: string;
  label: string;
  disabled?: boolean;
  exclude?: string;
}) {
  const { t } = useLocale();
  const visible = resources.filter((item) => item.id !== exclude);
  return (
    <Field label={label}>
      <select
        name={name}
        defaultValue={value ?? ""}
        disabled={disabled}
        required={!optional}
      >
        <option value="">{optional ?? t("Select…", "请选择…")}</option>
        {value && !visible.some((item) => item.id === value) && (
          <option value={value}>
            {t("Not in this loaded view", "当前列表中不可见")} · {value}
          </option>
        )}
        {visible.map((item) => (
          <option key={item.id} value={item.id}>
            {item.label}
          </option>
        ))}
      </select>
    </Field>
  );
}

function MapField({
  name,
  value,
  label,
  help,
}: {
  name: string;
  value?: Record<string, string>;
  label: string;
  help?: string;
}) {
  return (
    <Field label={label} help={help}>
      <textarea
        name={name}
        className="code-input"
        defaultValue={value ? JSON.stringify(value, null, 2) : ""}
        rows={3}
        spellCheck={false}
      />
    </Field>
  );
}

export function ResourceEditor({
  kind,
  original,
  inventory,
  members,
  disabled,
  saving,
  onSave,
  onCancel,
}: {
  kind: CollectionKind;
  original?: AnyResource;
  inventory: Inventory;
  members: TeamMemberResource[];
  disabled: boolean;
  saving: boolean;
  onSave: (fields: AnyFields) => Promise<void>;
  onCancel: () => void;
}) {
  const { t } = useLocale();
  const [error, setError] = useState(false);
  const initial =
    original && "fields" in original.data
      ? (original.data.fields as Record<string, unknown>)
      : {};
  const initialGroup =
    original && kind === "groups"
      ? (original as ResourcesByKind["groups"]).data
      : undefined;
  const initialPolicy =
    original && kind === "policies"
      ? (original as ResourcesByKind["policies"]).data
      : undefined;
  const [routeKind, setRouteKind] = useState(Number(initial.kind ?? 1));
  const [profileHost, setProfileHost] = useState(String(initial.host ?? ""));
  const [groupMembers, setGroupMembers] = useState<string[]>(
    initialGroup?.members ?? [],
  );
  const labels = <K extends keyof Inventory>(key: K) =>
    inventory[key].map((item) => ({
      id: item.id,
      label: (item.data.fields as { name?: string }).name ?? item.id,
    }));
  const optional = t("None", "无");

  async function submit(form: HTMLFormElement) {
    setError(false);
    let fields: AnyFields;
    try {
      const data = new FormData(form);
      if (kind === "groups")
        fields = {
          name: String(data.get("name")),
          members: [...groupMembers].sort(),
        };
      else if (kind === "policies")
        fields = {
          name: String(data.get("name")),
          source: String(data.get("source")),
          enabled: data.has("enabled"),
        };
      else fields = fieldsFromForm(kind, data);
    } catch {
      setError(true);
      return;
    }
    await onSave(fields);
  }

  return (
    <form
      className="editor"
      onSubmit={(event) => {
        event.preventDefault();
        void submit(event.currentTarget);
      }}
    >
      <fieldset disabled={disabled} className="form-fields">
        {kind === "hosts" && (
          <>
            <div className="form-row">
              <Field label={t("Host name", "主机名称")}>
                <input
                  name="name"
                  defaultValue={String(initial.name ?? "")}
                  required
                />
              </Field>
              <Field label={t("Address", "地址")}>
                <input
                  name="address"
                  className="mono"
                  defaultValue={String(initial.address ?? "")}
                  required
                  autoCapitalize="none"
                  spellCheck={false}
                />
              </Field>
              <Field label={t("Port", "端口")}>
                <input
                  name="port"
                  type="number"
                  min={1}
                  max={65_535}
                  defaultValue={Number(initial.port ?? 22)}
                  required
                />
              </Field>
            </div>
            <fieldset className="check-list">
              <legend>{t("Host groups", "主机分组")}</legend>
              {inventory["host-groups"].map((group) => (
                <label key={group.id}>
                  <input
                    type="checkbox"
                    name="groups"
                    value={group.id}
                    defaultChecked={Boolean(
                      (initial.groups as Record<string, true> | undefined)?.[
                        group.id
                      ],
                    )}
                  />
                  {group.data.fields.name}
                </label>
              ))}
              {Object.keys(initial.groups ?? {})
                .filter(
                  (id) =>
                    !inventory["host-groups"].some((group) => group.id === id),
                )
                .map((id) => (
                  <label key={id}>
                    <input
                      type="checkbox"
                      name="groups"
                      value={id}
                      defaultChecked
                    />
                    {t("Not in this loaded view", "当前列表中不可见")} ·{" "}
                    <span className="mono">{id}</span>
                  </label>
                ))}
            </fieldset>
            {original && (
              <RefSelect
                name="default_profile"
                value={initial.default_profile as string | undefined}
                resources={inventory["access-profiles"]
                  .filter((profile) => profile.data.fields.host === original.id)
                  .map((profile) => ({
                    id: profile.id,
                    label: `${profile.data.fields.name ?? profile.data.fields.username} · ${profile.data.fields.username}`,
                  }))}
                optional={optional}
                label={t("Default Login", "默认登录配置")}
              />
            )}
            {!original && (
              <p className="field-help">
                {t(
                  "After creating this Host, add a Login and select it as the default. Choose Direct to connect without a jump host or proxy.",
                  "创建主机后，请添加登录配置并将其设为默认值。选择直连即可连接，无需跳板主机或代理。",
                )}
              </p>
            )}
            <Field label={t("Notes", "备注")}>
              <textarea
                name="notes"
                defaultValue={String(initial.notes ?? "")}
                rows={3}
              />
            </Field>
            <label className="check">
              <input
                type="checkbox"
                name="favorite"
                defaultChecked={Boolean(initial.favorite)}
              />
              {t("Favorite", "收藏")}
            </label>
            <details>
              <summary>{t("Advanced host fields", "高级主机字段")}</summary>
              <MapField
                name="tags"
                value={initial.tags as Record<string, string>}
                label={t("Tags (JSON text map)", "标签（JSON 文本映射）")}
              />
              <MapField
                name="ssh_options"
                value={initial.ssh_options as Record<string, string>}
                label={t(
                  "SSH options (JSON text map)",
                  "SSH 选项（JSON 文本映射）",
                )}
              />
              <MapField
                name="mosh"
                value={initial.mosh as Record<string, string>}
                label={t(
                  "Mosh settings (JSON text map)",
                  "Mosh 设置（JSON 文本映射）",
                )}
              />
            </details>
          </>
        )}
        {kind === "access-profiles" && (
          <>
            <Field label={t("Host", "主机")}>
              <select
                name="host"
                value={profileHost}
                onChange={(event) => setProfileHost(event.target.value)}
                required
              >
                <option value="">{t("Select a Host…", "请选择主机…")}</option>
                {initial.host &&
                !inventory.hosts.some((host) => host.id === initial.host) ? (
                  <option value={String(initial.host)}>
                    {t("Not in this loaded view", "当前列表中不可见")} ·{" "}
                    {String(initial.host)}
                  </option>
                ) : null}
                {inventory.hosts.map((host) => (
                  <option key={host.id} value={host.id}>
                    {host.data.fields.name}
                  </option>
                ))}
              </select>
            </Field>
            <div className="form-row">
              <Field label={t("Login name (optional)", "登录配置名称（可选）")}>
                <input name="name" defaultValue={String(initial.name ?? "")} />
              </Field>
              <Field
                label={t("Remote username", "远程用户名")}
                help={t(
                  "Preserved exactly. This is the SSH login user.",
                  "将按原样保留。这是 SSH 登录用户。彼此独立的访问权限仍需配置。 ",
                )}
              >
                <input
                  name="username"
                  className="mono"
                  defaultValue={String(initial.username ?? "")}
                  required
                  autoCapitalize="none"
                  spellCheck={false}
                />
              </Field>
            </div>
            <RefSelect
              name="route"
              value={
                initial.route === 0
                  ? undefined
                  : (initial.route as string | undefined)
              }
              resources={labels("routes")}
              optional={t("Direct", "直连")}
              label={t("Route", "路由")}
            />
            <p className="field-help">
              {t(
                "Team Logins use team certificates. Personal credentials are not available here. Saving a Login does not grant visibility or connection permission.",
                "团队登录配置使用团队证书，不能引用个人凭据。保存登录配置不会授予可见或连接权限。",
              )}
            </p>
            <details>
              <summary>{t("Advanced Login settings", "高级登录设置")}</summary>
              <Field label={t("Terminal profile", "终端配置")}>
                <input
                  name="terminal_profile"
                  defaultValue={String(initial.terminal_profile ?? "")}
                />
              </Field>
              <Field label={t("Startup command", "启动命令")}>
                <textarea
                  name="startup_command"
                  className="code-input"
                  defaultValue={String(initial.startup_command ?? "")}
                  rows={3}
                />
              </Field>
              <label className="check">
                <input
                  type="checkbox"
                  name="agent_forwarding"
                  defaultChecked={Boolean(initial.agent_forwarding)}
                />
                {t("Allow SSH agent forwarding", "允许 SSH 代理转发")}
              </label>
            </details>
          </>
        )}
        {kind === "host-groups" && (
          <>
            <Field label={t("Host group name", "主机分组名称")}>
              <input
                name="name"
                defaultValue={String(initial.name ?? "")}
                required
              />
            </Field>
            <RefSelect
              name="parent"
              value={initial.parent as string | undefined}
              resources={labels("host-groups")}
              optional={optional}
              label={t("Parent host group", "上级主机分组")}
              exclude={original?.id}
            />
            <Field label={t("Color label (optional)", "颜色标签（可选）")}>
              <input name="color" defaultValue={String(initial.color ?? "")} />
            </Field>
            <MapField
              name="defaults"
              value={initial.defaults as Record<string, string>}
              label={t("Defaults (JSON text map)", "默认值（JSON 文本映射）")}
              help={t(
                "Only non-secret team defaults. Credentials cannot be referenced.",
                "仅可设置非秘密的团队默认值，不能引用凭据。 ",
              )}
            />
          </>
        )}
        {kind === "routes" && (
          <>
            <Field label={t("Route name", "路由名称")}>
              <input
                name="name"
                defaultValue={String(initial.name ?? "")}
                required
              />
            </Field>
            <Field label={t("Route type", "路由类型")}>
              <select
                name="kind"
                value={routeKind}
                onChange={(event) => setRouteKind(Number(event.target.value))}
              >
                <option value={1}>{t("SSH jump chain", "SSH 跳板链")}</option>
                <option value={2}>{t("SOCKS5 proxy", "SOCKS5 代理")}</option>
                <option value={3}>
                  {t("HTTP CONNECT proxy", "HTTP CONNECT 代理")}
                </option>
                <option value={4}>
                  {t("Command (desktop)", "命令（桌面端）")}
                </option>
                <option value={5}>
                  {t("Managed gateway network", "托管网关网络")}
                </option>
              </select>
            </Field>
            {routeKind === 1 && (
              <Field
                label={t(
                  "Ordered jump Login IDs",
                  "按顺序排列的跳板登录配置 ID",
                )}
                help={t(
                  "One UUID per line, from the first jump to the last. Each dependency needs separate view permission. Choose IDs from Logins.",
                  "每行一个 UUID，按跳转顺序排列。每个依赖对象都需要单独的可见权限，可从登录配置列表获取 ID。 ",
                )}
              >
                <textarea
                  name="hops"
                  className="code-input"
                  defaultValue={
                    Array.isArray(initial.hops) ? initial.hops.join("\n") : ""
                  }
                  rows={4}
                  required
                />
              </Field>
            )}
            {(routeKind === 2 || routeKind === 3) && (
              <Field
                label={t("Proxy address (host:port)", "代理地址（host:port）")}
                help={t(
                  "This team route cannot store proxy authentication secrets.",
                  "团队路由不能存储代理认证秘密。 ",
                )}
              >
                <input
                  name="proxy"
                  className="mono"
                  defaultValue={String(initial.proxy ?? "")}
                  required
                />
              </Field>
            )}
            {routeKind === 4 && (
              <Field
                label={t("Proxy command", "代理命令")}
                help={t(
                  "The desktop app asks before executing this command. %h, %p and %r are supported.",
                  "桌面端执行此命令前会请求确认，支持 %h、%p 和 %r。 ",
                )}
              >
                <textarea
                  name="command"
                  className="code-input"
                  defaultValue={String(initial.command ?? "")}
                  rows={3}
                  required
                />
              </Field>
            )}
            {routeKind === 5 && (
              <Field
                label={t("Gateway network ID", "网关网络 ID")}
                help={t(
                  "Use an existing same-team network ID. This console cannot create or inspect gateway networks; the server checks its visibility.",
                  "请输入现有的同团队网络 ID。本控制台不提供网关网络创建或查看，服务器会检查其可见权限。 ",
                )}
              >
                <input
                  name="gateway_network"
                  className="mono"
                  defaultValue={String(initial.gateway_network ?? "")}
                  required
                />
              </Field>
            )}
          </>
        )}
        {kind === "groups" && (
          <>
            <Field label={t("Group name", "成员组名称")}>
              <input
                name="name"
                defaultValue={initialGroup?.name ?? ""}
                required
                maxLength={128}
              />
            </Field>
            <fieldset className="check-list">
              <legend>{t("Active team members", "当前有效的团队成员")}</legend>
              {members
                .filter((member) => member.data.status === "active")
                .map((member) => (
                  <label key={member.id}>
                    <input
                      type="checkbox"
                      checked={groupMembers.includes(member.id)}
                      onChange={(event) =>
                        setGroupMembers(
                          event.target.checked
                            ? [...groupMembers, member.id]
                            : groupMembers.filter((id) => id !== member.id),
                        )
                      }
                    />
                    {member.data.username}
                  </label>
                ))}
              {groupMembers
                .filter(
                  (id) =>
                    !members.some(
                      (member) =>
                        member.id === id && member.data.status === "active",
                    ),
                )
                .map((id) => (
                  <label key={id}>
                    <input
                      type="checkbox"
                      checked
                      onChange={() =>
                        setGroupMembers(
                          groupMembers.filter((value) => value !== id),
                        )
                      }
                    />
                    {t(
                      "Not in this loaded member view",
                      "当前成员列表中不可见",
                    )}{" "}
                    · <span className="mono">{id}</span>
                  </label>
                ))}
            </fieldset>
            <p className="field-help">
              {t(
                "Load more members before selecting people outside this page. Removed or suspended memberships cannot be restored by adding them to a group.",
                "选择当前页面之外的成员前，请先加载更多成员。加入成员组不能恢复已移除或停用的团队成员。 ",
              )}
            </p>
          </>
        )}
        {kind === "policies" && (
          <>
            <Field label={t("Rule name", "规则名称")}>
              <input
                name="name"
                defaultValue={initialPolicy?.name ?? ""}
                required
                maxLength={128}
              />
            </Field>
            <Field
              label={t("Advanced · Cedar source", "高级 · Cedar 源码")}
              help={t(
                "One policy. The server validates the team boundary, schema and references. Time-conditioned asset visibility is not supported.",
                "仅接受一条策略。服务器会验证团队边界、模式及引用，暂不支持基于时间条件的资产可见规则。 ",
              )}
            >
              <textarea
                name="source"
                className="code-input policy-source"
                defaultValue={initialPolicy?.source ?? ""}
                rows={12}
                required
                spellCheck={false}
              />
            </Field>
            <label className="check">
              <input
                type="checkbox"
                name="enabled"
                defaultChecked={initialPolicy?.enabled ?? true}
              />
              {t("Enabled", "启用")}
            </label>
          </>
        )}
      </fieldset>
      {error && (
        <p className="notice error" role="alert">
          {t(
            "Check the required fields and settings. No request was sent.",
            "请检查必填项及设置。尚未发送请求。",
          )}
        </p>
      )}
      <div className="form-actions">
        <button
          className="primary-button"
          disabled={disabled}
          aria-busy={saving}
        >
          {saving ? t("Saving…", "正在保存…") : t("Save", "保存")}
        </button>
        <button
          type="button"
          className="secondary"
          onClick={onCancel}
          disabled={disabled}
        >
          {t("Cancel", "取消")}
        </button>
      </div>
    </form>
  );
}

export function fieldsFromForm(
  kind: "hosts" | "access-profiles" | "host-groups" | "routes",
  data: FormData,
): AnyFields {
  const get = (key: string) => String(data.get(key) ?? "");
  const result: Record<string, unknown> = {};
  const optional = (...names: string[]) => {
    for (const name of names) if (get(name) !== "") result[name] = get(name);
  };
  const maps = (...names: string[]) => {
    for (const name of names)
      if (get(name) !== "") {
        const value = object(strictJson(get(name)));
        if (Object.values(value).some((part) => typeof part !== "string"))
          throw new Error("Invalid text map.");
        result[name] = value;
      }
  };
  if (kind === "hosts") {
    result.name = get("name");
    result.address = get("address");
    result.port = Number(get("port"));
    result.favorite = data.has("favorite");
    result.groups = Object.fromEntries(
      data.getAll("groups").map((id) => [uuid(String(id)), true]),
    );
    optional("notes", "default_profile");
    maps("tags", "ssh_options", "mosh");
  } else if (kind === "access-profiles") {
    result.host = get("host");
    result.username = get("username");
    result.route = !get("route") || get("route") === "0" ? 0 : get("route");
    result.agent_forwarding = data.has("agent_forwarding");
    optional("name", "terminal_profile", "startup_command");
  } else if (kind === "host-groups") {
    result.name = get("name");
    optional("parent", "color");
    maps("defaults");
  } else {
    result.name = get("name");
    result.kind = Number(get("kind"));
    if (result.kind === 1)
      result.hops = get("hops").split(/\r?\n/).filter(Boolean).map(uuid);
    else if (result.kind === 2 || result.kind === 3)
      result.proxy = get("proxy");
    else if (result.kind === 4) result.command = get("command");
    else result.gateway_network = get("gateway_network");
  }
  return parseFields(kind, result);
}
