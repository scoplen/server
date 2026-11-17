// SPDX-License-Identifier: AGPL-3.0-only
import { useEffect, useRef, useState } from "react";
import type {
  GroupResource,
  PolicyFields,
  SimpleRuleInput,
  SimpleRuleSelector,
  TeamMemberResource,
} from "./generated/api.ts";
import type { AnyResource, CollectionKind } from "./team.ts";
import { Field } from "./editors.tsx";
import { useLocale } from "./locale.tsx";
import { GrantChoice } from "./grant-choice.tsx";

export interface RuleGenerator {
  generate(input: SimpleRuleInput): Promise<string>;
}
type Selector = SimpleRuleSelector & {
  label: string;
  kind: CollectionKind;
  resource: AnyResource;
};

export function SimpleRuleEditor({
  organization,
  members,
  groups,
  assets,
  shared,
  disabled,
  saving,
  onSave,
  onCancel,
}: {
  organization: string;
  members: TeamMemberResource[];
  groups: GroupResource[];
  assets: Selector[];
  shared: RuleGenerator;
  disabled: boolean;
  saving: boolean;
  onSave: (fields: PolicyFields) => Promise<void>;
  onCancel: () => void;
}) {
  const { t } = useLocale();
  const [kind, setKind] = useState<"view" | "connect" | "request_access">(
    "view",
  );
  const [subject, setSubject] = useState("");
  const [selected, setSelected] = useState<string[]>([]);
  const [remoteUser, setRemoteUser] = useState("");
  const [source, setSource] = useState("");
  const [generating, setGenerating] = useState(false);
  const [previewFailed, setPreviewFailed] = useState(false);
  const previewButton = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    if (!generating && (source || previewFailed))
      previewButton.current?.focus();
  }, [generating, source, previewFailed]);
  const assetNames: Partial<Record<CollectionKind, string>> = {
    hosts: t("Host", "主机"),
    "access-profiles": t("Login", "登录配置"),
    routes: t("Route", "路由"),
    snippets: t("Snippet", "片段"),
    "host-groups": t("Host group", "主机分组"),
  };
  const choices = assets.filter(
    (asset) =>
      kind === "view" ||
      asset.type === 1 ||
      (kind === "connect" && asset.type === 5),
  );
  function changed() {
    setSource("");
    setPreviewFailed(false);
  }
  const selectedAssets = choices.filter((asset) =>
    selected.includes(`${asset.type}:${asset.id}`),
  );
  const missing =
    kind === "view"
      ? selectedAssets.flatMap((asset) => {
          if (!("fields" in asset.resource.data)) return [];
          const fields = asset.resource.data.fields as Record<string, unknown>;
          const references =
            asset.type === 1 && fields.default_profile
              ? [String(fields.default_profile)]
              : asset.type === 2
                ? [
                    String(fields.host),
                    ...(typeof fields.route === "string" ? [fields.route] : []),
                  ]
                : asset.type === 4 && Array.isArray(fields.hops)
                  ? fields.hops.map(String)
                  : [];
          return references.filter(
            (id) => !selectedAssets.some((item) => item.id === id),
          );
        })
      : [];
  async function preview() {
    setGenerating(true);
    setSource("");
    setPreviewFailed(false);
    try {
      const [subjectKind, subjectId] = subject.split(":");
      if (
        !subjectId ||
        selectedAssets.length === 0 ||
        (kind === "request_access" && selectedAssets.length > 64)
      )
        throw new Error("rule_selection_required");
      const principal =
        subjectKind === "membership"
          ? { membership: subjectId }
          : { group: subjectId };
      const rule =
        kind === "view"
          ? { view: selectedAssets.map(({ type, id }) => ({ type, id })) }
          : kind === "request_access"
            ? { request_access: selectedAssets.map((asset) => asset.id) }
            : {
                connect: {
                  hosts: selectedAssets
                    .filter((asset) => asset.type === 1)
                    .map((asset) => asset.id),
                  host_groups: selectedAssets
                    .filter((asset) => asset.type === 5)
                    .map((asset) => asset.id),
                  remote_user: remoteUser,
                },
              };
      setSource(await shared.generate({ organization, ...principal, ...rule }));
    } catch {
      setPreviewFailed(true);
    } finally {
      setGenerating(false);
    }
  }
  return (
    <form
      className="editor"
      onSubmit={(event) => {
        event.preventDefault();
        const data = new FormData(event.currentTarget);
        if (!source) return;
        void onSave({
          name: String(data.get("name")),
          source,
          enabled: data.has("enabled"),
        });
      }}
    >
      <fieldset className="form-fields" disabled={disabled || generating}>
        <Field label={t("Rule name", "规则名称")}>
          <input name="name" required maxLength={128} />
        </Field>
        <GrantChoice
          label={t("Who", "适用对象")}
          placeholder={t("Select a member or group…", "选择成员或成员组…")}
          options={[
            ...members
              .filter((member) => member.data.status === "active")
              .map((member) => ({
                id: `membership:${member.id}`,
                label: member.data.username,
                detail: t("Member", "成员"),
              })),
            ...groups
              .filter((group) => group.data.source === "local")
              .map((group) => ({
                id: `group:${group.id}`,
                label: group.data.name,
                detail: t("Local group", "本地成员组"),
              })),
          ]}
          value={subject}
          disabled={disabled || generating}
          onChange={(value) => {
            setSubject(value);
            changed();
          }}
        />
        <fieldset className="check-list">
          <legend>{t("Permission", "权限")}</legend>
          <label>
            <input
              type="radio"
              name="rule-kind"
              checked={kind === "view"}
              onChange={() => {
                setKind("view");
                setSelected([]);
                changed();
              }}
            />
            {t("May view selected assets", "可以查看所选资产")}
          </label>
          <label>
            <input
              type="radio"
              name="rule-kind"
              checked={kind === "connect"}
              onChange={() => {
                setKind("connect");
                setSelected([]);
                changed();
              }}
            />
            {t(
              "May connect to selected Hosts / host groups",
              "可以连接所选主机／主机分组",
            )}
          </label>
          <label>
            <input
              type="radio"
              name="rule-kind"
              checked={kind === "request_access"}
              onChange={() => {
                setKind("request_access");
                setSelected([]);
                changed();
              }}
            />
            {t("May request temporary access", "可以申请临时访问")}
          </label>
        </fieldset>
        <p className="field-help">
          {t(
            "Visibility and connection permission are independent. Create a separate rule for each permission. This console configures desktop access; it does not open SSH sessions.",
            "可见权限与连接权限彼此独立，请为每种权限分别创建规则。本控制台配置桌面端访问，不会发起 SSH 连接。",
          )}
        </p>
        {kind === "request_access" && (
          <p className="field-help">
            {t(
              "Select 1–64 Hosts. This rule permits requesting access; it grants no visibility, connection or approval permission and does not restrict another applicable permit. The approver reviews the exact remote username in each request.",
              "请选择 1–64 台主机。此规则仅允许申请访问，不授予可见、连接或审批权限，也不会限制其他适用的许可。审批者会查看每次申请的精确远程用户名。",
            )}
          </p>
        )}
        <fieldset className="check-list asset-select">
          <legend>{t("Assets", "资产")}</legend>
          {choices.map((asset) => {
            const key = `${asset.type}:${asset.id}`;
            return (
              <label key={key}>
                <input
                  type="checkbox"
                  checked={selected.includes(key)}
                  disabled={
                    kind === "request_access" &&
                    selected.length >= 64 &&
                    !selected.includes(key)
                  }
                  onChange={(event) => {
                    setSelected(
                      event.target.checked
                        ? [...selected, key]
                        : selected.filter((value) => value !== key),
                    );
                    changed();
                  }}
                />
                <span>
                  {asset.label}
                  <small>
                    {assetNames[asset.kind]} · {asset.id}
                  </small>
                </span>
              </label>
            );
          })}
          {choices.length === 0 && (
            <p>
              {t(
                "No readable assets are loaded. Load assets before creating a rule.",
                "尚未加载可读资产。创建规则前，请先加载资产。",
              )}
            </p>
          )}
        </fieldset>
        {kind === "connect" && (
          <Field label={t("Exact remote username", "精确远程用户名")}>
            <input
              value={remoteUser}
              onChange={(event) => {
                setRemoteUser(event.target.value);
                changed();
              }}
              className="mono"
              required
              autoCapitalize="none"
              spellCheck={false}
            />
          </Field>
        )}
        {missing.length > 0 && (
          <div className="notice error">
            <p>
              {t(
                "Some selected assets reference dependencies outside this view rule. Those dependencies need their own visibility permission; this editor will not grant it automatically.",
                "部分所选资产引用了此可见规则之外的依赖对象。这些对象需要单独的可见权限，编辑器不会自动授予。",
              )}
            </p>
            <ul>
              {[...new Set(missing)].map((id) => (
                <li className="mono identifier" key={id}>
                  {id}
                </li>
              ))}
            </ul>
          </div>
        )}
        <div>
          <button
            type="button"
            className="secondary"
            ref={previewButton}
            onClick={() => void preview()}
            disabled={
              disabled ||
              generating ||
              !subject ||
              selectedAssets.length === 0 ||
              (kind === "request_access" && selectedAssets.length > 64) ||
              (kind === "connect" && !remoteUser)
            }
          >
            {generating
              ? t("Generating…", "正在生成…")
              : t("Preview shared rule", "预览共享生成的规则")}
          </button>
        </div>
        {previewFailed && (
          <p className="notice error" role="alert">
            {t(
              "The shared rule preview could not be generated. Check the selected subject, assets and exact remote username, then try the preview again. No request was sent.",
              "无法生成共享规则预览。请检查所选对象、资产及精确远程用户名后，再次预览。尚未发送请求。",
            )}
          </p>
        )}
        {source && (
          <section className="rule-preview">
            <h3>{t("Generated Cedar policy", "已生成的 Cedar 策略")}</h3>
            <pre className="source-preview" tabIndex={0}>
              {source}
            </pre>
            <p className="caption">
              {t(
                "The preview grants no permission. Saving sends this exact source for current server validation.",
                "预览不会授予权限。保存时将发送此精确源码，由服务器按当前状态验证。",
              )}
            </p>
          </section>
        )}
        <label className="check">
          <input type="checkbox" name="enabled" defaultChecked />
          {t("Enabled", "启用")}
        </label>
      </fieldset>
      <div className="form-actions">
        <button
          className="primary-button"
          disabled={disabled || generating || !source}
        >
          {saving ? t("Saving…", "正在保存…") : t("Save rule", "保存规则")}
        </button>
        <button
          type="button"
          className="secondary"
          disabled={disabled || generating}
          onClick={onCancel}
        >
          {t("Cancel", "取消")}
        </button>
      </div>
    </form>
  );
}
