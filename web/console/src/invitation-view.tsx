// SPDX-License-Identifier: AGPL-3.0-only
import { useEffect, useRef, useState, type RefObject } from "react";
import type { TeamInvitationResource, TeamRole } from "./generated/api.ts";
import {
  InvitationOperation,
  parseJoinLink,
  type InvitationCrypto,
  type JoinTarget,
} from "./invitation.ts";
import { RequestFailure, TeamApi } from "./team.ts";
import { Field, RoleOptions } from "./editors.tsx";
import { useLocale } from "./locale.tsx";

export interface InvitationHandle {
  hasSecret: () => boolean;
  dispose: () => void;
}
export function InvitationPanel({
  api,
  shared,
  organization,
  ownerAllowed,
  initialTarget,
  handle,
  onChanged,
  onFailure,
  onBusy,
  confirm,
  disabled = false,
}: {
  api: TeamApi;
  shared: InvitationCrypto;
  organization?: string;
  ownerAllowed: boolean;
  initialTarget?: JoinTarget;
  handle: RefObject<InvitationHandle | null>;
  onChanged: () => Promise<void>;
  onFailure: (failure: unknown) => void;
  onBusy: (busy: boolean) => void;
  confirm: (message: string) => Promise<boolean>;
  disabled?: boolean;
}) {
  const { t } = useLocale();
  const operation = useRef<InvitationOperation | undefined>(undefined);
  const [version, setVersion] = useState(0);
  const [busy, setBusy] = useState(false);
  const [roles, setRoles] = useState<TeamRole[]>(["member"]);
  const [visible, setVisible] = useState(false);
  const [target, setTarget] = useState<JoinTarget | undefined>(initialTarget);
  const [preview, setPreview] = useState<TeamInvitationResource | undefined>(
    undefined,
  );
  const [notice, setNotice] = useState("");
  const mounted = useRef(true);
  const running = useRef(false);
  const rolesText: Record<string, string> = {
    administrator: t("Administrator", "管理员"),
    approver: t("Approver", "审批者"),
    member: t("Member", "成员"),
    owner: t("Owner", "所有者"),
    security_auditor: t("Security auditor", "安全审计员"),
  };
  const statusesText: Record<string, string> = {
    pending: t("Pending", "待接受"),
    accepted: t("Accepted", "已接受"),
    revoked: t("Revoked", "已撤销"),
    expired: t("Expired", "已过期"),
    locked: t("Locked", "已锁定"),
  };
  useEffect(() => {
    mounted.current = true;
    handle.current = {
      hasSecret: () => Boolean(operation.current?.hasSecret),
      dispose: () => {
        operation.current?.dispose();
        operation.current = undefined;
      },
    };
    const beforeUnload = (event: BeforeUnloadEvent) => {
      if (operation.current?.hasSecret) {
        event.preventDefault();
        event.returnValue = "";
      }
    };
    window.addEventListener("beforeunload", beforeUnload);
    return () => {
      mounted.current = false;
      operation.current?.dispose();
      handle.current = null;
      window.removeEventListener("beforeunload", beforeUnload);
    };
  }, [handle]);
  const pending = operation.current;

  async function act(run: () => Promise<void>) {
    if (running.current || disabled) return;
    running.current = true;
    setBusy(true);
    onBusy(true);
    setNotice("");
    try {
      await run();
    } catch (error) {
      if (mounted.current) onFailure(error);
    } finally {
      running.current = false;
      if (mounted.current) {
        setBusy(false);
        onBusy(false);
        setVersion((value) => value + 1);
      }
    }
  }
  async function submitOriginal() {
    const current = operation.current;
    if (!current) return;
    await current.submit(api);
    if (!mounted.current) return;
    setNotice(
      current.kind === "create"
        ? t(
            "Invitation created. Share its link and separate password with the named recipient.",
            "邀请已创建。请将链接及单独的邀请密码分享给指定接收者。",
          )
        : t(
            "Acceptance confirmed. The team list shows your current membership; the receipt confirms only the original acceptance.",
            "已确认接受邀请。团队列表显示当前成员资格；回执仅确认原接受操作。",
          ),
    );
    await onChanged();
  }
  async function dismiss() {
    if (
      !(await confirm(
        t(
          "Dismiss this invitation operation? Its separate password and original confirmation payload will be removed from this tab. An unresolved outcome stays unresolved. Review current invitations or teams before taking a new action.",
          "要丢弃此邀请操作吗？本标签页中的单独密码及原确认请求将被清除。未确认的结果仍未确认。进行新操作前，请检查当前邀请或团队。",
        ),
      ))
    )
      return;
    operation.current?.dispose();
    operation.current = undefined;
    setVisible(false);
    setVersion((value) => value + 1);
    setNotice("");
  }
  return (
    <section className="invitation-panel" data-operation-version={version}>
      <fieldset className="form-fields" disabled={disabled}>
        {pending ? (
          <>
            <h3>
              {pending.kind === "create"
                ? t("Captured invitation", "已保留的邀请")
                : t("Captured acceptance", "已保留的接受操作")}
            </h3>
            <p className="mono identifier">{pending.invitation}</p>
            <p
              className={
                pending.state === "uncertain" ? "notice error" : "caption"
              }
            >
              {pending.state === "confirmed"
                ? t(
                    "The server confirmed this operation.",
                    "服务器已确认此操作。",
                  )
                : t(
                    "The original ID, key and exact payload remain in this tab. Confirm only this captured operation; no replacement is generated.",
                    "原 ID、操作键及精确请求仍保留在此标签页。只能确认原操作，不会生成替代请求。",
                  )}
            </p>
            {pending.kind === "create" && pending.state === "confirmed" && (
              <div className="share-invitation">
                <Field label={t("Invitation link", "邀请链接")}>
                  <input
                    readOnly
                    value={pending.link}
                    onFocus={(event) => event.target.select()}
                  />
                </Field>
                <div className="inline-actions">
                  <button
                    className="secondary"
                    disabled={busy}
                    onClick={() => {
                      setVisible((value) => !value);
                    }}
                  >
                    {visible
                      ? t("Hide password", "隐藏密码")
                      : t("Show separate password", "显示单独的邀请密码")}
                  </button>
                  <button
                    className="secondary"
                    disabled={busy || !navigator.clipboard}
                    onClick={() =>
                      void act(async () => {
                        await navigator.clipboard.writeText(
                          pending.revealPassword(),
                        );
                        setNotice(
                          t(
                            "Invitation password copied. Share it separately from the link.",
                            "邀请密码已复制。请与链接分开分享。",
                          ),
                        );
                      })
                    }
                  >
                    {t("Copy password", "复制密码")}
                  </button>
                </div>
                {visible && (
                  <output
                    className="invitation-password mono"
                    aria-label={t(
                      "Separate invitation password",
                      "单独的邀请密码",
                    )}
                  >
                    {pending.revealPassword()}
                  </output>
                )}
              </div>
            )}
            {pending.state !== "confirmed" && (
              <button
                className="primary-button"
                disabled={busy || !pending.canRetry}
                onClick={() => void act(submitOriginal)}
              >
                {busy
                  ? t("Confirming…", "正在确认…")
                  : t("Confirm original operation", "确认原操作")}
              </button>
            )}
            {!pending.canRetry && pending.state !== "confirmed" && (
              <p className="notice error">
                {t(
                  "The original receipt window ended. Review current invitations or memberships. Their current state cannot confirm the lost operation.",
                  "原回执确认期限已结束。请检查当前邀请或成员资格；当前状态不能确认丢失的原操作结果。",
                )}
              </p>
            )}
            <button
              className="quiet"
              disabled={busy}
              onClick={() => void dismiss()}
            >
              {t("Dismiss and clear this operation", "丢弃并清除此操作")}
            </button>
          </>
        ) : organization ? (
          <form
            onSubmit={(event) => {
              event.preventDefault();
              const data = new FormData(event.currentTarget),
                recipient = String(data.get("recipient"));
              void act(async () => {
                if (roles.length === 0) throw new Error("role_required");
                operation.current = await InvitationOperation.create(
                  api,
                  shared,
                  organization,
                  recipient,
                  roles,
                );
                if (!mounted.current) {
                  operation.current.dispose();
                  return;
                }
                setVersion((value) => value + 1);
                await submitOriginal();
              });
            }}
          >
            <div className="form-fields">
              <Field
                label={t("Recipient username", "接收者用户名")}
                help={t(
                  "The recipient must already have an Account on this deployment. Only that Account can use this invitation.",
                  "接收者必须已有此部署上的账号。只有该账号可以使用此邀请。 ",
                )}
              >
                <input
                  name="recipient"
                  required
                  pattern="[a-z0-9][a-z0-9._-]{2,63}"
                  autoCapitalize="none"
                  spellCheck={false}
                  disabled={busy}
                />
              </Field>
              <RoleOptions
                roles={roles}
                onChange={setRoles}
                ownerAllowed={ownerAllowed}
                disabled={busy}
              />
            </div>
            <div className="form-actions">
              <button
                className="primary-button"
                disabled={busy || roles.length === 0}
                aria-busy={busy}
              >
                {busy
                  ? t("Creating invitation…", "正在创建邀请…")
                  : t("Create addressed invitation", "创建指定接收者的邀请")}
              </button>
            </div>
          </form>
        ) : (
          <>
            <form
              onSubmit={(event) => {
                event.preventDefault();
                const source = String(
                  new FormData(event.currentTarget).get("link"),
                );
                void act(async () => {
                  let next: JoinTarget;
                  try {
                    next = parseJoinLink(source, api.transport.origin);
                  } catch {
                    throw new RequestFailure("invalid_invitation_link");
                  }
                  const result = await api.invitation(
                    next.organization,
                    next.invitation,
                  );
                  if (result.data.recipient_account_id !== api.accountId)
                    throw new Error("invalid_recipient");
                  setTarget(next);
                  setPreview(result);
                });
              }}
            >
              <Field label={t("Team invitation link", "团队邀请链接")}>
                <input
                  name="link"
                  type="url"
                  required
                  defaultValue={
                    initialTarget
                      ? `${api.transport.origin}/join-team#organization=${initialTarget.organization}&invitation=${initialTarget.invitation}`
                      : ""
                  }
                  disabled={busy}
                />
              </Field>
              <div className="form-actions">
                <button className="secondary" disabled={busy}>
                  {t("Review invitation", "查看邀请")}
                </button>
              </div>
            </form>
            {preview && target && (
              <form
                className="join-preview"
                onSubmit={(event) => {
                  event.preventDefault();
                  const input = event.currentTarget.elements.namedItem(
                    "password",
                  ) as HTMLInputElement;
                  const password = input.value;
                  input.value = "";
                  void act(async () => {
                    operation.current = await InvitationOperation.accept(
                      api,
                      shared,
                      target,
                      password,
                    );
                    if (!mounted.current) {
                      operation.current.dispose();
                      return;
                    }
                    setVersion((value) => value + 1);
                    await submitOriginal();
                  });
                }}
              >
                <h3>{preview.data.organization_name}</h3>
                <p>
                  {t("Recipient", "接收者")}{" "}
                  <strong>{preview.data.recipient_username}</strong> ·{" "}
                  {preview.data.roles
                    .map((role) => rolesText[role] ?? role)
                    .join(", ")}
                </p>
                <p>
                  {t("Invitation status", "邀请状态")}:{" "}
                  {statusesText[preview.data.status]}
                </p>
                <Field
                  label={t("Separate invitation password", "单独的邀请密码")}
                >
                  <input
                    name="password"
                    type="password"
                    autoComplete="off"
                    maxLength={8}
                    minLength={8}
                    pattern="[0-9A-HJKMNP-TV-Z]{8}"
                    required
                    disabled={busy || preview.data.status !== "pending"}
                  />
                </Field>
                <button
                  className="primary-button"
                  disabled={busy || preview.data.status !== "pending"}
                >
                  {t("Accept this team invitation", "接受此团队邀请")}
                </button>
              </form>
            )}
            <p className="caption">
              {t(
                "An inaccessible invitation may belong to another Account. Sign in with the intended Account and review it again. Joining never changes your Personal keys or other teams.",
                "无法查看的邀请可能发给了其他账号。请使用预期账号登录后重新查看。加入团队不会更改个人密钥或其他团队。",
              )}
            </p>
          </>
        )}
        {notice && (
          <p className="notice" role="status">
            {notice}
          </p>
        )}
        <p className="caption">
          {t(
            "The separate invitation password exists only in this tab. Dismissal, Lock, reload or closing the tab clears it. The server cannot recover it. To replace a lost password, review and explicitly revoke the selected pending invitation before creating a new one.",
            "单独的邀请密码仅保留在此标签页中。丢弃、锁定、刷新或关闭标签页都会清除它，服务器无法恢复。密码丢失后，请查看并明确撤销所选的待接受邀请，再创建新邀请。",
          )}
        </p>
      </fieldset>
    </section>
  );
}
