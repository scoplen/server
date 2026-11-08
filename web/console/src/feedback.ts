// SPDX-License-Identifier: AGPL-3.0-only
import { RequestFailure } from "./team.ts";

type Translate = (en: string, zh: string) => string;
export function requestFeedback(failure: unknown, t: Translate): string {
  if (!(failure instanceof RequestFailure))
    return t(
      "The response could not be verified. A mutation may have completed. Keep any captured original operation for explicit confirmation; for other edits, refresh and review current state before another action.",
      "无法验证响应，修改可能已经完成。若保留了原操作，请显式确认；其他编辑应先刷新并检查当前状态，再进行操作。",
    );
  const message =
    failure.code === "invitation_preparation_failed"
      ? t(
          "The invitation password could not be prepared. No request was sent. Reload the console and try again in a current browser.",
          "无法准备邀请密码，未发送请求。请重新加载控制台，并使用当前版本的浏览器重试。",
        )
      : failure.code === "invalid_invitation_password"
        ? t(
            "The separate invitation password is invalid. No acceptance request was sent. Enter the original eight-character password exactly.",
            "单独的邀请密码无效，未发送接受请求。请按原样输入八个字符的原始密码。",
          )
        : failure.code === "invalid_invitation_link"
          ? t(
              "This invitation link is invalid. No request was sent. Use the original link for this deployment and its separate password.",
              "邀请链接无效，未发送请求。请使用此部署的原始链接及单独密码。",
            )
          : failure.code === "policy.denied"
            ? t(
                "Your current permissions do not allow this action. You can still use any permitted read view. Contact a team owner for the required permission.",
                "当前权限不允许此操作。您仍可使用已获许可的查看功能。如需相应权限，请联系团队所有者。",
              )
            : failure.code === "organization.not_found"
              ? t(
                  "This resource is unavailable to the current Account. Refresh your teams and readable assets. Its absence does not confirm an earlier mutation.",
                  "当前账号无法访问此资源。请刷新团队及可读资产列表。资源不存在并不能确认之前的修改结果。",
                )
              : failure.code === "organization.precondition_failed"
                ? t(
                    "This resource changed after you opened it. No edit was applied by this request. Refresh, review the current values and make a new explicit edit.",
                    "此资源在打开后发生了变化。本次请求未应用编辑。请刷新并检查当前值，再明确执行新的编辑。",
                  )
                : failure.code === "organization.conflict"
                  ? t(
                      "The change conflicts with current state. Check live references, the last active Owner and the original operation before continuing. No replacement is sent automatically.",
                      "此修改与当前状态冲突。继续前，请检查有效引用、最后一名有效所有者及原操作。不会自动发送替代请求。",
                    )
                  : failure.code === "organization.invitation_denied"
                    ? t(
                        "The invitation could not be issued or accepted. Check the exact recipient username, separate password, current invitation and issuer authority. The server does not disclose which check failed.",
                        "无法创建或接受邀请。请检查精确接收者用户名、单独密码、当前邀请及邀请者权限。服务器不会披露具体失败条件。",
                      )
                    : failure.code === "auth.authentication_required" ||
                        failure.code === "sign_in_required"
                      ? t(
                          "This session could not be verified. Keep unresolved operations in mind, then lock this tab and sign in again. A new sign-in does not confirm an earlier operation.",
                          "无法验证此会话。请记住尚未确认的操作，再锁定标签页并重新登录。重新登录不能确认之前的操作结果。",
                        )
                      : failure.code.endsWith("rate_limited")
                        ? t(
                            `The request was limited. Wait ${failure.retryAfter || 60} seconds, then choose the appropriate explicit action.`,
                            `请求已受限。请等待 ${failure.retryAfter || 60} 秒后，明确选择相应操作。`,
                          )
                        : failure.changed
                          ? t(
                              "The outcome is unconfirmed and the mutation may have completed. Confirm only a captured original receipt operation; other mutations need an explicit refresh and reviewed edit. No retry runs automatically.",
                              "结果尚未确认，修改可能已经完成。仅可确认已保留的原回执操作；其他修改需要明确刷新并审阅后再编辑。不会自动重试。",
                            )
                          : failure.code.endsWith("storage_unavailable")
                            ? t(
                                "The deployment could not complete this request. No business change was made. Retry a captured original operation, or refresh when the service is available.",
                                "部署无法完成此请求，未更改业务数据。可重试已保留的原操作，或在服务恢复后刷新。",
                              )
                            : t(
                                "The request was rejected without a business change. Check the required fields, references and current permissions before trying again.",
                                "请求被拒绝，未更改业务数据。请检查必填字段、引用及当前权限后重试。",
                              );
  const code = /^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$/.test(failure.code)
    ? ` ${t("Code", "代码")}: ${failure.code}`
    : "";
  return failure.requestId
    ? `${message}${code} ${t("Reference", "参考编号")}: ${failure.requestId}`
    : message + code;
}
