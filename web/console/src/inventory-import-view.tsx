// SPDX-License-Identifier: AGPL-3.0-only
import { useEffect, useRef, useState, type RefObject } from "react";
import {
  InventoryCsvFailure,
  InventoryImportApi,
  InventoryImportWorkflow,
  type InventoryCsvParser,
  type InventoryImportState,
} from "./inventory-import.ts";
import type { InventoryImportRequest } from "./generated/api.ts";
import { RequestFailure, TeamApi } from "./team.ts";
import { Field } from "./editors.tsx";
import { useLocale } from "./locale.tsx";
import { requestFeedback } from "./feedback.ts";

export interface InventoryImportHandle {
  hasPending: () => boolean;
  dispose: () => void;
}

export function InventoryImportPreview({
  body,
}: {
  body: InventoryImportRequest;
}) {
  const { t } = useLocale();
  return (
    <ol className="import-rows" aria-label={t("Hosts to import", "待导入主机")}>
      {body.rows.map((row, index) => (
        <li key={row.host_id}>
          <p className="caption">
            {t(`Host ${index + 1}`, `主机 ${index + 1}`)}
          </p>
          <dl className="import-row-fields">
            <div>
              <dt>{t("Host name", "主机名称")}</dt>
              <dd>{row.name}</dd>
            </div>
            <div>
              <dt>{t("Address", "地址")}</dt>
              <dd className="mono">{row.address}</dd>
            </div>
            <div>
              <dt>{t("Port", "端口")}</dt>
              <dd className="mono">{row.port}</dd>
            </div>
            <div>
              <dt>{t("Username", "用户名")}</dt>
              <dd className="mono">{row.username}</dd>
            </div>
            <div>
              <dt>{t("Login name", "登录配置名称")}</dt>
              <dd>{row.login_name ?? t("Not set", "未设置")}</dd>
            </div>
          </dl>
        </li>
      ))}
    </ol>
  );
}

function ImportFailure({
  failure,
  uncertain,
}: {
  failure: unknown;
  uncertain: boolean;
}) {
  const { t } = useLocale();
  if (failure instanceof InventoryCsvFailure) {
    const messages = {
      invalid_utf8: t(
        "The file is not valid UTF-8. Save it as UTF-8 and choose it again.",
        "文件不是有效的 UTF-8。请另存为 UTF-8 后重新选择。",
      ),
      invalid_csv: t(
        "The CSV structure is invalid. Check quotes and the five cells in each record.",
        "CSV 结构无效。请检查引号及每条记录的五个单元格。",
      ),
      invalid_header: t(
        "The header must be exactly name,address,port,username,login_name in that order.",
        "表头必须按顺序精确为 name,address,port,username,login_name。",
      ),
      invalid_cell: t(
        "A cell does not meet the Host or Login field requirements. Correct the file and choose it again.",
        "某个单元格不符合主机或登录配置字段要求。请修改文件后重新选择。",
      ),
      empty_input: t(
        "The file needs a header and at least one Host record.",
        "文件需要表头及至少一条主机记录。",
      ),
      too_many_records: t(
        "The file has more than 100 Host records. Split it into smaller files.",
        "文件超过 100 条主机记录。请拆分为较小的文件。",
      ),
      too_large: t(
        "The file is larger than 1 MiB. Choose a smaller file.",
        "文件超过 1 MiB。请选择较小的文件。",
      ),
      request_too_large: t(
        "The prepared import is larger than 2 MiB. Split the CSV into smaller files.",
        "准备后的导入请求超过 2 MiB。请将 CSV 拆分为较小的文件。",
      ),
      unreadable: t(
        "The file could not be read. Choose the file again.",
        "无法读取文件。请重新选择文件。",
      ),
      unavailable: t(
        "The CSV preview could not be prepared. Reload the console and choose the file again.",
        "无法准备 CSV 预览。请重新加载控制台并再次选择文件。",
      ),
    };
    const fields = {
      name: t("Host name", "主机名称"),
      address: t("Address", "地址"),
      port: t("Port", "端口"),
      username: t("Username", "用户名"),
      login_name: t("Login name", "登录配置名称"),
    };
    return (
      <p className="notice error" role="alert">
        {messages[failure.kind]}{" "}
        {failure.record !== undefined &&
          t(
            `Data record ${failure.record}.`,
            `数据记录 ${failure.record}。`,
          )}{" "}
        {failure.field &&
          t(
            `Field: ${fields[failure.field]}.`,
            `字段：${fields[failure.field]}。`,
          )}{" "}
        {t("No import request was sent.", "未发送导入请求。")}
      </p>
    );
  }
  const authority =
    failure instanceof RequestFailure &&
    [401, 403, 404].includes(failure.status);
  return (
    <p className="notice error" role="alert">
      {uncertain
        ? authority
          ? t(
              "Your current session or permissions could not confirm the original import. Its earlier outcome is still unknown.",
              "当前会话或权限无法确认原导入操作。此前的结果仍未知。",
            )
          : t(
              "This attempt did not confirm the original import. Its earlier outcome is still unknown.",
              "本次尝试未能确认原导入操作。此前的结果仍未知。",
            )
        : failure instanceof RequestFailure &&
            failure.code === "import_preparation_failed"
          ? t(
              "The import request could not be prepared. No request was sent. Reload the console and review the file again.",
              "无法准备导入请求，未发送请求。请重新加载控制台并再次检查文件。",
            )
          : requestFeedback(failure, t)}
      {uncertain && failure instanceof RequestFailure && failure.requestId
        ? ` ${t("Reference", "参考编号")}: ${failure.requestId}`
        : ""}
    </p>
  );
}

export function InventoryImportContent({
  state,
  disabled,
  now,
  refreshFailed = false,
  onFile,
  onSubmit,
  onConfirm,
  onClose,
}: {
  state: InventoryImportState;
  disabled: boolean;
  now: number;
  refreshFailed?: boolean;
  onFile: (file: File) => void;
  onSubmit: () => void;
  onConfirm: () => void;
  onClose: () => void;
}) {
  const { t } = useLocale();
  const working = ["parsing", "importing", "confirming"].includes(state.phase);
  const blocked = disabled || working;
  const pending = state.pending;
  const uncertain = state.phase === "uncertain" || state.phase === "confirming";
  return (
    <div aria-busy={working}>
      <p className="section-intro">
        {t(
          "Create a new Direct Host and default Login for every row, including duplicate names or endpoints. This does not overwrite assets or connect to any Host. Team inventory is readable by this deployment.",
          "每行将创建一台新的直连主机及默认登录配置，包括名称或地址相同的行。不会覆盖资产，也不会连接主机。此部署可以读取团队资产。",
        )}
      </p>
      {state.phase === "complete" ? (
        <p className="notice" role="status">
          {t(
            `Import confirmed for ${state.imported} hosts.`,
            `已确认导入 ${state.imported} 台主机。`,
          )}{" "}
          {refreshFailed
            ? t(
                "Current inventory could not be refreshed. Return to Hosts and refresh before preparing another import.",
                "无法刷新当前资产。请返回主机列表并刷新，再准备下一次导入。",
              )
            : t(
                "The current Hosts view has been refreshed.",
                "当前主机列表已刷新。",
              )}
        </p>
      ) : pending && uncertain ? (
        <section
          className="notice pending-operation"
          aria-label={t("Original import retained", "原导入操作已保留")}
        >
          <h3>{t("Import outcome unknown", "导入结果未知")}</h3>
          <p>
            {t(
              "The import may have completed. This tab retains the exact original rows and operation. No request is retried automatically. Confirmation does not prove current asset contents or access.",
              "导入可能已经完成。本标签页保留了精确的原始行和操作。不会自动重试请求。确认不证明当前资产内容或访问权限。",
            )}
          </p>
          <p className="caption">
            {t("Original confirmation window ends", "原操作确认期限结束于")}:{" "}
            <time dateTime={new Date(pending.deadline).toISOString()}>
              {new Date(pending.deadline).toISOString()}
            </time>
          </p>
          {now >= pending.deadline && (
            <p>
              {t(
                "The original confirmation window has expired. Review current inventory; absence or similar fields cannot establish the earlier outcome.",
                "原操作确认期限已过。请检查当前资产；资产不存在或字段相似都不能证明此前的结果。",
              )}
            </p>
          )}
        </section>
      ) : (
        !working && (
          <div className="form-fields">
            <Field
              label={t("CSV file", "CSV 文件")}
              help={t(
                "UTF-8, at most 1 MiB and 100 Hosts. Leave port empty for 22 and login_name empty to omit it. Required cells and legal whitespace are preserved exactly; text must already be NFC.",
                "UTF-8，最多 1 MiB、100 台主机。端口留空则为 22，login_name 留空则省略。必填单元格及合法空白会原样保留；文本必须已为 NFC。",
              )}
            >
              <input
                type="file"
                accept=".csv,text/csv"
                disabled={blocked}
                onChange={(event) => {
                  const file = event.currentTarget.files?.[0];
                  event.currentTarget.value = "";
                  if (file) onFile(file);
                }}
              />
            </Field>
            <p className="caption">
              {t("Exact header", "精确表头")}:{" "}
              <code className="import-header">
                name,address,port,username,login_name
              </code>
            </p>
          </div>
        )
      )}
      {working && (
        <p role="status">
          {state.phase === "parsing"
            ? t("Preparing CSV preview…", "正在准备 CSV 预览…")
            : state.phase === "confirming"
              ? t("Confirming the original import…", "正在确认原导入操作…")
              : t("Importing the reviewed Hosts…", "正在导入已审阅的主机…")}
        </p>
      )}
      {state.failure !== undefined && (
        <ImportFailure failure={state.failure} uncertain={Boolean(pending)} />
      )}
      {state.preview && <InventoryImportPreview body={state.preview} />}
      <div className="form-actions">
        {state.phase === "preview" && state.preview && (
          <button
            className="primary-button"
            disabled={blocked}
            onClick={onSubmit}
          >
            {t(
              `Import ${state.preview.rows.length} hosts`,
              `导入 ${state.preview.rows.length} 台主机`,
            )}
          </button>
        )}
        {pending && uncertain && (
          <button
            className="primary-button"
            disabled={blocked || now >= pending.deadline}
            onClick={onConfirm}
          >
            {t("Confirm original import", "确认原导入操作")}
          </button>
        )}
        <button className="secondary" disabled={blocked} onClick={onClose}>
          {pending
            ? t("Discard and review inventory", "丢弃并查看资产")
            : t("Back to Hosts", "返回主机列表")}
        </button>
      </div>
    </div>
  );
}

export function InventoryImportPanel({
  teamApi,
  organization,
  account,
  parser,
  disabled,
  handle,
  onBusy,
  onImported,
  onClose,
}: {
  teamApi: TeamApi;
  organization: string;
  account: string;
  parser: InventoryCsvParser;
  disabled: boolean;
  handle: RefObject<InventoryImportHandle | null>;
  onBusy: (busy: boolean) => void;
  onImported: () => Promise<void>;
  onClose: () => void;
}) {
  const { t } = useLocale();
  const workflow = useRef<InventoryImportWorkflow | undefined>(undefined);
  const running = useRef(false);
  const heading = useRef<HTMLHeadingElement>(null);
  const [state, setState] = useState<InventoryImportState>({
    phase: "empty",
    imported: 0,
  });
  const [now, setNow] = useState(Date.now());
  const [refreshFailed, setRefreshFailed] = useState(false);
  useEffect(() => {
    const actions = new InventoryImportWorkflow(
      new InventoryImportApi(teamApi, organization, account),
      parser,
    );
    workflow.current = actions;
    setState(actions.state);
    setRefreshFailed(false);
    handle.current = {
      hasPending: () => Boolean(actions.state.pending),
      dispose: () => actions.dispose(),
    };
    const timer = window.setInterval(() => setNow(Date.now()), 30_000);
    return () => {
      actions.dispose();
      workflow.current = undefined;
      running.current = false;
      handle.current = null;
      window.clearInterval(timer);
      onBusy(false);
    };
  }, [teamApi, organization, account, parser, handle, onBusy]);
  useEffect(() => {
    heading.current?.focus();
  }, [state.phase]);
  async function run(
    action: (actions: InventoryImportWorkflow) => Promise<void>,
  ) {
    const actions = workflow.current;
    if (!actions || disabled || running.current) return;
    running.current = true;
    onBusy(true);
    setRefreshFailed(false);
    const result = action(actions);
    setState(actions.state);
    try {
      await result;
      if (workflow.current !== actions) return;
      if (actions.state.phase === "complete") {
        try {
          await onImported();
        } catch {
          if (workflow.current === actions) setRefreshFailed(true);
        }
      }
    } catch {
      // Disposal fences work from the previous team or login family.
    } finally {
      if (workflow.current === actions) {
        setState(actions.state);
        setNow(Date.now());
        running.current = false;
        onBusy(false);
      }
    }
  }
  return (
    <section className="inventory-import">
      <h2 ref={heading} tabIndex={-1}>
        {t("Import Hosts from CSV", "从 CSV 导入主机")}
      </h2>
      <InventoryImportContent
        state={state}
        disabled={disabled}
        now={now}
        refreshFailed={refreshFailed}
        onFile={(file) => void run((actions) => actions.prepare(file))}
        onSubmit={() => void run((actions) => actions.submit())}
        onConfirm={() => void run((actions) => actions.confirmOriginal())}
        onClose={onClose}
      />
    </section>
  );
}
