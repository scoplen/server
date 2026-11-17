// SPDX-License-Identifier: AGPL-3.0-only
import { useEffect, useRef, useState, type RefObject } from "react";
import type {
  InventorySnippetFields,
  InventorySnippetResource,
} from "./generated/api.ts";
import { Field } from "./editors.tsx";
import { GrantChoice } from "./grant-choice.tsx";
import { useLocale } from "./locale.tsx";
import { useConfirmation } from "./confirm.tsx";
import { requestFeedback } from "./feedback.ts";
import { snippetFields } from "./snippet-fields.ts";
import { SnippetActions } from "./snippets.ts";
import { TeamApi } from "./team.ts";

interface VariableDraft {
  key: string;
  kind: 1 | 2 | 3 | 4;
  choices: string[];
  hasDefault: boolean;
  fallback: string;
}
export interface SnippetHandle {
  hasPending(): boolean;
  hasDraft(): boolean;
  dispose(): void;
}

export function SnippetEditor({
  initial,
  disabled,
  onSave,
  onCancel,
}: {
  initial?: InventorySnippetFields;
  disabled: boolean;
  onSave: (fields: InventorySnippetFields) => Promise<void>;
  onCancel: () => void;
}) {
  const { t } = useLocale();
  const [name, setName] = useState(initial?.name ?? ""),
    [template, setTemplate] = useState(initial?.template ?? ""),
    [folder, setFolder] = useState(initial?.folder ?? ""),
    [hasFolder, setHasFolder] = useState(initial?.folder !== undefined);
  const [variables, setVariables] = useState<VariableDraft[]>(() =>
    Object.entries(initial?.variables ?? {}).map(([key, spec]) => ({
      key,
      kind: spec.kind,
      choices: spec.kind === 3 ? [...spec.choices] : [],
      hasDefault: "default" in spec,
      fallback: "default" in spec ? spec.default! : "",
    })),
  );
  const [tags, setTags] = useState(() => Object.keys(initial?.tags ?? {}));
  const [invalid, setInvalid] = useState(false);
  const first = useRef<HTMLInputElement>(null);
  useEffect(() => {
    first.current?.focus();
  }, []);
  function variable(index: number, patch: Partial<VariableDraft>) {
    setVariables((current) =>
      current.map((item, position) =>
        position === index ? { ...item, ...patch } : item,
      ),
    );
  }
  return (
    <form
      className="editor snippet-editor"
      onSubmit={(event) => {
        event.preventDefault();
        setInvalid(false);
        try {
          if (
            new Set(variables.map((item) => item.key)).size !==
              variables.length ||
            new Set(tags).size !== tags.length
          )
            throw new Error("Repeated name.");
          const fields = snippetFields({
            name,
            template,
            ...(hasFolder ? { folder } : {}),
            ...(initial?.variables !== undefined || variables.length
              ? {
                  variables: Object.fromEntries(
                    variables.map((item) => [
                      item.key,
                      {
                        kind: item.kind,
                        ...(item.kind === 3 ? { choices: item.choices } : {}),
                        ...(item.kind !== 4 && item.hasDefault
                          ? { default: item.fallback }
                          : {}),
                      },
                    ]),
                  ),
                }
              : {}),
            ...(initial?.tags !== undefined || tags.length
              ? { tags: Object.fromEntries(tags.map((tag) => [tag, true])) }
              : {}),
          });
          void onSave(fields);
        } catch {
          setInvalid(true);
        }
      }}
    >
      <fieldset className="form-fields" disabled={disabled}>
        <legend>
          {initial
            ? t("Edit Snippet", "编辑片段")
            : t("New Snippet", "新建片段")}
        </legend>
        <Field label={t("Name", "名称")}>
          <input
            ref={first}
            value={name}
            onChange={(event) => setName(event.target.value)}
          />
        </Field>
        <Field
          label={t("Template", "模板")}
          help={t(
            "Define placeholders such as {{name}}. Saving never runs this template.",
            "可使用 {{name}} 等占位符。保存不会执行模板。",
          )}
        >
          <textarea
            className="code-input"
            rows={7}
            spellCheck={false}
            value={template}
            onChange={(event) => setTemplate(event.target.value)}
          />
        </Field>
        <label className="check-option">
          <input
            type="checkbox"
            checked={hasFolder}
            onChange={(event) => setHasFolder(event.target.checked)}
          />
          {t("Set folder", "设置文件夹")}
        </label>
        {hasFolder && (
          <Field label={t("Folder", "文件夹")}>
            <input
              value={folder}
              onChange={(event) => setFolder(event.target.value)}
            />
          </Field>
        )}
        <section
          className="snippet-variables"
          aria-label={t("Variable definitions", "变量定义")}
        >
          <h2>{t("Variables", "变量")}</h2>
          <p className="caption">
            {t(
              "These are definitions, not values for a session. Secret variables never have defaults.",
              "这里仅定义变量，不填写会话中的值。秘密变量没有默认值。",
            )}
          </p>
          {variables.map((item, index) => (
            <fieldset className="snippet-variable" key={index}>
              <legend>
                {t("Variable", "变量")} {index + 1}
              </legend>
              <div className="snippet-variable-heading">
                <Field label={t("Variable name", "变量名称")}>
                  <input
                    value={item.key}
                    onChange={(event) =>
                      variable(index, { key: event.target.value })
                    }
                  />
                </Field>
                <GrantChoice
                  label={t("Type", "类型")}
                  placeholder={t("Choose type", "选择类型")}
                  value={String(item.kind)}
                  disabled={disabled}
                  options={[
                    { id: "1", label: t("Text", "文本") },
                    { id: "2", label: t("Integer", "整数") },
                    { id: "3", label: t("Choice", "选项") },
                    { id: "4", label: t("Secret", "秘密") },
                  ]}
                  onChange={(kind) =>
                    variable(index, {
                      kind: Number(kind) as VariableDraft["kind"],
                      ...(kind === "4"
                        ? { hasDefault: false, fallback: "" }
                        : {}),
                      ...(kind === "3" && !item.choices.length
                        ? { choices: [""] }
                        : {}),
                    })
                  }
                />
              </div>
              {item.kind === 3 && (
                <div className="snippet-choices">
                  {item.choices.map((choice, position) => (
                    <div className="snippet-choice-row" key={position}>
                      <Field label={`${t("Choice", "选项")} ${position + 1}`}>
                        <textarea
                          rows={1}
                          value={choice}
                          onChange={(event) =>
                            variable(index, {
                              choices: item.choices.map((current, at) =>
                                at === position ? event.target.value : current,
                              ),
                            })
                          }
                        />
                      </Field>
                      <button
                        type="button"
                        className="secondary"
                        aria-label={`${t("Remove choice", "移除选项")} ${position + 1}`}
                        onClick={() =>
                          variable(index, {
                            choices: item.choices.filter(
                              (_, at) => at !== position,
                            ),
                          })
                        }
                      >
                        {t("Remove", "移除")}
                      </button>
                    </div>
                  ))}
                  <button
                    type="button"
                    className="secondary"
                    disabled={item.choices.length >= 4096}
                    onClick={() =>
                      variable(index, { choices: [...item.choices, ""] })
                    }
                  >
                    {t("Add choice", "添加选项")}
                  </button>
                </div>
              )}
              {item.kind !== 4 && (
                <>
                  <label className="check-option">
                    <input
                      type="checkbox"
                      checked={item.hasDefault}
                      onChange={(event) =>
                        variable(index, { hasDefault: event.target.checked })
                      }
                    />
                    {t("Set default", "设置默认值")}
                  </label>
                  {item.hasDefault && (
                    <Field
                      label={t("Default", "默认值")}
                      help={
                        item.kind === 2
                          ? t(
                              "A signed 64-bit decimal integer, without a leading + or zeros.",
                              "有符号 64 位十进制整数，不含前导加号或多余零。",
                            )
                          : item.kind === 3
                            ? t(
                                "Must match one of the choices exactly.",
                                "必须与某个选项完全一致。",
                              )
                            : undefined
                      }
                    >
                      <textarea
                        rows={1}
                        value={item.fallback}
                        onChange={(event) =>
                          variable(index, { fallback: event.target.value })
                        }
                      />
                    </Field>
                  )}
                </>
              )}
              <button
                type="button"
                className="secondary"
                onClick={() =>
                  setVariables((current) =>
                    current.filter((_, at) => at !== index),
                  )
                }
              >
                {t("Remove variable", "移除变量")}
              </button>
            </fieldset>
          ))}
          <button
            type="button"
            className="secondary"
            disabled={variables.length >= 4096}
            onClick={() =>
              setVariables((current) => [
                ...current,
                {
                  key: "",
                  kind: 1,
                  choices: [],
                  hasDefault: false,
                  fallback: "",
                },
              ])
            }
          >
            {t("Add variable", "添加变量")}
          </button>
        </section>
        <section aria-label={t("Tags", "标签")}>
          <h2>{t("Tags", "标签")}</h2>
          {tags.map((tag, index) => (
            <div className="snippet-choice-row" key={index}>
              <Field label={`${t("Tag", "标签")} ${index + 1}`}>
                <input
                  value={tag}
                  onChange={(event) =>
                    setTags((current) =>
                      current.map((item, at) =>
                        at === index ? event.target.value : item,
                      ),
                    )
                  }
                />
              </Field>
              <button
                type="button"
                className="secondary"
                aria-label={`${t("Remove tag", "移除标签")} ${index + 1}`}
                onClick={() =>
                  setTags((current) => current.filter((_, at) => at !== index))
                }
              >
                {t("Remove", "移除")}
              </button>
            </div>
          ))}
          <button
            type="button"
            className="secondary"
            disabled={tags.length >= 4096}
            onClick={() => setTags((current) => [...current, ""])}
          >
            {t("Add tag", "添加标签")}
          </button>
        </section>
        <p className="caption">
          {t(
            "Use NFC text, at most 16 KiB per value. Variable and tag names must be distinct; Choice needs 1–4096 distinct options.",
            "请使用 NFC 文本，每个值最多 16 KiB。变量名及标签名不能重复；选项变量需要 1–4096 个不重复的选项。",
          )}
        </p>
        {invalid && (
          <p className="notice error" role="alert">
            {t(
              "Check the text limits, unique names, variable types, choices and defaults. Nothing was sent.",
              "请检查文本长度、名称是否重复、变量类型、选项及默认值。尚未发送请求。",
            )}
          </p>
        )}
      </fieldset>
      <div className="form-actions">
        <button
          type="button"
          className="secondary"
          disabled={disabled}
          onClick={onCancel}
        >
          {t("Cancel", "取消")}
        </button>
        <button className="primary-button" disabled={disabled}>
          {t("Save Snippet", "保存片段")}
        </button>
      </div>
    </form>
  );
}

export function SnippetDefinition({
  fields,
}: {
  fields: InventorySnippetFields;
}) {
  const { t } = useLocale();
  const kinds = {
    1: t("Text", "文本"),
    2: t("Integer", "整数"),
    3: t("Choice", "选项"),
    4: t("Secret", "秘密"),
  };
  return (
    <section className="snippet-detail">
      <h2>{fields.name || t("Unnamed Snippet", "未命名片段")}</h2>
      <pre className="snippet-template">{fields.template}</pre>
      {fields.folder !== undefined && (
        <p>
          {t("Folder", "文件夹")}: {fields.folder}
        </p>
      )}
      {Object.keys(fields.tags ?? {}).length > 0 && (
        <p>
          {t("Tags", "标签")}: {Object.keys(fields.tags!).join(" · ")}
        </p>
      )}
      <dl className="grant-preview">
        {Object.entries(fields.variables ?? {}).map(([key, spec]) => (
          <div key={key}>
            <dt>{key}</dt>
            <dd>
              {kinds[spec.kind]}
              {spec.kind === 3 && (
                <ul>
                  {spec.choices.map((choice) => (
                    <li key={choice}>{choice}</li>
                  ))}
                </ul>
              )}
              {"default" in spec && (
                <p>
                  {t("Default", "默认值")}:{" "}
                  <span className="mono">{spec.default}</span>
                </p>
              )}
            </dd>
          </div>
        ))}
      </dl>
    </section>
  );
}

export function SnippetDetail({ item }: { item: InventorySnippetResource }) {
  return (
    <>
      <SnippetDefinition fields={item.data.fields} />
      <p className="caption mono identifier">{item.id}</p>
    </>
  );
}

export function SnippetPanel({
  teamApi,
  organization,
  account,
  disabled,
  handle,
  onBusy,
}: {
  teamApi: TeamApi;
  organization: string;
  account: string;
  disabled: boolean;
  handle: RefObject<SnippetHandle | null>;
  onBusy: (busy: boolean) => void;
}) {
  const { t } = useLocale(),
    { confirm, dialog } = useConfirmation();
  const workflow = useRef<SnippetActions | null>(null),
    generation = useRef(0),
    running = useRef(false),
    draftOpen = useRef(false);
  const [items, setItems] = useState<InventorySnippetResource[]>([]),
    [next, setNext] = useState<string | null>(null);
  const [draft, setDraft] = useState<{ original?: InventorySnippetResource }>(),
    [detail, setDetail] = useState<InventorySnippetResource>();
  const [busy, setBusy] = useState(true),
    [failure, setFailure] = useState<unknown>(),
    [notice, setNotice] = useState("");
  const [, render] = useState(0),
    [now, setNow] = useState(Date.now());
  const pending = workflow.current?.pending,
    reviewRequired = workflow.current?.reviewRequired ?? false;
  const blocked = disabled || busy,
    editable = !blocked && !pending && !reviewRequired;
  async function read(actions: SnippetActions, epoch: number, cursor?: string) {
    const page = cursor ? await actions.list(cursor) : await actions.review();
    if (generation.current !== epoch) return;
    setItems((current) => (cursor ? [...current, ...page.items] : page.items));
    setNext(page.next_cursor);
  }
  useEffect(() => {
    const actions = new SnippetActions(teamApi, organization, account),
      epoch = ++generation.current;
    workflow.current = actions;
    handle.current = {
      hasPending: () => Boolean(actions.pending),
      hasDraft: () => draftOpen.current,
      dispose: () => {
        actions.dispose();
        generation.current++;
      },
    };
    running.current = true;
    setBusy(true);
    onBusy(true);
    setItems([]);
    setNext(null);
    setDraft(undefined);
    setDetail(undefined);
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
          onBusy(false);
        }
      });
    const timer = window.setInterval(() => setNow(Date.now()), 30_000);
    return () => {
      window.clearInterval(timer);
      actions.dispose();
      generation.current++;
      handle.current = null;
      draftOpen.current = false;
      onBusy(false);
    };
  }, [teamApi, organization, account, handle, onBusy]);
  async function run(
    action: (actions: SnippetActions, epoch: number) => Promise<void>,
  ) {
    const actions = workflow.current,
      epoch = generation.current;
    if (!actions || running.current || disabled) return;
    running.current = true;
    setBusy(true);
    onBusy(true);
    setFailure(undefined);
    setNotice("");
    try {
      await action(actions, epoch);
    } catch (error) {
      if (generation.current === epoch) {
        setFailure(error);
        if (actions.reviewRequired) {
          setDraft(undefined);
          draftOpen.current = false;
          setDetail(undefined);
        }
      }
    } finally {
      if (generation.current === epoch) {
        running.current = false;
        setBusy(false);
        onBusy(false);
        render((value) => value + 1);
      }
    }
  }
  async function closeDraft() {
    if (
      !(await confirm(
        t(
          "Discard this unsaved Snippet draft?",
          "要放弃尚未保存的片段草稿吗？",
        ),
      ))
    )
      return;
    setDraft(undefined);
    draftOpen.current = false;
  }
  return (
    <section className="snippet-panel" aria-busy={busy}>
      <p className="section-intro">
        {t(
          "Manage shared templates and their variable definitions. Execution and session values stay in the desktop app. Each read and change uses current team permissions.",
          "管理团队共享模板及变量定义。执行及会话变量值仅在桌面端处理。每次读取及修改均检查当前团队权限。",
        )}
      </p>
      <div className="inline-actions">
        <button
          className="secondary"
          disabled={blocked || (Boolean(draft) && !pending)}
          onClick={() =>
            void run(async (actions, epoch) => {
              setItems([]);
              setDetail(undefined);
              setNext(null);
              await read(actions, epoch);
            })
          }
        >
          {t("Refresh and review", "刷新并审阅")}
        </button>
        <button
          className="primary-button"
          disabled={!editable || Boolean(draft)}
          onClick={() => {
            setDraft({});
            draftOpen.current = true;
            setDetail(undefined);
          }}
        >
          {t("Create Snippet", "创建片段")}
        </button>
      </div>
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
      {reviewRequired && (
        <p className="notice" role="status">
          {t(
            "The change is unconfirmed or its version is stale. Refresh and review current Snippets before another edit. Current state does not prove the earlier outcome.",
            "修改尚未确认或版本已过期。再次编辑前请刷新并审阅当前片段。当前状态不能证明此前的结果。",
          )}
        </p>
      )}
      {pending && (
        <section className="notice pending-operation">
          <h2>
            {t("Original Snippet operation retained", "已保留原片段操作")}
          </h2>
          <p>
            {t(
              "Creation may have completed. Confirm only this original operation in this login session, within 24 hours. Refreshing the list does not confirm it; a later refusal does not prove it failed.",
              "创建可能已经完成。可在此登录会话内的 24 小时内确认同一原操作。刷新列表不能确认它，后续拒绝也不能证明此前失败。",
            )}
          </p>
          <p className="mono identifier">{pending.body.id}</p>
          <SnippetDefinition fields={pending.body.data.fields} />
          {now >= pending.deadline && (
            <p>
              {t(
                "The original confirmation period has ended. Review current Snippets before creating again.",
                "原操作确认期限已结束。再次创建前请审阅当前片段。",
              )}
            </p>
          )}
          <div className="inline-actions">
            <button
              className="secondary"
              disabled={blocked || now >= pending.deadline}
              onClick={() =>
                void run(async (actions, epoch) => {
                  await actions.confirm();
                  if (generation.current !== epoch) return;
                  setDraft(undefined);
                  draftOpen.current = false;
                  setNotice(
                    t(
                      "Original Snippet creation confirmed.",
                      "原片段创建已确认。",
                    ),
                  );
                  await read(actions, epoch);
                })
              }
            >
              {t("Confirm original creation", "确认原创建操作")}
            </button>
            <button
              className="secondary"
              disabled={blocked}
              onClick={() =>
                void (async () => {
                  if (
                    await confirm(
                      t(
                        "Discard the original confirmation data? Creation may already have completed. Refresh and review before creating again.",
                        "要丢弃原操作确认数据吗？创建可能已经完成。再次创建前请刷新并审阅。",
                      ),
                    )
                  ) {
                    workflow.current?.discard();
                    setDraft(undefined);
                    draftOpen.current = false;
                    render((value) => value + 1);
                  }
                })()
              }
            >
              {t("Discard confirmation data", "丢弃确认数据")}
            </button>
          </div>
        </section>
      )}
      {draft && !pending && (
        <SnippetEditor
          key={draft.original?.etag ?? "new"}
          initial={draft.original?.data.fields}
          disabled={!editable}
          onCancel={() => void closeDraft()}
          onSave={async (fields) => {
            await run(async (actions, epoch) => {
              if (draft.original) await actions.replace(draft.original, fields);
              else await actions.create(fields);
              if (generation.current !== epoch) return;
              setDraft(undefined);
              draftOpen.current = false;
              setNotice(t("Snippet saved.", "片段已保存。"));
              await read(actions, epoch);
            });
          }}
        />
      )}
      {detail && (!draft || pending) && <SnippetDetail item={detail} />}
      {(!draft || pending) && (
        <div className="resource-list">
          {items.map((item) => (
            <article className="resource-row" key={item.id}>
              <div>
                <h2>
                  {item.data.fields.name || t("Unnamed Snippet", "未命名片段")}
                </h2>
                <p className="caption">
                  {Object.keys(item.data.fields.variables ?? {}).length}{" "}
                  {t("variables", "个变量")}
                  {item.data.fields.folder !== undefined &&
                    ` · ${item.data.fields.folder}`}
                </p>
              </div>
              <div className="row-actions">
                <button
                  className="secondary"
                  disabled={blocked}
                  onClick={() =>
                    void run(async (actions, epoch) => {
                      setDetail(undefined);
                      const current = await actions.read(item.id);
                      if (generation.current === epoch) setDetail(current);
                    })
                  }
                >
                  {t("View", "查看")}
                </button>
                <button
                  className="secondary"
                  disabled={!editable}
                  onClick={() =>
                    void run(async (actions, epoch) => {
                      const current = await actions.read(item.id);
                      if (generation.current === epoch) {
                        setDraft({ original: current });
                        draftOpen.current = true;
                        setDetail(undefined);
                      }
                    })
                  }
                >
                  {t("Edit", "编辑")}
                </button>
                <button
                  className="danger"
                  disabled={!editable}
                  onClick={() =>
                    void (async () => {
                      if (
                        !(await confirm(
                          t(
                            "Delete this Snippet? An unconfirmed result requires refresh and review; deletion is never replayed automatically.",
                            "要删除此片段吗？未确认的结果需要刷新并审阅，不会自动重试删除。",
                          ),
                        ))
                      )
                        return;
                      await run(async (actions, epoch) => {
                        await actions.remove(item);
                        if (generation.current !== epoch) return;
                        setDetail(undefined);
                        setNotice(
                          t("Snippet deletion confirmed.", "片段删除已确认。"),
                        );
                        await read(actions, epoch);
                      });
                    })()
                  }
                >
                  {t("Delete", "删除")}
                </button>
              </div>
            </article>
          ))}
        </div>
      )}
      {!busy && items.length === 0 && (!draft || pending) && (
        <p className="empty-state">
          {t(
            "No Snippets in the loaded view. Create a template when permitted, or refresh your current view.",
            "当前列表中没有片段。拥有权限时可创建模板，或刷新当前列表。",
          )}
        </p>
      )}
      {next && (!draft || pending) && (
        <button
          className="secondary load-more"
          disabled={blocked}
          onClick={() =>
            void run((actions, epoch) => read(actions, epoch, next))
          }
        >
          {t("Load more", "加载更多")}
        </button>
      )}
      {busy && (
        <p className="loading-status" role="status">
          {t("Waiting for the deployment…", "正在等待部署响应…")}
        </p>
      )}
      {dialog}
    </section>
  );
}
