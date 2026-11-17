// SPDX-License-Identifier: AGPL-3.0-only
import type {
  InventorySnippetFields,
  InventorySnippetVariable,
} from "./generated/api.ts";
import { object, text } from "./wire.ts";

function modelText(value: unknown): string {
  const result = text(value);
  if (
    !result.isWellFormed() ||
    result.normalize("NFC") !== result ||
    new TextEncoder().encode(result).length > 16_384
  )
    throw new Error("Invalid Snippet text.");
  return result;
}
function entries(value: unknown): [string, unknown][] {
  const result = Object.entries(object(value));
  if (result.length > 4_096) throw new Error("Too many Snippet entries.");
  for (const [key] of result) modelText(key);
  return result.sort(([left], [right]) =>
    left < right ? -1 : left > right ? 1 : 0,
  );
}
function variable(value: unknown): InventorySnippetVariable {
  const input = object(value);
  const kind = input.kind;
  if (
    ![1, 2, 3, 4].includes(kind as number) ||
    Object.keys(input).some(
      (key) => !["kind", "default", "choices"].includes(key),
    ) ||
    (kind !== 3 && "choices" in input) ||
    (kind === 4 && "default" in input)
  )
    throw new Error("Invalid Snippet variable.");
  const choices = kind === 3 ? input.choices : undefined;
  if (
    kind === 3 &&
    (!Array.isArray(choices) || choices.length < 1 || choices.length > 4_096)
  )
    throw new Error("Invalid Snippet choices.");
  const parsed = Array.isArray(choices) ? choices.map(modelText) : undefined;
  if (parsed && new Set(parsed).size !== parsed.length)
    throw new Error("Repeated Snippet choice.");
  const fallback = "default" in input ? modelText(input.default) : undefined;
  if (kind === 2 && fallback !== undefined) {
    if (!/^(0|-?[1-9][0-9]*)$/.test(fallback))
      throw new Error("Invalid Snippet integer.");
    const integer = BigInt(fallback);
    if (integer < -(1n << 63n) || integer >= 1n << 63n)
      throw new Error("Invalid Snippet integer.");
  }
  if (parsed && fallback !== undefined && !parsed.includes(fallback))
    throw new Error("Snippet default is not a choice.");
  return {
    kind,
    ...(parsed ? { choices: parsed } : {}),
    ...(fallback !== undefined ? { default: fallback } : {}),
  } as InventorySnippetVariable;
}

/** Complete replacements accept only fields this editor can preserve. */
export function snippetFields(value: unknown): InventorySnippetFields {
  const input = object(value);
  if (
    Object.keys(input).some(
      (key) =>
        !["name", "template", "variables", "tags", "folder"].includes(key),
    )
  )
    throw new Error("Unsupported Snippet field.");
  return {
    name: modelText(input.name),
    template: modelText(input.template),
    ...("variables" in input
      ? {
          variables: Object.fromEntries(
            entries(input.variables).map(([key, value]) => [
              key,
              variable(value),
            ]),
          ),
        }
      : {}),
    ...("tags" in input
      ? {
          tags: Object.fromEntries(
            entries(input.tags).map(([key, value]) => {
              if (value !== true) throw new Error("Invalid Snippet tag.");
              return [key, true as const];
            }),
          ),
        }
      : {}),
    ...("folder" in input ? { folder: modelText(input.folder) } : {}),
  };
}
