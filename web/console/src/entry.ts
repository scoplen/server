// SPDX-License-Identifier: AGPL-3.0-only
import { takeSetupFragment } from "./operator.ts";
import { takeJoinFragment, type JoinTarget } from "./invitation.ts";

export type ConsoleEntry =
  | { kind: "operator"; setupToken?: string; invalidLink: boolean }
  | { kind: "account"; target?: JoinTarget; invalidLink: boolean };

export function consoleEntry(
  url: URL,
  replace: (path: string) => void,
): ConsoleEntry {
  if (url.pathname === "/setup" || url.pathname === "/operator") {
    try {
      return {
        kind: "operator",
        setupToken: takeSetupFragment(url, replace),
        invalidLink: false,
      };
    } catch {
      return { kind: "operator", invalidLink: true };
    }
  }
  try {
    const target = takeJoinFragment(url, replace);
    if (url.pathname !== "/join-team" && url.hash) replace(url.pathname);
    return { kind: "account", target, invalidLink: false };
  } catch {
    return { kind: "account", invalidLink: true };
  }
}
