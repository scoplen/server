// SPDX-License-Identifier: AGPL-3.0-only
import init, {
  generateSimpleRule,
  generateTeamInvitation,
  parseTeamInvitationPassword,
} from "@scoplen/browser";
import wasmUrl from "@scoplen/browser/scoplen_browser_bg.wasm?url";
import type { InvitationCrypto } from "./invitation.ts";
import type { RuleGenerator } from "./rule-editor.tsx";

let initialization: Promise<void> | undefined;
const ready = () =>
  (initialization ??= init({ module_or_path: wasmUrl }).then(() => undefined));

export const sharedBrowser: {
  invitations: InvitationCrypto;
  rules: RuleGenerator;
} = {
  invitations: {
    async generate(origin, organization, invitation, password, verifier) {
      await ready();
      generateTeamInvitation(
        origin,
        organization,
        invitation,
        password,
        verifier,
      );
    },
    async parse(password) {
      await ready();
      parseTeamInvitationPassword(password);
    },
  },
  rules: {
    async generate(input) {
      await ready();
      return generateSimpleRule(
        new TextEncoder().encode(JSON.stringify(input)),
      );
    },
  },
};
