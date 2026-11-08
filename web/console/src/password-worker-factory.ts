// SPDX-License-Identifier: AGPL-3.0-only
interface ScriptUrlPolicy {
  createScriptURL(value: string): unknown;
}
interface TrustedTypes {
  createPolicy(
    name: string,
    rules: { createScriptURL(value: string): string },
  ): ScriptUrlPolicy;
}

export function passwordWorkerFactory(source: string, origin: string) {
  const expected = new URL(source, origin);
  if (
    expected.origin !== origin ||
    expected.username ||
    expected.password ||
    expected.hash
  )
    throw new Error(
      "The password Worker must use its compiled same-origin URL.",
    );
  let policy: ScriptUrlPolicy | undefined;
  return () => {
    const trustedTypes = (
      globalThis as unknown as { trustedTypes?: TrustedTypes }
    ).trustedTypes;
    if (trustedTypes && !policy)
      policy = trustedTypes.createPolicy("scoplen-browser-worker", {
        createScriptURL(value) {
          if (value !== expected.href)
            throw new Error(
              "Only the compiled password Worker URL is trusted.",
            );
          return value;
        },
      });
    const url = policy ? policy.createScriptURL(expected.href) : expected.href;
    return new Worker(url as string, {
      type: "module",
      name: "scoplen-password-login",
    });
  };
}
