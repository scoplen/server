# Contributing

Read [`../AGENTS.md`](../AGENTS.md) and the repository [`AGENTS.md`](AGENTS.md) before changing
files. Contracts are specified in `scoplen-docs` before they are implemented here.

Use the pinned Rust and Node toolchains, run the checks in `AGENTS.md`, and include tests for
failure paths when behavior changes. Every commit must use the repository commit format and carry
your Developer Certificate of Origin sign-off:

```text
Signed-off-by: Your Name <you@example.com>
```

Do not commit generated secrets, local data, `.env` files, or deployment credentials.

The DCO workflow treats the signed repository-import snapshot in
`DCO_IMPORT_BASELINE` as the boundary of the imported history. An initial default-branch push
checks that snapshot and every descendant commit. A new branch checks all commits absent from
the fetched default branch, including side branches merged into it. Published default-branch
history is not rechecked. Later pushes and pull requests check their full event range. Missing
default-branch refs fail closed; a signed tip cannot hide an unsigned intermediate commit.
Run `bash scripts/test-dco.sh` to verify these cases locally.

If a published commit accidentally lacks its sign-off, its original author can add a later
signed commit that explicitly certifies the original contribution under the DCO. Include a
`DCO-Remediation-For: <full-40-character-commit-hash>` trailer for each certified ancestor.
The certification commit must be authored by that same name and email and contain their exact
`Signed-off-by` identity. Only certifications reachable from the checked head count. This
preserves published history; it does not exempt unsigned commits or allow someone else to
certify the original author's contribution. Use `git merge --signoff` for every merge.
