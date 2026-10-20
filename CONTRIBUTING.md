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
