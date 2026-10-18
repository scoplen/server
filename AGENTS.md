# Repository guidance

The workspace guidance in [`../AGENTS.md`](../AGENTS.md) is authoritative. The canonical
contracts are in [`../scoplen-docs`](../scoplen-docs). Keep shared contract types in
`proto`; this repository must not read or depend on `client` source.

## Commands

Use the pinned Rust toolchain and run:

```text
cargo fmt --all -- --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets --all-features -- -D warnings
pnpm --dir web/console install --frozen-lockfile
pnpm --dir web/console lint
pnpm --dir web/console typecheck
```

Every commit must include a `Signed-off-by:` trailer. Do not publish images, packages, or
references from an agent checkout.
