# Vendored dependency patches

## sqlx-sqlite 0.8.6

The directory `sqlx-sqlite-0.8.6` contains all 56 files from the official crates.io release,
including `LICENSE-APACHE`, `LICENSE-MIT` and its original `Cargo.toml.orig`.

- Source: <https://static.crates.io/crates/sqlx-sqlite/sqlx-sqlite-0.8.6.crate>
- Registry metadata: <https://crates.io/api/v1/crates/sqlx-sqlite/0.8.6>
- Archive SHA-256: `c2d12fe70b2c1b4401038055f90f151b78208de1f9f89a7dbfd41587a10c3eea`
- Upstream revision: `bab1b022bd56a64f9a08b46b36b97c5cff19d77e`, path `sqlx-sqlite`, as recorded
  in the archive's `.cargo_vcs_info.json`.
- License: MIT OR Apache-2.0, with both upstream license files retained.

The only change to the extracted package is in its normalized `Cargo.toml`:
`dependencies.libsqlite3-sys.version` changes from `0.30.1` to `=0.39.1`. Every Rust source
file and every other upstream file is byte-for-byte unchanged. The root workspace excludes
this upstream package from first-party formatting and linting while applying it through
`[patch.crates-io]`. The production Docker build includes the same source, and the runtime
image retains both license files under `/app/licenses/sqlx-sqlite/`.

The selected native binding release is official `libsqlite3-sys 0.39.1`:

- Source: <https://static.crates.io/crates/libsqlite3-sys/libsqlite3-sys-0.39.1.crate>
- Registry metadata: <https://crates.io/api/v1/crates/libsqlite3-sys/0.39.1>
- Archive SHA-256: `14a5f01b87b92705d07b433c06f96cbc764637d81a0bffb5734ce17cf0f9a2b3`
- Bundled SQLite: 3.54.1. The server's storage test queries `sqlite_version()` from the
  production SQLx connection to verify the actual engine, alongside WAL/migration/reopen checks.

Both downloaded archives were checked against the SHA-256 values in the registry metadata.
The native binding remains a checksummed registry dependency in `Cargo.lock`; its source is
not copied into this repository. This patch addresses
[RUSTSEC-2026-0459](https://rustsec.org/advisories/RUSTSEC-2026-0459.html), whose bundled SQLite
fix starts at `libsqlite3-sys 0.39.0` / SQLite 3.54.0. No advisory is ignored or suppressed.

Remove this directory, the root path patch/workspace exclusion and its Docker context entries
when a supported upstream SQLx release selects a fixed SQLite binding without this override.
Update the lockfile, runtime version assertion and patch record together, then repeat storage,
populated migration, WAL recovery and production-container checks before removing the patch.
