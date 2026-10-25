# Scoplen server

The self-hosted Scoplen server, host agent, administration CLI, and web-console workspace.
Scoplen is a Plystra project. This repository is licensed under AGPL-3.0-only.

## Status

Maturity: Exploration. Maintenance: Active. The repository baseline (roadmap V1) is complete. The
current binary provides role selection, validated TOML and `SPL_` environment configuration,
first-run deployment material, a single public listener, health/readiness/metrics endpoints, and
plain, file-based, or ACME TLS. The `api`, `worker`, and `edge` roles open the selected SQLite or
PostgreSQL database and apply forward migrations; readiness checks that database. The SQLite
storage layer has the first sync foundation: per-vault gap-free sequence allocation, atomic
compare-and-swap batches, current change and snapshot paging, acknowledgement cursors, and
bounded version reads. Its atomic worker retention pass keeps the current version plus at most
20 previous versions for 30 days. For an enrolled Personal vault, it verifies the complete signed
certificate/revocation set and current admission identities, then reads every device's ACK and
purges eligible tombstones in the same transaction. A missing ACK counts as zero; an inactive or
missing unrevoked identity disables early purging. Empty or unsupported membership, including
Shared/organization and bare Personal vaults, retains the 180-day tombstone policy. Invalid signed
state or an ACK ahead of the vault fails the pass without partial deletion. Purging removes all
retained versions of the tombstone and advances the purge horizon. The `scoplen-store` queue now
persists opaque jobs with bounded payloads, atomic claims, owner-checked leases, retry/failure
state, and expired-lease requeue; the `worker` role runs a 30-second heartbeat that requeues
abandoned leases.
Standalone `ca` and `gateway` roles do not open a database or generate Personal setup material.
New bootstrap material uses exclusive file creation and, on Unix, owner read/write permissions
(`0600`). Existing files are preserved; an incomplete CA pair requires recovery from the
operator's backup. Windows creates a missing data directory with a protected, inheritable DACL
for the server account, Local System and Administrators before opening storage. Existing
directories and private keys with unsafe or unsupported ACLs are rejected without changing
their permissions. This requires OS Windows PowerShell 5.1; see
[Windows data-directory permissions](docs/windows-data-directory.md) for provisioning and
recovery. Operators remain responsible for preventing untrusted parent-directory replacement.
The `scoplen-sync` crate now exposes a K-4 HTTP/CBOR router for a session handshake that lists
account-owned personal vaults and current shared-vault memberships with their rotation state,
shared-vault creation, key retrieval, epoch publication, and member addition and removal, plus
account key bundles, changes,
snapshots, version reads, object writes, acknowledgements, and the authenticated
`/sync/v1/notify` WebSocket. The notification adapter sends the D-75 method context, verifies the
strict binary CBOR token/proof message within ten seconds of opening, and acknowledges successful
authentication before any event. Both classic GET and HTTP/2 extended CONNECT are supported.
It fans out deterministic CBOR events through a caller-owned local hub. Committed object writes
publish a vault-advancement hint to connected devices that
still pass notification and vault-read authorization; notification delivery cannot roll back a
write, and clients can fall back to polling. SQLite delivers locally after commit; PostgreSQL
queues the hint in the mutation transaction and uses one LISTEN connection per API instance
for both local and remote delivery. Rolled-back transactions emit no hint. The router
requires an injected authenticator that binds DPoP proofs to the request method and
URI, authorizes vault, account-key, and notification operations, records the creator's initial
shared-vault membership and opaque epoch-1 key wrap, adds and removes members with historical
opaque wraps, commits account-key signatures and the complete certified, unrevoked recipient set,
and validates encrypted
envelopes before storage. The caller selects a SQLite or PostgreSQL store for the entire
authenticated router. The PostgreSQL path has been exercised through HTTP/CBOR against PostgreSQL
17. The API listener now mounts only the Personal session, account-key read and publication, vault-key read,
changes, snapshot, version read, signed object write, ACK, and notification routes. It verifies the enrolled
device token, exact method/path/ath DPoP proof, durable replay claim, current device certificate,
required scope, and Personal vault ownership. Writes verify the envelope signature and current
key epoch; writes and ACKs recheck authorization inside the storage transaction. Notifications
require `sync:read`, close at token expiry, and recheck current device/account authorization every
second and before sending events. State checks and event sends have bounded deadlines so stalled
storage or a non-reading peer cannot retain a subscription until token expiry. The listener and
committed writes use the same local hub on SQLite or PostgreSQL. PostgreSQL receipt and a bounded
64-hint dispatcher run as futures owned by the API listener; recipient authorization is bounded
to five seconds. LISTEN must complete before readiness and socket admission. An observed listener
gap, queue overflow, authorization outage or worker shutdown fences current connections with
1011; new connections during an outage also fail with 1011. Reconnect attempts use five-second
database deadlines and capped 100 ms to five-second backoff. Hints carry no object or key material,
are validated before dispatch and remain best effort: reconnect and pull changes, or poll every
60 seconds while unavailable. A lost COMMIT reply can still accompany a committed hint; the HTTP
result remains uncertain and must never trigger automatic batch replay. Shared-vault mutations
remain unmounted. The retired Personal invitation/enrollment and pairing entry points are
removed from the server, including their verifier, storage adapters, authorization and worker
maintenance. Historical migrations and tables remain intact and unused by runtime.
Operator tokens retain the published inert legacy scope claim; it authorizes no current business
operation or Account/Device entry. Existing
Accounts and Devices keep authentication and sync; new Account password registration/sign-in,
bootstrap and device admission remain incomplete. `scoplen-identity` retains the maintained
Operator passkey verifier. A separate SQLite/PostgreSQL
device access-token keyring stores an encrypted Ed25519 seed, exposes only public verification
keys, rotates the active key after 30 days with a seven-day verification overlap, and audits
creation and rotation in the same transaction. The API listener mounts
`POST /api/v1/auth/challenge`, `/api/v1/auth/device`, and `/api/v1/auth/refresh`, plus public
`GET /.well-known/jwks.json`. The store backs these routes with durable device challenge digests,
per-endpoint admission and cooldowns, same-transaction nonce consumption and token issuance,
absolute-expiry refresh families, single-use rotation and reuse revocation, and cross-instance
DPoP replay claims on SQLite and PostgreSQL. Native refresh uses a JSON credential; browser
refresh accepts only the scoped `HttpOnly` cookie with the exact trusted Origin and returns the
rotated credential only in `Set-Cookie`. Independent Operator authentication storage also
provides per-endpoint source, setup-digest, ceremony and verified-Operator admission, durable
DPoP replay claims, and audit-atomic setup finish cooldown updates on both databases.
The stores also provide discoverable Operator login with current passkey counter and backup-state
verification, atomic ceremony consumption and audited browser-session creation, independent
30-day refresh families, single-use cookie rotation and matching-token reuse revocation. Refresh
proofs are reverified and durably claimed within the rotation transaction. Current family,
Operator and credential authorization can be rechecked inside an administration mutation
transaction. Complete token JSON and the scoped secure cookie are validated before commit, and
an uncertain commit returns no session secrets. The API listener mounts the strict Operator
setup and login options/finish routes, and dispatches Operator browser refresh cookies to their
independent verifier and family store. The Operator console connects setup and fresh Passkey login, with explicit current-session server sign out distinct from
local tab locking. A dedicated Operator keyring uses
independent Ed25519 seeds, `operator-` key identifiers, and purpose-bound encrypted envelopes,
with the same audited 30-day rotation
and seven-day overlap. Public `GET /.well-known/operator-jwks.json` exposes only that keyring;
the device JWKS remains separate. Both routes return a non-cacheable 503 if key storage,
integrity, KMS validation, or a required audit write fails. Remaining console administration and
control-plane authorization remain roadmap work.

The Account password probe-key storage boundary provides independent random Kprobe initialization
and same-value KMS rewrapping on SQLite and PostgreSQL. It stores only a purpose-bound encrypted
key, serializes independent instances and commits every initialization/rewrap with deployment
audit before returning. Missing singleton state, invalid ciphertext or an incorrect KMS key fails
without generating a replacement. Database guards also reject clearing, deleting or replacing
an initialized singleton and changing its original creation metadata. Same-value KMS rewrapping
remains available. Restart and ordinary token-key rotation preserve Kprobe.
This boundary is not yet connected to Account password routes; credentials, bootstrap snapshots
and independent password sign-in remain incomplete. Intentional Kprobe replacement is not exposed.

Account-key publication retains the complete accepted canonical signed K-4 PUT with its
serving projection and audit in the same transaction. The bounded storage reader requires exact
agreement with every current field, signature and wrap. Existing projection-only rows remain
without acceptance evidence; historical accepted evidence is preserved. Lower-level new revisions
invalidate prior evidence, and exact replay does not backfill it. This storage prerequisite adds
no Account password route or credentials to existing Accounts.

Account-id retention has a separate SQLite/PostgreSQL storage boundary. Explicit initialization
reserves existing Account ids before enabling registration and durably admits a ceiling (default
1,048,576). Each retained row contains only the shared domain-separated digest. Database guards
preserve it after ordinary Account deletion. The registration transaction helper serializes a
new digest with the caller's business state, receipt and audit; it does not commit independently.
Explicit audited maintenance can raise the ceiling without eviction. Capacity pressure is returned
as non-identifying counters, and exhaustion does not change database readiness. This boundary is
not yet mounted as registration, an operator maintenance API or a warning-delivery mechanism.

The worker retires expired device and Operator refresh credentials in one atomic transaction
per 30-second heartbeat, independently of later authentication requests. For each kind it
locks at most 16 expired families, removes at most 256 digests and removes only empty expired
families. Further work waits for another heartbeat; a heavily rotated family cannot cause an
unbounded cascading deletion. Unexpired families and spent digests, including revoked families,
remain intact until absolute expiry. Expiry is rechecked after family locks, shutdown cancels
a blocked pass, and logs contain only confirmed counts or fixed failures. This retirement
reuses database pages; it does not vacuum or promise a smaller database file.
All Rust protocol consumers, route-contract CI and generated console API types use published
`proto@a604b726`. The server consumes `scoplen-api`, `scoplen-crypto` and `scoplen-model`.
The published Account password and device-admission contracts are not yet server endpoints.
The sync service retains encrypted object envelopes without reading their Credential fields.
Server-hosted SSH and agent execution remain separate roadmap work.

The `scoplen-store` crate now provides a backend-neutral object
storage boundary with local filesystem and S3-compatible implementations, including bounded key
validation and streaming/multipart operations; database-backed roles initialize the configured
backend and include it in `/readyz`. Complete control-plane policy filtering,
Shared/organization membership-aware purge orchestration, organization vault ownership in session listings, higher wire ceilings and
other route body limits, control, gateway, and remaining console administration are still
roadmap work. The audit crate and SQLite/PostgreSQL stores provide bounded canonical-event SHA-256
hashing, same-transaction append helpers, durable checkpoints, and chain verification for separate
organization and deployment audit chains. The worker signs advanced verified heads at most hourly
with an independent Ed25519 seed; deployment signatures use their own domain. Event producers,
checkpoint export, and retention wiring remain open. The storage crate also validates and redacts
a local 32-byte deployment key-file backend behind the `KeyManagementService` trait; cloud KMS,
PKCS#11, column encryption, and external KMS runtime wiring remain open. Database-backed role
preparation loads and validates the local backend before startup. Bootstrap also creates the
independent `audit-signing.key`; `storage.kms.backend = "local"`, `storage.kms.key_file`, and
`storage.kms.audit_key_file` are configurable in TOML or via `SPL_STORAGE_KMS_*` environment overrides.
For a stale object-write batch, the sync adapter returns every conflicting object in request order
with its current change or an explicit absent value. If a stored change cannot be encoded within
the K-4 bounds, it returns `503 sync.storage_unavailable` instead of an incomplete conflict body.
Authenticated change, snapshot, object-version, account-key, and vault-key reads also return
`503 sync.storage_unavailable` when persisted data cannot form a valid complete response; malformed
caller input retains its request error and no partial success body is sent.
Object writes and business-state ACK commits return that same status and code with `changed: true`
and `retryable: false` when COMMIT was attempted without a confirmed result. A confirmed precommit
failure, or failure to close an idempotent ACK no-op, uses `changed: false` and `retryable: true`.
Clients keep their local edits and keys, do not advance a cursor from an uncertain response, and
pull current state for merge/CAS reconciliation before another object write instead of replaying
the batch automatically. SQLite deferred-commit failures and PostgreSQL committed writes and ACKs
with deliberately withheld acknowledgements cover these paths through the HTTP/CBOR adapter.
The SQLite and PostgreSQL sync stores enforce configured current-object, shared-vault-per-account,
and member-per-vault cardinality limits in mutation transactions. Defaults are 100,000 current
objects per vault (including tombstones), 1,000
shared vault memberships per account, and 1,000 accounts per shared vault. The K-4
session advertises these limits. Quota rejection returns `413 sync.quota_exceeded` without changing
state. Member limits cannot exceed 1,000 because epoch publication requires one key wrap per member
and the current wire codec accepts at most 1,000 wraps. The authenticated K-4 router enforces configured
per-device write rates in durable SQLite/PostgreSQL token buckets shared across API instances
and restarts, and advertises those same values in the
session (defaults: 50 requests per second, burst 200). An exhausted bucket returns
`429 sync.rate_limited` and `Retry-After`. The router also enforces configured envelope bytes,
batch object count, and encoded batch bytes, advertises those bounds in the session, and returns
`413 sync.invalid_request` for an oversized write before changing state. These three bounds may be
lowered from their defaults; the current K-4 codec and SQLite store prevent raising them.
Account-key updates, shared-vault epoch publication, and member addition each enforce their fixed
4 MiB K-4 request bound before collecting the body and return `413 sync.invalid_request` when
oversized. Shared-vault creation enforces its fixed 64 KiB wrap plus 256-byte encoded-body bound
the same way. The session handshake enforces its fixed 4 KiB request limit before collecting the
body and returns `413 sync.invalid_request` for an oversized request. Member removal and epoch
retirement reject any non-empty request body with a CBOR `400 sync.invalid_request` problem before
changing state. Acknowledgements collect at most 17 bytes, the maximum canonical `{cursor: uint}`
encoding, and reject larger bodies with a CBOR `400 sync.invalid_request` problem after authorization.
Change-feed and snapshot reads accept at most 37 query bytes for canonical `after` and `limit`
parameters, rejecting longer queries with a CBOR `400 sync.invalid_request` problem after
authorization. A read cursor below the purge horizon or ahead of the vault sequence returns a
CBOR `410 sync.cursor_expired` problem so the client can restart full reconciliation; an ACK cursor
ahead of the sequence remains `400 sync.cursor_ahead`. These limits are not session-advertised write
settings. Other route body limits remain roadmap work.
The SQLite and PostgreSQL stores atomically provision one personal vault per account with an opaque
ARK-wrapped initial key. Both scope personal-key reads to the owner and list the account's personal
vault and current shared memberships. The authenticated K-4 vault-key route delivers that key only
to its owner using the shared `{keys}` response shape on either backend. Existing Device authentication uses these primitives; Personal vault-key rotation remains open.
Both stores also atomically create a shared vault with its admin membership and epoch-one wrap,
list current shared memberships in vault-id order, and return only a member's non-retired wraps.
Both stores publish the next epoch for exactly the current member set, add members with every
served wrap, remove members and their wraps while marking rotation pending, and retire older
epochs only after current objects no longer reference them. Mutations enforce the fixed key
response count and size bounds before commit.
The storage crate also carries a parallel PostgreSQL migration set and a logical schema check
against the SQLite set. The API, edge, and worker roles can select PostgreSQL with
`storage.backend = "postgres"` and `storage.database_url`; the listener's `/readyz` checks the
selected database and object store. Worker queue, sync-retention, account-key, audit, account-scoped
vault-list, and personal-vault key queries use PostgreSQL. PostgreSQL also supports atomic CAS
batches with gap-free vault sequences, current change and full-reconciliation snapshot pages from
one read transaction, bounded retained-version reads, and monotone device acknowledgements. The
runtime passes the configured object limit to that writer. The injected sync HTTP adapter selects
SQLite or PostgreSQL consistently for all K-4 routes; the API listener mounts the Personal subset
described above.

Shared-vault key epochs have a bounded retirement path: the authenticated sync adapter accepts
`POST /sync/v1/vaults/{vault}/epochs/{epoch}/retire`, and the SQLite store records retirement
markers, keeps validated key epochs on object history, removes retired wraps atomically, and
rejects writes that reference a retired epoch. Retirement is idempotent and refuses the newest
served epoch or any epoch still referenced by a current object.
Epoch publication and member addition also check that every affected member's complete key
response remains within the fixed 64 non-retired epoch and 4 MiB encoded-response bounds. A
mutation that would exceed either bound returns `413 sync.quota_exceeded` without changing state;
retiring an older epoch after re-encryption or using smaller wraps can free capacity.
Account-key bundle updates and certificate/revocation replacement also check every resulting
device-specific `GET /sync/v1/keys` response against the fixed 4 MiB CBOR limit inside the same
account transaction. An update that would exceed it returns `413 sync.quota_exceeded` without
changing the bundle or statements. Statements may precede the first bundle; that bundle must pass
the same check before it becomes visible.
PostgreSQL account-key GET reads the bundle, device wrap, certificates, and revocations from one
read-only repeatable-read snapshot, so concurrent rotations cannot splice separate versions into
a response.
The production Personal `PUT /sync/v1/keys` retains the initially authenticated account, device,
exact certificate and DPoP key binding while receiving the bounded body. The SQLite write
transaction or PostgreSQL account lock rechecks that binding and current authorization, verifies
the current account-root signature and complete certified-minus-revoked recipient set (including
inactive admission rows), and commits revision CAS, all wraps, projected responses and a deployment
audit event together. It serializes with account identity/statement changes.
The original token must remain valid after lock acquisition and before COMMIT, for new updates
and exact replays alike; a slow body or lock wait cannot extend its authorization lifetime.
Authenticated exact replay compares the complete stored signed request before checking a new
signature. It makes no second mutation or audit, including after a later signing-root change.
Changed bytes at the current revision return `409 sync.conflict`.
A confirmed rollback returns `503 sync.storage_unavailable` with `changed: false` and
`retryable: true`; an unconfirmed new-update COMMIT returns the same code with `changed: true`
and `retryable: false`. A replay read transaction has no mutation even if its close fails.
Retain the exact pending bytes and local keys, verify GET state first, and recover explicitly with
fresh DPoP; only a successful response to those exact bytes confirms publication. GET's projection
does not establish exact replay. Publication does not replace public signing/KEM roots or implement
ARK rotation or device revocation workflows.

## Repository shape

The Cargo workspace contains the server supervisor and one crate boundary for each server role.
`web/console` is the React and strict TypeScript Operator console. `deploy/` and `docs/`
hold deployment and operational material as those roadmap gates become implementable.

## Personal container trial

Follow [the Personal container procedure](docs/personal-container.md) for the source-built
single-node Compose entry. It builds and carries the Operator console, persists SQLite and keys
in a private Docker volume, and serves direct HTTPS using an external certificate matching the
configured DNS name and public port. The runtime is distroless and non-root; ordinary setup uses
the one-time Operator setup link, fresh Passkey sign-in, and explicit server sign out. Deployment and
release gates remain Incomplete; this entry does not establish signed release artifacts,
backup/restore, physical Passkey interoperability, or every `all`-role workflow.
The disposable container check also runs a populated pre-migration SQLite database through the
current image, then starts a matching old server against an explicit offline snapshot recovery.
It covers that upgrade path without implementing complete deployment backup/restore.

## Personal console assets

Run `pnpm --dir web/console install --frozen-lockfile` and
`pnpm --dir web/console build` before starting an API-role development server. The build emits
hashed scripts, styles, local fonts, their redistribution licenses, and a bounded SHA-256 manifest
in `web/console/dist`. The API role serves `/` and `/setup` plus only manifest-listed assets,
with a strict CSP, Trusted Types, no inline scripts, no-store and no-referrer policies. It loads
verified bytes once at startup; rebuild and restart after changing the assets.

`console.assets_dir`, overridden by `SPL_CONSOLE_ASSETS_DIR`, defaults to `web/console/dist`
relative to the process working directory. For an installed deployment, configure the absolute
directory shipped by the package. Packaging must include the built directory. A missing or
invalid build returns a clear 503 from console entry paths; API, health and readiness remain
independent. An edge-only process has no console routes. The console requires its configured
HTTPS origin and a current browser with passkeys, WebCrypto and Web Locks. The Vite development
server is `pnpm --dir web/console dev`; it does not provide an API proxy or bypass these guards.

Console API types are copied unchanged from the exact published proto revision by
`node scripts/sync-console-contract.mjs`; `--check` verifies the pinned artifact. Browser-key
interoperability uses a public fixture generated by
`node web/console/scripts/generate-dpop-fixture.ts` and verified by the existing Rust DPoP
verifier. Unit credential stubs exercise only controller boundaries. Physical passkey creation,
cross-browser authenticator interoperability, TLS deployment and release packaging require
separate verification.

## Development

For independent Personal integration tests, build the registered
`personal_live_bootstrap` example and follow [the disposable HTTPS fixture procedure](docs/live-personal-fixture.md).
It prepares a private localhost TLS configuration, then performs real public Operator
Operator setup/login/logout and retired-route absence against the production server. SQLite is the default; PostgreSQL takes
a private disposable-database configuration. The caller owns the server process and database.

The maintained WebAuthn verifier builds vendored OpenSSL. Install Perl and a native C toolchain
before running Cargo: MSVC Build Tools and Strawberry Perl on Windows, Xcode Command Line Tools
on macOS, or the usual C compiler, Make and Perl packages on Linux. Put `perl` on `PATH` (the
Strawberry default is `C:\Strawberry\perl\bin`). NASM is optional on Windows; the vendored build
automatically disables assembly when NASM is unavailable.

Windows startup also requires the OS Windows PowerShell 5.1 executable and .NET filesystem
access-control APIs for permission admission. A missing or restricted runtime stops startup
with an actionable error; existing ACLs are never silently repaired.

SQL migrations use LF line endings on every platform. SQLx embeds and hashes the exact SQL
bytes, so keep the repository's migration attributes when creating a checkout. A database made
by an earlier build with different migration bytes can fail with a checksum mismatch; retain
the matching build and back up its data before rebuilding the database. Do not edit historical
SQL or recorded migration checksums to bypass the failure.

```text
cargo fmt --all -- --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets --all-features -- -D warnings
pnpm --dir web/console install --frozen-lockfile
pnpm --dir web/console lint
pnpm --dir web/console typecheck
pnpm --dir web/console test
pnpm --dir web/console build
node scripts/sync-console-contract.mjs --check
```

For a local configuration check:

```text
cargo run -p scoplen-server -- --validate-config
```

Run `cargo run -p scoplen-server -- --help` for role selection and configuration options. The
Personal defaults bind to `127.0.0.1:8443` and use a local data directory. A reverse proxy may
terminate TLS and select `tls.mode = "plain"`; direct TLS uses `tls.mode = "files"` with a PEM
certificate and key. `tls.mode = "acme"` obtains and renews a Let's Encrypt TLS-ALPN-01
certificate for `server.public_host`, using the contact in `tls.acme_email`. ACME account keys and
certificates are cached below `server.data_dir/acme-cache`; keep the data directory in protected
operator storage. The `tls.acme_production` setting defaults to `true`; set it to `false` only when
testing against the Let's Encrypt staging directory.

TLS-ALPN-01 requires external port 443, even when the local listener uses another port.
Set `server.public_host` to a canonical lowercase DNS name, canonical IPv4 address, or
unbracketed canonical IPv6 address. `server.public_port` (or `SPL_SERVER_PUBLIC_PORT`) is the
externally reachable HTTPS port, defaulting to 443; it is independent of the local
`server.listen_port`. The server validates the resulting canonical HTTPS origin at startup and
uses it for generated setup links. Port 443 is omitted from those links; a different external
port is included. Invalid or ambiguous public hosts fail `--validate-config` and startup.
When first-operator setup is pending, `server.public_host` must be a DNS name with valid HTTPS.
Once a setup entitlement exists, the `api`, `worker`, and `edge` roles compare the configured
origin with its durable origin before creating local key, CA, or object-storage material. They
refuse startup if `server.public_host` or `server.public_port` changes. Restore the original
configuration before restarting. Completed setup does not authorize an origin change; a
separate identity-preserving migration procedure is required and is not yet available. An
IP-literal origin can be used only when it already exactly matches the retained completed origin.
Only the first API initializer discloses a one-hour setup link through local terminal output,
after its digest and audit are durably committed. Protect that output: the link is not logged,
written to `setup-link.txt`, or recoverable from the database. Other replicas, restarts, edge
and worker roles preserve the existing pending expiry without printing or replacing its secret.
To replace a lost or expired pending link explicitly on the server host, run:

```text
cargo run -p scoplen-ctl --bin splctl -- bootstrap --reissue-pending --config spl-server.toml
```

The command uses the local database and configured KMS, invalidates prior setup ceremonies,
and discloses the replacement only after confirmed commit. Completed setup never reopens,
including after operator revocation. A result with an unknown commit outcome discloses no link;
use the deliberate local reissue action only if setup remains pending.

The storage service supports current-family Operator logout through `logout_operator` on both
databases. Its caller verifies the Operator access token, exact Origin and token-bound DPoP,
durably claims the proof and charges source admission before invoking the mutation. The store
serializes with refresh and other protected mutations, checks current credential/family state,
the stored ES256/P-256 public key and time, and atomically revokes that family with one
deployment audit. A fresh eligible retry
can confirm an already revoked family without producing general authorization evidence. It
retains all refresh digests until normal expiry maintenance and preserves every other family.
An unconfirmed revocation commit requires explicit fresh-proof confirmation while the original
access token remains valid. The public HTTP route and console behavior are described below.

The storage service verifies real ES256 passkey registration and discoverable assertions with
the maintained WebAuthn core under the configured exact origin/RP, required residency and UV,
and `none` attestation policy. SQLite and PostgreSQL atomically persist the first operator,
credential, permanent setup completion, ceremony consumption and deployment audit. The API
listener mounts `POST /api/v1/auth/operator/setup/options` and `/api/v1/auth/operator/setup/finish`.
Both require the exact trusted Origin, a fresh browser DPoP proof and the setup secret, with
durable source/private admission and replay claims. Invalid outer requests or wrong proof keys
leave a ceremony usable; a failed embedded WebAuthn check consumes that ceremony with its audit
but preserves the setup entitlement. Successful registration returns only the Operator id,
without a token or cookie. An uncertain finish returns `auth.commit_outcome_unknown`; retain the
passkey and attempt fresh login before explicitly returning to pending setup.
`POST /api/v1/auth/operator/login/options` accepts exactly `{}` and returns discoverable passkey
options without enumerating credentials. `/api/v1/auth/operator/login/finish` consumes the
assertion ceremony and creates an independent Operator session with only the browser four-field
token response and a scoped `HttpOnly; Secure; SameSite=Strict` refresh cookie. Both require the
same exact Origin and fresh DPoP proof as setup. `POST /api/v1/auth/refresh` accepts that Operator
credential only in the cookie with the exact Origin and `{}` body; it rotates the credential
inside the proof/replay/session/audit transaction. Wrong proof keys or reused DPoP proofs cannot
revoke a family. Authenticated matching-token reuse revokes it. Native JSON refresh remains a
device-only surface. An uncertain login or refresh commit returns no token or cookie and must
restart passkey login with a fresh ceremony. The Operator console implements first-passkey setup, fresh discoverable sign-in and explicit
server sign out through these public APIs. It scrubs the setup fragment immediately, keeps its non-extractable P-256 proof key and
access token only in memory, and never exports private key material. Reloading requires passkey
login; it does not try an old refresh cookie with a new proof key. Refresh is serialized using
Web Locks. Unknown setup outcomes retain the passkey and offer sign-in; unknown login/refresh
outcomes restart login. Lock this tab clears its in-memory sign-in; it does not revoke
the server session.

`POST /api/v1/auth/operator/logout` accepts exactly `{}` as complete UTF-8 JSON of at most
256 bytes. It requires exactly one trusted HTTPS Origin, including its port, the retained
unexpired Operator access token and a fresh token-bound ES256 DPoP proof. The route does not
read or change refresh cookies; the console sends `credentials: "omit"`. Source admission
allows 30 attempts per minute; only a transaction-current Operator/family binding selects the
independent ten-per-minute Operator bucket. SQLite and PostgreSQL serialize current-state
validation, family revocation and its deployment audit. Confirmed success returns exactly
`{"revoked":true}`; an eligible fresh-proof retry can confirm the same already-revoked family
without another revocation audit. Other browser sessions and existing Device credentials remain valid.
All responses omit `Set-Cookie` and use no-store/no-cache/no-referrer headers.

An unknown logout commit returns `503 auth.commit_outcome_unknown` with `changed: true` and
`retryable: true`. A lost or invalid response has the same unresolved console state. The console
retains the original proof key and access token for an explicit fresh-proof retry while that
token remains unexpired. It never refreshes or replays logout automatically, and a later login
does not settle the old family's outcome. Only strict server confirmation clears credentials;
Lock this tab can discard them locally while clearly leaving server sign out unconfirmed.
Same-tab operations are serialized and local locking fences late responses.

Enrolled devices can request a 120-second challenge, sign it with their registered P-256 key,
and receive a ten-minute DPoP-bound access token and a single-use refresh credential. The API
listener returns no-store JSON and RFC 9457 problems. Device and refresh admission is durable
across API instances; a verified spent-token reuse revokes its 30-day family. A refresh response
whose commit cannot be confirmed requires a new device challenge instead of retrying the old
credential. `GET /.well-known/jwks.json` publishes only the active and unexpired overlap public
token keys. Source-admission and device-refresh storage failures emit a warning correlated
with the problem's request id, a static operation phase and error category, and elapsed
milliseconds. SQLite busy/locked errors and closed or timed-out connection pools have distinct
categories; raw database errors, credentials and proofs are excluded. The device-refresh phases
distinguish source admission, keyring loading and the refresh transaction. A controlled SQLite writer
timeout returns `auth.storage_unavailable` without consuming the refresh credential; this
coverage does not establish the cause of the unresolved native post-reopen refresh failure.
Unknown commit outcomes retain their separate non-retryable device-challenge recovery.
`GET /api/v1/accounts/me` uses the same enrolled-device boundary with the exact
`account:read` scope. It rechecks the account, device, proof key, certificate publication and
revocation inside the read transaction, and returns only the caller's bounded account Resource.
The HTTP ETag equals the stable strong body tag; responses disable caching and preserve
`email: null` for legacy Accounts without email. Stored email is returned exactly when valid;
missing or corrupt state and storage failures disclose no profile. Origin is optional for
native callers and must match the deployment exactly when supplied; GET bodies are rejected.
Profiles currently have no mutation endpoint, so both timestamps come from persisted identity
time. Profile mutation and email verification remain separate work.
`GET /api/v1/accounts/me/devices` uses the same exact `account:read` boundary and returns the
complete signed certificate and revocation snapshot for that account. Each artifact is at most
64 KiB, their combined decoded size is at most 4 MiB, and the JSON response is at most 6 MiB.
The read transaction rechecks caller admission and verifies every stored signature, account
binding and device-id uniqueness; inactive peer identity rows do not remove signed statements.
Missing key state, corrupt collections and capacity failures return a non-cacheable 503 without
partial data. The read accepts no body, query, `Idempotency-Key` or `If-Match`, and returns no ETag
or pagination fields. Names and platforms remain signed account claims. Remaining device
lifecycle mutations remain separate work. The protected Personal
sync subset above also uses these credentials; other control-plane APIs remain unmounted.

Server integration tests seed real signed legacy Account/Device artifacts directly into owned
SQLite and PostgreSQL fixtures, then exercise passkey setup, fresh Operator login, public
device challenge/token exchange, authenticated account-profile and device-statement reads,
Personal session/key reads, encrypted signed host write, download verification/decryption, and
durable ACK. They use the production API router and verify its deployment audit chain.
New Account registration, device admission and native desktop two-device acceptance remain
separate roadmap work.

PostgreSQL tests use `SCOPLEN_TEST_DATABASE_URL` for disposable databases. The device-token
keyring suite intentionally leaves a corrupt encrypted seed after checking fail-closed behavior.
Run Personal sync authentication and certified-signature limit tests in a separate database,
as CI does; both Personal suites use the same test deployment key and may share that database.
Operator HTTP quota fixtures set both the exhausted count and a fresh full window, clearing
failure cooldowns so quota-before-parsing assertions remain valid across minute boundaries.

The SQLite database is `scoplen.sqlite` in `server.data_dir`; migrations run before SQLite-backed
roles start, and a migration failure stops startup. Before a pooled SQLite connection becomes
available to another request, any remaining tracked transaction is rolled back; failed cleanup
discards the connection. A deterministic cancellation test covers SQLx's acknowledged custom-BEGIN
validation window, subsequent source admission and rollback failure. This separate cancellation
defect does not establish the cause of the unresolved native post-reopen refresh failure.
The server and local `splctl` mutations retain a shared lock on the private
`server.data_dir/deployment.lease` file through their process lifetime. An offline operation must
first obtain an exclusive lock, so stop every server and local mutation process before copying
deployment state. Do not delete or replace the lease file to bypass an occupied lock. On shutdown,
the server fences notification connections and allows up to 10 seconds for requests, role tasks and
database pools to drain. If that deadline expires, it cancels remaining tasks and reports a fatal
error while retaining the lease until the host process exits. A caller embedding the server library
must exit its process after this error before attempting an offline operation. A raw SQLx pool
obtained outside the server's admission path does not participate in this lease protocol.
API, edge, and worker roles may instead use
PostgreSQL by setting `storage.backend = "postgres"` and `storage.database_url` (or
`SPL_STORAGE_DATABASE_URL`). Object storage is initialized alongside the database for
database-backed roles. The default `storage.object.backend = "filesystem"` stores below
`server.data_dir/objects`; an S3-compatible backend can be selected with the nested S3 settings
in `spl-server.example.toml` or their `SPL_STORAGE_OBJECT_*` environment overrides. `/readyz`
checks both the database and the configured object-storage backend.
Set the three `[sync]` cardinality values in `spl-server.example.toml` or override them with
`SPL_SYNC_MAX_OBJECTS_PER_VAULT`, `SPL_SYNC_MAX_SHARED_VAULTS_PER_ACCOUNT`, and
`SPL_SYNC_MAX_MEMBERS_PER_SHARED_VAULT`. Values must be positive; object and account limits must fit
SQLite's signed count range, and the member limit must be at most 1,000.
Set `sync.write_requests_per_second` and `sync.write_burst` in the same file, or use
`SPL_SYNC_WRITE_REQUESTS_PER_SECOND` and `SPL_SYNC_WRITE_BURST`. Both values must be positive. The
mounted Personal sync router uses the validated write-rate settings across independent API
instances and restarts sharing the database, on plain HTTP, configured-certificate TLS and
ACME TLS listeners. Each authorized object POST charges one attempt in a short transaction
before collecting its body; malformed, oversized or conflicting requests do not refund it.
Reads, ACKs and key operations are independent. Replicas must use the same rate/burst settings.
After changing configuration, a stored bucket refills under its old policy before the new
policy can take effect; pending transitions return retryable `503 sync.storage_unavailable`.
Database time is sampled after the device lock. Integer fractional balances preserve the
complete positive unsigned range; native clocks have millisecond SQLite and microsecond
PostgreSQL precision, so a configured rate is a ceiling rather than guaranteed throughput.
Backward time grants no refill; an exhausted response's `Retry-After` includes a future origin.
At most 16 indexed retirement candidates are examined per admission. Only fully refilled state
with another 60 seconds of inactivity can retire, and deletion retains a monotonic clock
watermark in the same transaction so rollback of database time cannot recreate early refill.
Admission storage/clock/state errors, including a counter COMMIT with an unconfirmed result,
return `503 sync.storage_unavailable`, `changed: false`, `retryable: true`: no object write
has been dispatched. The server does not automatically repeat admission. Upgrade all API
replicas before relying on durable enforcement; older binaries still have process-local buckets.
Set `sync.max_envelope_bytes`, `sync.max_batch_objects`, and `sync.max_batch_bytes` in the same file,
or use `SPL_SYNC_MAX_ENVELOPE_BYTES`, `SPL_SYNC_MAX_BATCH_OBJECTS`, and
`SPL_SYNC_MAX_BATCH_BYTES`. Each must be positive and fit the platform; limits may be raised or
lowered from the defaults of 266,240 bytes, 500 objects, and 4,194,304 encoded bytes respectively.
The checked assignment bound `9 + 29 * max_batch_objects` must also fit. The same deployment
limits govern the HTTP request, durable SQLite/PostgreSQL admission, complete ordered receipts,
and request-bound conflicts. Batch bytes include the complete CBOR request, not just payloads.
The complete conflict cap remains 128 MiB; an unencodable conflict returns
`503 sync.storage_unavailable` with no partial results or object mutations.

Read budgets are separate: `sync.max_read_envelope_bytes` and `sync.max_read_body_bytes`, or
`SPL_SYNC_MAX_READ_ENVELOPE_BYTES` and `SPL_SYNC_MAX_READ_BODY_BYTES`. Their defaults are 266,240
payload bytes and 266,295,039 complete encoded response bytes. Select adequate read budgets when
raising write limits, and retain them when lowering write limits so previously stored objects
and history remain readable. Changes and snapshots return the longest eligible prefix that fits
the budgets, with `more = true` and the last returned sequence as the cursor when shortened. If
the first entry cannot fit, or complete unpaged history cannot fit, the read returns
`503 sync.storage_unavailable`; it does not expire a cursor or advance stored state. Exact size
checks precede response encoding and payload copies. The production reader first loads at most
1,001 metadata rows, including the pagination lookahead, validates the entire requested source
page and selects its prefix using exact CBOR sizes. Only approved payload rows then enter Rust,
through a sequence- and length-guarded query in the same database snapshot. Version history first
checks all retained metadata and its complete encoded size, then loads all approved payloads or
fails before a payload query. Complete history remains at most 21 entries. The internal raw
storage primitives retain their storage-only semantics; HTTP exclusively uses explicit bounded
reads. Key and notification limits remain independent.

The configurable-limit forward migration preserves current objects, retained versions, epochs,
signers, timestamps, foreign keys, uniqueness and indexes while moving the envelope upper bound
into validated storage admission. SQLite rebuilds the two leaf tables inside the migration
transaction; allow temporary disk space for the copy. Before the first pending migration on an
existing SQLite schema, startup creates a consistent standalone snapshot, including committed
WAL pages, in `scoplen.sqlite.migration-snapshots/` beside the database. It verifies SQLite and
foreign-key integrity before publishing a private `pre-migration-<UUIDv7>.sqlite` file and keeps
the three newest completed snapshots. Ordering stays monotonic against retained snapshot ids
after a clock rollback. Fresh empty databases and already-current databases create
no snapshot. Failed snapshot creation, verification, or retention blocks migration. A persistent
`scoplen.sqlite.migration.lock` serializes startup; leave that file in place.
Another startup waits up to five seconds for the lock, then stops without applying migrations
if it is still held. Let the active startup finish before retrying.

Each failed migration rolls back its own transaction and prevents startup; earlier migrations
from the same startup may already have committed. The snapshot retains the schema before any of
those steps. There is no automatic downgrade or replacement of the live database. Recovery uses
an offline copy of the snapshot, the matching old server image, and the unchanged deployment
keys and local objects; stop every writer before recovery and never reuse newer WAL/SHM files
with an older database. Retention only removes recognized completed snapshots beyond the newest
three. Unrecognized files and interrupted `.partial` files remain for operator inspection.
Unix snapshot directories/files are created with mode 0700/0600; Windows inherits the admitted
private data-directory ACL and refuses unsafe existing snapshot ACLs at startup.

## Security

See [SECURITY.md](SECURITY.md). The SQLite database, generated deployment keys, CA keys, and setup
links are private deployment material; keep the data directory out of source control and unprotected
backups. Copying only `scoplen.sqlite` while the server is running is not a consistent backup in WAL
mode. Upgrade snapshots contain database material and need the same protection. They do not
include object files, deployment/CA/audit keys, external key paths, or certificates. Preserve a
consistent complete deployment backup before upgrading. Single-archive encrypted backup,
scheduled backup and `splctl backup` recovery remain roadmap work.
