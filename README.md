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
bounded version reads. It also exposes an atomic retention pass for the worker: historical rows are
version plus 20 retained versions, and acknowledged or expired tombstones advance the purge
horizon while deleting their retained history. The `scoplen-store` queue now persists opaque jobs
with bounded payloads, atomic claims, owner-checked leases, retry/failure state, and expired-lease
requeue; the `worker` role runs a 30-second heartbeat that requeues abandoned leases.
Standalone `ca` and `gateway` roles do not open a database or generate Personal setup material.
New bootstrap material uses exclusive file creation and, on Unix, owner read/write permissions
(`0600`). Existing files are preserved; an incomplete CA pair requires recovery from the
operator's backup. Windows inherits the data directory's access controls: the operator must
protect that directory before first startup. Bootstrap does not restrict or validate its Windows
ACL, so a directory that grants other users access also exposes generated secrets to them.
Existing deployments retain their current file permissions, which the operator must restrict
separately if needed.
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
remain unmounted. The
`scoplen-identity` crate verifies a decoded D-101 first-device
enrollment's K-4 account signature, K-2 device certificate, and origin-bound P-256 possession
proof. It returns a redacted, read-only verified value with the invitation-token digest and exact
canonical artifacts. `scoplen-store` now persists one-use, 24-hour Personal invitations and
atomically redeems a verified enrollment into a null-email account, active first device,
revision-one K-4 bundle, Personal vault, consumed invitation, and deployment audit event on
SQLite or PostgreSQL. Existing K-4 and vault identifiers are rejected without consuming the
invitation. The API listener mounts anonymous `POST /api/v1/auth/personal-enroll` with strict
JSON and artifact validation, configured-origin checks, device possession verification, durable
source and invitation-digest admission, failure auditing, and one-use redemption. It returns a
uniform denial for unknown, expired, consumed, or conflicting invitations. A lost commit
acknowledgement returns `auth.commit_outcome_unknown` so the client can retain its identity and
attempt device authentication. `POST /api/v1/admin/personal-invitations` issues one-use invitations
for current Operator sessions with the exact `personal-invitation:issue` scope, protected DPoP,
durable replay claims and the published Cedar policy. It rechecks and locks the current Operator,
credential and refresh family inside the issuance transaction. A separate SQLite/PostgreSQL
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
independent verifier and family store. Console integration and
control-plane authorization remain separate roadmap work. A dedicated Operator keyring uses
independent Ed25519 seeds, `operator-` key identifiers, and purpose-bound encrypted envelopes,
with the same audited 30-day rotation
and seven-day overlap. Public `GET /.well-known/operator-jwks.json` exposes only that keyring;
the device JWKS remains separate. Both routes return a non-cacheable 503 if key storage,
integrity, KMS validation, or a required audit write fails. Console integration and remaining
control-plane authorization remain roadmap work. All server proto dependencies
are pinned to `proto@22a83ad3` for shared authentication, Operator token, scope,
object-signature, complete account-device statement, D-114 pairing and notification scope lookup
contracts, D-115 account-key problem vectors and RUSTSEC-2026-0387 dependency fixes.
The server lock also resolves patched `crypto-bigint` 0.7.6 and `ctutils` 0.4.5;
published K-2 formats and shared public APIs remain unchanged.
The stores also provide independent durable pairing admission for each method/route:
30 mutation attempts or 120 reads per actual source, 30 mutations or 60 reads per verified
capability, and 30 mutations or 120 reads per current authenticated account per 60 seconds.
Denial cooldowns double from one to 300 seconds; authenticated success or ten minutes without
failure clears the streak while preserving window counts. Failure audit and denial updates
commit together; success clearing participates in its business transaction. Bounded cleanup
and source normalization apply on both databases.
The durable relay stores only a capability digest and seven ordered, role-specific opaque
slots. Five-minute expiry, bounded cleanup, a 1,000-live/10,000-retained session limit and a
256 MiB aggregate payload limit serialize across replicas. Cancellation and expiry erase
payloads immediately and retain terminal metadata until original expiry plus 24 hours.
Second-device completion rechecks current authorization and verifies the exact signed
certificate, complete next K-4 bundle, certified/unrevoked recipient set and context-bound
new-device acceptance in one transaction. It commits identity, keys, response-capacity checks,
payload erasure, a 24-hour receipt/fingerprint and deployment audit together. Exact completion
replay returns its retained receipt after current authorization, and never reactivates a later
revoked device. Unconfirmed commit outcomes disclose no receipt.
The API listener mounts all six `/api/v1/auth/pairings` operations with strict bounded JSON,
canonical session ids, native configured-origin checks and no-store/no-cache/no-referrer
responses. Creation is anonymous; the new role uses its verified session capability, and the
old role requires a current enrolled-device token, durable token-bound DPoP and exact
`keys:write`. Source admission precedes parsing; only verified roles select private quotas.
Failure-audit storage is fail-closed, and an uncertain business commit returns
`auth.commit_outcome_unknown` without a success body or capability. The public `/pair` page
only explains how to paste the full fragment-bearing link into Scoplen; it has no password
field, script or network action. Pairing routes reject cookies, mixed credentials, queries,
idempotency and conditional cache headers, and never publish credentialed CORS access.

The `scoplen-store` crate now provides a backend-neutral object
storage boundary with local filesystem and S3-compatible implementations, including bounded key
validation and streaming/multipart operations; database-backed roles initialize the configured
backend and include it in `/readyz`. Complete control-plane policy filtering,
membership-aware purge orchestration, organization vault ownership in session listings, higher wire ceilings and
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
per-device write rates in a process-local token bucket and advertises those same values in the
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
settings. Other route body limits and multi-instance rate admission remain roadmap work.
The SQLite and PostgreSQL stores atomically provision one personal vault per account with an opaque
ARK-wrapped initial key. Both scope personal-key reads to the owner and list the account's personal
vault and current shared memberships. The authenticated K-4 vault-key route delivers that key only
to its owner using the shared `{keys}` response shape on either backend. Personal enrollment and
device authentication use these primitives; Personal vault-key rotation remains open.
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
audit event together. It serializes with pairing completion and account identity/statement changes.
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
`web/console` is the React and strict TypeScript Personal console. `deploy/` and `docs/`
hold deployment and operational material as those roadmap gates become implementable.

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
setup/login/invitation against the production server. SQLite is the default; PostgreSQL takes
a private disposable-database configuration. The caller owns the server process and database.

The maintained WebAuthn verifier builds vendored OpenSSL. Install Perl and a native C toolchain
before running Cargo: MSVC Build Tools and Strawberry Perl on Windows, Xcode Command Line Tools
on macOS, or the usual C compiler, Make and Perl packages on Linux. Put `perl` on `PATH` (the
Strawberry default is `C:\Strawberry\perl\bin`). NASM is optional on Windows; the vendored build
automatically disables assembly when NASM is unavailable.

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
An IP-literal origin remains usable for devices after initial operator setup has completed.
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
restart passkey login with a fresh ceremony. The Personal console implements first-passkey setup,
fresh discoverable sign-in, and authenticated Personal invitation requests through these public
APIs. It scrubs the setup fragment immediately, keeps its non-extractable P-256 proof key and
access token only in memory, and never exports private key material. Reloading requires passkey
login; it does not try an old refresh cookie with a new proof key. Refresh is serialized using
Web Locks. Unknown setup outcomes retain the passkey and offer sign-in; unknown login/refresh
outcomes restart login; an unknown invitation outcome requires an explicit new invitation and
cannot recover the earlier URL. Lock this tab clears its in-memory sign-in; it does not revoke
the server session. The Personal enrollment route
requires an already issued invitation and no existing session or cookie. It rejects
`Authorization`, `DPoP`, and `Idempotency-Key` headers. It
admits at most 30 attempts per peer address and five attempts per decoded invitation digest in
each fixed 60-second window, with a bounded cooldown after an admitted denial. These counters
are shared through the configured SQLite or PostgreSQL database. A reverse proxy without a
verified peer-address resolver causes callers to share the proxy's address quota. The current
invitation-issuance route accepts exactly `{}` as JSON (at most 256 bytes), rejects query strings
and idempotency headers, and requires any supplied Origin to match the configured trusted origin.
Its independent durable quotas allow 30 requests per source and ten per authenticated Operator
in each fixed 60-second window. Device credentials and Operator tokens without the required
scope receive `policy.denied`; revoked sessions cannot issue. The one-time invitation URL and
expiry are returned only after the invitation and mandatory deployment audit commit. An
unconfirmed commit returns `auth.commit_outcome_unknown` with `changed: true` and
`retryable: false`, without a URL or cookie. Its URL cannot be recovered: an Operator must
explicitly decide whether to issue another invitation. Successes and failures are non-cacheable
and use `Referrer-Policy: no-referrer`.
Enrolled devices can request a 120-second challenge, sign it with their registered P-256 key,
and receive a ten-minute DPoP-bound access token and a single-use refresh credential. The API
listener returns no-store JSON and RFC 9457 problems. Device and refresh admission is durable
across API instances; a verified spent-token reuse revokes its 30-day family. A refresh response
whose commit cannot be confirmed requires a new device challenge instead of retrying the old
credential. `GET /.well-known/jwks.json` publishes only the active and unexpired overlap public
token keys. `GET /api/v1/accounts/me` uses the same enrolled-device boundary with the exact
`account:read` scope. It rechecks the account, device, proof key, certificate publication and
revocation inside the read transaction, and returns only the caller's bounded account Resource.
The HTTP ETag equals the stable strong body tag; responses disable caching and preserve
`email: null` for invitation-created accounts. Stored email is returned exactly when valid;
missing or corrupt state and storage failures disclose no profile. Origin is optional for
native callers and must match the deployment exactly when supplied; GET bodies are rejected.
Profiles currently have no mutation endpoint, so both timestamps come from persisted enrollment
time. Profile mutation and email verification remain separate work.
`GET /api/v1/accounts/me/devices` uses the same exact `account:read` boundary and returns the
complete signed certificate and revocation snapshot for that account. Each artifact is at most
64 KiB, their combined decoded size is at most 4 MiB, and the JSON response is at most 6 MiB.
The read transaction rechecks caller admission and verifies every stored signature, account
binding and device-id uniqueness; inactive peer enrollment rows do not remove signed statements.
Missing key state, corrupt collections and capacity failures return a non-cacheable 503 without
partial data. The read accepts no body, query, `Idempotency-Key` or `If-Match`, and returns no ETag
or pagination fields. Names and platforms remain signed account claims. Device admission,
revocation mutations and additional-device enrollment remain separate work. The protected Personal
sync subset above also uses these credentials; other control-plane APIs remain unmounted.

Server integration tests exercise the complete public Personal path on SQLite and PostgreSQL:
passkey setup, fresh Operator login, invitation issuance, signed first-device enrollment,
device challenge/token exchange, authenticated account-profile and device-statement reads,
Personal session/key reads, encrypted signed host write, download verification/decryption, and
durable ACK. They use the production API router and verify its deployment audit chain. Native
desktop and two-device acceptance remain separate roadmap work.

PostgreSQL tests use `SCOPLEN_TEST_DATABASE_URL` for disposable databases. The device-token
keyring suite intentionally leaves a corrupt encrypted seed after checking fail-closed behavior.
Run Personal sync authentication and certified-signature limit tests in a separate database,
as CI does; both Personal suites use the same test deployment key and may share that database.

The SQLite database is `scoplen.sqlite` in `server.data_dir`; migrations run before SQLite-backed
roles start, and a migration failure stops startup. API, edge, and worker roles may instead use
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
mounted Personal sync router uses the validated write-rate settings. Limits are enforced per
process until shared admission is implemented; connections share the same buckets on plain HTTP,
configured-certificate TLS, and ACME TLS listeners.
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
transaction; allow temporary disk space for the copy. Preserve a consistent deployment backup
before an upgrade. A failed migration rolls back and prevents startup; it does not partially
upgrade the tables. The migration has no automatic down path; rollback uses the pre-upgrade
backup and matching server version.

## Security

See [SECURITY.md](SECURITY.md). The SQLite database, generated deployment keys, CA keys, and setup
links are private deployment material; keep the data directory out of source control and unprotected
backups. Copying only `scoplen.sqlite` while the server is running is not a consistent backup in WAL
mode. Built-in backup and restore are still roadmap work.
