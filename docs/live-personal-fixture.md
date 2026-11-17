# Disposable public Personal HTTPS fixture

## Purpose and boundary

`personal_live_bootstrap` prepares an independent integration deployment from a clean server
checkout. It uses the production `spl-server` binary, real localhost HTTPS, the maintained
software passkey authenticator already used in server tests, and only public Operator
setup/login/logout APIs and verifies the eight retired invitation/enrollment/pairing API routes
and the old `/pair` landing return 404. The separate `verify-account` command exercises real
Account password entry and encrypted synchronization using two independently generated Devices.
The separate `prepare-browser-accounts` command registers two disposable password Accounts
and exports private password files for browser team acceptance. None of these commands seeds
identity tables, opens SQL connections, manages a server process,
creates/drops a PostgreSQL database, or installs a CA
in the operating system. Physical passkeys and browser interaction require separate coverage.

Build both programs from this checkout; old cached example binaries are not a substitute:

```text
cargo build --locked -p scoplen-server --bin spl-server --example personal_live_bootstrap
cargo test --locked -p scoplen-server --example personal_live_bootstrap
```

The examples below use the default `target` directory. If `CARGO_TARGET_DIR` is set, use its
`debug` directory instead. Unset all `SPL_*` variables before preparing **and starting** the
fixture: production environment overrides must not redirect it to another listener/database.

The fixture directory must be new, outside every Git checkout, below an existing private
parent. On Unix the helper creates it with `0700` and each file with `0600`. On Windows, files
inherit the parent's ACL; choose a parent limited to your Windows account before proceeding.
The helper does not restrict or validate Windows ACLs. Never use a shared directory or a real
deployment, passkey, account or database. TLS roots stay local to each test consumer.

On Windows, preparation records ordinary absolute local-drive paths after canonicalizing the
existing parent and confirming that removing Rust's verbatim drive prefix preserves the resolved
directory. Bootstrap uses the same normalization and compares every configured
fixture path exactly. UNC and device paths are rejected. Production Windows path and ACL
admission still applies unchanged; preparation does not admit an existing data directory or
repair its permissions.

## Windows PowerShell

Run these commands from the server checkout. Select an unused port; if another process wins
the port between preparation and startup, stop this attempt and prepare a new fixture.

```powershell
$fixtureParent = Join-Path $env:LOCALAPPDATA ('Scoplen-fixture-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixtureParent | Out-Null
$fixtureOwner = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$fixtureAcl = Get-Acl -LiteralPath $fixtureParent
$fixtureAcl.SetAccessRuleProtection($true, $false)
$fixtureAcl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
  $fixtureOwner, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
Set-Acl -LiteralPath $fixtureParent -AclObject $fixtureAcl
$fixture = Join-Path $fixtureParent 'personal'
$helper = (Resolve-Path 'target/debug/examples/personal_live_bootstrap.exe').Path
$server = (Resolve-Path 'target/debug/spl-server.exe').Path
$port = 18443
& $helper prepare $fixture --port $port
if ($LASTEXITCODE -ne 0) { throw 'Fixture preparation failed' }

$serverProcess = Start-Process -FilePath $server -WindowStyle Hidden -PassThru `
  -ArgumentList @('--config', ('"{0}"' -f (Join-Path $fixture 'server.toml'))) `
  -RedirectStandardOutput (Join-Path $fixture 'server.log') `
  -RedirectStandardError (Join-Path $fixture 'server-error.log')
try {
  $ready = $false
  for ($attempt = 0; $attempt -lt 50; $attempt++) {
    & curl.exe --silent --fail --max-time 1 --noproxy '*' --ssl-revoke-best-effort `
      --cacert (Join-Path $fixture 'ca.pem') `
      "https://localhost:$port/readyz" *> $null
    if ($LASTEXITCODE -eq 0) { $ready = $true; break }
    if ($serverProcess.HasExited) { throw 'Disposable server exited; inspect private diagnostics' }
    Start-Sleep -Milliseconds 200
  }
  if (-not $ready) { throw 'Disposable HTTPS server did not become ready' }
  & $helper bootstrap $fixture
  if ($LASTEXITCODE -ne 0) { throw 'Public bootstrap failed; discard this fixture' }
} catch {
  if (-not $serverProcess.HasExited) { Stop-Process -Id $serverProcess.Id }
  throw
}
```

Keep `$serverProcess` while the independent consumer uses `$fixture/descriptor.json`.
Schannel's `--ssl-revoke-best-effort` permits this disposable CA's absent CRL distribution
points; CA, hostname and known revocation verification remain enabled. Never use `--insecure`.
When the consumer finishes, stop only this owned process:

```powershell
if (-not $serverProcess.HasExited) { Stop-Process -Id $serverProcess.Id }
$serverProcess.WaitForExit()
```

After its process and database connections close, remove only the fixture directory stored in
`$fixture`. Retain any failure diagnostics only in private storage until the issue is resolved.

## Linux or macOS shell

The parent made by `mktemp` is private. The helper requires the child to be absent. Keep the
shell alive while the consumer runs so its exit trap can stop the owned server.

```sh
set -eu
umask 077
fixture_parent="$(mktemp -d)"
fixture="$fixture_parent/personal"
helper=target/debug/examples/personal_live_bootstrap
server=target/debug/spl-server
"$helper" prepare "$fixture" --port 18443
"$server" --config "$fixture/server.toml" >"$fixture/server.log" 2>"$fixture/server-error.log" &
server_pid=$!
trap 'kill "$server_pid" 2>/dev/null; wait "$server_pid" 2>/dev/null' EXIT INT TERM
ready=false
for attempt in $(seq 1 50); do
  if curl --silent --fail --max-time 1 --noproxy '*' --cacert "$fixture/ca.pem" \
    https://localhost:18443/readyz >/dev/null 2>&1; then ready=true; break; fi
  sleep 0.2
done
test "$ready" = true && "$helper" bootstrap "$fixture"
```

Stop the owned server before removing that fixture and its private parent. On any nonzero
exit, abandon this fixture; do not proceed to a consumer or retry bootstrap automatically.

## PostgreSQL

The caller provisions a new empty disposable database and owns its credentials, process,
connections and eventual deletion. Use a loopback URL with a database name beginning
`scoplen_fixture_`, followed only by lowercase ASCII letters, digits or underscores. URL query
parameters and fragments are rejected so connection options cannot redirect the database.
Do not reuse a database from an earlier run. The helper checks the URL boundary, but does not
connect to check emptiness; the production server performs its normal migrations on startup.

In a separate private file outside the fixture and repository, supply exactly this JSON field,
using credentials provisioned for your disposable database:

```json
{"database_url":"postgres://fixture:synthetic-password@127.0.0.1:5432/scoplen_fixture_example"}
```

The example value is synthetic. Protect the actual input file with the same permissions as the
fixture. Pass its path during preparation:

```text
personal_live_bootstrap prepare <new-fixture-directory> --postgres-config <private-json-file> --port 18443
```

Startup and bootstrap are otherwise identical to SQLite. `server.toml` contains the private
connection URL and must never be printed, committed or uploaded. After stopping the owned
server and all consumers, the caller removes only their disposable database and private inputs.
The helper never carries database administrator privileges or drops data.

## Browser Account preparation

Before starting the prepared server, place the production console's built assets in the
fixture's `unused-console` directory and set `[organizations] allow_creation = true` in
its private `server.toml`. Keep its listener, TLS and data paths unchanged. This lets browser
acceptance create the team itself through the public API, independently of fixture preparation.

Against that running owned server, execute once:

```text
personal_live_bootstrap prepare-browser-accounts <fixture-directory> --server-pid <owned-server-pid>
```

It uses public password registration for two independent Accounts and publishes
`browser-accounts.json` only after both registrations and both private password files are
confirmed. The descriptor contains the trusted origin, absolute CA/config paths, the controller's
server process id, `owner_username`, `member_username`, `owner_password_file` and
`member_password_file`, plus `disposable: true`. Password files contain exact UTF-8 bytes with
no newline. Stdout gives only the result and descriptor path. Protect all three files and never
print or commit their contents.

This descriptor contains no team or asset ids: the browser must create those through the shipped
console. It does not claim browser login or team acceptance succeeded. The command exclusively
creates `browser-accounts.started` before its first request; after any failure, abandon the
owned fixture instead of repeating a possibly committed registration. These Accounts and
their initial Devices share the fixture's disposable lifecycle.

## Organization audit acceptance

Build the server and example from the same current checkout. Prepare a fresh fixture with
only the default `api` role, enable `[organizations] allow_creation = true` in its private
`server.toml` before startup, and complete `bootstrap` as above. Run once:

```text
personal_live_bootstrap verify-audit <fixture-directory>
```

Run this flow independently with SQLite and a new owned PostgreSQL database. It registers two
password Accounts through public HTTPS, authenticates and refreshes their genuine Devices,
and signs into independent Account-browser families with separately generated proof keys.
Each Account creates a team; a named invitation and browser acceptance establish the second
Account's membership in the first team. All business mutations use public APIs, without SQL
identity seeds, forged tokens or direct audit inserts.

The check exercises both audit GET routes with both credential profiles. Owner and Security
auditor can read; Member, Administrator and Approver receive no implicit permit. Original
credentials remain in use across role changes, an explicit Account policy permit, policy
disable/enable, membership suspension/reactivation and removal. A custom permit never bypasses
current membership or tenant isolation. The other Account's independent team stays usable.
Foreign, absent and inactive-member reads return the common bounded 404 problem.

Real team creation/name, invitation, member, Host and policy mutations produce the history.
The consumer checks recorded Device and browser-family attribution, including the same browser
family across a real refresh and the accepting Account's retained actor after member removal.
It compares every filter dimension, both time boundaries and the complete AND combination
against captured history. Small pages exercise descending cursor continuation and exact
sequence/hash relationships; Device/browser and subsequent reads must preserve the same
immutable projections. Bodies and headers use a dedicated reader: Page 1 MiB, Verification
and problems 4 KiB, with request binding, no-store/no-cache, request id, no ETag and no cookie
changes. The pre-existing bootstrap and Account readers retain their original bounds.

Genesis, a later range with its immediate predecessor, and adjacent range joining are checked
against those captured hashes. The API-only fixture deliberately has no checkpoint worker:
successful results must honestly identify the whole selected interval as uncheckpointed.
This flow does not establish checkpoint signatures, corruption/large-byte boundaries, original
database-byte preservation, legacy scope upgrades, CA/KRL behavior, restart/backup recovery or
rendered Console acceptance. Those require their independent suites; no synthetic historical
attribution substitutes for genuine producers here.

`audit-check.started` is created exclusively before the first request. Any failure abandons
the fixture rather than retrying possibly committed mutations. Only complete success writes
`audit-acceptance.json` with exactly these content-free fields, all `true`:

```json
{"audit_device_browser_https_verified":true,"audit_current_authority_verified":true,"audit_filter_pagination_verified":true,"audit_unsigned_ranges_verified":true}
```

No Account password, Device/browser key, access token, refresh cookie or event body is printed
or exported. The command does not start/stop services, create/drop databases, install system
trust roots or change the original integration descriptor. Its caller retains responsibility
for the existing private diagnostics and exact owned-resource cleanup.

## Named-member Host Grant HTTPS acceptance

Build the server and example from the same current checkout. Prepare a new private fixture
with only the default `api` role, set `[organizations] allow_creation = true` before startup,
and complete `bootstrap`. Against the running owned server, execute once:

```text
personal_live_bootstrap verify-grants <fixture-directory>
```

Run independently on SQLite and a new disposable PostgreSQL database. Three random password
Accounts register through public HTTPS and authenticate/refresh genuine Devices; separate
Account-browser families use independently generated proof keys. Two teams, named invitations,
Host/HostGroup inventory, visibility policies and local user CAs are created through public APIs.
The driver does not seed SQL, forge tokens, reset admission debt or retry mutations. Its twenty
certificate requests and bounded per-Account management attempts retain production rate limits.

The first member can independently read a Host but initially cannot connect. Browser Grant
management enables Device certificate issuance. The consumer verifies the subject, signature,
exact trusted CA, Account/Device key id, scoped principals, current validity and effective
expiry: a ten-minute Grant, the later of two
applicable Grants, and the earliest cap across two Hosts. Host Grants deny HostGroup issuance.
Exact certificate confirmation retains original bytes. Ordinary policy permission retains
the normal thirty-minute lifetime while finite Grants remain active; an explicit forbid
also denies receipt confirmation. Those test policies are then removed before checking
that Grant withdrawal denies issuance.

Device and browser Grant reads agree, including ascending cursor pagination. Browser refresh
preserves creation-receipt ownership; another login family cannot confirm it. Replacement,
equal-field no-op, stale ETags, current authority before protected preconditions, withdrawal
and historical creation confirmation are checked. Confirmation after withdrawal preserves
the original response while current GET/list remain absent and issuance is denied.

The second team checks future, expired, nonexpiring and replaced finite intervals, exact
remote-user denial, foreign reads/references and cross-team used-id rejection. After removing
the independent policy reference, current, future and expired unwithdrawn Grants each block
Host deletion; withdrawal permits deletion and historical confirmation cannot restore it.
Membership suspension and removal withdraw Grants. Restore does not revive them; a fresh
Grant is required. Original Device credentials remain in use throughout, and both independent
encrypted Personal Host uploads still verify and decrypt after these team transitions.

`grants-check.started` is created exclusively before the first request. Any failure or
interruption abandons the fixture rather than repeating possibly committed business. The
complete flow has a six-minute deadline; each HTTPS request retains its fifteen-second bound.
Only full success creates `grants-acceptance.json` with exactly these content-free fields:

```json
{"grant_device_browser_https_verified":true,"grant_certificate_expiry_verified":true,"grant_lifecycle_tenant_verified":true,"grant_personal_sync_preserved":true}
```

No password, private key, token, cookie, identifier or certificate is exported by this check.
The command neither starts/stops services nor changes the original consumer descriptor.
This is HTTPS evidence only: an independent existing client must still complete actual SSH
and binary SFTP against an owned target. Rendered/native interaction, immediate withdrawal
of disclosed certificates, existing-session termination and the complete integration gate
remain independent acceptance work.

## Independent Grant client handoff

Use a separate fresh HTTPS fixture on each database, with team creation enabled and
`bootstrap` completed as above. The independent client controller first supplies its existing
owned OpenSSH descriptor with exactly `disposable`, `container`, `owner` and `port`. Start one
long-lived producer against that running fixture:

```text
personal_live_bootstrap prepare-grant-client <fixture-directory> --openssh-descriptor <owned-openssh-descriptor>
```

Before registering Accounts or creating assets, the producer inspects the existing
`scoplen-team-ssh-*` container. It requires a UUID ownership value matching the
`com.scoplen.fixture` label, running state and exactly one `2222/tcp` binding at
`127.0.0.1:<descriptor.port>`. It neither creates nor configures an SSH target. Inspection has
a fifteen-second deadline, captures bounded output and does not print it.

Two random password Accounts register through public HTTPS and sign in as genuine
Account-browser families. Through public APIs the producer creates one team, named Member
invitation, local user CA, loopback Host and Login. CA setup uses the owner's genuinely
authenticated Device, as required by that endpoint; team assets and Grants use browser
authority. The Login uses `smoke`, direct
route `0` and the Host's `default_profile`. One view policy permits the member to read both
Host and Login. No ordinary connect policy is created and no certificate is pre-issued.
The prepared Host and Login are read back unchanged through the member's browser session.

The producer keeps its owner browser credentials in memory and publishes three phases using
the same Account/team/Host/Login/CA identities:

| Phase | Descriptor | Required independent result |
| --- | --- | --- |
| Before any Grant | `grant-client-before.json` | `issuance_denied`, explicit null cutoff |
| Finite Grant active | `grant-client-active.json` | `ssh_sftp`, cutoff exactly ten minutes after Grant creation time |
| Grant withdrawn | `grant-client-withdrawn.json` | `issuance_denied`, explicit null cutoff |

Every private descriptor is at most 8,192 bytes and has exactly these twelve fields:
`disposable`, `origin`, `ca_certificate`, `organization_id`, `host_id`, `profile_id`,
`owner_username`, `owner_password_file`, `member_username`, `member_password_file`,
`expected_outcome` and `certificate_not_after`. `disposable` is true; the origin retains the
prepared trusted loopback HTTPS boundary. CA and password paths are absolute. Password files
contain only the generated password bytes, without a newline. The active cutoff is a finite
whole Unix second; both denial phases contain explicit JSON null.

For each phase, the controller waits for `grant-client-<phase>.ready` containing `ready\n`
before reading the corresponding complete descriptor. It runs the existing independent
consumer once with a cold Store and a new Device. Denial must be the expected permission
failure; network, storage or fixture errors fail the check. Active success requires actual
SSH and binary SFTP plus inspection of the resulting cached certificate against the supplied
cutoff. The client performs normal Host-key review, target validation and automatic issuance;
it does not repair team assets, policies, Grants or the CA.

Only after that consumer reports one passed and zero failed checks with exit status zero may
the controller exclusively create `grant-client-<phase>.complete` with exactly `passed\n`.
The producer waits at most four minutes for each signal, refreshes its browser family before
creating or withdrawing the Grant, and advances only on the exact signal. The entire producer
has a fifteen-minute deadline. Its descriptors, ready markers, passwords and
`grant-client.started` marker are created exclusively. Any failure or interruption abandons
the fixture; never replay it or overwrite its files. No credential, identifier or certificate
is printed, and completion does not claim rendered/native acceptance or completion of the
integration gate. The caller owns all services, private diagnostics and exact resource cleanup.

## Independent access-request client handoff

Build the production server and example from the same current checkout. Prepare another new
private HTTPS fixture on each database, enable Account registration and team creation before
startup, and complete `bootstrap`. Use a new empty database and fresh owned OpenSSH target;
never reuse a previous attempt's Accounts, markers or descriptors. The OpenSSH descriptor and
ownership inspection use the same exact four-field profile as the Grant handoff above.
Against that running fixture, start the long-lived producer once:

```text
personal_live_bootstrap prepare-request-client <fixture-directory> --openssh-descriptor <owned-openssh-descriptor>
```

This is a terminal-driven public HTTPS and independent client-core/SSH acceptance flow. It
does not launch a desktop window or browser. The caller owns service startup, target setup,
private diagnostics and cleanup. The producer only inspects the existing owned target; it
neither starts nor configures it, installs system trust, nor opens the database.

The producer reuses genuine independent Owner/Member password registration, Device
authentication, browser families, named invitation, local user CA and visible Host/Login
preparation. The Login retains the exact `smoke` username, direct route `0` and Host default
profile. The Member receives only View for that Host/Login and the ordinary single-Host
RequestAccess rule. There is no connect policy, Grant or pre-issued SSH certificate. Public
Grant listing must confirm the initial empty set before any client phase is published.

Each private descriptor preserves all twelve original Grant descriptor fields unchanged and
adds exactly `request_id`, `request_duration_seconds` and `request_reason`, for fifteen fields
in total and the same complete 8,192-byte bound. The requested duration is 600 seconds; the
consumer must use the exact descriptor reason without normalization. `request_id` is explicit
null in `before`, then the same original canonical UUIDv7 in `active` and `withdrawn`.

| Phase | Descriptor | Required independent result |
| --- | --- | --- |
| Before application/approval | `request-client-before.json` | Definite team connect denial, exact-input check and explicit creation of the pending request; `issuance_denied` with null cutoff |
| Original request approved | `request-client-active.json` | Refresh the original request and explicitly connect; `ssh_sftp` with the actual approval-created Grant's finite cutoff |
| Approval-created Grant withdrawn | `request-client-withdrawn.json` | Original request history remains approved, but cold-Store/new-Device certificate issuance is denied; `issuance_denied` with null cutoff |

Wait for `request-client-<phase>.ready` containing exactly `ready\n` before reading the
corresponding descriptor. Run the independent consumer once per phase with its cold Store
and new Device, retaining the common Account/team/Host/Login/request identity. The consumer
owns request creation and normal certificate acquisition, Host-key review, actual SSH and
binary SFTP. It must not create or repair a Grant, asset, policy or CA, substitute a Login/user,
pre-issue a certificate, or treat historical approval as present authority.

The consumer itself exclusively creates `request-client-<phase>.complete`. Its contents are
one compact UTF-8 JSON object followed by exactly one LF, with these exact fields:

| Phase | Completion fields and values |
| --- | --- |
| `before` | `request_id`: actual canonical UUIDv7; `host_id`: descriptor Host; `remote_user`: `"smoke"`; `duration_seconds`: 600; `status`: `"pending"` |
| `active` | `request_id`: original request; `status`: `"approved"`; `ssh_sftp`: true |
| `withdrawn` | `request_id`: original request; `status`: `"approved"`; `issuance_denied`: true |

There is no reason field in completion evidence and no separate `.complete.json` file.
Unknown, duplicate or missing fields, changed identities/input, wrong statuses and false
evidence fail the handoff. The producer waits for the final LF before decoding a possibly
partial write. The controller must independently confirm exactly one passed consumer check,
zero failed/ignored checks and exit status zero; it must never synthesize, replace or overwrite
the consumer's completion file. The existing Grant mode still uses its original twelve-field
descriptors and controller-created `passed\n` completion signal.

After `before`, the producer refreshes its genuine Owner browser family, lists the currently
routed approvals and GETs the original request. It requires exactly one pending request with
the original Member Account/Membership and exact Host, username, duration and reason. Only
then does it explicitly approve through the public request decision API with the original
ETag and a fresh operation key. Approval itself must create the unique finite Grant; the
producer never separately creates one. A current public Grant read/list must match the
original Membership/Host/user and approved interval before the active cutoff is published.

After active SSH/SFTP completion, the producer refreshes again, reads that same current Grant
and withdraws it through the ordinary conditional Grant API. It confirms the request's
approved history is unchanged and the Grant set is empty before publishing `withdrawn`.
Previously disclosed certificates and existing SSH sessions are not claimed to terminate.

Each phase has a four-minute deadline and the complete producer a fifteen-minute deadline.
Descriptors, ready markers, generated password files and `request-client.started` are created
exclusively. Any failure, interruption or unknown business outcome abandons this entire
fixture; never automatically replay mutations, replace an operation key/ETag, overwrite
handoff material or reuse the same Accounts. Retain failure evidence privately. Success does
not establish rendered/native interaction, the wider request failure matrix or the complete
integration gate; those require their separate checks.

## Descriptor, privacy and failures

After confirmed Operator setup, login, logout, eligible terminal logout confirmation and
retired-route absence, the helper publishes `descriptor.json`, at most 8192 bytes, with exactly
`disposable: true`, `origin: "https://localhost:<port>"`, `operator_lifecycle_verified: true`,
and `ca_certificate` (an absolute PEM path). It contains no Account invitation or Device
registration entitlement. This consumer descriptor is unchanged by the separate Account check.
Keep the descriptor private.

For the production-container acceptance check, run `personal_live_bootstrap verify-account
<fixture-directory>` once against the same running server. It registers a random password
Account through D-128, authenticates the first Device and writes an encrypted Host. A fresh
independent Device obtains password options, derives its credential, verifies/decrypts the
complete signed bootstrap and completes public Device admission. It authenticates and refreshes,
opens its own ARK and vault-key wraps, and verifies/decrypts the existing Host. Its signed edit is
then verified/decrypted by the original Device after native refresh. Neither Device's private
key is supplied to the other, and all server state changes use public HTTPS APIs.

The command writes `account-check.started` exclusively before its first request. Only a complete
successful flow writes the separate `account-acceptance.json` containing exactly
`{"account_password_sync_verified":true}`. It never upgrades or edits `descriptor.json`.
A failed or interrupted check cannot be retried; discard the caller-owned fixture and its
database. Its random Account, encrypted objects and keys have the same disposable lifecycle;
no credential is printed or exported. This check does not establish native desktop restart
behavior, physical passkey interaction or complete deployment backup/restore.

The production file-TLS listener supports TLS 1.3 and HTTP/2. Bootstrap requires TLS 1.3
and HTTP/2, validates `localhost` against only this fixture CA, bounds response headers and
bodies, uses a 15-second request deadline, and never follows redirects. It does not disable
certificate verification or rely on system trust or HTTP proxy configuration.

`server.log` contains the one-time first-start setup link. Redirect both server streams inside
the private directory before startup. For another private stdout filename, use
`bootstrap <directory> --server-log <private-file>`. The helper accepts one exact-origin setup
line; it never prints setup links, tokens, cookies, private keys or response bodies.
Its software passkey and proof key exist only for this process and are not exported.

`bootstrap.started` is created exclusively before any API call. A failed, interrupted or
uncertain attempt publishes no usable descriptor and cannot be replayed. Discard its deployment
and prepare a fresh one, since setup/login/logout may already have committed and the ephemeral
passkey is gone. No automatic reissue, identity deletion, SQL repair or application-state rollback
occurs. A prepare failure removes only the newly created fixture directory; a bootstrap failure
leaves the caller's process/database untouched for private diagnosis and caller-owned cleanup.
