# Disposable public Personal HTTPS fixture

## Purpose and boundary

`personal_live_bootstrap` prepares an independent integration deployment from a clean server
checkout. It uses the production `spl-server` binary, real localhost HTTPS, the maintained
software passkey authenticator already used in server tests, and only public Operator
setup/login/logout APIs and verifies the eight retired invitation/enrollment/pairing API routes
and the old `/pair` landing return 404. The separate `verify-account` command exercises real
Account password entry and encrypted synchronization using two independently generated Devices.
Neither command seeds identity tables, opens SQL connections, manages a server process,
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
