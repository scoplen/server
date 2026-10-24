# Windows data-directory permissions

Windows server startup requires the OS Windows PowerShell 5.1 executable and .NET filesystem
access-control support. PowerShell 7 does not replace this dependency. The server starts the OS
executable directly, without a profile, interactive input, a visible window or PATH lookup.
The permission check has a 15-second deadline. Missing or restricted execution support stops
startup; there is no permission-check override.

Before opening or migrating a database, creating object storage, generating keys or issuing a
setup link, the server checks `server.data_dir`. The standalone bootstrap entry performs the
same admission. A missing directory is created with a protected DACL in the directory-creation
operation, granting inheritable full control only to the server account, Local System and
the built-in Administrators group. Missing components inside the configured path use the same
creation policy. Existing directories are inspected without changing their permissions.

The accepted existing DACL contains ordinary allow entries for only those three principals and
grants the server account full control, including inheritable full control for directories.
The owner must be one of those principals. NULL DACLs, other principals, deny/conditional/object
ACEs and reparse points in the selected directory or its ancestry are refused. This narrow
policy can reject an otherwise intentionally restricted custom ACL; provision the documented
policy rather than weakening or bypassing admission.

The selected paths must resolve to ordinary local-drive paths. DriveInfo must confirm a ready
local drive; mapped network drives and unavailable or unclassifiable roots are refused. UNC,
device/verbatim prefixes, alternate data streams, reserved DOS device names and trailing-dot/space
aliases are refused.
Attribute lookup checks existing destinations, including dangling reparse points; an ordinary
missing key is allowed only beneath an existing admitted parent.

Existing deployment, configured local KMS, audit-signing and internal-CA private-key files are
checked too. Their parents must satisfy directory admission. Configured external key parents
are never created or repaired by this check. Newly generated files inherit the private DACL;
exclusive creation still refuses to replace a destination. File creation or flush failure stops
startup and requires inspection of incomplete material.

The persistent `scoplen.sqlite.migration.lock` and `deployment.lease` files are admitted as
private material too. The server and local `splctl` mutations hold a shared deployment lease
through their process lifetime. An offline operation requires an exclusive lease; stop those
processes before copying deployment state, and do not delete or replace the file to bypass an
occupied lock. If server shutdown exceeds its 10-second graceful drain deadline, remaining tasks
are cancelled but the lease stays held until the host process exits. An embedding process must
exit after that error before attempting an offline operation.

Before storage startup, an existing `scoplen.sqlite.migration-snapshots` directory and every entry are
checked with the same native ACL policy without repair. New upgrade-snapshot directories and
files inherit the admitted data-directory DACL. A rejected recovery point must be inspected,
not deleted to bypass admission; see [the container operations notes](personal-container.md)
for snapshot retention and the separate complete-backup requirement.

For a new deployment, run under the intended server account, select a missing data directory
below a parent controlled by that account, and set `server.data_dir` or `SPL_SERVER_DATA_DIR`
to that path. The server creates the restricted directory before storing any deployment data.

For an existing directory rejected at startup:

1. Stop the deployment and back up the database and key material. Do not remove or regenerate
   existing keys to get past a permission failure.
2. Review that exact directory in Windows Properties, Security, Advanced. Set its owner to the
   server account, Local System or Administrators. Disable inheritance and remove inherited
   access for other principals. Grant the server account full control applying to this folder,
   subfolders and files; Local System and Administrators may retain the same access.
3. Review the deployment key, configured KMS and audit keys, internal CA private key, migration
   lock, deployment lease, and any migration-snapshot directory/files
   individually. Remove broad or unusual file permissions; a directory repair does not prove
   that an existing file has changed its DACL. Do not change unrelated parent permissions.
4. Ensure the intended server account can run Windows PowerShell 5.1 and use .NET filesystem
   access-control APIs. If the environment prohibits that runtime, provision a supported host
   rather than starting without permission admission. Retry startup after the review.

Parent-directory safety remains an operator responsibility. Untrusted users must not have
write, replacement or delete-child access on the data directory's parents. This admission does
not authenticate existing file contents, prevent an administrator from taking ownership or
repair exposure that happened before the permissions were corrected. It never changes ACLs
outside newly created components of the explicitly configured data directory.

Run the Windows-native boundary regression suite with:

```powershell
& "$env:SystemRoot/System32/WindowsPowerShell/v1.0/powershell.exe" -NoProfile -NonInteractive -File scripts/test-windows-data-acl.ps1
cargo test --locked -p scoplen-server --test windows_data_acl
```

The directory-creation behavior uses the .NET Framework
[`Directory.CreateDirectory(String, DirectorySecurity)`](<https://learn.microsoft.com/en-us/dotnet/api/system.io.directory.createdirectory?view=netframework-4.8.1#system-io-directory-createdirectory(system-string-system-security-accesscontrol-directorysecurity)>)
overload so access controls are supplied before secret bytes exist.
