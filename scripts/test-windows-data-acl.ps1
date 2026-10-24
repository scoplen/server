# SPDX-License-Identifier: AGPL-3.0-only
$ErrorActionPreference = 'Stop'
$powershell = Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
$script = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot '../crates/scoplen-server/src/private_material/windows-acl.ps1')
$parent = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\')
$run = [guid]::NewGuid().ToString('N')
$root = Join-Path $parent ('scoplen-windows-acl-test-' + $run)
[void][System.IO.Directory]::CreateDirectory($root)
[System.IO.File]::WriteAllText((Join-Path $root '.test-owner'), $run)
$junction = Join-Path $root 'redirected'
$dangling = Join-Path $root 'dangling.key'
$danglingCreated = $false

function Assert([bool] $condition, [string] $message) {
    if (-not $condition) { throw $message }
}

function Admission([string] $directory, [string[]] $files = @()) {
    $previous = $env:SCOPLEN_PRIVATE_DIRECTORY_INPUT
    try {
        $env:SCOPLEN_PRIVATE_DIRECTORY_INPUT = @{directory=$directory; files=$files} | ConvertTo-Json -Compress
        $output = @(& $powershell -NoLogo -NoProfile -NonInteractive -OutputFormat Text -Command $script 2>&1)
        $status = $LASTEXITCODE
        Assert ($output.Count -eq 0) 'permission helper disclosed output'
        return $status
    } finally {
        $env:SCOPLEN_PRIVATE_DIRECTORY_INPUT = $previous
    }
}

function Add-PublicRead([string] $path, [bool] $directory) {
    $security = if ($directory) { [System.IO.Directory]::GetAccessControl($path) } else { [System.IO.File]::GetAccessControl($path) }
    $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
        [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0'),
        [System.Security.AccessControl.FileSystemRights]::Read,
        [System.Security.AccessControl.AccessControlType]::Allow)
    $security.AddAccessRule($rule)
    if ($directory) { [System.IO.Directory]::SetAccessControl($path, $security) } else { [System.IO.File]::SetAccessControl($path, $security) }
}

function Security([string] $path, [bool] $directory) {
    $security = if ($directory) { [System.IO.Directory]::GetAccessControl($path) } else { [System.IO.File]::GetAccessControl($path) }
    return $security.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::All)
}

try {
    $parentSecurity = Security $root $true
    $private = Join-Path $root 'new/nested'
    $key = Join-Path $private 'synthetic.key'
    Assert ((Admission $private @($key)) -eq 0) 'new nested private directory was rejected'
    Assert ([System.IO.Directory]::GetAccessControl($private).AreAccessRulesProtected) 'new DACL inherited parent permissions'
    Assert ((Security $root $true) -eq $parentSecurity) 'creation changed existing parent permissions'
    [System.IO.File]::WriteAllText($key, 'synthetic material')
    $directorySecurity = Security $private $true
    $fileSecurity = Security $key $false
    Assert ((Admission $private @($key)) -eq 0) 'new file did not inherit a private DACL'
    Assert ((Security $private $true) -eq $directorySecurity) 'admission rewrote an existing directory'
    Assert ((Security $key $false) -eq $fileSecurity) 'admission rewrote an existing file'

    $broad = Join-Path $root 'broad'
    Assert ((Admission $broad) -eq 0) 'broad test preparation failed'
    Add-PublicRead $broad $true
    $broadSecurity = Security $broad $true
    Assert ((Admission $broad) -eq 2) 'a public directory was admitted'
    Assert ((Security $broad $true) -eq $broadSecurity) 'rejection repaired an existing directory'
    Assert ([System.IO.Directory]::GetFileSystemEntries($broad).Count -eq 0) 'rejection created material'

    Add-PublicRead $key $false
    $broadFileSecurity = Security $key $false
    Assert ((Admission $private @($key)) -eq 2) 'a public existing key was admitted'
    Assert ((Security $key $false) -eq $broadFileSecurity) 'rejection repaired an existing key'
    Assert ([System.IO.File]::ReadAllText($key) -eq 'synthetic material') 'rejection changed existing material'

    $externalKey = Join-Path $broad 'not-created.key'
    Assert ((Admission $private @($externalKey)) -eq 2) 'a public custom key parent was admitted'
    Assert (-not [System.IO.File]::Exists($externalKey)) 'custom-path rejection created material'
    $missingParent = Join-Path $root 'not-created/custom.key'
    Assert ((Admission $private @($missingParent)) -eq 2) 'a missing custom key parent was admitted'
    Assert (-not [System.IO.Directory]::Exists((Join-Path $root 'not-created'))) 'custom-path rejection created a parent'

    foreach ($unsupported in @($key + ':stream', '\\server.invalid\share\data', '\\?\' + $private, '\\.\NUL', (Join-Path $root 'NUL.key'), (Join-Path $root 'trailing.'), (Join-Path $root 'trailing '), (Join-Path $root ('COM' + [char]0xB9 + '.key')))) {
        Assert ((Admission $private @($unsupported)) -eq 2) 'a special Windows key path was admitted'
        Assert ((Admission $unsupported) -eq 2) 'a special Windows data path was admitted'
    }

    $driveRoots = @([System.IO.DriveInfo]::GetDrives() | ForEach-Object { $_.Name })
    $absentRoot = @(90..65 | ForEach-Object { [string][char]$_ + ':\' } | Where-Object { $driveRoots -notcontains $_ })[0]
    Assert ($null -ne $absentRoot) 'unavailable-drive test requires one unused drive letter'
    $unavailablePath = $absentRoot + 'scoplen-windows-acl-test-' + $run
    Assert ((Admission $absentRoot) -eq 2) 'an unavailable data-directory drive was admitted'
    Assert ((Admission $private @($unavailablePath)) -eq 2) 'an unavailable key drive was admitted'

    $nullAclFile = Join-Path $private 'null-acl.key'
    [System.IO.File]::WriteAllText($nullAclFile, 'synthetic material')
    $original = [System.IO.File]::GetAccessControl($nullAclFile)
    try {
        $nullAcl = [System.Security.AccessControl.FileSecurity]::new()
        $nullAcl.SetSecurityDescriptorSddlForm('D:NO_ACCESS_CONTROL', [System.Security.AccessControl.AccessControlSections]::Access)
        [System.IO.File]::SetAccessControl($nullAclFile, $nullAcl)
        Assert ((Admission $private @($nullAclFile)) -eq 2) 'a NULL DACL key was admitted'
    } finally {
        $restored = [System.Security.AccessControl.FileSecurity]::new()
        $restored.SetSecurityDescriptorSddlForm($original.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::Access), [System.Security.AccessControl.AccessControlSections]::Access)
        [System.IO.File]::SetAccessControl($nullAclFile, $restored)
    }

    [void](New-Item -ItemType Junction -Path $junction -Target $private)
    Assert ((Admission $junction) -eq 2) 'a reparse-point directory was admitted'
    Assert ((Admission (Join-Path $junction 'child')) -eq 2) 'a reparse-point ancestor was admitted'
    Assert (-not [System.IO.Directory]::Exists((Join-Path $private 'child'))) 'reparse rejection created a redirected directory'

    $danglingTarget = Join-Path $root 'removed-target'
    [void][System.IO.Directory]::CreateDirectory($danglingTarget)
    [void](New-Item -ItemType Junction -Path $dangling -Target $danglingTarget)
    $danglingCreated = $true
    [System.IO.Directory]::Delete($danglingTarget)
    Assert ((Admission $private @($dangling)) -eq 2) 'a dangling reparse key destination was admitted'
    Assert ((Admission $dangling) -eq 2) 'a dangling reparse directory was admitted'

    $literal = Join-Path $root "literal'; exit 41; '"
    Assert ((Admission $literal) -eq 0) 'path data was interpreted as PowerShell source'
    Assert ([System.IO.Directory]::Exists($literal)) 'literal path was not preserved'
    Assert ((Security $root $true) -eq $parentSecurity) 'tests changed existing parent permissions'
    Write-Output 'Windows ACL checks passed: private creation/inheritance, idempotence, unsafe directory/key/custom parent/NULL DACL refusal, missing parent/unavailable drive refusal, special Windows path/dangling reparse refusal and literal path handling.'
} finally {
    # Remove only this marked, exact test root; unlink its known junction before recursion.
    Assert ([System.IO.Path]::GetDirectoryName($root) -eq $parent) 'test cleanup parent changed'
    Assert ([System.IO.Path]::GetFileName($root) -eq ('scoplen-windows-acl-test-' + $run)) 'test cleanup name changed'
    Assert ([System.IO.File]::ReadAllText((Join-Path $root '.test-owner')) -eq $run) 'test cleanup ownership changed'
    if ([System.IO.Directory]::Exists($junction)) { [System.IO.Directory]::Delete($junction) }
    if ($danglingCreated) { [System.IO.Directory]::Delete($dangling) }
    [System.IO.Directory]::Delete($root, $true)
}
