# SPDX-License-Identifier: AGPL-3.0-only
# All caller paths are data in one environment value, never PowerShell source.
$ErrorActionPreference = 'Stop'
try {
    if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1) { exit 3 }
    $inputValue = ConvertFrom-Json -InputObject $env:SCOPLEN_PRIVATE_DIRECTORY_INPUT
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $trusted = @($identity.Value, 'S-1-5-18', 'S-1-5-32-544')
    $full = [int][System.Security.AccessControl.FileSystemRights]::FullControl
    $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'

    function Local-Path([string] $value) {
        # Extended/device/UNC names and ADS have different Win32 resolution semantics.
        if ($value -match '^[\\/]{2}' -or $value -match '^[A-Za-z]:($|[^\\/])') { exit 2 }
        foreach ($component in $value.Replace('/', '\').Split('\')) {
            if ($component.Length -eq 0 -or $component -eq '.' -or $component -eq '..' -or $component -match '^[A-Za-z]:$') { continue }
            if ($component.EndsWith('.') -or $component.EndsWith(' ') -or $component.IndexOfAny([System.IO.Path]::GetInvalidFileNameChars()) -ge 0) { exit 2 }
        }
        try { $path = [System.IO.Path]::GetFullPath($value) } catch { exit 2 }
        if ($path -notmatch '^[A-Za-z]:\\' -or $path.Substring(2).Contains(':')) { exit 2 }
        try {
            # A mapped network drive also has drive-letter syntax.
            $drive = [System.IO.DriveInfo]::new([System.IO.Path]::GetPathRoot($path))
            if ($drive.DriveType -notin @([System.IO.DriveType]::Fixed, [System.IO.DriveType]::Removable, [System.IO.DriveType]::CDRom, [System.IO.DriveType]::Ram) -or -not $drive.IsReady) { exit 2 }
        } catch { exit 2 }
        foreach ($component in $path.Substring(3).Split('\')) {
            if ($component.Length -eq 0) { continue }
            if ($component.EndsWith('.') -or $component.EndsWith(' ') -or $component.IndexOfAny([System.IO.Path]::GetInvalidFileNameChars()) -ge 0) { exit 2 }
            if ($component -match '^(CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|COM[1-9\u00b9\u00b2\u00b3]|LPT[1-9\u00b9\u00b2\u00b3])(\.|$)') { exit 2 }
        }
        return $path
    }

    function Attributes([string] $path) {
        try { return [System.IO.File]::GetAttributes($path) } catch {
            $cause = $_.Exception.GetBaseException()
            if ($cause -is [System.IO.FileNotFoundException] -or $cause -is [System.IO.DirectoryNotFoundException]) { return $null }
            exit 2
        }
    }

    function Assert-NoReparse([string] $path) {
        $current = [System.IO.DirectoryInfo]::new($path)
        while ($null -ne $current) {
            $attributes = Attributes $current.FullName
            if ($null -ne $attributes -and (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or ($attributes -band [System.IO.FileAttributes]::Directory) -eq 0)) { exit 2 }
            $current = $current.Parent
        }
    }

    function Assert-Private([string] $path, [bool] $directory) {
        $attributes = [System.IO.File]::GetAttributes($path)
        if (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { exit 2 }
        if ($directory -ne (($attributes -band [System.IO.FileAttributes]::Directory) -ne 0)) { exit 2 }
        $security = if ($directory) { [System.IO.Directory]::GetAccessControl($path) } else { [System.IO.File]::GetAccessControl($path) }
        if ($trusted -notcontains $security.GetOwner([System.Security.Principal.SecurityIdentifier]).Value) { exit 2 }
        $descriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new($security.GetSecurityDescriptorBinaryForm(), 0)
        if ($null -eq $descriptor.DiscretionaryAcl) { exit 2 }
        $ownRights = 0
        $childRights = 0
        foreach ($ace in $descriptor.DiscretionaryAcl) {
            # Conditional/object/deny ACEs are outside this deliberately narrow policy.
            if ($ace -isnot [System.Security.AccessControl.CommonAce] -or $ace.IsCallback -or $ace.AceType -ne [System.Security.AccessControl.AceType]::AccessAllowed) { exit 2 }
            if ($trusted -notcontains $ace.SecurityIdentifier.Value) { exit 2 }
            if ($ace.SecurityIdentifier.Value -eq $identity.Value -and (([int]$ace.AceFlags -band [int][System.Security.AccessControl.AceFlags]::InheritOnly) -eq 0)) {
                $ownRights = $ownRights -bor $ace.AccessMask
                if (([int]$ace.AceFlags -band 7) -eq 3) {
                    $childRights = $childRights -bor $ace.AccessMask
                }
            }
        }
        if (($ownRights -band $full) -ne $full -or ($directory -and ($childRights -band $full) -ne $full)) { exit 2 }
    }

    $root = Local-Path ([string]$inputValue.directory)
    Assert-NoReparse $root
    $missing = [System.Collections.Generic.List[string]]::new()
    $current = [System.IO.DirectoryInfo]::new($root)
    while (-not $current.Exists) {
        $missing.Add($current.FullName)
        $current = $current.Parent
        if ($null -eq $current) { exit 2 }
    }
    $security = [System.Security.AccessControl.DirectorySecurity]::new()
    $security.SetOwner($identity)
    $security.SetAccessRuleProtection($true, $false)
    foreach ($sid in $trusted) {
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            [System.Security.Principal.SecurityIdentifier]::new($sid),
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            $inherit,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow)
        $security.AddAccessRule($rule)
    }
    for ($index = $missing.Count - 1; $index -ge 0; $index--) {
        # The security descriptor is supplied to creation, before files or secrets exist.
        [void][System.IO.Directory]::CreateDirectory($missing[$index], $security)
        Assert-NoReparse $missing[$index]
        Assert-Private $missing[$index] $true
    }
    Assert-Private $root $true
    foreach ($file in $inputValue.files) {
        $path = Local-Path ([string]$file)
        $parent = [System.IO.Path]::GetDirectoryName($path)
        Assert-NoReparse $parent
        if ($null -eq (Attributes $parent)) { exit 2 }
        Assert-Private $parent $true
        if ($null -ne (Attributes $path)) { Assert-Private $path $false }
    }
    exit 0
} catch {
    # Never disclose exception text, ACLs, paths or caller input through child output.
    exit 3
}
