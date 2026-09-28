# redStackPRO: apply an AD ACL escalation chain (clean-room MIT). Each entry is
# principal -> target : right. Best-effort and idempotent-ish: a principal group
# the chain references but the directory does not have yet is created, a target
# that cannot be resolved is skipped rather than aborting the run, and every
# entry is wrapped so one bad ACE does not sink the rest. Majority-coverage by
# design.
param($AclsJson)
Import-Module ActiveDirectory
$ErrorActionPreference = "Stop"
$acls = $AclsJson | ConvertFrom-Json

# Pin every AD cmdlet at the local controller. Right after promotion the SRV
# records that locate a server lag, so the default discovery fails with "no
# default server with ADWS running"; localhost is up. The AD: provider drive is
# bound to whatever the module found at import, so a private drive is opened on
# localhost for the ACL get/set.
$PSDefaultParameterValues = @{ '*-AD*:Server' = 'localhost' }
New-PSDrive -Name ADL -PSProvider ActiveDirectory -Server localhost -Root "//RootDSE/" -Scope Script -ErrorAction SilentlyContinue | Out-Null

# Extended-right GUIDs the GOAD chain uses.
$extended = @{
    "Ext-User-Force-Change-Password" = [GUID]"00299570-246d-11d0-a768-00aa006e0529"
    "Ext-Self-Self-Membership"       = [GUID]"bf9679c0-0de6-11d0-a285-00aa003049e2"
    "Ext-Write-Self-Membership"      = [GUID]"bf9679c0-0de6-11d0-a285-00aa003049e2"
}
$plain = @{
    "GenericAll"     = [System.DirectoryServices.ActiveDirectoryRights]"GenericAll"
    "GenericWrite"   = [System.DirectoryServices.ActiveDirectoryRights]"GenericWrite"
    "WriteDacl"      = [System.DirectoryServices.ActiveDirectoryRights]"WriteDacl"
    "WriteOwner"     = [System.DirectoryServices.ActiveDirectoryRights]"WriteOwner"
    "GenericExecute" = [System.DirectoryServices.ActiveDirectoryRights]"GenericExecute"
    "ReadProperty"   = [System.DirectoryServices.ActiveDirectoryRights]"ReadProperty"
    "WriteProperty"  = [System.DirectoryServices.ActiveDirectoryRights]"WriteProperty"
    "Self"           = [System.DirectoryServices.ActiveDirectoryRights]"Self"
}
# Property-writes scoped to one attribute (WriteProperty + the attribute's
# schemaIDGUID). Targeted-kerberoast writes the servicePrincipalName of a victim
# so the attacker sets an SPN and roasts it.
$propWrite = @{
    "Ext-Write-SPN" = [GUID]"f3a64788-5306-11d1-a9c5-0000f80367c1"
}

function Resolve-TargetDn($name) {
    if ($name -match "^(CN|OU|DC)=") { return $name }
    $n = $name.TrimEnd('$')
    $o = Get-ADObject -Server localhost -Filter "sAMAccountName -eq '$n' -or name -eq '$n'" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($o) { return $o.DistinguishedName }
    return $null
}

function Resolve-PrincipalSid($name) {
    if ($name -match "\\") { return (New-Object System.Security.Principal.NTAccount($name)) }
    $n = $name.TrimEnd('$')
    $o = Get-ADObject -Server localhost -Filter "sAMAccountName -eq '$n' -or name -eq '$n'" -Properties objectSid -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $o) {
        $g = New-ADGroup -Server localhost -Name $n -GroupScope Global -PassThru
        $o = Get-ADObject -Server localhost -Identity $g.DistinguishedName -Properties objectSid
    }
    return (New-Object System.Security.Principal.SecurityIdentifier($o.objectSid))
}

# Pre-pass: make sure every principal and target the chain names exists before
# any ACE is applied, so an entry that references a group as a target before a
# later entry introduces it as a principal still resolves. A plain name becomes a
# global group; an OU distinguished name becomes an OU; users, computers, and
# built-in containers already exist.
function Confirm-Exists($name) {
    if ([string]::IsNullOrEmpty($name)) { return }
    if ($name -match "\\") { return }
    if ($name -match "^OU=") {
        if (-not (Get-ADObject -Server localhost -Filter "distinguishedName -eq '$name'" -ErrorAction SilentlyContinue)) {
            $leaf = ($name -split ",", 2)[0] -replace "^OU=", ""
            $parent = ($name -split ",", 2)[1]
            New-ADOrganizationalUnit -Server localhost -Name $leaf -Path $parent -ProtectedFromAccidentalDeletion $false -ErrorAction SilentlyContinue
        }
        return
    }
    if ($name -match "^(CN|DC)=") { return }
    if ($name.EndsWith('$')) { return }
    $n = $name.TrimEnd('$')
    if (-not (Get-ADObject -Server localhost -Filter "sAMAccountName -eq '$n' -or name -eq '$n'" -ErrorAction SilentlyContinue)) {
        New-ADGroup -Server localhost -Name $n -GroupScope Global -ErrorAction SilentlyContinue
    }
}
foreach ($a in $acls) {
    try { Confirm-Exists $a.principal } catch {}
    try { Confirm-Exists $a.target } catch {}
}

$applied = 0
$skipped = @()
foreach ($a in $acls) {
    try {
        $targetDn = Resolve-TargetDn $a.target
        if (-not $targetDn) { $skipped += "$($a.principal)->$($a.target) (no target)"; continue }
        $sid = Resolve-PrincipalSid $a.principal
        if ($extended.ContainsKey($a.right)) {
            $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, "ExtendedRight", "Allow", $extended[$a.right])
        }
        elseif ($plain.ContainsKey($a.right)) {
            $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, $plain[$a.right], "Allow")
        }
        elseif ($propWrite.ContainsKey($a.right)) {
            $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, "WriteProperty", "Allow", $propWrite[$a.right])
        }
        else { $skipped += "$($a.principal)->$($a.target) (right $($a.right))"; continue }
        $acl = Get-Acl -Path "ADL:\$targetDn"
        $acl.AddAccessRule($rule)
        Set-Acl -Path "ADL:\$targetDn" -AclObject $acl
        $applied++
    }
    catch { $skipped += "$($a.principal)->$($a.target): $($_.Exception.Message)" }
}
[Ordered]@{ applied = $applied; skipped = $skipped }
