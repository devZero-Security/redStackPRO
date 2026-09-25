# redStackPRO: plant ESC5, vulnerable PKI object access control (clean-room MIT).
#
# ESC5 is not a certificate template. It is write access over the AD objects the
# PKI itself trusts, which all live under
# CN=Public Key Services,CN=Services,<configuration NC>. Whoever can rewrite
# those decides what the forest trusts, so it is a route to forest compromise
# that never touches a template's enrolment rights.
#
# Three objects are granted here, because each is a different way in and a lab
# that only offered one would teach only that one:
#
#   the CA's own Enrollment Services object   what the CA is and what it publishes
#   CN=NTAuthCertificates                     the store of CAs allowed to authenticate
#   the CA's computer object                  the host holding the private key
#
# Writing NTAuthCertificates is the sharpest of the three: add your own CA
# certificate and the forest will authenticate anything you issue.
#
# Runs as an Enterprise Admin (configuration-partition writes). Idempotent: an
# ACE already present is left alone rather than added twice.
param($CaName, $Principal, $CaHost)
$ErrorActionPreference = "Stop"

$configNC = ([ADSI]"LDAP://RootDSE").configurationNamingContext.ToString()
$domainNC = ([ADSI]"LDAP://RootDSE").defaultNamingContext.ToString()
$pkiDn = "CN=Public Key Services,CN=Services,$configNC"

$sid = (New-Object System.Security.Principal.NTAccount($Principal)).Translate([System.Security.Principal.SecurityIdentifier])

# Resolve the CA's computer object by name. Absent on a CA that is not a domain
# member, which is not a shape we build, so a miss is reported rather than
# ignored -- a silently skipped target is a lab that looks planted and is not.
$caHostDn = $null
if ($CaHost) {
  $s = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$domainNC")
  $s.Filter = "(&(objectClass=computer)(cn=$CaHost))"
  $found = $s.FindOne()
  if ($null -ne $found) { $caHostDn = $found.Properties["distinguishedname"][0] }
}

$targets = @(
  "CN=$CaName,CN=Enrollment Services,$pkiDn",
  "CN=NTAuthCertificates,$pkiDn"
)
if ($caHostDn) { $targets += $caHostDn }

$granted = @()
$skipped = @()
foreach ($dn in $targets) {
  if (-not [System.DirectoryServices.DirectoryEntry]::Exists("LDAP://$dn")) {
    $skipped += $dn
    continue
  }
  $obj = [ADSI]"LDAP://$dn"
  $sec = $obj.psbase.ObjectSecurity
  # GenericAll rather than a narrower right on purpose: ESC5 as taught is "an
  # attacker controls this object", and a partial grant makes half the published
  # techniques fail for reasons that look like the technique not working.
  $already = $false
  foreach ($ace in $sec.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier])) {
    if ($ace.IdentityReference -eq $sid -and $ace.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll) {
      $already = $true
      break
    }
  }
  if ($already) { continue }
  $sec.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, "GenericAll", "Allow")))
  $obj.psbase.CommitChanges()
  $granted += $dn
}

if ($skipped.Count -gt 0) {
  throw "ESC5: these PKI objects were not found, so nothing was planted on them: $($skipped -join '; ')"
}
if ($granted.Count -eq 0) { "exists: $Principal already holds GenericAll on every ESC5 target" }
else { "planted ESC5 -> $Principal GenericAll on $($granted.Count) object(s): $($granted -join '; ')" }
