# redStackPRO: enable the ESC15 (EKUwu) path (clean-room MIT). ESC15 abuses a
# schema-version-1 template: because a v1 template does not pin application
# policies, a requester can inject an arbitrary Application Policy (e.g. Client
# Authentication) into the CSR. The built-in "WebServer" template is schema v1, so
# the whole exploit is: make it enrollable by a low-priv group and publish it.
# Runs as Enterprise Admin. Idempotent.
param($CaName, $EnrollGroup = "Domain Users")
$ErrorActionPreference = "Stop"

$templateCn = "WebServer"
$configNC = ([ADSI]"LDAP://RootDSE").configurationNamingContext.ToString()
$templatesDn = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"
$t = [ADSI]"LDAP://CN=$templateCn,$templatesDn"
if ($null -eq $t.Path) { throw "built-in WebServer template not found" }

# Grant Enroll + AutoEnroll to the low-priv group (idempotent add).
$sid = (New-Object System.Security.Principal.NTAccount($EnrollGroup)).Translate([System.Security.Principal.SecurityIdentifier])
$enroll = [GUID]"0e10c968-78fb-11d2-90d4-00c04f79dc55"
$autoEnroll = [GUID]"a05b8cc2-17bc-4802-a710-e7c15ab866a2"
$sec = $t.psbase.ObjectSecurity
$already = $false
foreach ($r in $sec.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
  if ($r.IdentityReference -eq $sid -and $r.ObjectType -eq $enroll -and $r.AccessControlType -eq "Allow") { $already = $true }
}
if (-not $already) {
  foreach ($g in @($enroll, $autoEnroll)) {
    $sec.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, "ExtendedRight", "Allow", $g)))
  }
  $t.psbase.CommitChanges()
}

# Publish on the CA so it can be enrolled.
$es = [ADSI]"LDAP://CN=$CaName,CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNC"
$published = ($es.Properties["certificateTemplates"] -contains $templateCn)
if (-not $published) {
  $es.Properties["certificateTemplates"].Add($templateCn) | Out-Null
  $es.SetInfo()
}
if ($already -and $published) { "template exists" } else { "planted $templateCn enroll=$EnrollGroup, published on $CaName" }
