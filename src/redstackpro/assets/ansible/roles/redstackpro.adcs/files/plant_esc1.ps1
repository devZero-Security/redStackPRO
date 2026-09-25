# redStackPRO: plant a vulnerable ESC1 certificate template (clean-room MIT).
# ESC1 = a template that (a) allows client authentication, (b) lets the enrollee
# supply the subject/SAN, (c) needs no manager approval or extra signatures, and
# (d) can be enrolled by a low-privileged group. An attacker requests a cert as
# any user (e.g. a domain admin) and authenticates with it. Runs as an Enterprise
# Admin (writes the config partition). Idempotent.
param($TemplateCn, $TemplateDisplay, $EnrollGroup, $CaName)
$ErrorActionPreference = "Stop"

$configNC = ([ADSI]"LDAP://RootDSE").configurationNamingContext.ToString()
$templatesDn = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"
$oidContainerDn = "CN=OID,CN=Public Key Services,CN=Services,$configNC"

# Already there? (idempotent)
if ([System.DirectoryServices.DirectoryEntry]::Exists("LDAP://CN=$TemplateCn,$templatesDn")) {
  "template exists"; return
}

# 1. Mint a unique template OID under the forest's base, and register it.
$oidContainer = [ADSI]"LDAP://$oidContainerDn"
$forestBase = $oidContainer.Properties["msPKI-Cert-Template-OID"].Value
$r1 = Get-Random -Minimum 10000000 -Maximum 99999999
$r2 = Get-Random -Minimum 10000000 -Maximum 99999999
$newOid = "$forestBase.$r1.$r2"
$oidCn = "$r1.$r2"
$oidObj = $oidContainer.Create("msPKI-Enterprise-Oid", "CN=$oidCn")
$oidObj.Put("msPKI-Cert-Template-OID", $newOid)
$oidObj.Put("flags", 1)
$oidObj.Put("displayName", $TemplateDisplay)
$oidObj.SetInfo()

# 2. Duplicate the built-in User template (client-auth capable) and make it ESC1.
$base = [ADSI]"LDAP://CN=User,$templatesDn"
$t = ([ADSI]"LDAP://$templatesDn").Create("pKICertificateTemplate", "CN=$TemplateCn")
foreach ($a in @("pKIExpirationPeriod","pKIOverlapPeriod","pKIDefaultKeySpec",
                 "pKIKeyUsage","pKIMaxIssuingDepth","pKICriticalExtensions",
                 "pKIDefaultCSPs","msPKI-Minimal-Key-Size")) {
  $v = $base.Properties[$a].Value
  if ($null -ne $v) { $t.Properties[$a].Value = $v }
}
$t.Put("displayName", $TemplateDisplay)
$t.Put("msPKI-Cert-Template-OID", $newOid)
$t.Put("msPKI-Template-Schema-Version", 2)
$t.Put("revision", 100)
$t.Put("msPKI-Template-Minor-Revision", 1)
$t.Put("flags", 66104)
# Client Authentication EKU / application policy.
$t.Properties["pKIExtendedKeyUsage"].Value = "1.3.6.1.5.5.7.3.2"
$t.Properties["msPKI-Certificate-Application-Policy"].Value = "1.3.6.1.5.5.7.3.2"
# The vulnerable bits: enrollee supplies subject (0x1), no approval, no RA sigs.
$t.Put("msPKI-Certificate-Name-Flag", 1)
$t.Put("msPKI-Enrollment-Flag", 0)
$t.Put("msPKI-RA-Signature", 0)
$t.SetInfo()

# 3. Grant Enroll + AutoEnroll to the low-privileged group.
$sid = (New-Object System.Security.Principal.NTAccount($EnrollGroup)).Translate([System.Security.Principal.SecurityIdentifier])
$enroll = [GUID]"0e10c968-78fb-11d2-90d4-00c04f79dc55"
$autoEnroll = [GUID]"a05b8cc2-17bc-4802-a710-e7c15ab866a2"
$sec = $t.psbase.ObjectSecurity
foreach ($g in @($enroll, $autoEnroll)) {
  $sec.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, "ExtendedRight", "Allow", $g)))
}
$sec.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, "GenericRead", "Allow")))
$t.psbase.CommitChanges()

# 4. Publish the template on the CA so it can be enrolled.
$es = [ADSI]"LDAP://CN=$CaName,CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNC"
if (-not ($es.Properties["certificateTemplates"] -contains $TemplateCn)) {
  $es.Properties["certificateTemplates"].Add($TemplateCn) | Out-Null
  $es.SetInfo()
}
"planted $TemplateCn -> $newOid, enroll=$EnrollGroup, published on $CaName"
