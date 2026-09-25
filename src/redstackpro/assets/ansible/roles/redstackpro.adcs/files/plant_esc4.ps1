# redStackPRO: plant the ESC4 certificate template (clean-room MIT). ESC4 is not
# a template misconfiguration in itself -- the vulnerability is an over-permissive
# ACL on the template (a low-priv principal with write control can rewrite it into
# an ESC1). This planter just creates and publishes an enrollable, client-auth
# template named "ESC4"; the write-control ACL (khal.drogo GenericAll) is applied
# separately from the domain's acls list, whose target is CN=ESC4,... So the CN
# here MUST be ESC4 for that ACL to resolve. Runs as Enterprise Admin. Idempotent.
param($CaName, $EnrollGroup = "Domain Users", $TemplateName = "ESC4")
$ErrorActionPreference = "Stop"

$templateCn = $TemplateName
$display = $TemplateName
$configNC = ([ADSI]"LDAP://RootDSE").configurationNamingContext.ToString()
$templatesDn = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"
$oidContainerDn = "CN=OID,CN=Public Key Services,CN=Services,$configNC"

# Create the template only if it is not already there, but ALWAYS ensure it is
# published on the CA below -- a template object left over from a prior partial
# run would otherwise never get published, so the path silently does nothing.
$exists = [System.DirectoryServices.DirectoryEntry]::Exists("LDAP://CN=$templateCn,$templatesDn")
if (-not $exists) {

# Mint and register a template OID.
$oidContainer = [ADSI]"LDAP://$oidContainerDn"
$forestBase = $oidContainer.Properties["msPKI-Cert-Template-OID"].Value
$r1 = Get-Random -Minimum 10000000 -Maximum 99999999
$r2 = Get-Random -Minimum 10000000 -Maximum 99999999
$newOid = "$forestBase.$r1.$r2"
$oidObj = $oidContainer.Create("msPKI-Enterprise-Oid", "CN=$r1.$r2")
$oidObj.Put("msPKI-Cert-Template-OID", $newOid)
$oidObj.Put("flags", 1)
$oidObj.Put("displayName", $display)
$oidObj.SetInfo()

# Duplicate the built-in User template and publish it as ESC4.
$base = [ADSI]"LDAP://CN=User,$templatesDn"
$t = ([ADSI]"LDAP://$templatesDn").Create("pKICertificateTemplate", "CN=$templateCn")
foreach ($a in @("pKIExpirationPeriod","pKIOverlapPeriod","pKIDefaultKeySpec",
                 "pKIKeyUsage","pKIMaxIssuingDepth","pKICriticalExtensions",
                 "pKIDefaultCSPs","msPKI-Minimal-Key-Size",
                 # INHERITED, not written: see the note below the loop.
                 "msPKI-Certificate-Name-Flag")) {
  $v = $base.Properties[$a].Value
  if ($null -ne $v) { $t.Properties[$a].Value = $v }
}
$t.Put("displayName", $display)
$t.Put("msPKI-Cert-Template-OID", $newOid)
$t.Put("msPKI-Template-Schema-Version", 2)
$t.Put("revision", 100)
$t.Put("msPKI-Template-Minor-Revision", 1)
$t.Put("flags", 66104)
$t.Properties["pKIExtendedKeyUsage"].Value = "1.3.6.1.5.5.7.3.2"
$t.Properties["msPKI-Certificate-Application-Policy"].Value = "1.3.6.1.5.5.7.3.2"
# The subject comes from the User template above (directory path, UPN and email
# in the SAN), which is what "built from AD, not from the enrollee" means. It is
# inherited rather than written: this line used to say 0x8000000, which is
# CT_FLAG_SUBJECT_ALT_REQUIRE_DNS, not the 0x80000000 directory-path flag the
# comment described. A dropped digit that lands on another real flag fails
# silently -- the template plants and enrols, and the certificate comes back with
# a DNS SAN and no UPN, so it authenticates nobody. Same typo was in the ESC13
# planter. This template is the one NHA's SignatureValidation ACL target uses.
$t.Put("msPKI-Enrollment-Flag", 0)
$t.Put("msPKI-RA-Signature", 0)
$t.SetInfo()

# Grant Enroll to the low-priv group so the template is enrollable.
$sid = (New-Object System.Security.Principal.NTAccount($EnrollGroup)).Translate([System.Security.Principal.SecurityIdentifier])
$enroll = [GUID]"0e10c968-78fb-11d2-90d4-00c04f79dc55"
$autoEnroll = [GUID]"a05b8cc2-17bc-4802-a710-e7c15ab866a2"
$sec = $t.psbase.ObjectSecurity
foreach ($g in @($enroll, $autoEnroll)) {
  $sec.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, "ExtendedRight", "Allow", $g)))
}
$sec.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, "GenericRead", "Allow")))
$t.psbase.CommitChanges()

}  # end: create-if-missing

# Publish on the CA (always -- idempotent add, so it fixes an unpublished leftover).
$es = [ADSI]"LDAP://CN=$CaName,CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNC"
if (-not ($es.Properties["certificateTemplates"] -contains $templateCn)) {
  $es.Properties["certificateTemplates"].Add($templateCn) | Out-Null
  $es.SetInfo()
}
if ($exists) { "template exists, published on $CaName" }
else { "planted $templateCn, enroll=$EnrollGroup, published on $CaName" }
