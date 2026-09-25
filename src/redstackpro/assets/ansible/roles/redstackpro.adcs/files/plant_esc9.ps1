# redStackPRO: plant an ESC9 certificate template (clean-room MIT).
#
# ESC9 = a template that asks the CA to LEAVE OUT the SID security extension
# (szOID_NTDS_CA_SECURITY_EXT, 1.3.6.1.4.1.311.25.2). That extension is what the
# May 2022 "Certifried" updates added so a DC could bind a certificate to an
# account by SID rather than by a name someone can change. A template carrying
# CT_FLAG_NO_SECURITY_EXTENSION (0x80000) in msPKI-Enrollment-Flag produces
# certificates with nothing in them but a name.
#
# Why that is an escalation: with write access over some account (GenericWrite,
# or a shadow-credential path) an attacker sets that account's userPrincipalName
# to a privileged user's, enrols this template as the account, and puts the UPN
# back. The certificate now names the privileged user and carries no SID to
# contradict it, so PKINIT authenticates as them. It needs the KDC not to be
# enforcing strong binding, which is what the esc10 toggle relaxes -- the two are
# usually planted together and this file does not touch the registry.
#
# Runs as an Enterprise Admin (writes the configuration partition). Idempotent.
param($TemplateCn, $TemplateDisplay, $EnrollGroup, $CaName)
$ErrorActionPreference = "Stop"

$configNC = ([ADSI]"LDAP://RootDSE").configurationNamingContext.ToString()
$templatesDn = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"
$oidContainerDn = "CN=OID,CN=Public Key Services,CN=Services,$configNC"

$exists = [System.DirectoryServices.DirectoryEntry]::Exists("LDAP://CN=$TemplateCn,$templatesDn")

if (-not $exists) {

# 1. Mint a unique template OID under the forest's base, and register it.
$oidContainer = [ADSI]"LDAP://$oidContainerDn"
$forestBase = $oidContainer.Properties["msPKI-Cert-Template-OID"].Value
$r1 = Get-Random -Minimum 10000000 -Maximum 99999999
$r2 = Get-Random -Minimum 10000000 -Maximum 99999999
$newOid = "$forestBase.$r1.$r2"
$oidObj = $oidContainer.Create("msPKI-Enterprise-Oid", "CN=$r1.$r2")
$oidObj.Put("msPKI-Cert-Template-OID", $newOid)
$oidObj.Put("flags", 1)
$oidObj.Put("displayName", $TemplateDisplay)
$oidObj.SetInfo()

# 2. Duplicate the built-in User template.
#
# msPKI-Certificate-Name-Flag is INHERITED from User on purpose. ESC9 needs the
# subject and the UPN to be built by the directory, because the whole technique
# is that the DC believes the name in the certificate; a template where the
# enrollee supplies the subject would be ESC1 and would not need this flag at
# all. User already carries the right combination, and the directory-path
# constant does not fit a signed 32-bit int, so writing it by hand is a way to
# get this wrong that inheriting avoids.
$base = [ADSI]"LDAP://CN=User,$templatesDn"
$t = ([ADSI]"LDAP://$templatesDn").Create("pKICertificateTemplate", "CN=$TemplateCn")
foreach ($a in @("pKIExpirationPeriod","pKIOverlapPeriod","pKIDefaultKeySpec",
                 "pKIKeyUsage","pKIMaxIssuingDepth","pKICriticalExtensions",
                 "pKIDefaultCSPs","msPKI-Minimal-Key-Size",
                 "msPKI-Certificate-Name-Flag")) {
  $v = $base.Properties[$a].Value
  if ($null -ne $v) { $t.Properties[$a].Value = $v }
}
$t.Put("displayName", $TemplateDisplay)
$t.Put("msPKI-Cert-Template-OID", $newOid)
$t.Put("msPKI-Template-Schema-Version", 2)
$t.Put("revision", 100)
$t.Put("msPKI-Template-Minor-Revision", 1)
$t.Put("flags", 66104)
# Client Authentication EKU / application policy: without it the certificate
# cannot be used to log on and there is nothing to escalate with.
$t.Properties["pKIExtendedKeyUsage"].Value = "1.3.6.1.5.5.7.3.2"
$t.Properties["msPKI-Certificate-Application-Policy"].Value = "1.3.6.1.5.5.7.3.2"
# THE ESC9 PRIMITIVE. 0x80000 = CT_FLAG_NO_SECURITY_EXTENSION: issue without the
# SID extension. Everything else about this template is ordinary, which is what
# makes it a realistic misconfiguration rather than an obviously broken one.
$t.Put("msPKI-Enrollment-Flag", 0x80000)
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

}  # end: create-if-missing

# 4. Publish on the CA. Outside the create block on purpose, so a re-run against a
# half-built range repairs a template that exists but was never published.
$es = [ADSI]"LDAP://CN=$CaName,CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNC"
if (-not ($es.Properties["certificateTemplates"] -contains $TemplateCn)) {
  $es.Properties["certificateTemplates"].Add($TemplateCn) | Out-Null
  $es.SetInfo()
}
if ($exists) { "template exists, published on $CaName" }
else { "planted $TemplateCn -> no security extension, enroll=$EnrollGroup, published on $CaName" }
