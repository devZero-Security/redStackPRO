# redStackPRO: plant the ESC13 certificate template (clean-room MIT). ESC13 = a
# template whose issuance policy OID is linked (msDS-OIDToGroupLink) to a
# privileged group, so anyone who can enrol the template gets a token carrying
# that group's membership. We create a client-auth template named "ESC13", mint an
# issuance-policy OID object, link that OID to the target group, stamp the policy
# onto the template, and publish to the low-priv group. Runs as Enterprise Admin
# (config-partition writes). Idempotent. See goad-fidelity-build.
param($CaName, $GroupCn, $EnrollGroup = "Domain Users")
$ErrorActionPreference = "Stop"

$templateCn = "ESC13"
$display = "ESC13"
$configNC = ([ADSI]"LDAP://RootDSE").configurationNamingContext.ToString()
$domainNC = ([ADSI]"LDAP://RootDSE").defaultNamingContext.ToString()
$templatesDn = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"
$oidContainerDn = "CN=OID,CN=Public Key Services,CN=Services,$configNC"

$exists = [System.DirectoryServices.DirectoryEntry]::Exists("LDAP://CN=$templateCn,$templatesDn")

# Resolve the group DN the issuance policy grants; create the group if it is not
# there. An issuance-policy target like "greatmaster" is an empty group (no user
# members), so the directory-population step does not create it -- create it here
# as a universal security group in the Users container.
$usersDn = "CN=Users,$domainNC"
$grpSearch = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$domainNC")
$grpSearch.Filter = "(&(objectClass=group)(cn=$GroupCn))"
$grpResult = $grpSearch.FindOne()
if ($null -eq $grpResult) {
  $gc = ([ADSI]"LDAP://$usersDn").Create("group", "CN=$GroupCn")
  $gc.Put("sAMAccountName", $GroupCn)
  $gc.Put("groupType", 0x80000008)   # universal security group
  $gc.SetInfo()
  $groupDn = "CN=$GroupCn,$usersDn"
} else {
  $groupDn = $grpResult.Properties["distinguishedname"][0]
}

if (-not $exists) {

# Mint an issuance-policy OID and link it to the group (msDS-OIDToGroupLink).
$oidContainer = [ADSI]"LDAP://$oidContainerDn"
$forestBase = $oidContainer.Properties["msPKI-Cert-Template-OID"].Value
$r1 = Get-Random -Minimum 10000000 -Maximum 99999999
$r2 = Get-Random -Minimum 10000000 -Maximum 99999999
$policyOid = "$forestBase.$r1.$r2"
$oidObj = $oidContainer.Create("msPKI-Enterprise-Oid", "CN=$r1.$r2")
$oidObj.Put("msPKI-Cert-Template-OID", $policyOid)
$oidObj.Put("flags", 2)                       # 2 = issuance policy
$oidObj.Put("displayName", "IssuancePolicyESC13")
$oidObj.Put("msDS-OIDToGroupLink", $groupDn)  # the ESC13 primitive
$oidObj.SetInfo()

# Create a client-auth template that carries this issuance policy.
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
$t.Put("msPKI-Cert-Template-OID", "$forestBase.$r2.$r1")
$t.Put("msPKI-Template-Schema-Version", 2)
$t.Put("revision", 100)
$t.Put("msPKI-Template-Minor-Revision", 1)
$t.Put("flags", 66104)
$t.Properties["pKIExtendedKeyUsage"].Value = "1.3.6.1.5.5.7.3.2"
$t.Properties["msPKI-Certificate-Application-Policy"].Value = "1.3.6.1.5.5.7.3.2"
# The subject and SAN come from the User template above, and are deliberately NOT
# written here.
#
# This line used to read 0x8000000 with a comment saying the directory builds the
# subject. It does not: 0x08000000 is CT_FLAG_SUBJECT_ALT_REQUIRE_DNS. The flag
# that builds the subject from the directory is CT_FLAG_SUBJECT_REQUIRE_DIRECTORY_PATH,
# 0x80000000 -- one zero longer. A dropped digit turned into a different, valid
# flag, so nothing failed: the template planted, published, and enrolled, and the
# certificate came back carrying a DNS SAN and no UPN. With no UPN and no SID
# extension there is nothing for a DC to map to an account, so PKINIT never
# authenticates anyone and the issuance-policy-to-group link this whole technique
# rests on never reaches a token. That is exactly the symptom part 14 recorded
# against ESC13.
#
# Inheriting is the fix rather than writing 0x80000000, because the built-in User
# template already carries the right combination for a user-auth certificate
# (directory path, UPN and email in the SAN), and because that constant does not
# fit a signed 32-bit int -- writing it by hand is a second way to get this wrong.
$t.Put("msPKI-Enrollment-Flag", 0)
$t.Put("msPKI-RA-Signature", 0)
# Stamp the issuance policy onto the template.
$t.Properties["msPKI-Certificate-Policy"].Value = $policyOid
$t.SetInfo()

# Grant Enroll to the low-priv group and publish on the CA.
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

# Publish on the CA (always -- idempotent, so it fixes an unpublished leftover).
$es = [ADSI]"LDAP://CN=$CaName,CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNC"
if (-not ($es.Properties["certificateTemplates"] -contains $templateCn)) {
  $es.Properties["certificateTemplates"].Add($templateCn) | Out-Null
  $es.SetInfo()
}
if ($exists) { "template exists, published on $CaName" }
else { "planted $templateCn -> policy linked to $GroupCn ($groupDn), published on $CaName" }
