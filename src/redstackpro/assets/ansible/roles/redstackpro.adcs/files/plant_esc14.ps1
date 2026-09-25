# redStackPRO: plant ESC14, a weak explicit certificate mapping (clean-room MIT).
#
# altSecurityIdentities is how an administrator says "this certificate is this
# account". Microsoft splits the mapping forms into strong and weak, and the
# split is whether the thing being matched can be reused:
#
#   WEAK    X509IssuerSubject   "X509:<I>IssuerDN<S>SubjectDN"
#           X509SubjectOnly     "X509:<S>SubjectDN"
#           X509RFC822          "X509:<RFC822>user@example.com"
#   STRONG  X509IssuerSerialNumber, X509SKI, X509SHA1PublicKey
#
# A subject or an email address is a name somebody can put in a certificate
# request. A serial number, a key identifier or a key hash is not. So a weak
# mapping says: anyone who can obtain a certificate carrying this subject may log
# on as this account.
#
# This plants the weak mapping itself rather than the write access to it, because
# the mapping is the state a lab can hand you, and the route to it is already
# covered by the ACL vulns. What it produces is a complete chain with what we
# already plant: enrol the ESC1 template (which lets the requester supply the
# subject), ask for the subject named below, and authenticate as the target.
#
# It needs the KDC not to be enforcing strong certificate binding. That is the
# esc10 toggle (StrongCertificateBindingEnforcement = 0) and this file does not
# touch the registry: with enforcement at its default of 2 the mapping is written
# and simply refused, which is the correct behaviour of a patched domain and
# worth being able to show.
#
# Runs as an Enterprise Admin. Idempotent.
param($TargetUser, $MappingSubject)
$ErrorActionPreference = "Stop"

$domainNC = ([ADSI]"LDAP://RootDSE").defaultNamingContext.ToString()

$s = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$domainNC")
$s.Filter = "(&(objectClass=user)(objectCategory=person)(|(sAMAccountName=$TargetUser)(cn=$TargetUser)))"
$found = $s.FindOne()
if ($null -eq $found) {
  # Loud rather than skipped. A mapping planted onto nobody is a lab that reports
  # success and hands the walkthrough an account that does not exist.
  throw "ESC14: target user '$TargetUser' not found in $domainNC"
}
$userDn = $found.Properties["distinguishedname"][0]
$user = [ADSI]"LDAP://$userDn"

# X509SubjectOnly: the weakest of the three weak forms, and the one that pairs
# with a template where the enrollee supplies the subject.
$mapping = "X509:<S>$MappingSubject"

$current = @($user.Properties["altSecurityIdentities"])
if ($current -contains $mapping) {
  "exists: $TargetUser already carries the weak mapping $mapping"
  return
}

$user.Properties["altSecurityIdentities"].Add($mapping) | Out-Null
$user.SetInfo()
"planted ESC14 -> $TargetUser accepts any certificate whose subject is '$MappingSubject' ($mapping)"
