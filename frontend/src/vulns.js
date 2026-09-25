// The catalog of misconfigurations, attack paths, and CVEs a person can plant on
// a range host (a host's overlay.vulns is a list of these ids). It is a menu for
// building a custom lab, not just for the GOAD templates.
//
// Deliberately scoped and grounded in GOAD. Rather than invent techniques, each
// entry maps to how GOAD actually plants it: an Ansible role in its vulns library
// (see d:/tmp/GOAD/ansible/roles/vulns) or a property on the account/host. The
// `goad` field names that mechanism, which is also what range compilation will
// wire (see 0050). This is a common starting set of ~20; it grows as the range
// work does. The schema keeps vulns as free strings, so adding one needs no
// schema change. See 0047 and 0049.

export const VULN_CATALOG = [
  {
    group: "AD CS",
    items: [
      { id: "esc1", label: "ESC1", blurb: "Misconfigured certificate template lets an enrollee supply any subject.", goad: "adcs_templates" },
      { id: "esc2", label: "ESC2 (Any Purpose EKU)", blurb: "A template with the Any Purpose EKU lets a low-priv enrollee obtain a cert valid for anything, including client auth.", goad: "adcs_templates" },
      { id: "esc3", label: "ESC3 (enrollment agent)", blurb: "A template with the Certificate Request Agent EKU lets a low-priv user enrol on behalf of a privileged user.", goad: "adcs_templates" },
      { id: "esc4", label: "ESC4 (template ACL)", blurb: "A principal has write control over a certificate template's ACL.", goad: "adcs_templates" },
      { id: "esc5", label: "ESC5 (PKI object ACL)", blurb: "A low-privileged principal has write control over the PKI's own AD objects, including the store of CAs the forest trusts to authenticate.", goad: "adcs_templates" },
      { id: "esc6", label: "ESC6 (SAN in any request)", blurb: "The CA honours a requester-supplied SAN for any template (EDITF_ATTRIBUTESUBJECTALTNAME2).", goad: "adcs_ca" },
      { id: "esc7", label: "ESC7 (CA role)", blurb: "A low-privileged user holds the ManageCA / ManageCertificates role on the CA.", goad: "adcs_ca" },
      { id: "esc8", label: "ESC8 (web enrollment relay)", blurb: "AD CS web enrollment accepts relayed NTLM authentication.", goad: "adcs_templates" },
      { id: "esc9", label: "ESC9 (no security extension)", blurb: "A template issues certificates without the SID security extension, so the name in the certificate is all a DC has to go on.", goad: "adcs_templates" },
      { id: "esc10", label: "ESC10 (weak cert mapping)", blurb: "Weak certificate-to-account mapping lets a cert authenticate as another user.", goad: "adcs_esc10" },
      { id: "esc11", label: "ESC11 (unencrypted RPC enrol)", blurb: "The CA's RPC enrollment no longer enforces encryption (IF_ENFORCEENCRYPTICERTREQUEST off).", goad: "adcs_ca" },
      { id: "esc13", label: "ESC13 (issuance policy → group)", blurb: "A template's issuance policy OID grants membership in a privileged group.", goad: "adcs_templates" },
      { id: "esc14", label: "ESC14 (weak explicit mapping)", blurb: "An account's altSecurityIdentities accepts any certificate carrying a given subject, which a requester-supplies-subject template hands you.", goad: "adcs_templates" },
      { id: "esc15", label: "ESC15 (EKUwu)", blurb: "A schema-v1 template lets a requester inject an application policy (client auth).", goad: "adcs_templates" },
      { id: "esc16", label: "ESC16 (no security extension, CA-wide)", blurb: "The CA omits the SID security extension from every certificate it issues, so every template behaves like ESC9 whatever it says.", goad: "adcs_ca" },
      { id: "shadow_credentials", label: "Shadow credentials", blurb: "Write to msDS-KeyCredentialLink to authenticate as the target.", goad: "adcs" },
    ],
  },
  {
    // These are account/computer properties, not host tasks. Kerberoasting and
    // AS-REP roasting are realized by flagging a DOMAIN USER (users[].flaws
    // kerberoastable / asrep_roastable, plus spns), which the dc role acts on;
    // the delegation ids are realized on a user (delegate_to) or a member
    // computer (member vulns). Declaring them in a host's vulns list is a no-op
    // that plants nothing -- set the user flaw / computer vuln instead. The goad
    // key (user:spn, user:no_preauth, computer:delegation) names the real
    // mechanism. See dracarys-fidelity-gap and PAI F-dual-modeling.
    group: "Kerberos",
    items: [
      { id: "kerberoasting", label: "Kerberoasting", blurb: "An SPN is set on a user account, so its hash can be requested and cracked. Realized as a user flaw (kerberoastable + spns), not a host task.", goad: "user:spn" },
      { id: "asreproasting", label: "AS-REP roasting", blurb: "Kerberos pre-authentication is disabled on the account. Realized as a user flaw (asrep_roastable), not a host task.", goad: "user:no_preauth" },
      { id: "unconstrained_delegation", label: "Unconstrained delegation", blurb: "The host may impersonate any user that authenticates to it.", goad: "computer:delegation" },
      { id: "constrained_delegation", label: "Constrained delegation (protocol transition)", blurb: "The account may impersonate any user to a set of services (T2A4D / use-any-protocol).", goad: "computer:delegation" },
      { id: "constrained_delegation_kerberos", label: "Constrained delegation (Kerberos only)", blurb: "The account may delegate to a set of services using Kerberos only.", goad: "computer:delegation" },
    ],
  },
  {
    group: "ACL abuse",
    items: [
      { id: "genericall", label: "GenericAll", blurb: "Full control over the target object.", goad: "acls" },
      { id: "genericwrite", label: "GenericWrite", blurb: "Write any non-protected attribute of the target.", goad: "acls" },
      { id: "writedacl", label: "WriteDACL", blurb: "Rewrite the target's DACL to grant yourself rights.", goad: "acls" },
      { id: "forcechangepassword", label: "ForceChangePassword", blurb: "Reset the target user's password without knowing the old one.", goad: "acls" },
    ],
  },
  {
    group: "Credentials",
    items: [
      { id: "gpp_password", label: "GPP cpassword", blurb: "A Group Policy Preferences password sits decryptable in SYSVOL.", goad: "credentials" },
      { id: "autologon", label: "Autologon credential", blurb: "A cleartext auto-logon password sits in the Winlogon registry key.", goad: "autologon" },
      { id: "password_in_description", label: "Password in description", blurb: "A credential is left in the account's AD description field.", goad: "user:description" },
      { id: "weak_password", label: "Weak / cleartext creds", blurb: "The account uses a weak, sprayable password.", goad: "user:password" },
      { id: "laps_read", label: "LAPS read", blurb: "Rights to read the local admin password LAPS stores on a computer.", goad: "acls" },
      { id: "stored_credential", label: "Stored credential (CredMan)", blurb: "A cleartext credential is saved in Credential Manager (cmdkey / TERMSRV).", goad: "credentials" },
      { id: "sysvol_secret", label: "SYSVOL script secret", blurb: "A logon script left in SYSVOL contains a hardcoded credential.", goad: "files" },
    ],
  },
  {
    group: "Coercion & relay",
    items: [
      { id: "llmnr_poisoning", label: "LLMNR poisoning", blurb: "LLMNR is enabled, so name resolution can be poisoned to capture hashes. The capture path is name-resolution poisoning, which needs a real broadcast/multicast domain: Proxmox and ESXi put the range on a real bridge or vSwitch, and every cloud VPC's SDN drops it. Planted only there, so a cloud range does not carry a toggle that can never pay off.", providers: ["proxmox", "esxi"], goad: "enable_llmnr" },
      { id: "nbtns_poisoning", label: "NBT-NS poisoning", blurb: "NBT-NS is enabled, the same capture path as LLMNR. The capture path is name-resolution poisoning, which needs a real broadcast/multicast domain: Proxmox and ESXi put the range on a real bridge or vSwitch, and every cloud VPC's SDN drops it. Planted only there, so a cloud range does not carry a toggle that can never pay off.", providers: ["proxmox", "esxi"], goad: "enable_nbt-ns" },
      { id: "smbv1", label: "SMBv1 enabled", blurb: "The legacy, unsigned SMBv1 protocol is left enabled.", goad: "smbv1" },
      { id: "ntlm_downgrade", label: "NTLM downgrade", blurb: "The host sends and accepts weak NTLMv1/LM, easy to relay or crack.", goad: "ntlmdowngrade" },
      { id: "ntlm_relay", label: "NTLM relay posture", blurb: "SMB signing is left off so captured NTLM can be relayed. A privileged bot generates the authentication, but an attacker only receives it by poisoning the name it resolves. The capture path is name-resolution poisoning, which needs a real broadcast/multicast domain: Proxmox and ESXi put the range on a real bridge or vSwitch, and every cloud VPC's SDN drops it. Planted only there, so a cloud range does not carry a toggle that can never pay off.", providers: ["proxmox", "esxi"], goad: "ntlm_relay" },
      { id: "ldap_signing_off", label: "LDAP signing not enforced", blurb: "The DC does not require LDAP signing or channel binding, so coerced NTLM can be relayed to LDAP (RBCD / ESC8). The relay payoff needs a real broadcast domain (mitm6/WPAD) or an unpatched CVE-2019-1040 MIC, so the compiler only plants it on Proxmox/ESXi, where the range sits on a real L2 bridge; a cloud VPC's SDN drops the broadcast/multicast this needs.", goad: "ldap_signing", providers: ["proxmox", "esxi"] },
      { id: "responder", label: "Responder-friendly posture", blurb: "Broadcast name resolution is left open for a rogue responder. The capture path is name-resolution poisoning, which needs a real broadcast/multicast domain: Proxmox and ESXi put the range on a real bridge or vSwitch, and every cloud VPC's SDN drops it. Planted only there, so a cloud range does not carry a toggle that can never pay off.", providers: ["proxmox", "esxi"], goad: "responder" },
      { id: "ldaps", label: "LDAPS enabled (realism)", blurb: "The DC is given a certificate and serves LDAP over TLS (636). A defensive-posture / realism setting rather than a weakness: it forces LDAP tooling to speak LDAPS and shapes the enumeration path, matching labs that ship a real LDAPS endpoint.", goad: "ldaps" },
    ],
  },
  {
    group: "Delegation & privileged paths",
    items: [
      { id: "sid_history", label: "SID history injection", blurb: "A principal carries a privileged SID in its sIDHistory.", goad: "sidhistory" },
      { id: "adminsdholder", label: "AdminSDHolder ACL", blurb: "A principal has rights on AdminSDHolder, propagating to protected groups.", goad: "acls" },
      { id: "gpo_abuse", label: "GPO abuse", blurb: "A low-privileged principal can edit a linked Group Policy Object.", goad: "gpo_abuse" },
      { id: "rdp_scheduler", label: "RDP scheduled logon", blurb: "A scheduled task performs an interactive logon whose credentials can be captured.", goad: "rdp_scheduler" },
      { id: "account_is_sensitive", label: "Sensitive account (not delegable)", blurb: "An account is flagged sensitive and cannot be delegated (a defensive tell in the path).", goad: "account_is_sensitive" },
      { id: "gmsa_readable", label: "Readable gMSA", blurb: "A group-managed service account's password can be retrieved by a non-admin principal.", goad: "gmsa" },
      { id: "anonymous_rpc", label: "Anonymous RPC / null session", blurb: "ANONYMOUS LOGON can read the domain object over RPC.", goad: "acls" },
    ],
  },
  {
    group: "Services",
    items: [
      { id: "mssql_linked", label: "MSSQL linked servers", blurb: "A linked-server chain lets a query hop between MSSQL instances.", goad: "mssql" },
      { id: "mssql_impersonation", label: "MSSQL impersonation", blurb: "EXECUTE AS lets a low-privilege login impersonate a higher one.", goad: "mssql" },
      { id: "iis_webshell", label: "IIS web shell", blurb: "A writable IIS app path allows a web shell.", goad: "permissions" },
      { id: "openshares", label: "Open share", blurb: "An unauthenticated / everyone-readable SMB share exposes files.", goad: "openshares" },
      { id: "writable_share", label: "Writable share / permissions", blurb: "Loose NTFS/share permissions let a low-privileged user write where they should not.", goad: "permissions" },
      { id: "disable_firewall", label: "Windows Firewall off", blurb: "The host firewall is disabled on all profiles, exposing services (SMB, WinRM, RPC) it would otherwise filter from the range.", goad: "disable_firewall" },
      { id: "run_as_ppl", label: "LSASS RunAsPPL", blurb: "LSA protection is on (RunAsPPL), a hardening tell that shapes the credential-access path.", goad: "enable_run_as_ppl" },
      { id: "printnightmare", label: "PrintNightmare (spooler)", blurb: "Point-and-Print policy lets a non-admin install a printer driver, loading attacker code as SYSTEM (CVE-2021-34527). Opt-in, not a cloud default: KB5005652 hardens the server-side driver install on a fully-patched build, so the live exploit needs a patch-baseline image.", goad: "printnightmare" },
    ],
  },
  {
    group: "Double-hop & bots",
    items: [
      { id: "enable_credssp_server", label: "CredSSP server", blurb: "The host accepts CredSSP auth, the receiving end of an unconstrained double-hop.", goad: "enable_credssp_server" },
      { id: "enable_credssp_client", label: "CredSSP client delegation", blurb: "The host delegates fresh credentials anywhere (AllowFreshCredentials wildcard).", goad: "enable_credssp_client" },
      { id: "schedule", label: "Scheduled login bot", blurb: "A recurring scheduled task runs as a user, leaving a session/credential to capture.", goad: "schedule" },
      { id: "keepass_vault", label: "KeePass credential vault", blurb: "A KeePass database is generated on the host holding a privileged credential, opened on a schedule (see the login bot) so its master password and contents are exposed to whoever holds the host. The vault entry's password is filled from a named lab user at deploy, so no secret is baked into the template.", goad: "files" },
    ],
  },
  {
    group: "Lab markers",
    items: [
      { id: "administrator_folder", label: "Administrator desktop flag", blurb: "Drops a CTF-style flag file on the local Administrator's desktop: the reward for reaching admin on this host. Host-provided marker, not an attack technique.", goad: null },
      { id: "directory", label: "Planted directory", blurb: "Creates a directory on the host (a staging folder or drop point a lab references). A marker, not an SMB share (see Open share for that).", goad: "directory" },
      { id: "files", label: "Planted files", blurb: "Drops file(s) with given content on the host: a note, script, or document left behind. The generic host file-plant.", goad: "files" },
    ],
  },
];

// The GOAD mechanism a vuln id maps to, or null when it is host-provided rather
// than a GOAD role. Range compilation reads this to pick the provisioning role.
export const VULN_GOAD = Object.fromEntries(
  VULN_CATALOG.flatMap((g) => g.items.map((i) => [i.id, i.goad]))
);

export const VULN_LABEL = Object.fromEntries(
  VULN_CATALOG.flatMap((g) => g.items.map((i) => [i.id, i.label]))
);

// The range providers a vuln id is exploitable on, or absent when it lands on
// every provider (the common case). A provider-restricted id is one whose
// payoff depends on something the provider's network model does or doesn't
// give the range (e.g. ldap_signing_off needs a real L2 broadcast domain, which
// only Proxmox/ESXi give a range; every cloud VPC's SDN drops broadcast and
// multicast). The compiler (redstackpro.ansible.VULN_PROVIDERS, kept in sync by
// tests/test_vuln_providers_sync.py) filters a host's declared vulns by this
// same map before planting them, so a template can declare an id everywhere and
// have it silently no-op on a provider it cannot land on; the canvas greys the
// checkbox the same way. See current-activity-list (provider-aware toggles).
export const VULN_PROVIDERS = Object.fromEntries(
  VULN_CATALOG.flatMap((g) => g.items)
    .filter((i) => i.providers)
    .map((i) => [i.id, i.providers])
);
