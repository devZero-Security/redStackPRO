"""The range briefing: a human-readable summary of a deployed range or stack.

Terraform outputs give the addresses and the generated credentials; the canvas
document gives what infrastructure never knows - the domains, the users and
their planted flaws, the trusts, the ACL attack paths. This joins the two into
one hand-off an operator reads after a deploy: every box and its role, every
account and credential, every lab user with their privilege and flaws, the
domains and trusts, the planted vulnerabilities, and the SIEM dashboards.

The addresses are `<<tf:name:field>>` placeholders that tf_inventory.py
fills in after `terraform apply`, the same tokens the Ansible tree uses. The one
credential not embedded is the generated lab password, which lives only in the
Terraform state; the briefing points at `terraform -chdir=terraform output -raw lab_password`.
"""

import re

from .ansible import VULN_PROVIDERS
from .deploy import _PROVIDER_LABEL
from .naming import platform_account
from .terraform.plan import HOST_KINDS
from .validate import Context

PLACEHOLDER = "<<tf:%s:%s>>"

# The canvas words for the trust types whose id is not already a word.
_TRUST_WORDS = {"parent_child": "parent and child", "tree_root": "tree root"}


def briefing_filename(mode):
    """The hand-off file's name, chosen by mode: DEFENSE-BRIEFING.md for a defense
    range, OFFENSE-BRIEFING.md for an offense stack. tf_inventory and the deploy
    script find it by the *-BRIEFING.md glob, so both names carry the same
    address tokens."""
    return "OFFENSE-BRIEFING.md" if mode == "offense" else "DEFENSE-BRIEFING.md"

_KIND_ROLE = {
    "dc": "Domain Controller",
    "srv": "Server",
    "wks": "Workstation",
    "siem": "SIEM",
    "jumpbox": "Jumpbox",
}

# The fallback the dc role sprays onto an account carrying the `weak_password`
# flaw that declares NO password of its own (attack_paths.yml). It is the only
# case that produces a password the document does not already state, and it is
# rare: nearly every flagged GOAD account declares its own credential.
_WEAK_PASSWORD = "Summer2024!"


def logon_bot_minutes(vulns_vars):
    """The logon bot's interval as host_vulns/tasks/rdp_scheduler.yml reads
    bot_interval_minutes: a whole number from 1 up, capped at Task Scheduler's
    31 days, and anything else the default 3."""
    raw = str((vulns_vars or {}).get("bot_interval_minutes", 3)).strip()
    if not re.fullmatch(r"[0-9]+", raw) or int(raw) < 1:
        return 3
    return min(int(raw), 44640)


# The providers that boot a Windows 10 or 11 build as a client edition. GCP and
# AWS boot Server 2022 for it (validate.py CAP005).
CLIENT_IMAGE_PROVIDERS = ("azure", "proxmox", "esxi")
_CLIENT_BUILDS = ("windows_10", "windows_11")


def console_signin_user(overlay, provider):
    """The user host_vulns/tasks/console_signin.yml signs in at the console at
    boot, or None. Windows 10 and 11 run a user's scheduled tasks only after a
    console sign-in, so a client build on a provider that boots one, with a bot
    or the stored credential running as a user, gets it. The role picks the
    same user in the same order; a host with the autologon vuln signs in that
    vuln's user instead."""
    ov = overlay or {}
    if provider not in CLIENT_IMAGE_PROVIDERS or ov.get("os") not in _CLIENT_BUILDS:
        return None
    vulns = [v for v in (ov.get("vulns") or [])
             if provider in VULN_PROVIDERS.get(v, (provider,))]
    if "autologon" in vulns:
        return None
    vv = ov.get("vulns_vars") if isinstance(ov.get("vulns_vars"), dict) else {}
    sub = lambda key: vv.get(key) if isinstance(vv.get(key), dict) else {}
    bot = vv.get("bot_user")
    for vuln, user in (("rdp_scheduler", bot),
                       ("stored_credential", sub("stored_credential").get("owner")),
                       ("schedule", sub("schedule").get("user")),
                       ("responder", bot),
                       ("ntlm_relay", vv.get("ntlm_relay_user") or bot)):
        if vuln in vulns and isinstance(user, str) and user.strip():
            return user.strip()
    return None


def _briefing_password(user):
    """The credential the dc role actually seeds for a user, stated the same way
    the role decides it (dc/tasks/main.yml + attack_paths.yml), so the briefing
    matches the deployed range rather than guessing from flaws.

    1. A declared `password` is the lab's documented credential and wins outright
       -- the role enforces it every run, and the weak-password step explicitly
       skips any account that declares one. These are already public in the
       shipped vars/domains/*.yml, so naming them here reveals nothing new and
       makes the briefing a usable hand-off.
    2. Otherwise, an account flagged `weak_password` gets its `weak_password`
       value or the Summer2024! fallback -- exactly the role's condition.
    3. Otherwise the account has the shared lab password.
    """
    declared = user.get("password")
    if declared:
        return "`%s`" % declared
    if "weak_password" in (user.get("flaws") or []):
        return "`%s`" % (user.get("weak_password") or _WEAK_PASSWORD)
    return "lab password"


def _tok(ctx, node_id, field):
    return PLACEHOLDER % (ctx.name(node_id), field)


def _cell(value):
    """A value safe to drop in a markdown table cell: a literal pipe would start a
    new column and a newline a new row, so both are neutralised. Operator handles
    and roles are validated (VPN005/VPN006), this is the second line of defence."""
    return str(value).replace("|", r"\|").replace("\r", " ").replace("\n", " ")


def _domain_of(ctx, host_id):
    for e in ctx.by_role.get("joins", []):
        if e["source"] == host_id and ctx.kind(e["target"]) == "domain":
            return e["target"]
    return None


def _dc_of(ctx, domain_id):
    for e in ctx.by_role.get("joins", []):
        if e["target"] == domain_id and ctx.kind(e["source"]) == "dc":
            return e["source"]
    return None


def range_briefing(document, registry=None, provider=None):
    ctx = Context(document, registry)
    account = platform_account(document.get("mode"))
    # Assumed-breach foothold users: patient zero, a jumpbox local admin
    # and a low-priv domain member at once.
    breach = [(u["username"], (d.get("overlay") or {}).get("fqdn"))
              for d in ctx.of_kind("domain")
              for u in ((d.get("overlay") or {}).get("users") or [])
              if u.get("assumed_breach")]
    is_offense = document.get("mode") == "offense"
    noun = "stack" if is_offense else "range"
    name = document.get("name") or ("redStackPRO offense" if is_offense
                                    else "redStackPRO range")
    lines = [
        "# %s - %s Briefing" % (name, "Offense" if is_offense else "Defense"),
        "",
        "Generated by redStackPRO. Addresses fill in after `terraform apply`,",
        "when `tf_inventory.py` resolves the address placeholders.",
        "The shared lab password is generated at apply and lives only in your",
        "state: read it with `terraform -chdir=terraform output -raw lab_password`.",
    ]

    jumps = ctx.of_kind("jumpbox")
    jump = jumps[0] if jumps else None

    # -- The access model, stated up front so the briefing reads the same on
    # every provider.
    if jump and is_offense:
        # A redirector on an internet-exposed segment takes a public address too,
        # so the jumpbox is not the only public host when one is present.
        public_rdr = any(ctx.public_address(r["id"])
                         for r in ctx.of_kind("redirector"))
        if public_rdr:
            intro = (
                "This is your attack infrastructure. The jumpbox and the "
                "redirectors are the internet-facing hosts: the jumpbox is your "
                "way in and each redirector is a public C2 front door. The "
                "teamservers, collector and operator boxes are private (no public "
                "IP), reachable only from the jumpbox or from inside the stack's "
                "own subnet.")
        else:
            intro = (
                "This is your attack infrastructure. The jumpbox is the only host "
                "with a public address and your way in; the teamservers, collector "
                "and operator boxes are private (no public IP), reachable only "
                "from the jumpbox or from inside the stack's own subnet.")
        lines += [
            "", "## The access model", "",
            intro,
            "",
            "- **Get in** at the Guacamole portal: every box is a tile, Windows "
            "over RDP and Linux over SSH, each one a click. Jumpbox SSH stays "
            "available for scripting and `ProxyJump`, but the portal is the "
            "intended path.",
            "- **Redirectors front your C2.** A beacon on a target calls the "
            "redirector's address, which forwards to the teamserver; the "
            "teamserver itself is never exposed.",
            "- **No direct path** from your machine to a backend host: management "
            "and C2 both route through the jumpbox and the redirectors.",
        ]
    elif jump:
        lines += [
            "", "## The access model", "",
            "This range is built for an **external red team POV**. The jumpbox is "
            "the only host with a public address and your single initial-access "
            "foothold; every other host is private (no public IP) and reachable "
            "only from the jumpbox or from inside the range subnet.",
            "",
            "- **Get in** at the Guacamole portal. That is the way in for this "
            "range: every host is a tile, Windows over RDP and Linux over SSH, "
            "and each one opens on a click. Jumpbox SSH stays available for "
            "scripting and `ProxyJump`, but the portal is the intended path.",
            "- **No direct path** from your machine to a backend host: management "
            "and attack traffic both route through the jumpbox, and there is no "
            "peering into the range.",
            "- **C2 rides outbound** (HTTPS or DNS) from a compromised host to the "
            "redirector; nothing calls back into the range.",
        ]
        if breach:
            lines.append(
                "- **Patient zero** is the assumed-breach foothold under Access "
                "below: a low-priv domain member you already hold. Open its RDP "
                "tile in the portal to work as that user, drop your beacon onto "
                "the mapped `redstackpro` drive, and run it there. The beacon "
                "then lives in patient zero's context, which is where the "
                "engagement starts.")

    # -- Access
    lines += ["", "## Access", ""]
    if jump:
        addr = _tok(ctx, jump["id"], "public_address")
        lines += [
            "- **Guacamole portal:** https://%s/guacamole" % addr,
            "- **Portal login:** `%s` / the lab password "
            "(`terraform -chdir=terraform output -raw lab_password`)" % account,
            "- **Jumpbox SSH:** `ssh -i keys/id_ed25519 %s@%s`" % (account, addr),
            "- Every box is reachable from the portal (Windows over RDP, Linux "
            "over SSH) and from any host on the %s subnet." % noun,
        ]
        for user, dom in breach:
            lines.append(
                "- **Assumed-breach foothold:** patient zero is `%s`, a low-priv "
                "`%s` domain member. Its portal tile logs straight in as that "
                "user with the lab password. The same name is also a local admin "
                "on the jumpbox, but jumpbox SSH is key-only, so that password "
                "opens the domain identity, not a shell here." % (user, dom))
    else:
        lines.append("- No jumpbox in this %s." % noun)

    # -- Shared credentials. An offense stack has no domains or lab users, and a
    # Windows operator box takes the password on the platform account: its boot
    # script sets the Administrator password only on a range.
    if is_offense:
        win_ops = any(str(ctx.overlay(o["id"], "os", "") or "").startswith("windows")
                      for o in ctx.of_kind("operator"))
        covers = (["and Guacamole portal), including its account on each",
                   "Windows operator box."] if win_ops else ["and Guacamole portal)."])
    else:
        covers = ["and Guacamole portal), the built-in / domain **Administrator** on every",
                  "Windows box, and every lab user below unless a flaw makes it weak."]
    lines += [
        "", "## Credentials", "",
        "One shared **lab password** covers `%s` (the platform account: SSH admin" % account,
    ] + covers + [
        "Get it with `terraform -chdir=terraform output -raw lab_password`.",
    ]

    # -- C2 redirectors and payload details (offense only). Everything an operator
    # needs to point a beacon at a front door: the callback domain, the gating
    # header the payload must carry to be forwarded rather than shown the decoy, and
    # each teamserver's URI prefix. The gating value is materialized at compile in
    # export.compile_topology, so it matches the value in ansible/host_vars. Confirm
    # the route with `python verify.py doors .` or `sudo rsp-check` on the redirector.
    redirectors = ctx.of_kind("redirector") if is_offense else []
    if redirectors:
        lines += ["", "## C2 redirectors & payloads", ""]
        lines.append(
            "A beacon reaches a teamserver by calling a redirector's domain under a "
            "teamserver's URI prefix while carrying the gating header below. A "
            "request missing any of the three is served the decoy site and never "
            "forwarded.")
        for rdr in redirectors:
            rid = rdr["id"]
            domain = ctx.overlay(rid, "hostname", "") or "(set the redirector domain on the canvas)"
            gating = ctx.overlay(rid, "gating", {}) or {}
            header_name = gating.get("header_name") or "X-Request-Id"
            header_value = gating.get("header_value") or "(generated at apply)"
            routes = [(ctx.name(e["target"]), e.get("uri_prefix"))
                      for e in ctx.by_role.get("fronts", [])
                      if e["source"] == rid and e.get("uri_prefix")]
            lines += ["", "### %s" % ctx.name(rid), ""]
            lines += [
                "- **Callback domain:** `%s`" % domain,
                "- **Gating header:** `%s: %s`" % (header_name, header_value),
            ]
            if routes:
                lines.append("- **Routes:**")
                for name, prefix in sorted(routes):
                    prefix = "/" + prefix.strip("/")
                    lines.append("  - `%s/` -> %s  (call `https://%s%s/...`)"
                                 % (prefix, name, domain, prefix))

    # -- Operators and VPN access (offense only). The roster and the VPN access mode
    # are offense concepts; a defense range ignores them (VPN002), so the section is
    # rendered only for an offense stack that declared either. Each operator gets a
    # personal portal account, and on a VPN access mode a personal credential the
    # jumpbox generates during provisioning; this names where to fetch each one.
    if jump and document.get("mode") == "offense":
        jov = jump.get("overlay", {}) or {}
        operators = jov.get("operators") or []
        vpn_mode = jov.get("access_mode", "public")
        is_vpn = vpn_mode in ("wireguard", "openvpn")
        if operators or is_vpn:
            addr = _tok(ctx, jump["id"], "public_address")
            vpn_dir = "/opt/redstackpro/vpn"
            lines += ["", "## Operators & VPN access", ""]
            ext = None
            if is_vpn:
                ext = "conf" if vpn_mode == "wireguard" else "ovpn"
                proto = "udp" if vpn_mode == "wireguard" \
                    else jov.get("vpn_protocol", "udp")
                port = jov.get("vpn_port") or \
                    {"wireguard": 51820, "openvpn": 1194}[vpn_mode]
                lines += [
                    "This stack fronts the team over a **%s** VPN. Each operator "
                    "has a personal portal account and a personal VPN credential, "
                    "generated on the jumpbox during provisioning; the keys never enter the "
                    "export, so fetch each operator's file from the jumpbox and hand it to "
                    "that operator." % vpn_mode,
                    "",
                    "- **VPN endpoint:** `%s:%s/%s`" % (addr, port, proto),
                    "- **Fetch a credential:** `scp -i keys/id_ed25519 %s@%s:%s/<handle>.%s .`" % (
                        account, addr, vpn_dir, ext),
                ]
            else:
                lines.append(
                    "Each operator has a personal portal account; access is the "
                    "shared public portal (no VPN).")
            header = "| Operator | Role | Portal account |"
            rule = "| --- | --- | --- |"
            if ext:
                header += " VPN credential (on the jumpbox) |"
                rule += " --- |"
            lines += ["", header, rule]
            if operators:
                for op in operators:
                    handle = _cell(op.get("handle", "-"))
                    row = "| %s | %s | `%s` / lab password |" % (
                        handle, _cell(op.get("role", "-")), handle)
                    if ext:
                        row += " `%s/%s.%s` |" % (vpn_dir, handle, ext)
                    lines.append(row)
            else:
                row = "| (none declared) | - | shared `%s` only |" % account
                if ext:
                    row += " - |"
                lines.append(row)

    # -- Hosts. Only what Terraform builds: a fw or appliance node gets no
    # machine, and its address token would never fill.
    hosts = sorted((h for h in ctx.hosts() if h["kind"] in HOST_KINDS),
                   key=lambda n: (n["kind"], n["id"]))
    unbuilt = sorted(h["id"] for h in ctx.hosts() if h["kind"] not in HOST_KINDS)
    lines += ["", "## Hosts (%d)" % len(hosts), "",
              "| Host | Role | OS | Domain | Address | EDR |",
              "| --- | --- | --- | --- | --- | --- |"]
    for h in hosts:
        ov = h.get("overlay", {})
        role = _KIND_ROLE.get(h["kind"], h["kind"])
        if h["kind"] == "siem" and ov.get("product"):
            role = "SIEM (%s)" % ov["product"]
        elif ov.get("role") and ov["role"] != "generic":
            role = "%s (%s)" % (role, ov["role"])
        services = ov.get("services") or []
        if services:
            role = "%s [%s]" % (role, ", ".join(services))
        dom_id = _domain_of(ctx, h["id"])
        domain = ctx.overlay(dom_id, "fqdn", "-") if dom_id else "-"
        public = h["kind"] == "jumpbox" or (
            is_offense and h["kind"] == "redirector" and ctx.public_address(h["id"]))
        field = "public_address" if public else "private_address"
        addr = _tok(ctx, h["id"], field)
        if is_offense:
            hostname = ctx.name(h["id"])
            if h["kind"] == "redirector" and ov.get("hostname"):
                hostname = "%s (%s)" % (hostname, ov["hostname"])
        else:
            hostname = ov.get("hostname", h["id"])
        edr = ov.get("edr", "-")
        # edr is a label; only defender_enabled turns Defender's real-time
        # protection on (host_vulns), so say when the label overstates it.
        if edr == "defender" and not ov.get("defender_enabled"):
            edr = "defender (off)"
        lines.append("| %s | %s | %s | %s | %s | %s |" % (
            hostname, role, ov.get("os", "-"), domain, addr, edr))
    if unbuilt:
        lines += ["", "Not built by this release (on the canvas only): %s."
                  % ", ".join(unbuilt)]

    # -- Domains and trusts
    domains = ctx.of_kind("domain")
    if domains:
        lines += ["", "## Domains & trusts", ""]
        trusts = ctx.by_role.get("trusts", [])
        for d in sorted(domains, key=lambda n: ctx.overlay(n["id"], "fqdn", "")):
            fqdn = ctx.overlay(d["id"], "fqdn", d["id"])
            netbios = ctx.overlay(d["id"], "netbios", "")
            dc = _dc_of(ctx, d["id"])
            dc_name = ctx.overlay(dc, "hostname", dc) if dc else "-"
            lines.append("- **%s**%s - DC `%s`" % (
                fqdn, (" (%s)" % netbios) if netbios else "", dc_name))
            for t in trusts:
                if t["source"] == d["id"]:
                    tgt = ctx.overlay(t["target"], "fqdn", t["target"])
                    lines.append("    - trusts **%s** (%s%s)" % (
                        tgt, _TRUST_WORDS.get(t.get("trust_type"), t.get("trust_type", "trust")),
                        ", transitive" if t.get("transitive") else ""))

    # -- Domain users
    user_domains = [d for d in domains if ctx.overlay(d["id"], "users")]
    if user_domains:
        lines += ["", "## Domain users", ""]
        for d in sorted(user_domains,
                        key=lambda n: ctx.overlay(n["id"], "fqdn", "")):
            fqdn = ctx.overlay(d["id"], "fqdn", d["id"])
            users = ctx.overlay(d["id"], "users") or []
            lines += ["", "### %s (%d users)" % (fqdn, len(users)), "",
                      "| User | Name | Privilege | Groups | Flaws | Password |",
                      "| --- | --- | --- | --- | --- | --- |"]
            for u in users:
                flaws = u.get("flaws") or []
                pw = _briefing_password(u)
                lines.append("| %s | %s | %s | %s | %s | %s |" % (
                    u.get("username", "-"),
                    u.get("display_name", u.get("username", "-")),
                    u.get("privilege", "user"),
                    ", ".join(u.get("groups") or []) or "-",
                    ", ".join(flaws) or "-",
                    pw))

    # -- Attack surface. A vuln the compiler drops for this provider (see
    # ansible.VULN_PROVIDERS) is marked rather than listed as planted.
    def _vuln_label(vuln):
        allowed = VULN_PROVIDERS.get(vuln)
        if allowed and provider not in allowed:
            return "%s (not on %s)" % (vuln, _PROVIDER_LABEL.get(provider, provider) or "this provider")
        return vuln

    # -- User activity: the bots, so an operator knows whose credentials sit on
    # which host, and when. Defaults mirror the host_vulns task files.
    def _not_here(vuln):
        allowed = VULN_PROVIDERS.get(vuln)
        return bool(allowed and provider not in allowed)

    activity = []
    for h in hosts:
        ov = h.get("overlay", {}) or {}
        vulns = ov.get("vulns") or []
        vv = ov.get("vulns_vars") if isinstance(ov.get("vulns_vars"), dict) else {}
        name = ov.get("hostname", h["id"])
        if "rdp_scheduler" in vulns and vv.get("bot_user"):
            activity.append((name, "logon bot (connect_bot)", vv["bot_user"],
                             "logs on and maps \\\\localhost\\C$, so the credentials "
                             "stay in memory", "%d min" % logon_bot_minutes(vv),
                             "rdp_scheduler"))
        if "schedule" in vulns:
            s = vv.get("schedule") if isinstance(vv.get("schedule"), dict) else {}
            cmd = s.get("command") or "Start-Sleep -Seconds 5"
            activity.append((name, "scheduled task (%s)" % (s.get("name") or "schedule_bot"),
                             s.get("user") or "SYSTEM", "runs `%s`" % cmd,
                             "%s min" % (s.get("interval_minutes") or 1), "schedule"))
        if "responder" in vulns and vv.get("bot_user"):
            activity.append((name, "share-browsing bot (responder_bot)", vv["bot_user"],
                             "opens %s, a name that does not resolve"
                             % (vv.get("responder_target") or "\\\\Bravos\\private"),
                             "2 min", "responder"))
        relay_user = vv.get("ntlm_relay_user") or vv.get("bot_user")
        if "ntlm_relay" in vulns and relay_user:
            activity.append((name, "relay bot (ntlm_bot)", relay_user,
                             "authenticates to %s"
                             % (vv.get("ntlm_relay_target") or "\\\\Meren\\Private"),
                             "5 min", "ntlm_relay"))
        sc = vv.get("stored_credential") if isinstance(vv.get("stored_credential"), dict) else {}
        if "stored_credential" in vulns and sc.get("owner"):
            activity.append((name, "saved credential", sc["owner"],
                             "vault holds %s for %s" % (
                                 sc.get("username") or "-",
                                 sc.get("target") or "TERMSRV/castelblack"),
                             "set once", "stored_credential"))
        signin = console_signin_user(ov, provider)
        if signin:
            activity.append((name, "console sign-in", signin,
                             "signed in at the console at boot, so its scheduled "
                             "tasks run", "at boot", None))
    if activity:
        lines += ["", "## User activity", "",
                  "Activity on each host that runs by itself (bots on a timer, saved "
                  "credentials, users signed in at the console), so their credentials and "
                  "authentication are there to capture.", "",
                  "| Host | Activity | Runs as | What it does | Every |",
                  "|---|---|---|---|---|"]
        for host, what, who, does, every, vuln in activity:
            if _not_here(vuln):
                does = "not planted on %s" % (_PROVIDER_LABEL.get(provider, provider) or "this provider")
            lines.append("| %s | %s | %s | %s | %s |" % (
                _cell(host), _cell(what), _cell(who), _cell(does), _cell(every)))

    host_vulns = [(h, [_vuln_label(v) for v in
                       (h.get("overlay", {}).get("vulns") or [])])
                  for h in hosts]
    host_vulns = [(h, v) for h, v in host_vulns if v]
    acl_domains = [d for d in domains if ctx.overlay(d["id"], "acls")]
    if host_vulns or acl_domains:
        lines += ["", "## Planted attack surface", ""]
        for h, v in host_vulns:
            hostname = h.get("overlay", {}).get("hostname", h["id"])
            lines.append("- **%s** host vulns: %s" % (hostname, ", ".join(v)))
        for d in acl_domains:
            fqdn = ctx.overlay(d["id"], "fqdn", d["id"])
            acls = ctx.overlay(d["id"], "acls") or []
            lines.append("- **%s** ACL chains (%d): %s" % (
                fqdn, len(acls),
                "; ".join("%s -%s-> %s" % (
                    a.get("principal", "?"), a.get("right", "?"),
                    a.get("target", "?")) for a in acls[:12])
                + (" ..." if len(acls) > 12 else "")))

    # -- SIEM
    siems = ctx.of_kind("siem")
    if siems:
        lines += ["", "## SIEM dashboards", ""]
        for s in siems:
            product = ctx.overlay(s["id"], "product", "")
            addr = _tok(ctx, s["id"], "private_address")
            if product in ("elk", "elasticsearch"):
                lines.append("- **Kibana (ELK):** http://%s:5601 (open, no login)"
                             % addr)
            elif product == "wazuh":
                lines.append("- **Wazuh dashboard:** https://%s - login `admin` "
                             "(the lab password with every character that is not "
                             "a letter, digit, or one of `. * + ? -` replaced by "
                             "`-`, per Wazuh's password charset rule)" % addr)
            else:
                lines.append("- **%s:** %s" % (product or "SIEM", addr))
        lines.append("- Every Windows host ships to each SIEM the range has "
                     "(Winlogbeat to ELK, the Wazuh agent to Wazuh).")

    return "\n".join(lines) + "\n"
