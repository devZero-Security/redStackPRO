#!/usr/bin/env python3
"""Check that an Azure subscription can take this export, before terraform apply.

    python azure_preflight.py [export_dir]
    python azure_preflight.py [export_dir] --brief

deploy.sh runs it with --brief after terraform init: a pass prints any warnings
and one `summary:` line, and a failure prints the full table as without it. It asks the subscription what an apply
would otherwise find out halfway through: whether each VM size is offered here
and not restricted for this subscription, whether the regional and per-family
vCPU quotas have room, whether the public IP quota has room, whether the
resource providers the HCL needs are registered, and whether the resource group
it would create already exists outside this export's state.

Read only, stdlib only. The hosts and roles come from terraform/preflight.json,
written at compile. The effective size per role comes from terraform itself
(`terraform console` on local.vm_sizes, the defaults merged with vm_sizes), so it
is the value apply will use whichever file or variable set it; when terraform
cannot answer, vm_sizes is read from deploy.tfvars instead.

Exit 0 when nothing blocks the apply (warnings included), 1 when something does.
A check that cannot run (no network, a 403, no credentials) warns and passes:
the checker's own failure must not block a deploy that may be fine, and apply
still reports the real limit. REDSTACKPRO_SKIP_PREFLIGHT=1 skips every check.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ARM = "https://management.azure.com"
RESOURCE_GROUP_API = "2021-04-01"
SKU_API = "2021-07-01"
COMPUTE_USAGE_API = "2023-07-01"
NETWORK_USAGE_API = "2023-09-01"
PROVIDER_API = "2021-04-01"
TIMEOUT = 60

# Network usage counters that bound the public IPs this export creates. Free
# subscriptions cap these at 3 per region (PublicIPCountLimitReached).
PUBLIC_IP_COUNTERS = ("publicipaddresses", "standardskupublicipaddresses")

VM_TYPES = ("azurerm_linux_virtual_machine", "azurerm_windows_virtual_machine")

SKIP_ENV = "REDSTACKPRO_SKIP_PREFLIGHT"


class ApiError(Exception):
    """One Azure call did not complete. Reported as a warning, never a pass.
    status is the HTTP code when there was one, so a 404 can mean "absent"."""

    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


# ---------------------------------------------------------------- http


def _http(method, url, headers=None, body=None):
    req = urllib.request.Request(url, data=body, method=method,
                                 headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as exc:
        code = ""
        try:
            err = json.loads(exc.read().decode("utf-8")).get("error")
            code = err.get("code", "") if isinstance(err, dict) else str(err or "")
        except (ValueError, AttributeError, OSError):
            pass
        raise ApiError("HTTP %d %s" % (exc.code, code), status=exc.code) from None
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise ApiError(str(getattr(exc, "reason", exc))) from None


class Azure:
    """Authenticated GETs against ARM, following nextLink pages."""

    def __init__(self, token, http=_http):
        self.token = token
        self.http = http

    def get(self, path, **params):
        url = path if path.startswith("http") else ARM + path
        if params:
            url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
        return self.http("GET", url, {"Authorization": "Bearer " + self.token})

    def get_all(self, path, **params):
        page = self.get(path, **params)
        values = list(page.get("value", []))
        while page.get("nextLink"):
            page = self.get(page["nextLink"])
            values.extend(page.get("value", []))
        return values


# ---------------------------------------------------------------- auth


def get_token(env, http=_http, run=subprocess.run):
    """(token, how) or (None, why). The service principal goes first when its
    three variables are all set, because azurerm prefers it over an az login
    too, so the check asks as the identity apply will run as."""
    tried = []
    if all(env.get(k) for k in ("ARM_CLIENT_ID", "ARM_CLIENT_SECRET", "ARM_TENANT_ID")):
        body = urllib.parse.urlencode({
            "client_id": env["ARM_CLIENT_ID"],
            "client_secret": env["ARM_CLIENT_SECRET"],
            "scope": ARM + "/.default",
            "grant_type": "client_credentials",
        }).encode()
        url = ("https://login.microsoftonline.com/%s/oauth2/v2.0/token"
               % urllib.parse.quote(env["ARM_TENANT_ID"]))
        try:
            token = http("POST", url, {"Content-Type":
                                       "application/x-www-form-urlencoded"},
                         body).get("access_token")
            if token:
                return token, "service principal (ARM_CLIENT_ID)"
            tried.append("service principal: no token in the response")
        except ApiError as exc:
            tried.append("service principal: %s" % exc)
    az = shutil.which("az")
    if az:
        try:
            done = run([az, "account", "get-access-token", "--resource", ARM + "/",
                        "--query", "accessToken", "-o", "tsv"],
                       capture_output=True, text=True, timeout=TIMEOUT)
            token = (done.stdout or "").strip()
            if done.returncode == 0 and token:
                return token, "az login"
            tried.append("az: not logged in")
        except (OSError, subprocess.TimeoutExpired) as exc:
            tried.append("az: %s" % exc)
    if not tried:
        tried.append("no az login and no ARM_CLIENT_ID/ARM_CLIENT_SECRET/ARM_TENANT_ID")
    return None, "; ".join(tried)


# ---------------------------------------------------------------- settings


def _strip_comments(text):
    """HCL comments out, strings left intact: #, // and /* */."""
    out, i, n, in_str = [], 0, len(text), False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 1
            elif c == '"':
                in_str = False
        elif c == '"':
            in_str = True
            out.append(c)
        elif c == "#" or text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
            continue
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 2
            continue
        else:
            out.append(c)
        i += 1
    return "".join(out)


def read_tfvars(path):
    """The values the preflight needs from a tfvars file: subscription_id,
    location, resource_group and the vm_sizes map. Anything absent is left
    out."""
    try:
        text = _strip_comments(Path(path).read_text(encoding="utf-8"))
    except OSError:
        return {}
    found = {}
    for key in ("subscription_id", "location", "resource_group"):
        m = re.findall(r'(?m)^\s*%s\s*=\s*"([^"]*)"' % key, text)
        if m:
            found[key] = m[-1]
    blocks = re.findall(r'(?ms)^\s*vm_sizes\s*=\s*\{(.*?)\}', text)
    if blocks:
        found["vm_sizes"] = dict(re.findall(
            r'"?([A-Za-z0-9_.-]+)"?\s*[=:]\s*"([^"]*)"', blocks[-1]))
    return found


def terraform_settings(tfdir, env, run=subprocess.run):
    """vm_sizes (merged), location and subscription_id as terraform resolves
    them, or None when terraform cannot say (not initialised, a variable with no
    value, terraform absent)."""
    expr = ("jsonencode({vm_sizes = local.vm_sizes, location = var.location, "
            "subscription_id = var.subscription_id, "
            "resource_group = var.resource_group})\n")
    try:
        done = run(["terraform", "-chdir=%s" % tfdir, "console"], input=expr,
                   capture_output=True, text=True, timeout=300,
                   env=dict(env, TF_INPUT="0"))
    except (OSError, subprocess.TimeoutExpired):
        return None
    lines = [ln for ln in (done.stdout or "").splitlines() if ln.strip()]
    if done.returncode != 0 or not lines:
        return None
    try:
        value = json.loads(json.loads(lines[-1]))
    except (ValueError, TypeError):
        return None
    if not isinstance(value, dict) or not isinstance(value.get("vm_sizes"), dict):
        return None
    return value


def resolve_settings(root, manifest, env, run=subprocess.run):
    """Effective sizes per role, location, subscription, and where they came from."""
    root = Path(root)
    tf = terraform_settings(root / "terraform", env, run=run)
    if tf is not None:
        sizes = tf["vm_sizes"]
        location = tf.get("location") or ""
        subscription = tf.get("subscription_id") or ""
        resource_group = tf.get("resource_group") or ""
        source = "terraform (defaults merged with vm_sizes)"
    else:
        tfvars = root / "deploy.tfvars"
        if not tfvars.is_file():
            tfvars = root / "terraform" / "terraform.tfvars"
        found = read_tfvars(tfvars)
        sizes = dict(manifest.get("default_vm_sizes", {}), **found.get("vm_sizes", {}))
        location = (found.get("location") or env.get("TF_VAR_location")
                    or manifest.get("default_location", ""))
        subscription = (found.get("subscription_id")
                        or env.get("TF_VAR_subscription_id") or "")
        resource_group = (found.get("resource_group")
                          or env.get("TF_VAR_resource_group")
                          or manifest.get("default_resource_group", ""))
        source = "%s (terraform console did not answer)" % tfvars.name
    # azurerm falls back to ARM_SUBSCRIPTION_ID when subscription_id is empty.
    subscription = subscription or env.get("ARM_SUBSCRIPTION_ID", "")
    return {"sizes": sizes, "location": location, "subscription": subscription,
            "resource_group": resource_group, "source": source}


def state_usage(tfdir):
    """VM sizes and public IP count already in this export's terraform state, so
    a re-run does not count its own running hosts against the quota twice."""
    try:
        state = json.loads((Path(tfdir) / "terraform.tfstate").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return [], 0
    sizes, ips = [], 0
    for res in state.get("resources", []):
        if res.get("mode") != "managed":
            continue
        for inst in res.get("instances", []):
            attrs = inst.get("attributes") or {}
            if res.get("type") in VM_TYPES and attrs.get("size"):
                sizes.append(attrs["size"])
            elif res.get("type") == "azurerm_public_ip":
                ips += 1
    return sizes, ips


def state_resource_groups(tfdir):
    """Lowercased names of the resource groups this export's state owns. Azure
    group names are case-insensitive."""
    try:
        state = json.loads((Path(tfdir) / "terraform.tfstate").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return set()
    return {((inst.get("attributes") or {}).get("name") or "").lower()
            for res in state.get("resources", [])
            if res.get("mode") == "managed"
            and res.get("type") == "azurerm_resource_group"
            for inst in res.get("instances", [])} - {""}


def check_resource_group(az, sub, rg, owned):
    """(fail lines, warning): a group of this name that already exists and is
    not in this export's state would make apply fail, or worse, teardown delete
    another range. Read only."""
    if not rg or rg.lower() in owned:
        return None, None
    try:
        az.get("%s/resourcegroups/%s" % (sub, urllib.parse.quote(rg)),
               **{"api-version": RESOURCE_GROUP_API})
    except ApiError as exc:
        if exc.status == 404:
            return None, None
        return None, "could not check whether resource group %s exists (%s); not checked." % (rg, exc)
    return ["resource group %s already exists. This deploy creates its own; set "
            "another resource_group in deploy.tfvars, or tear down the range "
            "that owns it." % rg], None


# ---------------------------------------------------------------- azure facts


def parse_skus(values, location):
    """{lower(name): sku} for VM sizes, with the restrictions that apply here."""
    loc = location.lower()
    out = {}
    for s in values:
        if s.get("resourceType") != "virtualMachines" or not s.get("name"):
            continue
        caps = {c.get("name"): c.get("value") for c in s.get("capabilities", [])}
        reason, zones = None, []
        for r in s.get("restrictions", []):
            where = [v.lower() for v in (r.get("values") or [])]
            if where and loc not in where:
                continue
            # A Location restriction blocks the size in the region. A Zone one
            # blocks only zonal placement, which this export never asks for, so
            # it is a caveat rather than a failure (az vm list-skus agrees).
            if r.get("type") == "Location":
                reason = r.get("reasonCode") or "restricted"
            elif r.get("type") == "Zone":
                zones += (r.get("restrictionInfo") or {}).get("zones") or []
        try:
            vcpus = int(caps.get("vCPUs"))
        except (TypeError, ValueError):
            vcpus = None
        try:
            memory = float(caps.get("MemoryGB"))
        except (TypeError, ValueError):
            memory = None
        out[s["name"].lower()] = {
            "name": s["name"],
            "family": s.get("family") or "",
            "vcpus": vcpus,
            "memory": memory,
            "restricted": reason,
            "zones_restricted": sorted(set(zones)),
            "gen2": "V2" in (caps.get("HyperVGenerations") or "V2"),
            # Never suggested: the images are x64 and not confidential-VM builds.
            "special": bool(caps.get("ConfidentialComputingType")
                            or caps.get("GPUs") not in (None, "0")
                            or (caps.get("CpuArchitectureType") or "x64") != "x64"),
        }
    return out


def parse_usages(values):
    """{lower(name.value): (label, current, limit)}."""
    out = {}
    for u in values:
        name = u.get("name") or {}
        key = (name.get("value") or "").lower()
        if key:
            out[key] = (name.get("localizedValue") or name.get("value"),
                        int(u.get("currentValue", 0)), int(u.get("limit", 0)))
    return out


_SIZE = re.compile(r"(?i)^standard_([a-z]+)(\d+)([a-z]*)(?:_v(\d+))?$")


def _parts(size):
    """Standard_D2as_v5 -> ("D", 2, "as", 5)."""
    m = _SIZE.match(size)
    if not m:
        return "", None, "", 0
    return (m.group(1)[0].upper(), int(m.group(2)), m.group(3).lower(),
            int(m.group(4) or 1))


# Burstable B is general purpose; its nearest non-burstable series is D.
_SERIES_ALIAS = {"B": "D"}


def _series(size):
    s = _parts(size)[0]
    return _SERIES_ALIAS.get(s, s)


def ref_memory(skus, vcpus, like):
    """Memory of `like`, or 4 GB per vCPU (the ratio every default size has) when
    the subscription's SKU list does not report it."""
    return (skus.get(like.lower()) or {}).get("memory") or 4 * vcpus


def candidates(skus, vcpus, like):
    """Sizes this subscription can use here in the same vCPU class, safest and
    closest to `like` first: no zone restriction, at least its memory, same
    series, nearest memory, same feature letters, newest version."""
    memory = ref_memory(skus, vcpus, like)
    series, feats = _series(like), _parts(like)[2]
    pool = [s for s in skus.values()
            if s["vcpus"] == vcpus and not s["restricted"] and s["gen2"]
            and not s["special"] and "-" not in s["name"]
            and "promo" not in s["name"].lower()
            and not re.match(r"(?i)standard_(dc|ec|n)", s["name"])]
    return sorted(pool, key=lambda s: (
        bool(s["zones_restricted"]),
        (s["memory"] or 0) < memory,
        _series(s["name"]) != series,
        abs((s["memory"] or 0) - memory),
        _parts(s["name"])[2] != feats,
        -_parts(s["name"])[3],
        len(s["name"]), s["name"]))


# ---------------------------------------------------------------- the checks


def _row(key, label, need, used, limit):
    need = max(need, 0)
    return {"key": key, "label": label, "need": need, "used": used,
            "limit": limit, "gap": used + need - limit}


def assess(manifest, settings, skus, compute, network, providers, state):
    """Pure: every fact in, (lines, fails, fix, warns, summary) out. A fail is
    a list of lines, the first saying what is wrong. fix is the vm_sizes change
    that clears the size and family failures, when there is one. summary is the
    one line deploy.sh shows for a pass."""
    location, sizes = settings["location"], settings["sizes"]
    defaults = manifest.get("default_vm_sizes", {})
    existing_sizes, existing_ips = state
    lines, fails, fix, warns = [], [], [], []

    roles = {}
    for h in manifest.get("hosts", []):
        roles.setdefault(h["role"], []).append(h["name"])
    for key in sorted(set(sizes) - set(roles)):
        warns.append("vm_sizes names %r, which is no role in this topology "
                     "(roles: %s); it changes nothing." % (key, ", ".join(sorted(roles))))

    def size_of(role):
        return sizes.get(role) or defaults.get(role, "")

    def sku_of(size):
        return (skus or {}).get(size.lower())

    # -- sizes
    bad, zonal = {}, set()
    if skus is not None:
        lines.append("   %-11s %5s  %-18s %4s  %-24s %s"
                     % ("role", "hosts", "size", "vCPU", "family", "here"))
        for role in sorted(roles):
            size = size_of(role)
            sku = sku_of(size)
            if sku is None:
                status = "not offered"
                bad[size] = "is not offered in %s" % location
            elif sku["restricted"]:
                status = "not available (%s)" % sku["restricted"]
                bad[size] = "is not available to this subscription in %s (%s)" % (
                    location, sku["restricted"])
            elif not sku["gen2"]:
                status = "Gen1 only"
                bad[size] = "runs only Gen1 VMs, and the images are Gen2"
            else:
                status = "ok"
            if status == "ok" and sku["zones_restricted"]:
                status = "ok, regional only"
                zonal.add(size)
            lines.append("   %-11s %5d  %-18s %4s  %-24s %s" % (
                role, len(roles[role]), size, sku["vcpus"] if sku else "?",
                sku["family"] if sku else "?", status))
        lines.append("")
        for size in sorted(zonal):
            sku = sku_of(size)
            safer = [c["name"] for c in candidates(skus, sku["vcpus"], size)
                     if not c["zones_restricted"]][:3]
            warns.append(
                "%s is restricted for this subscription in zones %s of %s. A VM "
                "with no zone, which is what this export creates, is normally "
                "still allowed; if apply stops with SkuNotAvailable, use a size "
                "with no restriction here%s." % (
                    size, ",".join(sku["zones_restricted"]), location,
                    ", for example " + ", ".join(safer) if safer else ""))

    # -- quota: what this apply adds, net of what its own state already holds.
    # A size that cannot be used here is left out of its family (it has to
    # change anyway) but still counts toward the regional total.
    rows = []
    if skus is not None and compute is not None:
        need_fam, need_total = {}, 0
        for role, hosts in roles.items():
            sku = sku_of(size_of(role))
            if not sku or not sku["vcpus"]:
                continue
            n = sku["vcpus"] * len(hosts)
            need_total += n
            if size_of(role) not in bad:
                fam = sku["family"].lower()
                need_fam[fam] = need_fam.get(fam, 0) + n
        for size in existing_sizes:
            sku = sku_of(size)
            if sku and sku["vcpus"]:
                fam = sku["family"].lower()
                need_fam[fam] = need_fam.get(fam, 0) - sku["vcpus"]
                need_total -= sku["vcpus"]
        if "cores" in compute:
            rows.append(_row("cores", "Total Regional vCPUs", need_total,
                             *compute["cores"][1:]))
        else:
            warns.append("Azure returned no regional vCPU quota; not checked.")
        for fam in sorted(need_fam):
            if need_fam[fam] <= 0:
                continue
            if fam in compute:
                rows.append(_row(fam, compute[fam][0], need_fam[fam], *compute[fam][1:]))
            else:
                warns.append("no vCPU quota entry for %s; not checked." % fam)
    if network is not None:
        ip_need = (sum(1 for h in manifest.get("hosts", []) if h.get("public_ip"))
                   + int(manifest.get("nat_public_ips", 0)) - existing_ips)
        for key in PUBLIC_IP_COUNTERS:
            if key in network:
                rows.append(_row(key, network[key][0], ip_need, *network[key][1:]))
    # The summary names the vCPU quota with the least room left after apply.
    hosts = manifest.get("hosts", [])
    used = sorted({size_of(h["role"]) for h in hosts if size_of(h["role"])})
    summary = "%d VM%s" % (len(hosts), "" if len(hosts) == 1 else "s")
    if used:
        summary += " on " + (", ".join(used) if len(used) <= 2 else "%d sizes" % len(used))
    vcpu = [r for r in rows if r["key"] not in PUBLIC_IP_COUNTERS and r["limit"]]
    if vcpu:
        tight = max(vcpu, key=lambda r: (r["used"] + r["need"]) / float(r["limit"]))
        summary += ", quota %d of %d vCPU" % (tight["used"] + tight["need"], tight["limit"])
    if rows:
        lines.append("   %-34s %5s %6s %6s  %s" % ("quota", "need", "used", "limit", "status"))
        for r in rows:
            lines.append("   %-34s %5d %6d %6d  %s" % (
                r["label"][:34], r["need"], r["used"], r["limit"],
                "ok" if r["gap"] <= 0 else "SHORT by %d" % r["gap"]))
        if existing_sizes or existing_ips:
            lines.append("   (need leaves out the %d VMs and %d public IPs this "
                         "export's state already holds)" % (len(existing_sizes), existing_ips))
        lines.append("")

    # -- the failures, each with what to change
    for size, why in sorted(bad.items()):
        users = [r for r in sorted(roles) if size_of(r) == size]
        sku = sku_of(size)
        each = (sku and sku["vcpus"]) or _parts(size)[1] or 0
        alts = [c["name"] for c in candidates(skus, each, size)][:6]
        fails.append([
            "%s %s. Roles using it: %s." % (size, why, ", ".join(users)),
            "%d-vCPU sizes it can use here: %s" % (each, ", ".join(alts) or "none"),
        ])
    short_fams = set()
    for r in rows:
        if r["gap"] <= 0:
            continue
        if r["key"] == "cores":
            fails.append([
                "Total Regional vCPUs quota is short: this apply needs %d, %d of %d "
                "are in use (short by %d)." % (r["need"], r["used"], r["limit"], r["gap"]),
                "Request a regional vCPU quota increase (Azure portal, Quotas > "
                "Compute, location %s), use smaller sizes in vm_sizes, or choose "
                "another location." % location,
            ])
        elif r["key"] in PUBLIC_IP_COUNTERS:
            fails.append([
                "%s quota is short: this export creates %d, %d of %d are in use "
                "(short by %d)." % (r["label"], r["need"], r["used"], r["limit"], r["gap"]),
                "Delete unused public IPs in %s, request a quota increase (Azure "
                "portal, Quotas > Networking), or choose another location." % location,
            ])
        else:
            short_fams.add(r["key"])
            fails.append([
                "%s quota is short: this apply needs %d vCPUs, %d of %d are in use "
                "(short by %d)." % (r["label"], r["need"], r["used"], r["limit"], r["gap"]),
            ])

    # One plan clears both a size that cannot be used here and a family without
    # room: each role keeps its size when that is allowed and its family has
    # room, and otherwise moves to an allowed size of the same vCPU class in a
    # family that does. Largest roles are placed first.
    if skus is not None and (bad or short_fams):
        left = {k: e[2] - e[1] for k, e in (compute or {}).items()}
        for size in existing_sizes:
            sku = sku_of(size)
            if sku and sku["vcpus"] and sku["family"].lower() in left:
                left[sku["family"].lower()] += sku["vcpus"]

        def need(role):
            sku = sku_of(size_of(role))
            each = (sku and sku["vcpus"]) or _parts(size_of(role))[1] or 0
            return each, each * len(roles[role])

        proposal, stuck, thin = {}, [], []
        for role in sorted(roles, key=lambda r: (-need(r)[1], r)):
            size = size_of(role)
            sku = sku_of(size)
            each, total = need(role)
            options = ([sku] if sku and size not in bad else []) + [
                c for c in candidates(skus, each, size) if c is not sku]
            pick = next((o for o in options
                         if left.get(o["family"].lower(), float("inf")) >= total), None)
            if pick is None:
                stuck.append(role)
                continue
            if pick["family"].lower() in left:
                left[pick["family"].lower()] -= total
            if pick is not sku:
                proposal[role] = pick["name"]
                want = ref_memory(skus, each, size)
                if pick["memory"] and pick["memory"] < want:
                    thin.append("%s gets %s with %g GB, less than the %g GB of %s; no "
                                "size with as much memory has quota room here."
                                % (role, pick["name"], pick["memory"], want, size))
        if proposal:
            width = max(len(r) for r in proposal)
            fix += ["Set vm_sizes in deploy.tfvars (only these roles change):",
                    "  vm_sizes = {"]
            fix += ['    %s = "%s"' % (r.ljust(width), s) for r, s in sorted(proposal.items())]
            fix += ["  }"]
            fix += ["  note: " + t for t in thin]
        if stuck:
            fix += ["No size this subscription can use here has family vCPU quota room "
                    "for: %s. Request a family vCPU quota increase (Azure portal, Quotas "
                    "> Compute, location %s), or choose another location."
                    % (", ".join(sorted(stuck)), location)]

    # -- resource providers
    if providers:
        required = manifest.get("providers_required", {})
        auto = [a for a in manifest.get("providers_auto_registered", [])
                if a not in required]
        asked = [ns for ns in list(required) + auto if ns in providers]
        lines.append("   resource providers: %d of %d registered" % (
            sum(1 for ns in asked if providers[ns] == "Registered"), len(asked)))
        lines.append("")
        for ns in asked:
            state_ = providers[ns]
            if state_ == "Registered":
                continue
            register = "az provider register --namespace %s --wait" % ns
            raw = ("without az: POST %s/subscriptions/<subscription_id>/providers/%s/"
                   "register?api-version=%s with an empty body (curl -d '')"
                   % (ARM, ns, PROVIDER_API))
            if state_ == "Registering":
                warns.append("%s is still registering; apply may wait on it." % ns)
            elif ns in required:
                fails.append([
                    "%s is %s. This export needs it for %s, and terraform does not "
                    "register it, so apply would fail partway." % (ns, state_, required[ns]),
                    "To register it, run:", "  %s" % register, raw])
            else:
                # The command on a line of its own, so it copies whole.
                warns.append("%s is %s. terraform registers it at apply when your "
                             "identity may register providers; if apply stops on a "
                             "registration error, run:\n           %s"
                             % (ns, state_, register))
    return lines, fails, fix, warns, summary


# ---------------------------------------------------------------- main


def _mask(subscription):
    return subscription[:8] + "..." if len(subscription) > 8 else subscription


def main(argv=None, env=None, http=_http, run=subprocess.run, out=print):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("export", nargs="?", default=".")
    ap.add_argument("--brief", action="store_true",
                    help="on a pass, print only warnings and one summary: line")
    args = ap.parse_args(argv)
    env = os.environ if env is None else env
    root = Path(args.export)

    if env.get(SKIP_ENV, "0") == "1":
        out("summary: skipped (%s=1)" % SKIP_ENV if args.brief
            else "azure preflight skipped (%s=1)." % SKIP_ENV)
        return 0

    def skip(why):
        out("WARNING: azure preflight did not run: %s" % why)
        out("         The deploy continues; apply reports any size or quota limit itself.")
        if args.brief:
            out("summary: not checked (see the warning)")
        return 0

    try:
        manifest = json.loads((root / "terraform" / "preflight.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return skip("no readable terraform/preflight.json (%s)" % exc.__class__.__name__)

    settings = resolve_settings(root, manifest, env, run=run)
    location, subscription = settings["location"], settings["subscription"]
    if not location:
        return skip("no location set")
    if not subscription:
        return skip("no subscription_id in deploy.tfvars and no ARM_SUBSCRIPTION_ID")

    token, how = get_token(env, http=http, run=run)
    if not token:
        return skip("no Azure token (%s)" % how)
    az = Azure(token, http=http)
    sub = "/subscriptions/%s" % urllib.parse.quote(subscription)

    # Held until the result is known: a brief pass leaves the table out.
    head = ["azure preflight: subscription %s, location %s" % (_mask(subscription), location),
            "   sizes from %s; asking as %s" % (settings["source"], how)]
    warns = []

    def ask(what, fn):
        try:
            return fn()
        except ApiError as exc:
            warns.append("could not read %s (%s); not checked." % (what, exc))
            return None

    skus = ask("VM sizes", lambda: parse_skus(az.get_all(
        sub + "/providers/Microsoft.Compute/skus", **{
            "api-version": SKU_API, "$filter": "location eq '%s'" % location}),
        location))
    if skus is not None and not skus:
        warns.append("Azure lists no VM sizes in %r; check the location name." % location)
        skus = None
    compute = ask("vCPU quota", lambda: parse_usages(az.get_all(
        sub + "/providers/Microsoft.Compute/locations/%s/usages" % location,
        **{"api-version": COMPUTE_USAGE_API})))
    network = ask("network quota", lambda: parse_usages(az.get_all(
        sub + "/providers/Microsoft.Network/locations/%s/usages" % location,
        **{"api-version": NETWORK_USAGE_API})))
    providers = {}
    for ns in (list(manifest.get("providers_required", {}))
               + manifest.get("providers_auto_registered", [])):
        got = ask("resource provider state", lambda ns=ns: az.get(
            sub + "/providers/%s" % ns, **{"api-version": PROVIDER_API}))
        if got is None:
            break  # one warning, not one per namespace
        providers[ns] = got.get("registrationState", "NotRegistered")

    lines, fails, fix, more, summary = assess(
        manifest, settings, skus, compute, network, providers,
        state_usage(root / "terraform"))
    rg_fail, rg_warn = check_resource_group(
        az, sub, settings.get("resource_group", ""),
        state_resource_groups(root / "terraform"))
    if rg_fail:
        fails.insert(0, rg_fail)
    if rg_warn:
        warns.append(rg_warn)
    while lines and not lines[-1]:
        lines.pop()
    if args.brief and not fails:
        for w in warns + more:
            out("WARNING: %s" % w)
        out("summary: %s" % summary)
        return 0
    for line in head + [""] + lines:
        out(line)
    for w in warns + more:
        out("WARNING: %s" % w)
    if not fails:
        out("")
        out("azure preflight passed.")
        return 0
    for fail in fails:
        out("")
        out("FAIL: %s" % fail[0])
        for line in fail[1:]:
            out("      %s" % line)
    if fix:
        out("")
        out("To fix the sizes:")
        for line in fix:
            out("  %s" % line)
    out("")
    out("azure preflight failed, so apply was not started and nothing was created.")
    out("  To deploy anyway, run:")
    # deploy.ps1 sets REDSTACKPRO_FROM_PS1 for deploy.sh, which runs this.
    if env.get("REDSTACKPRO_FROM_PS1") == "1":
        out("    $env:%s = '1'; .\\deploy.ps1" % SKIP_ENV)
    else:
        out("    %s=1 bash deploy.sh" % SKIP_ENV)
    return 1


if __name__ == "__main__":
    sys.exit(main())
