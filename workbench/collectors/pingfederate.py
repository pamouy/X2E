"""PingFederate: collector (admin API plus uploaded audit logs) and normaliser."""
from __future__ import annotations

import base64
import re
from datetime import timedelta

from ..core import as_list, finding, get, new_app, new_inventory, new_row, parse_time
from .base import BaseConnector, field

LISTS = {"spConnections": "/idp/spConnections", "oauthClients": "/oauth/clients", "idpAdapters": "/idp/adapters",
         "passwordCredentialValidators": "/passwordCredentialValidators", "dataStores": "/dataStores",
         "authenticationSelectors": "/authenticationSelectors", "idpConnections": "/sp/idpConnections",
         "accessTokenManagers": "/oauth/accessTokenManagers", "oidcPolicies": "/oauth/openIdConnect/policies", "signingKeys": "/keyPairs/signing"}
OPTIONAL_LISTS = {"tokenProcessors": "/idp/tokenProcessors", "tokenGenerators": "/sp/tokenGenerators"}


class Connector(BaseConnector):
    PLATFORM = "pingfederate"
    LABEL = "PingFederate"
    ACCEPTS_FILES = True
    PERMISSIONS = ("A local administrative account with the Auditor role (read-only) on the administrative API. Sign-in events are not in the API: "
                   "upload the audit.log files of every engine node to get usage.")
    FIELDS = [
        field("adminUrl", "Admin console URL", required=True, help="https://pf-admin.example.com:9999"),
        field("username", "Username", required=True),
        field("password", "Password", "secret", required=True),
        field("logDays", "Days of audit log to count", "number", default=90),
        field("skipTlsVerify", "Do not verify the TLS certificate", "bool", default=False, help="Admin consoles often carry a private certificate"),
        field("allowInsecure", "Allow http (lab only)", "bool", default=False),
    ]

    def __init__(self, cfg: dict):
        super().__init__(cfg)
        self.admin = str(self.cfg["adminUrl"]).rstrip("/")
        self.api = self.admin + "/pf-admin-api/v1"
        self.client([self.admin])
        basic = base64.b64encode(f"{self.cfg['username']}:{self.cfg['password']}".encode()).decode()
        self.headers = {"Authorization": f"Basic {basic}", "X-XSRF-Header": "PingFederate", "Accept": "application/json"}

    def source_name(self) -> str:
        return self.admin

    def pf(self, path: str):
        return self.http.get_json(self.api + path, self.headers)

    def items(self, path: str) -> list:
        return as_list(get(self.pf(path), "items"))

    def test(self) -> dict:
        return {"ok": True, "detail": f"Connected to PingFederate {get(self.pf('/version'), 'version', '')}".strip()}

    def collect(self, snap, files=None) -> None:
        snap.step("version", lambda: snap.put_obj("version", self.pf("/version")))
        snap.step("serverSettings", lambda: snap.put_obj("serverSettings", self.pf("/serverSettings"), protect=True))
        for name, path in LISTS.items():
            snap.step(name, lambda n=name, p=path: snap.put(n, self.items(p), protect=True))
        for name, path in OPTIONAL_LISTS.items():
            snap.step(name, lambda n=name, p=path: snap.put(n, self.items(p), protect=True), optional=True)
        snap.step("authenticationPolicies", lambda: snap.put_obj("authenticationPolicies", self.pf("/authenticationPolicies/default")))
        snap.step("authServerSettings", lambda: snap.put_obj("authServerSettings", self.pf("/oauth/authServerSettings"), protect=True))
        if files:
            snap.options["auditLogFiles"] = len(files)
            snap.step("appUsage", lambda: self._usage(snap, files))
        self.finish(snap)

    def _usage(self, snap, files) -> int:
        days = int(self.cfg["logDays"] or 90)
        cut = snap.started - timedelta(days=days)
        use: dict[str, dict] = {}
        lines = counted = 0
        for _name, blob in files:
            for line in blob.decode("utf-8", "replace").splitlines():
                lines += 1
                f = line.split("|")
                if len(f) < 11:
                    continue
                when = parse_time(f[0].strip())
                if when is None or when < cut:
                    continue
                kind, partner, status = f[2].strip(), f[6].strip(), f[10].strip()
                if status != "success" or not partner or kind not in ("SSO", "OAuth"):
                    continue
                e = use.setdefault(partner, {"signIns": 0, "users": set(), "last": None})
                e["signIns"] += 1
                counted += 1
                if f[3].strip():
                    e["users"].add(f[3].strip())
                if e["last"] is None or when > e["last"]:
                    e["last"] = when
        snap.put_obj("logSummary", {"days": days, "files": len(files), "linesRead": lines, "eventsCounted": counted})
        return snap.put("appUsage", [{"partnerId": k, "signIns": e["signIns"], "distinctUsers": len(e["users"]), "lastSignIn": e["last"].isoformat()}
                                     for k, e in use.items()])


def _fulfilment(mappings) -> tuple[int, int]:
    expr = lookups = 0
    for m in as_list(mappings):
        if not m:
            continue
        lookups += len(as_list(get(m, "attributeSources")))
        for v in (get(m, "attributeContractFulfillment") or {}).values():
            if get(v, "source.type") == "EXPRESSION":
                expr += 1
    return expr, lookups


def _tree_sources(node, out: list[str]) -> None:
    if not node:
        return
    src = get(node, "action.authenticationSource.sourceRef.id")
    if src and f"adapter:{src}" not in out:
        out.append(f"adapter:{src}")
    sel = get(node, "action.authenticationSelectorRef.id")
    if sel and f"selector:{sel}" not in out:
        out.append(f"selector:{sel}")
    for child in as_list(get(node, "children")):
        _tree_sources(child, out)


def _plugin(t: str) -> str:
    return re.sub(r"^com\.pingidentity\.", "", t)


def normalize(snap, config: dict) -> dict:
    inv = new_inventory("PingFederate", str(get(snap.obj("serverSettings"), "federationInfo.baseUrl") or snap.source))
    inv["usersKnown"] = False
    inv["usersNote"] = "PingFederate has no user store of its own; users and passwords live in the data stores listed under User stores."
    findings = []
    inv["usageKnown"] = snap.has("appUsage")
    usage = {str(r["partnerId"]): r for r in snap.rows("appUsage")}
    if inv["usageKnown"]:
        inv["usageDays"] = get(snap.obj("logSummary"), "days")
    else:
        inv["usageNote"] = "No audit log files were uploaded to this connector. PingFederate keeps sign-in events in files on each engine node."
    adapter_type = {str(a.get("id")): str(get(a, "pluginDescriptorRef.id") or "") for a in snap.rows("idpAdapters")}
    expr_total = 0
    for c in snap.rows("spConnections"):
        sso = c.get("spBrowserSso")
        proto = str(get(sso, "protocol") or "")
        flags, notes = [], []
        expr, lookups = _fulfilment(as_list(get(sso, "adapterMappings")) + as_list(get(sso, "authenticationPolicyContractAssertionMappings")))
        expr_total += expr
        if expr:
            flags.append("custom-mapper")
            notes.append(f"{expr} attribute(s) filled by OGNL expression")
        if lookups:
            flags.append("directory-lookup")
            notes.append(f"{lookups} data-store lookup(s) at sign-in")
        if c.get("wsTrust"):
            flags.append("ws-trust")
        u = usage.get(str(c.get("entityId")))
        inv["apps"].append(new_app(
            id=c.get("entityId"), label=str(c.get("name")), kind="SP connection", status="INACTIVE" if c.get("active") is False else "ACTIVE",
            pattern={"SAML20": "SAML", "SAML11": "SAML 1.1", "SAML10": "SAML 1.1", "WSFED": "WS-Fed"}.get(proto, "Other"),
            isPlatform=(c.get("entityId") == "urn:federation:MicrosoftOnline"), isMachine=bool(not sso and c.get("wsTrust")),
            signIns=int(u["signIns"]) if u else None, distinctUsers=int(u["distinctUsers"]) if u else None, lastSignIn=u["lastSignIn"] if u else None,
            provisioning="Outbound" if c.get("outboundProvision") else "None", complexClaims=expr,
            encrypted=get(sso, "encryptionPolicy.encryptAssertion") is True, owner=get(c, "contactInfo.email"), flags=flags, notes=notes, catalogHint=False))
    for c in snap.rows("oauthClients"):
        grants = as_list(c.get("grantTypes"))
        flags = []
        if "RESOURCE_OWNER_CREDENTIALS" in grants:
            flags.append("password-grant")
        if "IMPLICIT" in grants:
            flags.append("implicit-flow")
        machine = bool(grants) and all(g in ("CLIENT_CREDENTIALS", "ACCESS_TOKEN_VALIDATION") for g in grants)
        u = usage.get(str(c.get("clientId")))
        inv["apps"].append(new_app(
            id=c.get("clientId"), label=str(c.get("name") or c.get("clientId")), kind="OAuth client (machine)" if machine else "OAuth client",
            status="INACTIVE" if c.get("enabled") is False else "ACTIVE", pattern="OIDC", isMachine=machine,
            signIns=int(u["signIns"]) if u else None, distinctUsers=int(u["distinctUsers"]) if u else None, lastSignIn=u["lastSignIn"] if u else None,
            usesClientSecret=get(c, "clientAuth.type") == "SECRET", owner=c.get("description"), flags=flags, catalogHint=False))
    inv["m365Federated"] = any(a["isPlatform"] and a["status"] == "ACTIVE" for a in inv["apps"])
    inv["stateEvidence"] = ["PingFederate has an active SP connection for Microsoft 365" if inv["m365Federated"]
                            else "PingFederate has no active SP connection for Microsoft 365"]
    for d in snap.rows("dataStores"):
        dtype, ldap, name = str(d.get("type") or ""), str(d.get("ldapType") or ""), str(d.get("name") or d.get("id"))
        hosts = ", ".join(str(h) for h in as_list(d.get("hostnames")))
        if dtype == "LDAP" and ldap == "ACTIVE_DIRECTORY":
            inv["userStores"].append(new_row("userStore", name=name, type="LDAP: Active Directory", detail=hosts,
                                             entraTarget="Entra Connect Sync or Cloud Sync from the same AD; add the attributes that claims rely on"))
        elif dtype == "LDAP":
            inv["userStores"].append(new_row("userStore", name=name, type=f"LDAP: {ldap}", detail=hosts, migrationClass="Gap",
                                             entraTarget="No direct sync from this directory: inbound provisioning or a move of the identities"))
        else:
            inv["userStores"].append(new_row("userStore", name=name, type=dtype, detail=str(d.get("connectionUrl") or ""), migrationClass="Gap",
                                             entraTarget="Attributes read from this store must reach Entra another way, or the claims that use them are redesigned"))
    selector_type = {str(x.get("id")): str(get(x, "pluginDescriptorRef.id") or "") for x in snap.rows("authenticationSelectors")}
    for t in as_list(get(snap.obj("authenticationPolicies"), "authnSelectionTrees")):
        src: list[str] = []
        _tree_sources(get(t, "rootNode"), src)
        adapters = [s[8:] for s in src if s.startswith("adapter:")]
        selectors = [s[9:] for s in src if s.startswith("selector:")]
        mfa = any(re.search(r"(?i)pingid|otp|mfa|duo|securid", _plugin(adapter_type.get(a, ""))) for a in adapters)
        ca = ["Grant: require MFA"] if mfa else []
        for sel in selectors:
            st = selector_type.get(sel, "")
            if re.search("(?i)cidr", st):
                ca.append("Condition: named location")
            elif re.search("(?i)header|useragent", st):
                ca.append("Condition: client app or device platform")
            elif re.search("(?i)connectionset|requestedauthn|oauthscope", st):
                ca.append("Policy scoped to specific apps")
            else:
                ca.append(f"Selector '{sel}' needs manual translation")
        inv["policies"].append(new_row(
            "policy", policyType="Authentication policy", policy=str(get(t, "name") or "unnamed"), rule=" > ".join(adapters),
            status="INACTIVE" if get(t, "enabled") is False else "ACTIVE", conditions=("selectors: " + ", ".join(selectors)) if selectors else "",
            authentication="MFA" if mfa else "No MFA", conditionalAccessBuildingBlocks=" | ".join(ca),
            reviewNote="" if mfa else "No second-factor adapter found in this tree (judged by adapter type). Check, then decide the Entra baseline."))
    rules = [(r"(?i)pingid", "Microsoft Authenticator or passkeys; PingID can bridge as external MFA during coexistence", "User action"),
             (r"(?i)htmlform|httpbasic|identifierfirst", "Entra sign-in page with password hash sync", "Rebuild"),
             (r"(?i)kerberos", "Seamless SSO or Entra-joined devices", "Rebuild"),
             (r"(?i)x509", "Certificate-based authentication", "Rebuild"),
             (r"(?i)composite", "Folded into Conditional Access", "Rebuild"),
             (r"(?i)opentoken|referenceid|agentless", "Application-specific integration kit: the application changes its sign-in method", "Gap")]
    for a in snap.rows("idpAdapters"):
        t = str(get(a, "pluginDescriptorRef.id") or "")
        target, cls = "Custom or unrecognised adapter: review the plug-in", "Gap"
        for rx, tgt, c in rules:
            if re.search(rx, _plugin(t)):
                target, cls = tgt, c
                break
        inv["mfaMethods"].append(new_row("mfa", method=str(a.get("name") or a.get("id")), key=t, entraTarget=target, migrationClass=cls))
    for i in snap.rows("idpConnections"):
        inv["federation"].append(new_row("federation", name=str(i.get("name")), type="IdP connection", status="INACTIVE" if i.get("active") is False else "ACTIVE",
                                         detail=str(i.get("entityId") or "")))
    settings = snap.obj("authServerSettings")
    scopes = len(as_list(settings.get("scopes"))) + len(as_list(settings.get("exclusiveScopes")))
    oidc_expr = sum(_fulfilment(p.get("attributeMapping"))[0] for p in snap.rows("oidcPolicies"))
    expr_total += oidc_expr
    atm = len(snap.rows("accessTokenManagers"))
    if scopes or atm:
        inv["apis"].append(new_row("api", name="PingFederate authorization server",
                                   detail=f"{scopes} scopes, {atm} access token managers, {len(snap.rows('oidcPolicies'))} OIDC policies ({oidc_expr} expressions)",
                                   migrationClass="Gap" if oidc_expr else "Rebuild", note="One app registration per protected API; scopes become delegated permissions or app roles"))
    for name, kind in (("tokenProcessors", "WS-Trust token processor"), ("tokenGenerators", "WS-Trust token generator")):
        for x in snap.rows(name):
            inv["automations"].append(new_row("automation", kind=kind, name=str(x.get("name") or x.get("id")), detail=str(get(x, "pluginDescriptorRef.id") or ""),
                                              migrationClass="Gap", entraTarget="No general WS-Trust security token service in Entra"))
    if expr_total:
        findings.append(finding("PF-01", "High", "Custom code", "OGNL expressions to translate", expr_total, "Across SP connections and OIDC policies. Counted, not parsed.",
                                "Translate each into an Entra claims transformation, or mark it for redesign. This is the main design effort.", "Design"))
    soon = snap.started + timedelta(days=270)
    expiring = [k for k in snap.rows("signingKeys") if parse_time(k.get("expires")) and parse_time(k.get("expires")) < soon]
    if expiring:
        findings.append(finding("PF-03", "Medium", "Operations", "Signing certificates that expire within nine months", len(expiring),
                                "; ".join(f"{k.get('subjectDN')} ({parse_time(k.get('expires')).strftime('%Y-%m-%d')})" for k in expiring),
                                "Order the waves so that connections on these certificates move before the expiry, instead of renewing and re-exchanging metadata.", "Design"))
    inv["findings"] = findings
    inv["manualChecks"] = [
        new_row("manualCheck", item="PingAccess applications, rules and identity mappings", why="Each protected application needs a decision: application proxy, or PingAccess kept with Entra as token provider", where="PingAccess admin console or its own admin API"),
        new_row("manualCheck", item="PingID service configuration and enrolled devices", why="Sizes the MFA registration campaign and the bridge decision", where="PingID admin portal reports"),
        new_row("manualCheck", item="Number and location of engine nodes; audit logs of each", why="Usage is only complete with the logs of every node", where="Cluster management, log directories"),
        new_row("manualCheck", item="Custom plug-ins in the deploy directory", why="Custom adapters, selectors and data sources have no generated equivalent", where="server/default/deploy on each node"),
        new_row("manualCheck", item="The OGNL expressions themselves", why="The tool counts them; translating them is manual", where="Attribute contract fulfilment of each connection"),
    ]
    return inv
