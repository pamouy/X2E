"""PingOne (one environment): collector and normaliser."""
from __future__ import annotations

import base64
import json
import re
from collections import Counter
from datetime import timedelta

from ..core import as_list, dynamic_rule, finding, get, new_app, new_inventory, new_row
from ..httpc import HttpError
from .base import BaseConnector, field

REGIONS = {"NA": "com", "EU": "eu", "CA": "ca", "AP": "asia", "AU": "com.au"}
BUILT_IN_APP_TYPES = {"PING_ONE_PORTAL", "PING_ONE_SELF_SERVICE", "PING_ONE_ADMIN_CONSOLE", "PORTAL_LINK_APP", "PING_ONE_DAVINCI"}
PLAIN_ATTR = re.compile(r"^\$\{user\.[A-Za-z0-9_.]+\}$")


class Connector(BaseConnector):
    PLATFORM = "pingone"
    LABEL = "PingOne"
    PERMISSIONS = ("A Worker application in the environment (client credentials) with the roles Environment Admin (read-only variant where "
                   "available) and Identity Data Read Only. One connector per environment.")
    FIELDS = [
        field("environmentId", "Environment ID", required=True),
        field("region", "Region", "select", default="EU", options=[[k, k] for k in REGIONS]),
        field("clientId", "Worker client ID", required=True),
        field("clientSecret", "Worker client secret", "secret", required=True),
        field("activityDays", "Days of audit activity to read", "number", default=90, help="0 skips usage"),
        field("apiBase", "API base URL", help="Only to override the region default"),
        field("authBase", "Auth base URL", help="Only to override the region default"),
        field("allowInsecure", "Allow http (lab only)", "bool", default=False),
    ]

    def __init__(self, cfg: dict):
        super().__init__(cfg)
        tld = REGIONS.get(str(self.cfg["region"] or "EU"), "eu")
        self.api_base = str(self.cfg["apiBase"] or f"https://api.pingone.{tld}").rstrip("/")
        self.auth_base = str(self.cfg["authBase"] or f"https://auth.pingone.{tld}").rstrip("/")
        self.env = self.cfg["environmentId"]
        self.root = f"{self.api_base}/v1/environments/{self.env}"
        self.client([self.api_base, self.auth_base])

    def source_name(self) -> str:
        return self.root

    def fetch_token(self) -> tuple[str, int]:
        basic = base64.b64encode(f"{self.cfg['clientId']}:{self.cfg['clientSecret']}".encode()).decode()
        body = self.http.token(f"{self.auth_base}/{self.env}/as/token", data={"grant_type": "client_credentials"}, headers={"Authorization": f"Basic {basic}"})
        return body["access_token"], int(body.get("expires_in", 3600)) - 60

    def api_get(self, url: str, params: dict | None = None):
        if not url.startswith(self.api_base + "/"):
            raise HttpError(None, f"Refusing to send credentials outside the PingOne API host: {url.split('?')[0]}")
        return self.authed_json(url, params)

    def coll(self, path: str, key: str, params: dict | None = None):
        url, seen = self.root + path, set()
        params = params if params is not None else {"limit": 100}
        while url:
            if url in seen:
                raise HttpError(None, f"Paging loop on {path}")
            seen.add(url)
            body = self.api_get(url, params)
            params = None
            yield from as_list(get(body, f"_embedded.{key}"))
            url = get(body, "_links.next.href")

    def test(self) -> dict:
        env = self.api_get(self.root)
        return {"ok": True, "detail": f"Connected to environment {get(env, 'name', self.env)}"}

    def collect(self, snap, files=None) -> None:
        def environment():
            e = self.api_get(self.root)
            return snap.put_obj("environment", {k: get(e, k) for k in ("id", "name", "type", "region")})

        def applications():
            rows = []
            for app in self.coll("/applications", "applications"):
                extra = {"attributes": [], "signOnPolicyIds": []}
                if app.get("type") not in BUILT_IN_APP_TYPES:
                    extra["attributes"] = [{k: a.get(k) for k in ("name", "value", "mappingType")} for a in self.coll(f"/applications/{app['id']}/attributes", "attributes")]
                    extra["signOnPolicyIds"] = [get(a, "signOnPolicy.id") for a in self.coll(f"/applications/{app['id']}/signOnPolicyAssignments", "signOnPolicyAssignments")]
                app["_wb"] = extra
                rows.append(app)
            return snap.put("applications", rows, protect=True)

        def users():
            return snap.put("users", ({"id": u.get("id"), "username": u.get("username"), "email": u.get("email"), "enabled": u.get("enabled"),
                                       "lifecycleStatus": get(u, "lifecycle.status"), "populationId": get(u, "population.id"),
                                       "idpType": get(u, "identityProvider.type"), "gatewayId": get(u, "password.external.gateway.id"),
                                       "lastSignOnAt": get(u, "lastSignOn.at"), "mfaEnabled": u.get("mfaEnabled")} for u in self.coll("/users", "users")))

        def policies():
            rows = []
            for p in self.coll("/signOnPolicies", "signOnPolicies"):
                p["_wb"] = {"actions": list(self.coll(f"/signOnPolicies/{p['id']}/actions", "actions"))}
                rows.append(p)
            return snap.put("signOnPolicies", rows, protect=True)

        def resources():
            rows = []
            for r in self.coll("/resources", "resources"):
                r["_wb"] = {"scopes": [s.get("name") for s in self.coll(f"/resources/{r['id']}/scopes", "scopes")],
                            "attributes": [{"name": a.get("name"), "value": a.get("value")} for a in self.coll(f"/resources/{r['id']}/attributes", "attributes")]}
                rows.append(r)
            return snap.put("resources", rows, protect=True)

        def usage():
            days = int(self.cfg["activityDays"])
            since = (snap.started - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
            use: dict[str, dict] = {}
            read = 0
            for a in self.coll("/activities", "activities", {"limit": 1000, "filter": f'recordedat gt "{since}" and action.type eq "USER.ACCESS_ALLOWED"'}):
                read += 1
                app = str(get(a, "actors.client.id") or "")
                if not app:
                    continue
                e = use.setdefault(app, {"signIns": 0, "users": set(), "last": None})
                e["signIns"] += 1
                uid = str(get(a, "actors.user.id") or "")
                if uid:
                    e["users"].add(uid)
                at = a.get("recordedAt")
                if at and (e["last"] is None or at > e["last"]):
                    e["last"] = at
            snap.put_obj("activitySummary", {"days": days, "since": since, "activitiesRead": read})
            return snap.put("appUsage", [{"applicationId": k, "signIns": e["signIns"], "distinctUsers": len(e["users"]), "lastSignIn": e["last"]} for k, e in use.items()])

        snap.step("environment", environment)
        snap.step("applications", applications)
        snap.step("users", users)
        snap.step("populations", lambda: snap.put("populations", self.coll("/populations", "populations")))
        snap.step("groups", lambda: snap.put("groups", ({"id": g.get("id"), "name": g.get("name"), "userFilter": g.get("userFilter")} for g in self.coll("/groups", "groups"))))
        snap.step("signOnPolicies", policies)
        snap.step("identityProviders", lambda: snap.put("identityProviders", self.coll("/identityProviders", "identityProviders"), protect=True))
        snap.step("resources", resources)
        snap.step("gateways", lambda: snap.put("gateways", self.coll("/gateways", "gateways"), protect=True))
        snap.step("deviceAuthenticationPolicies", lambda: snap.put("deviceAuthenticationPolicies", self.coll("/deviceAuthenticationPolicies", "deviceAuthenticationPolicies")))
        snap.step("propagationStores", lambda: snap.put("propagationStores", ({"id": s.get("id"), "name": s.get("name"), "type": s.get("type")}
                                                                             for s in self.coll("/propagation/stores", "stores"))), optional=True)
        if int(self.cfg["activityDays"] or 0) > 0:
            snap.step("appUsage", usage)
        self.finish(snap)


METHODS = [("mobile", "PingID or PingOne mobile app", "Microsoft Authenticator; PingID can bridge as external MFA during coexistence", "User action"),
           ("totp", "Authenticator app (TOTP)", "Microsoft Authenticator or a software OATH token", "User action"),
           ("fido2", "FIDO2", "Passkey (FIDO2); keys are registered again", "User action"),
           ("sms", "SMS", "SMS; supported, not recommended as a target", "User action"),
           ("voice", "Voice", "Voice call; supported, not recommended as a target", "User action"),
           ("email", "Email one-time passcode", "Not a sign-in MFA method in Entra", "Gap")]


def normalize(snap, config: dict) -> dict:
    inv = new_inventory("PingOne", str(get(snap.obj("environment"), "name") or "environment"))
    inv["lastLoginKnown"] = True
    findings = []
    gateways = {str(g.get("id")): g for g in snap.rows("gateways")}
    for u in snap.rows("users"):
        gw, idp = str(u.get("gatewayId") or ""), str(u.get("idpType") or "PING_ONE")
        source = ("LDAP gateway: " + str(get(gateways.get(gw), "name") or gw)) if gw else f"External IdP: {idp}" if idp != "PING_ONE" else "PING_ONE"
        inv["users"].append(new_row("user", id=u.get("id"), login=u.get("username"), email=u.get("email"), status="DISABLED" if u.get("enabled") is False else "ACTIVE",
                                    source=source, localPassword=(source == "PING_ONE"), lastLogin=u.get("lastSignOnAt")))
    inv["usageKnown"] = snap.has("appUsage")
    usage = {str(r["applicationId"]): r for r in snap.rows("appUsage")}
    if inv["usageKnown"]:
        inv["usageDays"] = get(snap.obj("activitySummary"), "days")
    else:
        inv["usageNote"] = "Audit activities were not collected (days set to 0) or the worker application may not read them."
    policy_name = {str(p.get("id")): str(p.get("name")) for p in snap.rows("signOnPolicies")}
    apps_on_policy: Counter = Counter()
    for a in snap.rows("applications"):
        for pid in as_list(get(a, "_wb.signOnPolicyIds")):
            apps_on_policy[str(pid)] += 1
        if a.get("type") in BUILT_IN_APP_TYPES:
            continue
        proto, atype = str(a.get("protocol") or ""), str(a.get("type") or "")
        grants = as_list(a.get("grantTypes"))
        flags, notes = [], []
        if "IMPLICIT" in grants:
            flags.append("implicit-flow")
        complex_claims = group_claims = 0
        for m in as_list(get(a, "_wb.attributes")):
            v = str(get(m, "value") or "")
            if get(m, "mappingType") == "CORE" and PLAIN_ATTR.match(v):
                continue
            if re.search("(?i)memberOfGroup", v):
                group_claims += 1
            elif not PLAIN_ATTR.match(v):
                complex_claims += 1
        if complex_claims:
            flags.append("custom-mapper")
        if get(a, "accessControl.group"):
            notes.append("Access limited to groups: assign the same groups in Entra")
        machine = atype in ("WORKER", "SERVICE") or (bool(grants) and all(g == "CLIENT_CREDENTIALS" for g in grants))
        u = usage.get(str(a.get("id")))
        pol = [policy_name.get(str(p), str(p)) for p in as_list(get(a, "_wb.signOnPolicyIds"))]
        inv["apps"].append(new_app(
            id=a.get("id"), label=str(a.get("name")), kind=atype, status="INACTIVE" if a.get("enabled") is False else "ACTIVE",
            pattern={"SAML": "SAML", "OPENID_CONNECT": "OIDC", "EXTERNAL_LINK": "Bookmark", "WS_FED": "WS-Fed"}.get(proto, "Other"),
            isPlatform=(a.get("spEntityId") == "urn:federation:MicrosoftOnline"), isMachine=machine,
            signIns=int(u["signIns"]) if u else None, distinctUsers=int(u["distinctUsers"]) if u else None, lastSignIn=u["lastSignIn"] if u else None,
            complexClaims=complex_claims, groupClaims=group_claims,
            usesClientSecret=(proto == "OPENID_CONNECT" and str(a.get("tokenEndpointAuthMethod") or "").startswith("CLIENT_SECRET")),
            owner=a.get("description"), policy=", ".join(pol) or None, flags=flags, notes=notes))
    inv["m365Federated"] = any(a["isPlatform"] and a["status"] == "ACTIVE" for a in inv["apps"])
    inv["stateEvidence"] = ["PingOne has an active application for Microsoft 365 federation" if inv["m365Federated"]
                            else "PingOne has no application for Microsoft 365 federation"]
    for p in snap.rows("signOnPolicies"):
        actions = sorted(as_list(get(p, "_wb.actions")), key=lambda x: int(get(x, "priority") or 0))
        types = [str(get(x, "type") or "") for x in actions]
        mfa = [x for x in actions if get(x, "type") in ("MULTI_FACTOR_AUTHENTICATION", "PINGID")]
        conditional = any(get(x, "condition") for x in mfa)
        ca, note, auth = [], [], "No MFA"
        if mfa and not conditional:
            auth = "MFA"
            ca.append("Grant: require MFA")
        elif mfa:
            auth = "MFA with conditions"
            ca.append("Grant: require MFA")
            cond = json.dumps([get(x, "condition") for x in mfa])
            if re.search("(?i)ipRange", cond):
                ca.append("Condition: named location (trusted range excluded)")
                note.append("MFA is skipped inside an IP range: challenge whether that exception should survive")
            if re.search("(?i)secondsSince", cond):
                ca.append("Session: sign-in frequency")
        else:
            note.append("No MFA step in this policy")
        if "IDENTITY_PROVIDER" in types:
            note.append("Routes to an external identity provider")
        inv["policies"].append(new_row(
            "policy", policyType="Sign-on policy", policy=str(p.get("name")), rule=" > ".join(types), authentication=auth,
            conditions=f"apps on policy: {apps_on_policy.get(str(p.get('id')), 0)}" + ("; environment default" if p.get("default") is True else ""),
            conditionalAccessBuildingBlocks=" | ".join(ca), reviewNote=" | ".join(note)))
    daps = snap.rows("deviceAuthenticationPolicies")
    dap = next((d for d in daps if d.get("default") is True), daps[0] if daps else None)
    if dap:
        for key, method, target, cls in METHODS:
            if get(dap, f"{key}.enabled") is True:
                inv["mfaMethods"].append(new_row("mfa", method=method, key=key, entraTarget=target, migrationClass=cls))
    for g in snap.rows("groups"):
        flt = str(g.get("userFilter") or "")
        if not flt:
            continue
        m = re.match(r'^\s*([A-Za-z0-9_.]+)\s+eq\s+"([^"]*)"\s*$', flt)
        t = dynamic_rule(m.group(1), m.group(2), config) if m else dict(translation="Manual", rule="", note="Filter has several conditions or operators")
        inv["groupRules"].append(new_row("groupRule", rule=str(g.get("name")), expression=flt, target=str(g.get("name")), translation=t["translation"],
                                         suggestedDynamicMembershipRule=t["rule"], reviewNote=t["note"]))
    for i in snap.rows("identityProviders"):
        inv["federation"].append(new_row("federation", name=str(i.get("name")), type=str(i.get("type") or ""), status="INACTIVE" if i.get("enabled") is False else "ACTIVE"))
    for g in snap.rows("gateways"):
        if g.get("type") != "LDAP":
            continue
        vendor = str(g.get("vendor") or "")
        if re.search("(?i)active directory", vendor):
            inv["userStores"].append(new_row("userStore", name=str(g.get("name")), type="LDAP gateway: Active Directory",
                                             entraTarget="Entra Connect Sync or Cloud Sync from the same AD; password hash sync carries the passwords"))
        else:
            inv["userStores"].append(new_row("userStore", name=str(g.get("name")), type=f"LDAP gateway: {vendor}", migrationClass="Gap",
                                             entraTarget="No direct sync from this directory: inbound provisioning or a move of the identities"))
    for r in snap.rows("resources"):
        if r.get("type") != "CUSTOM":
            continue
        attrs = as_list(get(r, "_wb.attributes"))
        expr = sum(1 for x in attrs if not PLAIN_ATTR.match(str(get(x, "value") or "")))
        inv["apis"].append(new_row("api", name=str(r.get("name")), detail=f"{len(as_list(get(r, '_wb.scopes')))} scopes, {len(attrs)} token attributes ({expr} expressions)",
                                   migrationClass="Gap" if expr else "Rebuild", note="App registration exposing an API"))
    for st in snap.rows("propagationStores"):
        inv["automations"].append(new_row("automation", kind="Provisioning connection", name=str(st.get("name") or st.get("id")), detail=str(st.get("type") or ""),
                                          entraTarget="Entra provisioning service for the same target"))
    radius = [g for g in snap.rows("gateways") if g.get("type") == "RADIUS" and g.get("enabled") is not False]
    if radius:
        findings.append(finding("P1-01", "Blocker", "Applications", "RADIUS gateways", len(radius), ", ".join(str(g.get("name")) for g in radius),
                                "Identify the VPN or network devices behind each gateway; plan the NPS extension or a replacement before users move.", "Assess"))
    pf = [g for g in snap.rows("gateways") if g.get("type") == "PING_FEDERATE"]
    if pf:
        findings.append(finding("P1-02", "High", "Federation", "PingFederate is linked to this environment", len(pf), ", ".join(str(g.get("name")) for g in pf),
                                "Add a PingFederate connector to this project as well: part of the estate lives there.", "Assess"))
    inv["findings"] = findings
    inv["manualChecks"] = [
        new_row("manualCheck", item="DaVinci flows", why="Orchestrated sign-in logic has no generated equivalent", where="DaVinci console; flow policies assigned to applications"),
        new_row("manualCheck", item="PingID legacy configuration and enrolled devices", why="Sizes the MFA registration campaign", where="PingID admin portal reports"),
        new_row("manualCheck", item="Other environments in the organisation", why="One connector covers one environment", where="PingOne environment list"),
        new_row("manualCheck", item="Administrator role assignments", why="Admin access is redesigned as Entra roles under PIM", where="Directory, Administrator Roles"),
        new_row("manualCheck", item="Group and user assignment of applications", why="The snapshot shows that access control exists, not who is in scope", where="Each application, Access tab"),
    ]
    return inv
