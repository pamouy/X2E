"""OneLogin: collector and normaliser."""
from __future__ import annotations

import base64
import re
from collections import Counter
from datetime import timedelta
from urllib.parse import urlsplit

from ..core import as_list, dynamic_rule, finding, get, new_app, new_inventory, new_row
from ..httpc import HttpError
from .base import BaseConnector, ConnectorError, field

AUTH_METHOD = {"2": "SAML", "4": "SAML", "8": "OIDC", "7": "WS-Fed", "0": "SWA", "6": "SWA", "3": "Provisioning"}


class Connector(BaseConnector):
    PLATFORM = "onelogin"
    LABEL = "OneLogin"
    PERMISSIONS = "An API credential pair with the scope 'Read All'. User security policies are not in the API and are captured by hand."
    FIELDS = [
        field("subdomain", "Subdomain", help="'acme' for acme.onelogin.com"),
        field("baseUrl", "Base URL", help="Only if the subdomain form does not apply"),
        field("clientId", "API client ID", required=True),
        field("clientSecret", "API client secret", "secret", required=True),
        field("eventDays", "Days of events to read", "number", default=30, help="0 skips usage"),
        field("includeFactors", "Read enrolled factors per user", "bool", default=False, help="One request per active user"),
        field("skipAppAssignments", "Skip app assignments", "bool", default=False),
        field("allowInsecure", "Allow http (lab only)", "bool", default=False),
    ]

    def __init__(self, cfg: dict):
        super().__init__(cfg)
        if self.cfg["subdomain"]:
            if not re.match(r"^[A-Za-z0-9-]+$", str(self.cfg["subdomain"])):
                raise ConnectorError("Subdomain: letters, digits and hyphens only")
            self.base = f"https://{self.cfg['subdomain']}.onelogin.com"
        elif self.cfg["baseUrl"]:
            self.base = str(self.cfg["baseUrl"]).rstrip("/")
        else:
            raise ConnectorError("Missing: Subdomain or Base URL")
        self.client([self.base])

    def source_name(self) -> str:
        return self.base

    def fetch_token(self) -> tuple[str, int]:
        basic = base64.b64encode(f"{self.cfg['clientId']}:{self.cfg['clientSecret']}".encode()).decode()
        body = self.http.token(f"{self.base}/auth/oauth2/v2/token", json_body={"grant_type": "client_credentials"},
                               headers={"Authorization": f"Basic {basic}", "Content-Type": "application/json"})
        return body["access_token"], int(body.get("expires_in", 3600)) - 60

    def bearer(self) -> dict:
        h = super().bearer()
        h["Authorization"] = h["Authorization"].replace("Bearer ", "bearer ", 1)
        return h

    def v2(self, path: str, params: dict | None = None):
        cursor, seen = None, set()
        base_params = {"limit": 100} if params is None else dict(params)
        while True:
            q = dict(base_params)
            if cursor:
                q["cursor"] = cursor
            resp = self.authed(self.base + path, q)
            body = resp.json() if resp.content else []
            yield from (body if isinstance(body, list) else [body])
            cursor = resp.headers.get("After-Cursor")
            if not cursor:
                return
            if cursor in seen:
                raise HttpError(None, f"Paging loop on {path}")
            seen.add(cursor)

    def v1(self, path: str, params: dict | None = None):
        cursor, seen = None, set()
        while True:
            q = dict(params or {})
            if cursor:
                q["after_cursor"] = cursor
            body = self.authed_json(self.base + path, q)
            yield from as_list(get(body, "data"))
            cursor = str(get(body, "pagination.after_cursor") or "")
            if not cursor:
                return
            if cursor in seen:
                raise HttpError(None, f"Paging loop on {path}")
            seen.add(cursor)

    def test(self) -> dict:
        next(iter(self.v2("/api/2/roles", {"limit": 1})), None)
        return {"ok": True, "detail": f"Connected to {urlsplit(self.base).netloc}"}

    def collect(self, snap, files=None) -> None:
        c = self.cfg
        active_ids: list[str] = []

        def apps():
            rows = []
            for a in self.v2("/api/2/apps"):
                app = self.authed_json(f"{self.base}/api/2/apps/{a['id']}")
                assigned = None if c["skipAppAssignments"] else sum(1 for _ in self.v2(f"/api/2/apps/{a['id']}/users"))
                app["_wb"] = {"assignedUsers": assigned}
                rows.append(app)
            return snap.put("apps", rows, protect=True)

        def users():
            rows = []
            for u in self.v2("/api/2/users"):
                if u.get("status") == 1:
                    active_ids.append(str(u["id"]))
                rows.append({k: u.get(k) for k in ("id", "username", "email", "status", "state", "directory_id", "trusted_idp_id", "last_login", "department", "title")})
            return snap.put("users", rows)

        def api_auth():
            rows = []
            for x in self.v2("/api/2/api_authorizations"):
                x["_wb"] = {"scopes": [s.get("value") for s in self.v2(f"/api/2/api_authorizations/{x['id']}/scopes")],
                            "claims": [{"label": cl.get("label"), "mapping": cl.get("user_attribute_mappings"), "macro": cl.get("user_attribute_macros")}
                                       for cl in self.v2(f"/api/2/api_authorizations/{x['id']}/claims")]}
                rows.append(x)
            return snap.put("apiAuthorizations", rows, protect=True)

        def hooks():
            # the function source is deliberately not stored: only what is needed to size the redesign
            return snap.put("hooks", ({"id": h.get("id"), "type": h.get("type"), "disabled": h.get("disabled"), "status": h.get("status"), "runtime": h.get("runtime"),
                                       "envVarNames": as_list(h.get("env_vars")), "packages": sorted((h.get("packages") or {}).keys())} for h in self.v2("/api/2/hooks")))

        def usage():
            days = int(c["eventDays"])
            since = (snap.started - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
            use: dict[str, dict] = {}
            read = 0
            for ev in self.v1("/api/1/events", {"event_type_id": 8, "since": since, "limit": 50}):
                read += 1
                app = str(ev.get("app_id") or "")
                if not app:
                    continue
                e = use.setdefault(app, {"signIns": 0, "users": set(), "last": None})
                e["signIns"] += 1
                if ev.get("user_id"):
                    e["users"].add(str(ev["user_id"]))
                at = ev.get("created_at")
                if at and (e["last"] is None or at > e["last"]):
                    e["last"] = at
            snap.put_obj("eventSummary", {"days": days, "since": since, "eventsRead": read})
            return snap.put("appUsage", [{"appId": k, "signIns": e["signIns"], "distinctUsers": len(e["users"]), "lastSignIn": e["last"]} for k, e in use.items()])

        def factors():
            return snap.put("userFactors", ({"userId": uid, "factors": [str(d.get("type_display_name") or d.get("auth_factor_name") or "unknown")
                                                                       for d in self.v2(f"/api/2/mfa/users/{uid}/devices", {})]} for uid in active_ids))

        snap.step("apps", apps)
        snap.step("users", users)
        snap.step("roles", lambda: snap.put("roles", ({"id": r.get("id"), "name": r.get("name"), "apps": as_list(r.get("apps")), "userCount": len(as_list(r.get("users"))),
                                                       "adminCount": len(as_list(r.get("admins")))} for r in self.v2("/api/2/roles"))))
        snap.step("mappings", lambda: snap.put("mappings", self.v2("/api/2/mappings")))
        snap.step("groups", lambda: snap.put("groups", self.v1("/api/1/groups")))
        snap.step("apiAuthorizations", api_auth)
        snap.step("hooks", hooks)
        snap.step("riskRules", lambda: snap.put("riskRules", self.v2("/api/2/risk/rules")), optional=True)
        snap.step("privileges", lambda: snap.put("privileges", ({"id": p.get("id"), "name": p.get("name")} for p in self.v1("/api/1/privileges"))), optional=True)
        if int(c["eventDays"] or 0) > 0:
            snap.step("appUsage", usage)
        if c["includeFactors"]:
            snap.step("userFactors", factors)
        self.finish(snap)


FACTOR_RULES = [(r"(?i)protect", "Microsoft Authenticator; users register again", "User action"),
                (r"(?i)authenticator|otp|totp", "Microsoft Authenticator or a software OATH token", "User action"),
                (r"(?i)webauthn|yubi|security key|fido", "Passkey (FIDO2); keys are registered again", "User action"),
                (r"(?i)sms|voice|phone", "SMS or voice; supported, not recommended as a target", "User action"),
                (r"(?i)email|question", "Not a sign-in MFA method in Entra", "Gap")]


def normalize(snap, config: dict) -> dict:
    inv = new_inventory("OneLogin", urlsplit(str(snap.source)).netloc or str(snap.source))
    inv["lastLoginKnown"] = True
    findings = []
    for u in snap.rows("users"):
        d, t = u.get("directory_id"), u.get("trusted_idp_id")
        source = f"Directory {d}" if d else f"Trusted IdP {t}" if t else "ONELOGIN"
        inv["users"].append(new_row("user", id=u.get("id"), login=u.get("username"), email=u.get("email"), status="ACTIVE" if u.get("status") == 1 else "DISABLED",
                                    source=source, localPassword=(source == "ONELOGIN"), lastLogin=u.get("last_login")))
    by_source = Counter(u["source"] for u in inv["users"])
    for name, n in by_source.items():
        if name.startswith("Directory "):
            inv["userStores"].append(new_row("userStore", name=name, type="Directory connector (type not exposed by the API)", detail=f"{n} users",
                                             entraTarget="If this is the AD connector: sync from the same AD, password hash sync carries the passwords. Otherwise: inbound provisioning"))
        elif name.startswith("Trusted IdP "):
            inv["federation"].append(new_row("federation", name=name, type="Trusted IdP", detail=f"{n} users sign in there"))
    if snap.has("userFactors"):
        none = strong = 0
        names: Counter = Counter()
        for f in snap.rows("userFactors"):
            lst = as_list(f.get("factors"))
            none += 0 if lst else 1
            strong += 1 if any(re.search(r"(?i)webauthn|yubi|security key|fido", x) for x in lst) else 0
            names.update(lst)
        inv["factorSummary"] = {"usersChecked": len(snap.rows("userFactors")), "usersWithoutFactor": none, "usersWithPhishingResistantFactor": strong}
        for name, n in names.most_common():
            target, cls = "Third-party or unrecognised factor: external MFA or replacement", "Gap"
            for rx, tgt, c in FACTOR_RULES:
                if re.search(rx, name):
                    target, cls = tgt, c
                    break
            inv["mfaMethods"].append(new_row("mfa", method=f"{name} ({n} enrolments)", key=name, entraTarget=target, migrationClass=cls))
    inv["usageKnown"] = snap.has("appUsage")
    usage = {str(r["appId"]): r for r in snap.rows("appUsage")}
    if inv["usageKnown"]:
        inv["usageDays"] = get(snap.obj("eventSummary"), "days")
    else:
        inv["usageNote"] = "App sign-in events were not collected (days set to 0)."
    roles_per_app: dict[str, list[str]] = {}
    for r in snap.rows("roles"):
        for a in as_list(r.get("apps")):
            roles_per_app.setdefault(str(a), []).append(str(r.get("name")))
    policy_apps: Counter = Counter()
    for a in snap.rows("apps"):
        method = str(a.get("auth_method"))
        pattern = AUTH_METHOD.get(method, "Other")
        flags, notes = [], []
        complex_claims = sum(1 for p in (a.get("parameters") or {}).values() if str(get(p, "user_attribute_macros") or ""))
        if complex_claims:
            flags.append("custom-mapper")
            notes.append(f"{complex_claims} parameter(s) built with a macro")
        if a.get("enforcement_point"):
            flags.append("header-based")
        if roles_per_app.get(str(a.get("id"))):
            notes.append("Assigned through role(s): " + ", ".join(roles_per_app[str(a.get("id"))]))
        if method == "3":
            notes.append("Provisioning-only connector, no sign-on")
        policy = a.get("policy_id")
        if policy:
            policy_apps[str(policy)] += 1
        u = usage.get(str(a.get("id")))
        name = str(a.get("name"))
        inv["apps"].append(new_app(
            id=a.get("id"), label=name, kind=str(a.get("auth_method_description") or f"auth_method {method}"), pattern=pattern,
            isPlatform=(pattern == "WS-Fed" and bool(re.search(r"(?i)office ?365|microsoft ?365", name))), isMachine=(pattern == "Provisioning"),
            signIns=int(u["signIns"]) if u else None, distinctUsers=int(u["distinctUsers"]) if u else None, lastSignIn=u["lastSignIn"] if u else None,
            assignedUsers=get(a, "_wb.assignedUsers"), provisioning="Outbound" if get(a, "provisioning.enabled") is True else "None",
            complexClaims=complex_claims, encrypted=str(get(a, "configuration.encrypt_assertion") or "") in ("1", "true", "True"),
            usesClientSecret=(pattern == "OIDC" and bool(get(a, "sso.client_secret"))), owner=a.get("notes"),
            policy=f"policy {policy}" if policy else None, flags=flags, notes=notes))
    inv["m365Federated"] = any(a["isPlatform"] for a in inv["apps"])
    inv["stateEvidence"] = ["OneLogin has a WS-Federation app for Microsoft 365" if inv["m365Federated"] else "OneLogin has no WS-Federation app for Microsoft 365"]
    for pid in sorted(policy_apps):
        inv["policies"].append(new_row("policy", policyType="App policy", policy=f"policy {pid}", rule="(content not exposed by the API)",
                                       conditions=f"apps on policy: {policy_apps[pid]}", authentication="Unknown",
                                       reviewNote="Record MFA requirement, IP allow list and session settings from the admin console, then complete this row"))
    for r in snap.rows("riskRules"):
        inv["policies"].append(new_row("policy", policyType="Risk rule", policy=str(r.get("name") or r.get("id")), rule=f"{r.get('type')} on {r.get('target')}",
                                       authentication="n/a", conditionalAccessBuildingBlocks="Named location, or sign-in risk policy (Entra ID P2)"))
    role_name = {str(r.get("id")): str(r.get("name")) for r in snap.rows("roles")}
    for m in snap.rows("mappings"):
        conds, acts = as_list(m.get("conditions")), as_list(m.get("actions"))
        expr = f" {m.get('match') or 'all'} ".join(f"{get(x, 'source')} {get(x, 'operator')} '{get(x, 'value')}'" for x in conds)
        targets = [f"{get(x, 'action')}: {role_name.get(str(v), v)}" for x in acts for v in as_list(get(x, "value"))]
        only_roles = all(get(x, "action") in ("add_role", "set_role") for x in acts)
        if len(conds) == 1 and only_roles and get(conds[0], "operator") in ("=", "eq"):
            t = dynamic_rule(str(get(conds[0], "source")), str(get(conds[0], "value")), config)
        else:
            t = dict(translation="Manual", rule="", note="Several conditions, another operator, or an action other than role assignment")
        inv["groupRules"].append(new_row("groupRule", rule=str(m.get("name") or m.get("id")), status="INACTIVE" if m.get("enabled") is False else "ACTIVE", expression=expr,
                                         target="; ".join(targets), translation=t["translation"], suggestedDynamicMembershipRule=t["rule"], reviewNote=t["note"]))
    for h in snap.rows("hooks"):
        inv["automations"].append(new_row(
            "automation", kind=f"Smart Hook: {h.get('type') or '?'}", name=str(h.get("id")), status="INACTIVE" if h.get("disabled") is True else "ACTIVE",
            detail=f"runtime {h.get('runtime') or '?'}; env vars: {', '.join(str(x) for x in as_list(h.get('envVarNames')))}", migrationClass="Gap",
            entraTarget="Custom code in the sign-in path: Conditional Access, ID Protection or a custom authentication extension, case by case"))
    for x in snap.rows("apiAuthorizations"):
        claims = as_list(get(x, "_wb.claims"))
        macros = sum(1 for cl in claims if str(get(cl, "macro") or ""))
        inv["apis"].append(new_row("api", name=str(x.get("name")), detail=f"{len(as_list(get(x, '_wb.scopes')))} scopes, {len(claims)} claims ({macros} with a macro)",
                                   migrationClass="Gap" if macros else "Rebuild", note="App registration exposing an API"))
    roles = snap.rows("roles")
    if roles:
        multi = sum(1 for r in roles if len(as_list(r.get("apps"))) > 1)
        findings.append(finding("OL-01", "Info", "Authorization", "Roles to map onto Entra groups", len(roles),
                                f"Roles assign apps to users in OneLogin. {multi} roles carry more than one app.",
                                "One group per role keeps behaviour; splitting roles per app changes who gets what.", "Design"))
    if inv["userStores"]:
        findings.append(finding("OL-02", "High", "Identities", "Directory connectors to identify", len(inv["userStores"]),
                                "; ".join(f"{s['name']}: {s['detail']}" for s in inv["userStores"]),
                                "The API gives the directory id only. Identify each one in the admin console: it decides whether password hash sync is available for those users.", "Assess"))
    inv["findings"] = findings
    inv["manualChecks"] = [
        new_row("manualCheck", item="User security policies", why="Password, MFA, session and IP rules are the source of the Conditional Access design", where="Security > Policies; one sheet per policy, with the groups it applies to"),
        new_row("manualCheck", item="App security policies", why="The snapshot shows which app points to which policy, not what the policy requires", where="Security > Policies > App policies"),
        new_row("manualCheck", item="Directories and their connectors", why="Decides the credential path per user population", where="Users > Directories"),
        new_row("manualCheck", item="Authentication factors enabled for the account", why="Each needs an Entra target", where="Security > Authentication Factors"),
        new_row("manualCheck", item="RADIUS configurations", why="VPN and network devices have no direct Entra path", where="Authentication > RADIUS"),
        new_row("manualCheck", item="Virtual LDAP service", why="LDAP consumers need Entra Domain Services or a redesign", where="Authentication > VLDAP"),
        new_row("manualCheck", item="OneLogin Desktop and device trust", why="Device sign-in moves to Entra join", where="Devices settings"),
        new_row("manualCheck", item="Trusted IdP configuration and Microsoft 365 federation settings", why="Coexistence design and immutable ID source", where="Authentication > Trusted IdPs; the Office 365 app configuration"),
    ]
    return inv
