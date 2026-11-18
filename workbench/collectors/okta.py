"""Okta Workforce Identity: collector and normaliser."""
from __future__ import annotations

import re
import time
import uuid
from collections import Counter
from datetime import timedelta

import jwt

from ..core import as_list, dynamic_rule, finding, get, new_app, new_inventory, new_row, norm_name, parse_time
from ..httpc import HttpError
from .base import BaseConnector, ConnectorError, field

SCOPES = ["okta.orgs.read", "okta.users.read", "okta.groups.read", "okta.apps.read", "okta.policies.read", "okta.networkZones.read",
          "okta.idps.read", "okta.authenticators.read", "okta.eventHooks.read", "okta.inlineHooks.read", "okta.apiTokens.read",
          "okta.profileMappings.read", "okta.devices.read", "okta.behaviors.read", "okta.trustedOrigins.read", "okta.schemas.read",
          "okta.authorizationServers.read", "okta.roles.read", "okta.logs.read", "okta.factors.read"]
NEXT = re.compile(r'<([^>]+)>;\s*rel="next"')


class Connector(BaseConnector):
    PLATFORM = "okta"
    LABEL = "Okta"
    PERMISSIONS = ("Recommended: an API service app with a public key (private_key_jwt), DPoP switched off, the okta.*.read scopes granted, "
                   "and the Read-only Administrator role. Alternative: an API token of a Read-only Administrator.")
    FIELDS = [
        field("orgUrl", "Org URL", required=True, help="https://your-org.okta.com (not the -admin URL)"),
        field("authMode", "Authentication", "select", default="oauth", options=[["oauth", "Service app with key (recommended)"], ["ssws", "API token"]]),
        field("clientId", "Client ID", help="Service app client ID (OAuth)", group="oauth"),
        field("privateKey", "Private key (PEM)", "textarea-secret", help="RSA private key of the service app", group="oauth"),
        field("keyId", "Key ID (kid)", help="Optional", group="oauth"),
        field("apiToken", "API token", "secret", group="ssws"),
        field("logDays", "Days of System Log to read", "number", default=90, help="0 to 90. 0 skips usage"),
        field("includeFactors", "Read enrolled factors per user", "bool", default=False, help="One request per active user"),
        field("skipAppAssignments", "Skip app assignments", "bool", default=False, help="Faster on very large orgs; assignment counts are then missing"),
        field("allowInsecure", "Allow http (lab only)", "bool", default=False),
    ]

    def __init__(self, cfg: dict):
        super().__init__(cfg)
        self.org = str(self.cfg["orgUrl"]).rstrip("/")
        if "-admin." in self.org:
            raise ConnectorError("Use the org URL without -admin")
        mode = self.cfg["authMode"]
        if mode == "oauth" and not (self.cfg["clientId"] and self.cfg["privateKey"]):
            raise ConnectorError("Missing: Client ID and private key")
        if mode == "ssws" and not self.cfg["apiToken"]:
            raise ConnectorError("Missing: API token")
        if not 0 <= int(self.cfg["logDays"] or 0) <= 90:
            raise ConnectorError("Days of System Log must be between 0 and 90")
        self.client([self.org])

    def source_name(self) -> str:
        return self.org

    def fetch_token(self) -> tuple[str, int]:
        url = f"{self.org}/oauth2/v1/token"
        now = int(time.time())
        headers = {"kid": self.cfg["keyId"]} if self.cfg.get("keyId") else None
        try:
            assertion = jwt.encode({"iss": self.cfg["clientId"], "sub": self.cfg["clientId"], "aud": url, "iat": now, "exp": now + 300,
                                    "jti": str(uuid.uuid4())}, self.cfg["privateKey"], algorithm="RS256", headers=headers)
        except Exception as exc:
            raise ConnectorError(f"The private key cannot be used: {type(exc).__name__}") from exc
        try:
            body = self.http.token(url, data={"grant_type": "client_credentials", "scope": " ".join(SCOPES),
                                              "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                                              "client_assertion": assertion})
        except HttpError as exc:
            raise HttpError(exc.status, f"{exc}. Check the client ID, the key, that DPoP is off on the service app, and that every scope is granted.", url) from exc
        return body["access_token"], int(body.get("expires_in", 3600)) - 60

    def _headers(self) -> dict:
        if self.cfg["authMode"] == "ssws":
            return {"Authorization": f"SSWS {self.cfg['apiToken']}", "Accept": "application/json"}
        return self.bearer()

    def _get(self, url: str, params: dict | None = None):
        try:
            return self.http.get(url, self._headers(), params)
        except HttpError as exc:
            if exc.status == 401 and self.cfg["authMode"] == "oauth":
                self._token = None
                return self.http.get(url, self._headers(), params)
            raise

    def paged(self, path: str, params: dict | None = None):
        url, seen = self.org + path, set()
        while url:
            if url in seen:
                raise HttpError(None, f"Paging loop on {path}")
            seen.add(url)
            resp = self._get(url, params)
            params = None
            body = resp.json() if resp.content else []
            m = NEXT.search(resp.headers.get("Link", "") or "")
            url = m.group(1) if m else None
            if isinstance(body, dict) and isinstance(body.get("value"), list):      # the newer envelope: {"value": [...], "_links": {...}}
                items, url = body["value"], get(body, "_links.next.href")
            else:
                items = body if isinstance(body, list) else [body]
            yield from items
            if not items:
                return

    def test(self) -> dict:
        org = self._get(f"{self.org}/api/v1/org").json()
        return {"ok": True, "detail": f"Connected to {get(org, 'companyName', self.org)} ({self.cfg['authMode']})"}

    def collect(self, snap, files=None) -> None:
        c = self.cfg
        active_ids: list[str] = []

        def org():
            o = self._get(f"{self.org}/api/v1/org").json()
            return snap.put_obj("org", {k: get(o, k) for k in ("id", "companyName", "subdomain", "status")})

        def users():
            rows = []
            for q in ({"limit": 200}, {"limit": 200, "filter": 'status eq "DEPROVISIONED"'}):
                for u in self.paged("/api/v1/users", q):
                    row = {"id": u.get("id"), "status": u.get("status"), "created": u.get("created"), "lastLogin": u.get("lastLogin"),
                           "providerType": get(u, "credentials.provider.type"), "providerName": get(u, "credentials.provider.name"),
                           "login": get(u, "profile.login"), "email": get(u, "profile.email")}
                    rows.append(row)
                    if row["status"] == "ACTIVE":
                        active_ids.append(u["id"])
            return snap.put("users", rows)

        def apps():
            rows = []
            for app in self.paged("/api/v1/apps", {"limit": 200}):
                extra = {"groupAssignments": None, "userAssignments": None, "assignmentError": None}
                if not c["skipAppAssignments"]:
                    try:
                        extra["groupAssignments"] = [g.get("id") for g in self.paged(f"/api/v1/apps/{app['id']}/groups", {"limit": 200})]
                        total = direct = 0
                        for au in self.paged(f"/api/v1/apps/{app['id']}/users", {"limit": 500}):
                            total += 1
                            direct += 1 if au.get("scope") == "USER" else 0
                        extra["userAssignments"] = {"total": total, "direct": direct, "viaGroup": total - direct}
                    except HttpError as exc:
                        extra["assignmentError"] = str(exc)
                app["_wb"] = extra
                rows.append(app)
            return snap.put("apps", rows, protect=True)

        def policies():
            rows = []
            for ptype in ("OKTA_SIGN_ON", "ACCESS_POLICY", "MFA_ENROLL", "PASSWORD", "IDP_DISCOVERY", "PROFILE_ENROLLMENT"):
                try:
                    plist = list(self.paged("/api/v1/policies", {"type": ptype}))
                except HttpError as exc:
                    snap.add_error(f"policies/{ptype}", exc.status, str(exc))
                    continue
                for p in plist:
                    p["_wb"] = {"rules": list(self.paged(f"/api/v1/policies/{p['id']}/rules"))}
                    rows.append(p)
            return snap.put("policies", rows)

        def simple(name, path, params=None, protect=False, optional=False):
            snap.step(name, lambda: snap.put(name, self.paged(path, params), protect=protect), optional=optional)

        snap.step("org", org)
        snap.step("users", users)
        simple("groups", "/api/v1/groups", {"limit": 200, "expand": "stats"})
        simple("groupRules", "/api/v1/groups/rules", {"limit": 200})
        snap.step("apps", apps)
        snap.step("policies", policies)
        simple("zones", "/api/v1/zones", {"limit": 200})
        simple("idps", "/api/v1/idps", {"limit": 200}, protect=True)
        simple("authenticators", "/api/v1/authenticators")
        simple("eventHooks", "/api/v1/eventHooks", protect=True)
        simple("inlineHooks", "/api/v1/inlineHooks", protect=True)
        simple("apiTokens", "/api/v1/api-tokens", {"limit": 200}, protect=True)
        simple("devices", "/api/v1/devices", {"limit": 200}, optional=True)
        simple("behaviors", "/api/v1/behaviors", optional=True)
        simple("trustedOrigins", "/api/v1/trustedOrigins", {"limit": 200})

        def schema():
            s = self._get(f"{self.org}/api/v1/meta/schemas/user/default").json()
            custom = sorted((get(s, "definitions.custom.properties") or {}).keys())
            snap.put_obj("userSchema", {"customAttributes": custom})
            return len(custom)

        def auth_servers():
            rows = []
            for srv in self.paged("/api/v1/authorizationServers", {"limit": 200}):
                srv["_wb"] = {sub: list(self.paged(f"/api/v1/authorizationServers/{srv['id']}/{sub}")) for sub in ("scopes", "claims", "policies")}
                rows.append(srv)
            return snap.put("authorizationServers", rows, protect=True)

        def admin_roles():
            rows = []
            for a in self.paged("/api/v1/iam/assignees/users", {"limit": 100}):
                roles = [{k: r.get(k) for k in ("type", "label", "assignmentType", "status")} for r in self.paged(f"/api/v1/users/{a['id']}/roles")]
                rows.append({"userId": a["id"], "roles": roles})
            return snap.put("adminRoles", rows)

        def usage():
            since = (snap.started - timedelta(days=int(c["logDays"]))).strftime("%Y-%m-%dT%H:%M:%S.000Z")
            until = snap.started.strftime("%Y-%m-%dT%H:%M:%S.000Z")
            use: dict[str, dict] = {}
            radius_users, radius_events, read = set(), 0, 0
            q = {"since": since, "until": until, "limit": 1000, "sortOrder": "ASCENDING",
                 "filter": 'eventType eq "user.authentication.sso" or eventType eq "user.authentication.auth_via_radius"'}
            for ev in self.paged("/api/v1/logs", q):
                read += 1
                actor = get(ev, "actor.id", "")
                if ev.get("eventType") == "user.authentication.auth_via_radius":
                    radius_events += 1
                    radius_users.add(actor)
                    continue
                for t in as_list(ev.get("target")):
                    if get(t, "type") != "AppInstance":
                        continue
                    e = use.setdefault(t["id"], {"label": t.get("displayName"), "signIns": 0, "users": set(), "last": None})
                    e["signIns"] += 1
                    e["users"].add(actor)
                    pub = ev.get("published")
                    if pub and (e["last"] is None or pub > e["last"]):
                        e["last"] = pub
            snap.put_obj("logSummary", {"since": since, "until": until, "days": int(c["logDays"]), "eventsRead": read,
                                        "radius": {"events": radius_events, "distinctUsers": len(radius_users)}})
            return snap.put("appUsage", [{"appId": k, "label": e["label"], "signIns": e["signIns"], "distinctUsers": len(e["users"]),
                                          "lastSignIn": e["last"]} for k, e in use.items()])

        def factors():
            rows = []
            for uid in active_ids:
                kinds = [f"{f.get('factorType')}/{f.get('provider')}" for f in self.paged(f"/api/v1/users/{uid}/factors") if f.get("status") == "ACTIVE"]
                rows.append({"userId": uid, "factors": kinds})
            return snap.put("userFactors", rows)

        snap.step("userSchema", schema)
        snap.step("authorizationServers", auth_servers)
        snap.step("adminRoles", admin_roles)
        if int(c["logDays"] or 0) > 0:
            snap.step("appUsage", usage)
        if c["includeFactors"]:
            snap.step("userFactors", factors)
        self.finish(snap)


# ---- normaliser ---------------------------------------------------------------------------------

AUTHENTICATORS = {
    "okta_password": ("Password hash sync for directory users; new credential for Okta-sourced users", "Rebuild"),
    "okta_verify": ("Microsoft Authenticator (push, passkey) or a platform credential", "User action"),
    "okta_email": ("Not a sign-in MFA method in Entra; email is for password reset only", "Gap"),
    "phone_number": ("SMS or voice call; supported, not recommended as a target", "User action"),
    "security_question": ("Password reset only; not an MFA method in Entra", "Gap"),
    "webauthn": ("Passkey (FIDO2); keys are registered again", "User action"),
    "security_key": ("Passkey (FIDO2); keys are registered again", "User action"),
    "google_otp": ("Third-party software OATH token", "User action"),
    "rsa_token": ("External MFA provider or hardware OATH token; no native RSA support", "Gap"),
    "symantec_vip": ("External MFA provider or hardware OATH token", "Gap"),
    "duo": ("Duo as external MFA provider", "Rebuild"),
    "onprem_mfa": ("External MFA provider or replacement", "Gap"),
    "yubikey_token": ("Yubico OTP is not supported; use the same keys as FIDO2 passkeys where capable", "Gap"),
    "smart_card_idp": ("Certificate-based authentication", "Rebuild"),
    "custom_otp": ("Hardware OATH token", "Rebuild"),
    "custom_app": ("External MFA provider", "Gap"),
    "external_idp": ("External MFA provider or federation", "Rebuild"),
}
SIMPLE_VALUE = re.compile(r"^(user|appuser|source)\.[A-Za-z0-9_]+$")
DEFAULT_NAMEIDS = {"${user.userName}", "${user.email}", "${user.login}", "${source.login}", "${source.email}"}


def _pattern(app: dict) -> str:
    mode = str(app.get("signOnMode") or "")
    if re.search("radius", f"{mode} {app.get('name')} {app.get('label')}", re.I):
        return "RADIUS"
    return {"SAML_2_0": "SAML", "SAML_1_1": "SAML 1.1", "OPENID_CONNECT": "OIDC", "WS_FEDERATION": "WS-Fed", "BOOKMARK": "Bookmark",
            "AUTO_LOGIN": "SWA", "BROWSER_PLUGIN": "SWA", "SECURE_PASSWORD_STORE": "SWA", "BASIC_AUTH": "SWA"}.get(mode, "Other")


def normalize(snap, config: dict) -> dict:
    inv = new_inventory("Okta", str(get(snap.obj("org"), "companyName") or snap.source))
    inv["lastLoginKnown"] = True
    extra: list[dict] = []
    collected = snap.started

    for u in snap.rows("users"):
        status = u.get("status")
        ptype = str(u.get("providerType") or "UNKNOWN")
        inv["users"].append(new_row("user", id=u.get("id"), login=u.get("login"), email=u.get("email"),
                                    status="DELETED" if status == "DEPROVISIONED" else status, source=ptype,
                                    localPassword=(ptype == "OKTA"), lastLogin=u.get("lastLogin")))
    inv["usersNote"] = "Okta does not export passwords and Entra does not import foreign hashes."
    logins = {u.get("id"): u.get("login") for u in snap.rows("users")}

    stores = Counter((u.get("providerType"), u.get("providerName")) for u in snap.rows("users")
                     if u.get("status") == "ACTIVE" and u.get("providerType") in ("ACTIVE_DIRECTORY", "LDAP", "IMPORT"))
    for (ptype, pname), n in stores.most_common():
        if ptype == "ACTIVE_DIRECTORY":
            inv["userStores"].append(new_row("userStore", name=pname or "Active Directory", type="Active Directory agent", detail=f"{n} active users",
                                             entraTarget="Entra Connect Sync or Cloud Sync from the same AD; password hash sync carries the passwords"))
        elif ptype == "LDAP":
            inv["userStores"].append(new_row("userStore", name=pname or "LDAP", type="LDAP agent", detail=f"{n} active users", migrationClass="Gap",
                                             entraTarget="No direct sync from this directory: inbound provisioning or a move of the identities"))
        else:
            inv["userStores"].append(new_row("userStore", name=pname or "Import", type="Sourced from an application (HR or other)", detail=f"{n} active users",
                                             entraTarget="Inbound provisioning from the same source (API-driven or a gallery HR connector)"))

    if snap.has("userFactors"):
        none = strong = 0
        dist: Counter = Counter()
        for u in snap.rows("userFactors"):
            f = as_list(u.get("factors"))
            none += 0 if f else 1
            strong += 1 if any(k.startswith("webauthn/") or k.startswith("signed_nonce/") for k in f) else 0
            dist.update(f)
        inv["factorSummary"] = {"usersChecked": len(snap.rows("userFactors")), "usersWithoutFactor": none,
                                "usersWithPhishingResistantFactor": strong, "enrolmentsByFactor": dict(dist.most_common())}

    inv["usageKnown"] = snap.has("appUsage")
    usage = {r["appId"]: r for r in snap.rows("appUsage")}
    if inv["usageKnown"]:
        inv["usageDays"] = get(snap.obj("logSummary"), "days")
    else:
        inv["usageNote"] = "The System Log was not read (days set to 0) or the connector may not read it."

    policy_names = {p.get("id"): p.get("name") for p in snap.rows("policies")}
    subdomain = str(get(snap.obj("org"), "subdomain") or "")
    apps_per_policy: Counter = Counter()
    for app in snap.rows("apps"):
        pattern = _pattern(app)
        name = str(app.get("name") or "")
        custom_by_name = bool(re.match(r"^(oidc_client|bookmark|template_.*)$", name)) or bool(
            subdomain and (name.startswith(subdomain + "_") or name.startswith(norm_name(subdomain) + "_")))
        features = as_list(app.get("features"))
        outbound = any(str(f).startswith("PUSH_") for f in features)
        inbound = any(str(f).startswith("IMPORT_") for f in features)
        complex_claims = group_claims = 0
        for st in as_list(get(app, "settings.signOn.attributeStatements")):
            if get(st, "type") == "GROUP":
                group_claims += 1
                continue
            if any(not SIMPLE_VALUE.match(str(v)) for v in as_list(get(st, "values"))):
                complex_claims += 1
        name_id = get(app, "settings.signOn.subjectNameIdTemplate")
        custom_name_id = pattern.startswith("SAML") and bool(name_id) and name_id not in DEFAULT_NAMEIDS
        encrypted = False
        for k, v in (get(app, "settings.signOn") or {}).items():
            if re.search("encrypt", k, re.I) and (v is True or get(v, "enabled") is True):
                encrypted = True
        href = get(app, "_links.accessPolicy.href")
        pol_id = href.rsplit("/", 1)[-1] if href else None
        if pol_id and app.get("status") == "ACTIVE":
            apps_per_policy[pol_id] += 1
        u = usage.get(app.get("id"))
        notes = []
        if get(app, "_wb.assignmentError"):
            notes.append("Assignments could not be read")
        is_o365 = name == "office365"
        inv["apps"].append(new_app(
            id=app.get("id"), label=str(app.get("label") or name), pattern=pattern, kind=str(app.get("signOnMode") or ""),
            status="ACTIVE" if app.get("status") == "ACTIVE" else "INACTIVE", isPlatform=is_o365,
            isMachine=(get(app, "settings.oauthClient.application_type") == "service"),
            signIns=u["signIns"] if u else None, distinctUsers=u["distinctUsers"] if u else None, lastSignIn=u["lastSignIn"] if u else None,
            assignedUsers=get(app, "_wb.userAssignments.total"), directAssignments=get(app, "_wb.userAssignments.direct"),
            provisioning="Both" if outbound and inbound else "Outbound" if outbound else "Inbound" if inbound else "None",
            complexClaims=complex_claims, groupClaims=group_claims, customNameId=custom_name_id, encrypted=encrypted,
            usesClientSecret=(pattern == "OIDC" and str(get(app, "credentials.oauthClient.token_endpoint_auth_method") or "").startswith("client_secret")),
            owner=get(app, "settings.notes.admin"), policy=policy_names.get(pol_id, pol_id) if pol_id else None,
            notes=notes, catalogHint=not custom_by_name))

    o365 = [a for a in snap.rows("apps") if a.get("name") == "office365" and a.get("status") == "ACTIVE"]
    inv["m365Federated"] = any(a.get("signOnMode") == "WS_FEDERATION" for a in o365)
    inv["stateEvidence"] = ["Okta has an active Microsoft 365 app in WS-Federation mode" if inv["m365Federated"]
                            else "Okta has a Microsoft 365 app, but not in WS-Federation mode" if o365 else "No active Microsoft 365 app in Okta"]

    # policies: every rule becomes one row of the parity checklist
    zone_names = {z.get("id"): z.get("name") for z in snap.rows("zones")}
    zone_use: Counter = Counter()
    for p in snap.rows("policies"):
        rules = as_list(get(p, "_wb.rules")) or [None]
        for r in rules:
            cond = get(r, "conditions") or {}
            conn = get(cond, "network.connection")
            parts = []
            if conn == "ZONE":
                inc = [zone_names.get(z, z) for z in as_list(get(cond, "network.include"))]
                exc = [zone_names.get(z, z) for z in as_list(get(cond, "network.exclude"))]
                for z in as_list(get(cond, "network.include")) + as_list(get(cond, "network.exclude")):
                    zone_use[z] += 1
                if inc:
                    parts.append("network in: " + ", ".join(inc))
                if exc:
                    parts.append("network not in: " + ", ".join(exc))
            elif conn:
                parts.append("network: anywhere")
            device = "Managed" if get(cond, "device.managed") is True else "Registered" if get(cond, "device.registered") is True else ""
            risk = str(get(cond, "riskScore.level") or "")
            risk = "" if risk == "ANY" else risk
            platform = ", ".join(str(get(x, "os.type")) for x in as_list(get(cond, "platform.include")) if get(x, "os.type"))
            if device:
                parts.append(f"device: {device}")
            if risk:
                parts.append(f"risk: {risk}")
            if platform:
                parts.append(f"platform: {platform}")
            access = auth = session = ""
            ca: list[str] = []
            note: list[str] = []
            ptype = p.get("type")
            if ptype == "OKTA_SIGN_ON":
                so = get(r, "actions.signon") or {}
                access = str(so.get("access") or "")
                if access == "DENY":
                    ca.append("Block access")
                elif so.get("requireFactor") is True:
                    mode = str(so.get("factorPromptMode") or "SESSION")
                    auth = f"MFA, prompt: {mode}"
                    ca.append("Grant: require MFA")
                    if mode == "ALWAYS":
                        ca.append("Session: sign-in frequency, every time")
                    if mode == "DEVICE":
                        note.append("Per-device prompt has no like-for-like control; use sign-in frequency or a compliant-device condition")
                elif r:
                    auth = "No MFA"
                    note.append("Password-only access. In Entra this becomes an exclusion from the MFA policy; challenge whether it should survive")
                life, idle = get(so, "session.maxSessionLifetimeMinutes"), get(so, "session.maxSessionIdleMinutes")
                if life:
                    session = f"lifetime {life} min"
                    ca.append(f"Session: sign-in frequency {round(life / 60, 1)} h")
                if idle:
                    session += (", " if session else "") + f"idle {idle} min"
                    note.append("Idle timeout is not a Conditional Access control; decide on an app-level or tenant idle-session setting")
            elif ptype == "ACCESS_POLICY":
                ao = get(r, "actions.appSignOn") or {}
                access = str(ao.get("access") or "")
                mode = str(get(ao, "verificationMethod.factorMode") or "")
                pr = any(get(x, "possession.phishingResistant") == "REQUIRED" for x in as_list(get(ao, "verificationMethod.constraints")))
                if access == "DENY":
                    ca.append("Block access")
                elif pr:
                    auth = f"{mode}, phishing-resistant"
                    ca.append("Grant: authentication strength, phishing-resistant MFA")
                elif mode == "2FA":
                    auth = "2FA"
                    ca.append("Grant: require MFA")
                elif mode == "1FA":
                    auth = "1FA"
                    note.append("Single factor allowed. Below a sensible Entra baseline; decide whether to raise it")
                re_auth = get(ao, "verificationMethod.reauthenticateIn")
                if re_auth:
                    session = f"re-authenticate {re_auth}"
                    ca.append(f"Session: sign-in frequency ({re_auth})")
                parts.append(f"active apps on policy: {apps_per_policy.get(p.get('id'), 0)}")
            elif ptype == "MFA_ENROLL":
                ca.append("Authentication methods policy and registration campaign")
            elif ptype == "PASSWORD":
                ca.append("Password policy stays with the source directory; Entra password protection and SSPR")
            elif ptype == "IDP_DISCOVERY":
                ca.append("Home realm discovery or external identity provider federation")
                note.append("Routing rules are also the lever for reverse federation during coexistence")
            elif ptype == "PROFILE_ENROLLMENT":
                note.append("Self-registration: usually not needed for workforce identities")
            if conn == "ZONE":
                ca.append("Condition: named location")
            if device == "Managed":
                ca.append("Grant: require compliant or hybrid-joined device")
            elif device == "Registered":
                ca.append("Condition: device filter (registered)")
                note.append('Okta "registered" means Okta Verify is enrolled; there is no identical Entra signal')
            if risk:
                ca.append(f"Condition: sign-in risk {risk} (needs Entra ID P2)")
            if platform:
                ca.append("Condition: device platform")
            active = p.get("status") == "ACTIVE" and (r is None or get(r, "status") == "ACTIVE")
            inv["policies"].append(new_row("policy", policyType=str(ptype), policy=str(p.get("name")), rule=str(get(r, "name") or ""),
                                           status="ACTIVE" if active else "INACTIVE", conditions="; ".join(parts), access=access or "ALLOW",
                                           authentication=auth, session=session, conditionalAccessBuildingBlocks=" | ".join(ca), reviewNote=" | ".join(note)))

    for z in snap.rows("zones"):
        proxy = get(z, "proxyType")
        target = ("No direct equivalent: anonymous-IP detection in Entra ID Protection" if proxy else "Named location, IP ranges" if z.get("type") == "IP"
                  else "Named location, countries" if as_list(get(z, "locations")) else "Review manually")
        if get(z, "usage") == "BLOCKLIST":
            target += "; used in a block policy"
        inv["zones"].append(new_row("zone", zone=str(z.get("name")), type=str(z.get("type")), usage=str(get(z, "usage") or ""), status=str(get(z, "status") or ""),
                                    entries=len(as_list(get(z, "gateways"))) + len(as_list(get(z, "locations"))), usedByRules=zone_use.get(z.get("id"), 0), entraTarget=target))
    zone_gap = [z for z in inv["zones"] if z["entraTarget"].startswith("No direct equivalent")]
    if zone_gap:
        extra.append(finding("POL-03", "Medium", "Policies", "Network zones without a named-location equivalent", len(zone_gap),
                             ", ".join(z["zone"] for z in zone_gap), "Replace by risk-based policies or accept the difference.", "Design"))

    group_names = {g.get("id"): get(g, "profile.name") for g in snap.rows("groups")}
    for r in snap.rows("groupRules"):
        expr = str(get(r, "conditions.expression.value") or "")
        targets = [str(group_names.get(g, g)) for g in as_list(get(r, "actions.assignUserToGroups.groupIds"))]
        m = re.match(r'^\s*user\.([A-Za-z0-9_]+)\s*==\s*"([^"]*)"\s*$', expr)
        t = dynamic_rule(m.group(1), m.group(2), config) if m else dict(translation="Manual", rule="", note="Expression uses functions or several conditions")
        inv["groupRules"].append(new_row("groupRule", rule=str(r.get("name")), status=str(get(r, "status") or "ACTIVE"), expression=expr, target=", ".join(targets),
                                         translation=t["translation"], suggestedDynamicMembershipRule=t["rule"], reviewNote=t["note"]))

    for a in snap.rows("authenticators"):
        target, cls = AUTHENTICATORS.get(str(a.get("key")), ("Unknown authenticator: review manually", "Gap"))
        inv["mfaMethods"].append(new_row("mfa", method=str(a.get("name")), key=str(a.get("key")), status=str(get(a, "status") or "ACTIVE"), entraTarget=target, migrationClass=cls))

    def host_of(h):
        uri = get(h, "channel.config.uri")
        return re.sub(r"^https?://([^/]+).*$", r"\1", uri) if uri else ""

    for h in snap.rows("eventHooks"):
        inv["automations"].append(new_row("automation", kind="Event hook", name=str(h.get("name")), status=str(get(h, "status") or "ACTIVE"),
                                          detail=f"{', '.join(as_list(get(h, 'events.items')))} -> {host_of(h)}",
                                          entraTarget="Microsoft Graph change notifications, or log export to the same consumer"))
    for h in snap.rows("inlineHooks"):
        htype = str(get(h, "type") or "")
        target, cls = ("Custom claims provider (custom authentication extension)", "Gap") if htype.endswith("tokens.transform") else \
            ("No equivalent for workforce tenants; credentials are set anew", "Gap") if htype.endswith("password.import") else \
            ("Not applicable to workforce identities", "Gap") if htype.endswith("pre-registration") else \
            ("Provisioning attribute mapping expressions", "Rebuild") if htype.endswith("import.transform") else ("Review manually", "Gap")
        inv["automations"].append(new_row("automation", kind="Inline hook", name=str(h.get("name")), status=str(get(h, "status") or "ACTIVE"),
                                          detail=f"{htype} -> {host_of(h)}", migrationClass=cls, entraTarget=target))
    tokens = []
    for t in snap.rows("apiTokens"):
        last = parse_time(get(t, "lastUpdated"))
        age = (collected - last).days if last else None
        owner = logins.get(get(t, "userId"), get(t, "userId") or "")
        row = new_row("automation", kind="API token", name=str(t.get("name")), status="STALE" if age is not None and age > config["staleDays"] else "ACTIVE",
                      detail=f"client: {get(t, 'clientName', 'unknown')}; last used {get(t, 'lastUpdated') or 'unknown'}", owner=str(owner),
                      entraTarget="Find the script or integration behind the token; move it to Microsoft Graph with an app registration")
        tokens.append(row)
        inv["automations"].append(row)
    if tokens:
        stale = sum(1 for t in tokens if t["status"] == "STALE")
        extra.append(finding("AUT-03", "High", "Automations", "Okta API tokens: each one is a script or integration to find", len(tokens),
                             f"{stale} not used in {config['staleDays']} days. Owners: {', '.join(sorted({t['owner'] for t in tokens if t['owner']}))}",
                             "Interview the owners. These are the hidden dependencies that break at decommissioning.", "Assess"))

    for s in snap.rows("authorizationServers"):
        scopes = [x for x in as_list(get(s, "_wb.scopes")) if get(x, "system") is not True]
        claims = [x for x in as_list(get(s, "_wb.claims")) if get(x, "system") is not True]
        expr = [x for x in claims if get(x, "valueType") == "EXPRESSION" and not re.match(r"^(user|appuser|app)\.[A-Za-z0-9_]+$", str(get(x, "value")))]
        grp = [x for x in claims if get(x, "valueType") == "GROUPS"]
        plain_default = s.get("name") == "default" and not scopes and not claims
        note = ("Default server without custom scopes or claims: map clients to Microsoft Graph or OIDC scopes" if plain_default
                else "Inactive: confirm and drop" if get(s, "status") != "ACTIVE"
                else "One app registration exposing an API; scopes become delegated permissions or app roles")
        inv["apis"].append(new_row("api", name=str(s.get("name")), status=str(get(s, "status") or "ACTIVE"),
                                   detail=f"{len(scopes)} custom scopes, {len(claims)} custom claims ({len(expr)} expressions, {len(grp)} group claims), "
                                          f"{len(as_list(get(s, '_wb.policies')))} access policies; audiences: {', '.join(as_list(get(s, 'audiences')))}",
                                   migrationClass="Generate" if plain_default else "Gap" if expr else "Rebuild", note=note))

    for i in snap.rows("idps"):
        inv["federation"].append(new_row("federation", name=str(i.get("name")), type=str(get(i, "type") or ""), status=str(get(i, "status") or "ACTIVE"),
                                         detail=str(get(i, "protocol.type") or "")))

    radius = get(snap.obj("logSummary"), "radius.events") or 0
    if radius:
        extra.append(finding("APP-04", "Blocker", "Applications", "RADIUS authentications through Okta", radius,
                             f"{get(snap.obj('logSummary'), 'radius.distinctUsers')} distinct users in {get(snap.obj('logSummary'), 'days')} days.",
                             "Identify the VPN or network devices behind them before any user cohort moves.", "Assess"))
    if snap.has("adminRoles"):
        admins = snap.rows("adminRoles")
        supers = sum(1 for a in admins if any(get(r, "type") == "SUPER_ADMIN" for r in as_list(a.get("roles"))))
        extra.append(finding("ADM-01", "Info", "Administration", "Okta administrators to map onto Entra roles and PIM", len(admins), f"{supers} super administrators.",
                             "Design least-privilege Entra roles under PIM; keep Okta admin hygiene until decommissioning.", "Design"))
    if snap.rows("devices"):
        plat = Counter(str(get(d, "profile.platform") or "UNKNOWN") for d in snap.rows("devices"))
        extra.append(finding("DEV-01", "Info", "Devices", "Devices registered with Okta", len(snap.rows("devices")), ", ".join(f"{k} {v}" for k, v in plat.most_common()),
                             "Device trust moves to Entra join or hybrid join and Intune compliance; check the management estate.", "Design"))
    inv["findings"] = extra
    inv["manualChecks"] = [
        new_row("manualCheck", item="Okta Workflows", why="Flows have no export path through the API and no generated equivalent", where="Workflows console: export each flow folder"),
        new_row("manualCheck", item="Agents: AD, LDAP, RADIUS, IWA, on-premises provisioning", why="Each agent is a dependency to replace and a server to retire", where="Dashboard > Agents"),
        new_row("manualCheck", item="Okta Access Gateway applications", why="Header-based and Kerberos apps need application proxy or another gateway", where="Access Gateway admin console"),
        new_row("manualCheck", item="Device assurance and Okta Verify / FastPass settings", why="Device conditions translate to Intune compliance, not one to one", where="Security > Device Assurance Policies; Authenticators > Okta Verify"),
        new_row("manualCheck", item="Profile sourcing and attribute-level mastering", why="Decides the provisioning design and the source of authority per attribute", where="Directory > Profile Sources; Profile Editor mappings"),
        new_row("manualCheck", item="Custom domain, sign-in page and email templates", why="Branding and user communication change at cutover", where="Customizations > Brands"),
        new_row("manualCheck", item="Custom admin roles and resource sets", why="Admin access is redesigned as Entra roles under PIM", where="Security > Administrators > Roles"),
    ]
    return inv
