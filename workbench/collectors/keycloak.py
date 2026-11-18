"""Keycloak (one realm): collector and normaliser."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from urllib.parse import quote

from ..core import as_list, finding, get, new_app, new_inventory, new_row
from ..httpc import HttpError
from .base import BaseConnector, field

BUILT_IN_CLIENTS = {"account", "account-console", "admin-cli", "broker", "realm-management", "security-admin-console"}
SIMPLE_MAPPERS = {"oidc-usermodel-attribute-mapper", "oidc-usermodel-property-mapper", "oidc-full-name-mapper", "oidc-address-mapper",
                  "oidc-hardcoded-claim-mapper", "oidc-audience-mapper", "oidc-audience-resolve-mapper", "oidc-usersessionmodel-note-mapper",
                  "oidc-sha256-pairwise-sub-mapper", "oidc-allowed-origins-mapper", "oidc-acr-mapper", "oidc-sub-mapper", "saml-user-attribute-mapper",
                  "saml-user-property-mapper", "saml-hardcode-attribute-mapper", "saml-audience-mapper", "saml-user-session-note-mapper",
                  "saml-user-attribute-nameid-mapper"}
ROLE_MAPPERS = {"oidc-usermodel-realm-role-mapper", "oidc-usermodel-client-role-mapper", "oidc-role-name-mapper", "saml-role-list-mapper",
                "saml-role-name-mapper", "saml-hardcode-role-mapper", "oidc-hardcoded-role-mapper"}
GROUP_MAPPERS = {"oidc-group-membership-mapper", "saml-group-membership-mapper"}
BUILT_IN_AUTHENTICATORS = {
    "auth-cookie", "auth-spnego", "identity-provider-redirector", "auth-username-password-form", "auth-username-form", "auth-password-form",
    "auth-otp-form", "auth-conditional-otp-form", "conditional-user-configured", "conditional-user-role", "conditional-user-attribute",
    "conditional-level-of-authentication", "webauthn-authenticator", "webauthn-authenticator-passwordless", "auth-recovery-authn-code-form",
    "auth-x509-client-username-form", "direct-grant-validate-username", "direct-grant-validate-password", "direct-grant-validate-otp",
    "registration-page-form", "registration-user-creation", "registration-password-action", "registration-recaptcha-action",
    "registration-terms-and-conditions", "reset-credentials-choose-user", "reset-credential-email", "reset-password", "reset-otp", "client-secret",
    "client-jwt", "client-secret-jwt", "client-x509", "idp-review-profile", "idp-create-user-if-unique", "idp-confirm-link", "idp-email-verification",
    "idp-username-password-form", "idp-auto-link", "docker-http-basic-authenticator", "http-basic-authenticator", "deny-access-authenticator",
    "allow-access-authenticator", "organization", "idp-add-organization-member", "user-session-limits"}


class Connector(BaseConnector):
    PLATFORM = "keycloak"
    LABEL = "Keycloak"
    PERMISSIONS = ("A confidential client with a service account in the realm, holding the realm-management roles view-realm, view-users, "
                   "view-clients, view-identity-providers and view-events. One connector per realm.")
    FIELDS = [
        field("baseUrl", "Server URL", required=True, help="https://sso.example.com (add /auth for servers older than 17)"),
        field("realm", "Realm", required=True),
        field("authRealm", "Realm of the service account", help="Leave empty if the client lives in the same realm"),
        field("clientId", "Client ID", required=True),
        field("clientSecret", "Client secret", "secret", required=True),
        field("eventDays", "Days of login events to read", "number", default=90, help="0 skips usage. The realm must save login events"),
        field("includeUserCredentials", "Read credential types per user", "bool", default=False, help="One request per user; tells local passwords and MFA apart"),
        field("skipTlsVerify", "Do not verify the TLS certificate", "bool", default=False, help="Only for a server with a private certificate you trust"),
        field("allowInsecure", "Allow http (lab only)", "bool", default=False),
    ]

    def __init__(self, cfg: dict):
        super().__init__(cfg)
        self.base = str(self.cfg["baseUrl"]).rstrip("/")
        self.realm = self.cfg["realm"]
        self.auth_realm = self.cfg["authRealm"] or self.realm
        self.client([self.base])

    def source_name(self) -> str:
        return f"{self.base}/realms/{self.realm}"

    def fetch_token(self) -> tuple[str, int]:
        body = self.http.token(f"{self.base}/realms/{quote(self.auth_realm)}/protocol/openid-connect/token",
                               data={"grant_type": "client_credentials", "client_id": self.cfg["clientId"], "client_secret": self.cfg["clientSecret"]})
        return body["access_token"], int(body.get("expires_in", 60)) - 15

    def kc(self, path: str, params: dict | None = None):
        url = self.base + path if path.startswith("/admin") else f"{self.base}/admin/realms/{quote(self.realm)}{path}"
        return self.authed_json(url, params)

    def paged(self, path: str, params: dict | None = None, size: int = 100):
        first = 0
        while True:
            page = as_list(self.kc(path, {**(params or {}), "first": first, "max": size}))
            yield from page
            if len(page) < size:
                return
            first += size

    def test(self) -> dict:
        realm = self.kc("")
        return {"ok": True, "detail": f"Connected to realm {get(realm, 'realm', self.realm)}"}

    def collect(self, snap, files=None) -> None:
        c = self.cfg
        realm_box: dict = {}

        def realm():
            realm_box.update(self.kc("") or {})
            return snap.put_obj("realm", dict(realm_box), protect=True)

        def users():
            rows = []
            for u in self.paged("/users", {"briefRepresentation": "false"}):
                row = {k: u.get(k) for k in ("id", "username", "email", "enabled", "createdTimestamp", "federationLink", "totp")}
                row["credentialTypes"] = None
                if c["includeUserCredentials"]:
                    row["credentialTypes"] = sorted({str(x.get("type")) for x in as_list(self.kc(f"/users/{u['id']}/credentials"))})
                rows.append(row)
            return snap.put("users", rows)

        def flows():
            rows = []
            for f in as_list(self.kc("/authentication/flows")):
                ex = [{"displayName": e.get("displayName"), "providerId": e.get("providerId"), "requirement": e.get("requirement"), "level": e.get("level"),
                       "isSubFlow": bool(e.get("authenticationFlow"))} for e in as_list(self.kc(f"/authentication/flows/{quote(f['alias'], safe='')}/executions"))]
                rows.append({"alias": f.get("alias"), "builtIn": f.get("builtIn"), "providerId": f.get("providerId"), "executions": ex})
            return snap.put("flows", rows)

        def usage():
            if realm_box and realm_box.get("eventsEnabled") is not True:
                raise HttpError(None, "The realm does not save login events (Realm settings > Events > Save events).")
            days = int(c["eventDays"])
            date_from = (snap.started - timedelta(days=days)).strftime("%Y-%m-%d")
            use: dict[str, dict] = {}
            all_users, read = set(), 0
            for etype in ("LOGIN", "CLIENT_LOGIN"):
                for ev in self.paged("/events", {"type": etype, "dateFrom": date_from}, size=1000):
                    read += 1
                    cid = str(ev.get("clientId") or "")
                    if not cid:
                        continue
                    e = use.setdefault(cid, {"signIns": 0, "users": set(), "last": 0, "clientLogins": 0})
                    if etype == "CLIENT_LOGIN":
                        e["clientLogins"] += 1
                        continue
                    e["signIns"] += 1
                    uid = str(ev.get("userId") or "")
                    if uid:
                        e["users"].add(uid)
                        all_users.add(uid)
                    e["last"] = max(e["last"], int(ev.get("time") or 0))
            snap.put_obj("eventSummary", {"days": days, "dateFrom": date_from, "eventsRead": read, "distinctUsersWithLogin": len(all_users)})
            return snap.put("appUsage", [{"clientId": k, "signIns": e["signIns"], "distinctUsers": len(e["users"]), "clientLogins": e["clientLogins"],
                                          "lastSignIn": datetime.fromtimestamp(e["last"] / 1000, timezone.utc).isoformat() if e["last"] else None}
                                         for k, e in use.items()])

        snap.step("realm", realm)
        snap.step("clients", lambda: snap.put("clients", self.paged("/clients"), protect=True))
        snap.step("clientScopes", lambda: snap.put("clientScopes", as_list(self.kc("/client-scopes"))))
        snap.step("users", users)
        snap.step("groups", lambda: snap.put("groups", ({k: g.get(k) for k in ("id", "name", "path", "subGroupCount")} for g in self.paged("/groups"))))
        snap.step("roles", lambda: snap.put("roles", ({k: r.get(k) for k in ("id", "name", "composite")} for r in self.paged("/roles"))))
        snap.step("identityProviders", lambda: snap.put("identityProviders", as_list(self.kc("/identity-provider/instances")), protect=True))
        snap.step("userStorage", lambda: snap.put("userStorage", as_list(self.kc("/components", {"type": "org.keycloak.storage.UserStorageProvider"})), protect=True))
        snap.step("flows", flows)
        snap.step("requiredActions", lambda: snap.put("requiredActions", as_list(self.kc("/authentication/required-actions"))))
        if int(c["eventDays"] or 0) > 0:
            snap.step("appUsage", usage)
        snap.step("serverInfo", lambda: snap.put_obj("serverInfo", {"version": get(self.kc("/admin/serverinfo"), "systemInfo.version")}), optional=True)
        self.finish(snap)


def _first(value):
    v = as_list(value)
    return str(v[0]) if v else ""


def normalize(snap, config: dict) -> dict:
    realm = snap.obj("realm")
    inv = new_inventory("Keycloak", f"realm {get(realm, 'realm', '?')}")
    findings = []
    stores = {}
    for c in snap.rows("userStorage"):
        vendor = _first(get(c, "config.vendor"))
        stores[c.get("id")] = c.get("name")
        url = _first(get(c, "config.connectionUrl"))
        if c.get("providerId") == "ldap" and vendor == "ad":
            inv["userStores"].append(new_row("userStore", name=str(c.get("name")), type="LDAP: Active Directory", detail=url,
                                             entraTarget="Entra Connect Sync or Cloud Sync from the same AD; password hash sync carries the passwords"))
        elif c.get("providerId") in ("ldap", "kerberos"):
            inv["userStores"].append(new_row("userStore", name=str(c.get("name")), type=f"LDAP: {vendor}".rstrip(": "), detail=url, migrationClass="Gap",
                                             entraTarget="No direct sync from this directory: inbound provisioning or a move of the identities"))
        else:
            inv["userStores"].append(new_row("userStore", name=str(c.get("name")), type=f"Custom provider: {c.get('providerId')}", migrationClass="Gap",
                                             entraTarget="Custom user storage code: no equivalent"))
    creds_known = bool(get(snap.manifest or {}, "options.includeUserCredentials"))
    for u in snap.rows("users"):
        link = u.get("federationLink")
        types = as_list(u.get("credentialTypes"))
        local = False if link else ("password" in types) if creds_known else True
        inv["users"].append(new_row("user", id=u.get("id"), login=u.get("username"), email=u.get("email"),
                                    status="DISABLED" if u.get("enabled") is False else "ACTIVE",
                                    source=("Federated: " + str(stores.get(link, link))) if link else "KEYCLOAK", localPassword=local))
    inv["usersNote"] = "" if creds_known else "Upper bound: users who sign in through a brokered identity provider cannot be told apart unless credential types are read per user."
    enabled = sum(1 for u in inv["users"] if u["status"] == "ACTIVE")
    with_login = get(snap.obj("eventSummary"), "distinctUsersWithLogin")
    if with_login is not None:
        inv["staleActiveEstimate"] = max(0, enabled - int(with_login))
    if creds_known:
        active = [u for u in snap.rows("users") if u.get("enabled") is not False]
        none = sum(1 for u in active if not any(t in ("otp", "webauthn", "webauthn-passwordless") for t in as_list(u.get("credentialTypes"))))
        strong = sum(1 for u in active if any(str(t).startswith("webauthn") for t in as_list(u.get("credentialTypes"))))
        inv["factorSummary"] = {"usersChecked": len(active), "usersWithoutFactor": none, "usersWithPhishingResistantFactor": strong}

    inv["usageKnown"] = snap.has("appUsage")
    usage = {str(r["clientId"]): r for r in snap.rows("appUsage")}
    if inv["usageKnown"]:
        inv["usageDays"] = get(snap.obj("eventSummary"), "days")
    else:
        inv["usageNote"] = "Login events are not saved on the realm, or were not collected. Switch on event saving and collect again after at least 30 days."

    for c in snap.rows("clients"):
        cid = str(c.get("clientId"))
        if cid in BUILT_IN_CLIENTS or cid.endswith("-realm"):
            continue
        label = str(c.get("name") or cid)
        if label.startswith("${"):
            label = cid
        status = "INACTIVE" if c.get("enabled") is False else "ACTIVE"
        if c.get("bearerOnly") is True:
            inv["apis"].append(new_row("api", name=label, status=status, detail="Bearer-only client (resource server)",
                                       note="App registration exposing an API; validate tokens from the new issuer"))
            continue
        flags, notes = [], []
        complex_claims = role_or_group = 0
        for m in as_list(c.get("protocolMappers")):
            mtype = str(get(m, "protocolMapper") or "")
            if mtype in SIMPLE_MAPPERS:
                continue
            if mtype in ROLE_MAPPERS or mtype in GROUP_MAPPERS:
                role_or_group += 1
                continue
            complex_claims += 1
            if "custom-mapper" not in flags:
                flags.append("custom-mapper")
        saml = c.get("protocol") == "saml"
        service = c.get("serviceAccountsEnabled") is True
        std = c.get("standardFlowEnabled") is True
        direct = c.get("directAccessGrantsEnabled") is True
        implicit = c.get("implicitFlowEnabled") is True
        if not saml:
            if direct:
                flags.append("password-grant")
            if implicit:
                flags.append("implicit-flow")
            if c.get("authorizationServicesEnabled") is True:
                flags.append("uma-authorization")
            notes.append("Role or group claims: the claim name and format change in Entra tokens" if role_or_group
                         else "Check whether the app reads realm_access or resource_access from the token")
        if any(v for v in (c.get("authenticationFlowBindingOverrides") or {}).values()):
            notes.append("Client-specific sign-in flow")
        u = usage.get(cid)
        public = c.get("publicClient") is True
        machine = (not saml) and service and not std and not implicit and not direct
        inv["apps"].append(new_app(
            id=cid, label=label, status=status, pattern="SAML" if saml else "OIDC",
            kind="SAML client" if saml else "Service account" if machine else "Public client" if public else "Confidential client",
            isPlatform=(cid == "urn:federation:MicrosoftOnline"), isMachine=machine,
            signIns=(int(u["signIns"]) + int(u.get("clientLogins") or 0)) if u else None,
            distinctUsers=int(u["distinctUsers"]) if u else None, lastSignIn=u["lastSignIn"] if u else None,
            complexClaims=complex_claims, groupClaims=role_or_group,
            encrypted=(get(c, "attributes") or {}).get("saml.encrypt") == "true",
            usesClientSecret=(not saml and not public and (c.get("clientAuthenticatorType") or "client-secret") == "client-secret"),
            owner=c.get("description"), flags=flags, notes=notes, catalogHint=False))
    inv["m365Federated"] = any(a["isPlatform"] and a["status"] == "ACTIVE" for a in inv["apps"])
    inv["stateEvidence"] = ["The realm has an active client for Microsoft 365 federation" if inv["m365Federated"]
                            else "The realm has no client for Microsoft 365 federation"]

    custom: list[str] = []
    browser = str(get(realm, "browserFlow") or "browser")
    for f in snap.rows("flows"):
        ex = [e for e in as_list(f.get("executions")) if e.get("requirement") != "DISABLED"]
        for e in ex:
            prov = str(e.get("providerId") or "")
            if prov and not e.get("isSubFlow") and prov not in BUILT_IN_AUTHENTICATORS and prov not in custom:
                custom.append(prov)
        if f.get("alias") != browser:
            continue
        second = [e for e in ex if e.get("providerId") in ("auth-otp-form", "webauthn-authenticator", "auth-conditional-otp-form")]
        conditional = any(str(e.get("providerId") or "").startswith("conditional-") for e in ex)
        required = any(e.get("requirement") == "REQUIRED" for e in second)
        auth = "No MFA" if not second else "MFA only if enrolled" if (conditional or not required) else "MFA"
        inv["policies"].append(new_row(
            "policy", policyType="Authentication flow", policy=str(f.get("alias")), rule="Browser sign-in", authentication=auth,
            conditions=" > ".join(f"{e.get('providerId') or 'subflow'} [{e.get('requirement')}]" for e in ex),
            conditionalAccessBuildingBlocks="Grant: require MFA for all users; authentication methods policy",
            reviewNote="" if auth == "MFA" else "Second factor is not enforced for every user. Decide the Entra baseline instead of copying this."))
    life, idle = get(realm, "ssoSessionMaxLifespan"), get(realm, "ssoSessionIdleTimeout")
    if life or idle:
        hours = round(int(life or 0) / 3600, 1)
        inv["policies"].append(new_row("policy", policyType="Session", policy="Realm sessions", rule="SSO session",
                                       session=f"max {hours:g} h, idle {round(int(idle or 0) / 60):g} min",
                                       conditionalAccessBuildingBlocks=f"Session: sign-in frequency {hours:g} h", reviewNote="Idle timeout is not a Conditional Access control"))
    pw = str(get(realm, "passwordPolicy") or "")
    if pw:
        inv["policies"].append(new_row("policy", policyType="Password", policy="Realm password policy", rule=pw,
                                       conditionalAccessBuildingBlocks="Password rules stay with the source directory; Entra password protection"))
    if get(realm, "bruteForceProtected") is True:
        inv["policies"].append(new_row("policy", policyType="Lockout", policy="Brute force detection", rule="Enabled", conditionalAccessBuildingBlocks="Entra smart lockout"))
    if get(realm, "registrationAllowed") is True:
        inv["policies"].append(new_row("policy", policyType="Registration", policy="Self-registration", rule="Enabled",
                                       reviewNote="Not a workforce pattern: this realm may belong in External ID"))
        findings.append(finding("KC-04", "Medium", "Identities", "Self-registration is enabled", None, "registrationAllowed is true on the realm.",
                                "Classify the realm: customer identity belongs in External ID, not in the workforce tenant.", "Assess"))

    ra = {str(a.get("alias")): a.get("enabled") is True for a in snap.rows("requiredActions")}
    providers = [e.get("providerId") for f in snap.rows("flows") for e in as_list(f.get("executions")) if e.get("requirement") != "DISABLED"]
    inv["mfaMethods"].append(new_row("mfa", method="Password", key="password", migrationClass="Rebuild",
                                     entraTarget="Password hash sync for directory users; new credential for Keycloak-only users"))
    if ra.get("CONFIGURE_TOTP") or "auth-otp-form" in providers:
        inv["mfaMethods"].append(new_row("mfa", method=f"OTP ({get(realm, 'otpPolicyType', 'totp')})", key="otp",
                                         entraTarget="Microsoft Authenticator or a software OATH token; users register again"))
    if ra.get("webauthn-register") or "webauthn-authenticator" in providers:
        inv["mfaMethods"].append(new_row("mfa", method="WebAuthn", key="webauthn", entraTarget="Passkey (FIDO2); keys are registered again"))
    if "auth-x509-client-username-form" in providers:
        inv["mfaMethods"].append(new_row("mfa", method="X.509 client certificate", key="x509", entraTarget="Certificate-based authentication", migrationClass="Rebuild"))
    if "auth-spnego" in providers:
        inv["mfaMethods"].append(new_row("mfa", method="Kerberos (SPNEGO)", key="spnego", entraTarget="Seamless SSO or Entra-joined devices", migrationClass="Rebuild"))
    for cst in custom:
        inv["mfaMethods"].append(new_row("mfa", method=f"Custom authenticator: {cst}", key=cst, migrationClass="Gap",
                                         entraTarget="Custom code on the server: external MFA or redesign"))
    for i in snap.rows("identityProviders"):
        inv["federation"].append(new_row("federation", name=str(i.get("alias")), type=str(i.get("providerId") or ""),
                                         status="INACTIVE" if i.get("enabled") is False else "ACTIVE"))
    if custom:
        findings.append(finding("KC-02", "Blocker", "Custom code", "Custom authenticators in sign-in flows", len(custom), ", ".join(custom),
                                "Obtain the source of each provider. There is no generated equivalent; plan a redesign per authenticator.", "Design"))
    theme = str(get(realm, "loginTheme") or "")
    if theme and theme not in ("keycloak", "keycloak.v2", "base"):
        findings.append(finding("KC-03", "Medium", "Custom code", "Custom login theme", None, f"loginTheme = {theme}",
                                "Entra company branding is more limited; agree the visual change with the business early.", "Design"))
    roles = [r for r in snap.rows("roles") if not str(r.get("name")).startswith("default-roles-") and r.get("name") not in ("offline_access", "uma_authorization")]
    if roles:
        findings.append(finding("KC-05", "Info", "Authorization", "Realm roles to map onto groups or app roles", len(roles), ", ".join(str(r["name"]) for r in roles[:12]),
                                "Decide per role: Entra group, app role, or drop. Client roles are not in the snapshot and need the same exercise.", "Design"))
    scope_custom = [f"{sc.get('name')}: {get(m, 'protocolMapper')}" for sc in snap.rows("clientScopes") for m in as_list(sc.get("protocolMappers"))
                    if get(m, "protocolMapper") and get(m, "protocolMapper") not in SIMPLE_MAPPERS | ROLE_MAPPERS | GROUP_MAPPERS]
    if scope_custom:
        findings.append(finding("KC-06", "High", "Custom code", "Shared client scopes with scripted or custom mappers", len(scope_custom), ", ".join(scope_custom),
                                "These affect every client that uses the scope; treat as custom claim logic.", "Design"))
    inv["findings"] = findings
    inv["manualChecks"] = [
        new_row("manualCheck", item="Provider JARs deployed on the server", why="Custom authenticators, mappers, event listeners and storage providers have no generated equivalent", where="providers/ directory of every node"),
        new_row("manualCheck", item="Themes", why="Login, account and email themes are redone in company branding", where="themes/ directory"),
        new_row("manualCheck", item="Other realms on the same server", why="One connector covers one realm", where="Admin console realm list"),
        new_row("manualCheck", item="Client roles and their use in applications", why="Role claims change name and format in Entra tokens", where="Each client, Roles tab; application code"),
        new_row("manualCheck", item="Offline sessions and token lifetimes", why="Long-lived offline tokens stop working at cutover", where="Realm settings, Sessions and Tokens"),
        new_row("manualCheck", item="Realm administrators", why="Admin access is redesigned as Entra roles under PIM", where="realm-management role mappings"),
    ]
    return inv
