#!/usr/bin/env python3
"""
Mock admin APIs for testing the X2E collectors: Keycloak (/kc), PingFederate (/pf),
PingOne (/p1auth, /p1api) and OneLogin (/ol). Read-only, deterministic, small.
These are NOT emulators: they implement only what the collectors call, in the shape
the collectors were written against.

    python3 mock_idps.py --port 8770

GET /__expected/<platform> returns the ground truth the tests compare against.
"""
import argparse, base64, json, time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

NOW = datetime.now(timezone.utc).replace(microsecond=0)
def iso(dt): return dt.strftime("%Y-%m-%dT%H:%M:%SZ") if dt else None
def ms(dt): return int(dt.timestamp() * 1000)

class S:
    base = ""; requests = 0; writes = 0; throttled = set(); data = {}; expected = {}

# ============================== Keycloak ==============================
def build_keycloak():
    users = []
    for i in range(1, 121):
        u = {"id": f"kc-u-{i:03d}", "username": f"kuser{i:03d}", "email": f"kuser{i:03d}@example.com",
             "firstName": f"First{i}", "lastName": f"Last{i}", "enabled": i <= 110,
             "createdTimestamp": ms(NOW - timedelta(days=400)), "totp": i % 4 == 0,
             "attributes": {"phone": ["+49 170 1234567"]}}
        if i <= 80: u["federationLink"] = "comp-ad"
        elif i <= 90: u["federationLink"] = "comp-openldap"
        users.append(u)
    creds = {}
    for i, u in enumerate(users, start=1):
        c = []
        if i > 90 and i % 10 != 0: c.append({"id": f"c{i}p", "type": "password", "secretData": "{\"value\":\"HASH-SECRET\"}"})
        if i % 4 == 0: c.append({"id": f"c{i}o", "type": "otp"})
        if i % 15 == 0: c.append({"id": f"c{i}w", "type": "webauthn"})
        creds[u["id"]] = c
    def mapper(name, kind, proto="openid-connect"): return {"id": "m-" + name, "name": name, "protocol": proto, "protocolMapper": kind, "config": {}}
    clients = [{"id": f"int-{n}", "clientId": n, "name": "${client_" + n + "}", "protocol": "openid-connect", "enabled": True,
                "publicClient": n in ("account-console", "admin-cli", "security-admin-console")}
               for n in ("account", "account-console", "admin-cli", "broker", "realm-management", "security-admin-console")]
    def oidc(cid, name, **kw):
        c = {"id": "int-" + cid, "clientId": cid, "name": name, "protocol": "openid-connect", "enabled": True, "publicClient": False,
             "bearerOnly": False, "standardFlowEnabled": True, "implicitFlowEnabled": False, "directAccessGrantsEnabled": False,
             "serviceAccountsEnabled": False, "authorizationServicesEnabled": False, "clientAuthenticatorType": "client-secret",
             "secret": "KC-CLIENT-SECRET-" + cid, "redirectUris": [f"https://{cid}.example.com/*"], "protocolMappers": [], "attributes": {},
             "authenticationFlowBindingOverrides": {}, "description": None}
        c.update(kw); return c
    def saml(cid, name, **kw):
        c = {"id": "int-" + cid, "clientId": cid, "name": name, "protocol": "saml", "enabled": True, "protocolMappers": [],
             "attributes": {"saml.encrypt": "false", "saml_name_id_format": "username"}, "description": None}
        c.update(kw); return c
    clients += [
        saml("urn:federation:MicrosoftOnline", "Microsoft 365"),
        saml("https://zoom.example.net/saml", "Zoom", protocolMappers=[mapper("email", "saml-user-property-mapper", "saml")]),
        saml("https://hr.example.com/sp", "HR Suite", attributes={"saml.encrypt": "true", "saml_name_id_format": "email"},
             protocolMappers=[mapper("roles", "saml-role-list-mapper", "saml"), mapper("js", "saml-javascript-mapper", "saml")]),
        saml("https://legacy.example.com/sp", "Legacy Portal"),
        oidc("portal", "Customer Portal", description="Owner: digital team", protocolMappers=[mapper("realm roles", "oidc-usermodel-realm-role-mapper")]),
        oidc("spa", "Ops Dashboard", publicClient=True, secret=None, implicitFlowEnabled=True),
        oidc("mobile", "Mobile App", publicClient=True, secret=None, directAccessGrantsEnabled=True),
        oidc("batch", "Batch Service", standardFlowEnabled=False, serviceAccountsEnabled=True),
        oidc("docs", "Document Vault", authorizationServicesEnabled=True, serviceAccountsEnabled=True,
             protocolMappers=[mapper("script", "oidc-script-based-protocol-mapper"), mapper("dept", "oidc-usermodel-attribute-mapper"),
                              mapper("custom", "acme-entitlement-mapper"), mapper("groups", "oidc-group-membership-mapper")]),
        oidc("oldapp", "Old App", enabled=False),
        oidc("unused", "Unused Tool"),
        oidc("payments-api", "Payments API", bearerOnly=True, standardFlowEnabled=False),
    ]
    flows = [
        {"id": "f1", "alias": "browser", "builtIn": True, "providerId": "basic-flow"},
        {"id": "f2", "alias": "corp browser", "builtIn": False, "providerId": "basic-flow"},
        {"id": "f3", "alias": "direct grant", "builtIn": True, "providerId": "basic-flow"},
    ]
    execs = {
        "browser": [{"displayName": "Cookie", "providerId": "auth-cookie", "requirement": "ALTERNATIVE", "level": 0},
                    {"displayName": "forms", "requirement": "ALTERNATIVE", "level": 0, "authenticationFlow": True},
                    {"displayName": "Username Password Form", "providerId": "auth-username-password-form", "requirement": "REQUIRED", "level": 1}],
        "corp browser": [{"displayName": "Cookie", "providerId": "auth-cookie", "requirement": "ALTERNATIVE", "level": 0},
                         {"displayName": "Kerberos", "providerId": "auth-spnego", "requirement": "ALTERNATIVE", "level": 0},
                         {"displayName": "Username Password Form", "providerId": "auth-username-password-form", "requirement": "REQUIRED", "level": 1},
                         {"displayName": "Conditional OTP", "requirement": "CONDITIONAL", "level": 1, "authenticationFlow": True},
                         {"displayName": "Condition - user configured", "providerId": "conditional-user-configured", "requirement": "REQUIRED", "level": 2},
                         {"displayName": "OTP Form", "providerId": "auth-otp-form", "requirement": "REQUIRED", "level": 2},
                         {"displayName": "SMS code", "providerId": "acme-sms-authenticator", "requirement": "ALTERNATIVE", "level": 2},
                         {"displayName": "WebAuthn", "providerId": "webauthn-authenticator", "requirement": "DISABLED", "level": 2}],
        "direct grant": [{"displayName": "Username Validation", "providerId": "direct-grant-validate-username", "requirement": "REQUIRED", "level": 0}],
    }
    events = []
    usage = {}
    plan = {"urn:federation:MicrosoftOnline": (300, 100), "https://zoom.example.net/saml": (80, 40), "https://hr.example.com/sp": (60, 25),
            "portal": (120, 50), "spa": (40, 12), "mobile": (90, 30), "docs": (20, 8)}
    k = 0; all_users = set()
    for cid, (count, pool) in plan.items():
        seen = set()
        for j in range(count):
            u = users[(j * 7 + len(cid)) % pool]
            k += 1
            events.append({"time": ms(NOW - timedelta(days=(k % 25), minutes=k)), "type": "LOGIN", "realmId": "corp", "clientId": cid, "userId": u["id"], "ipAddress": "10.0.0.1"})
            seen.add(u["id"]); all_users.add(u["id"])
        usage[cid] = {"signIns": count, "distinctUsers": len(seen)}
    for j in range(15):
        k += 1
        events.append({"time": ms(NOW - timedelta(days=j)), "type": "CLIENT_LOGIN", "realmId": "corp", "clientId": "batch", "userId": "svc-batch"})
    usage["batch"] = {"signIns": 0, "distinctUsers": 0}      # client logins are kept apart from user sign-ins
    d = {
        "realm": {"id": "corp-id", "realm": "corp", "enabled": True, "registrationAllowed": True, "bruteForceProtected": True,
                  "passwordPolicy": "length(12) and digits(1) and notUsername", "otpPolicyType": "totp", "ssoSessionIdleTimeout": 1800,
                  "ssoSessionMaxLifespan": 36000, "eventsEnabled": True, "eventsExpiration": 7776000, "enabledEventTypes": ["LOGIN", "CLIENT_LOGIN"],
                  "browserFlow": "corp browser", "loginTheme": "acme-bank", "smtpServer": {"host": "smtp.example.com", "user": "kc", "password": "SMTP-PASSWORD"}},
        "clients": clients, "users": users, "creds": creds,
        "clientScopes": [{"id": "cs1", "name": "profile", "protocol": "openid-connect", "protocolMappers": [mapper("username", "oidc-usermodel-property-mapper")]},
                         {"id": "cs2", "name": "entitlements", "protocol": "openid-connect", "protocolMappers": [mapper("ent", "oidc-script-based-protocol-mapper")]}],
        "groups": [{"id": f"g{i}", "name": f"group-{i}", "path": f"/group-{i}", "subGroupCount": i % 3} for i in range(1, 13)],
        "roles": [{"id": "r0", "name": "default-roles-corp", "composite": True}, {"id": "r1", "name": "offline_access"}, {"id": "r2", "name": "uma_authorization"}]
                 + [{"id": f"r{i}", "name": n, "composite": False} for i, n in enumerate(("trader", "auditor", "hr-admin", "teller"), start=3)],
        "idps": [{"alias": "partner-saml", "providerId": "saml", "enabled": True, "config": {"singleSignOnServiceUrl": "https://idp.partner.example/sso"}},
                 {"alias": "google", "providerId": "google", "enabled": True, "config": {"clientId": "g-client", "clientSecret": "GOOGLE-IDP-SECRET"}}],
        "components": [{"id": "comp-ad", "name": "corp-ad", "providerId": "ldap", "providerType": "org.keycloak.storage.UserStorageProvider",
                        "config": {"vendor": ["ad"], "connectionUrl": ["ldaps://dc1.corp.example.com"], "bindCredential": ["AD-BIND-PASSWORD"], "editMode": ["READ_ONLY"]}},
                       {"id": "comp-openldap", "name": "partner-ldap", "providerId": "ldap", "providerType": "org.keycloak.storage.UserStorageProvider",
                        "config": {"vendor": ["other"], "connectionUrl": ["ldap://ldap.partner.example"], "bindCredential": ["LDAP-BIND-PASSWORD"]}}],
        "flows": flows, "execs": execs,
        "requiredActions": [{"alias": "CONFIGURE_TOTP", "name": "Configure OTP", "enabled": True}, {"alias": "webauthn-register", "name": "Webauthn Register", "enabled": False},
                            {"alias": "UPDATE_PASSWORD", "name": "Update Password", "enabled": True}],
        "events": sorted(events, key=lambda e: -e["time"]),
    }
    active = [u for u in users if u["enabled"]]
    S.expected["keycloak"] = {
        "users": len(users), "active": len(active), "clients_total": len(clients),
        "local_password_active": sum(1 for u in active if "federationLink" not in u and any(c["type"] == "password" for c in creds[u["id"]])),
        "not_federated_active": sum(1 for u in active if "federationLink" not in u),
        "usage": usage, "distinct_login_users": len(all_users),
        "secrets": ["KC-CLIENT-SECRET", "SMTP-PASSWORD", "GOOGLE-IDP-SECRET", "AD-BIND-PASSWORD", "LDAP-BIND-PASSWORD", "HASH-SECRET", "+49 170", "First1"],
    }
    return d

def kc_route(h, p, q):
    d = S.data["kc"]
    def page(items):
        first = int(q.get("first", [0])[0]); mx = int(q.get("max", [100])[0])
        return h.send_json(200, items[first:first + mx])
    if p == "/kc/admin/serverinfo": return h.send_json(403, {"error": "HTTP 403 Forbidden"})
    base = "/kc/admin/realms/corp"
    if not p.startswith(base): return h.send_json(404, {"error": "Realm not found."})
    r = p[len(base):]
    if r == "": return h.send_json(200, d["realm"])
    if r == "/clients": return page(d["clients"])
    if r == "/client-scopes": return h.send_json(200, d["clientScopes"])
    if r == "/users":
        if int(q.get("first", [0])[0]) > 0 and "kc" not in S.throttled:
            S.throttled.add("kc"); return h.send_json(429, {"error": "Too many requests"}, {"Retry-After": "1"})
        return page(d["users"])
    if r.startswith("/users/") and r.endswith("/credentials"): return h.send_json(200, d["creds"].get(r.split("/")[2], []))
    if r == "/groups": return page(d["groups"])
    if r == "/roles": return h.send_json(403, {"error": "Forbidden"})     # simulate a missing role on the service account
    if r == "/identity-provider/instances": return h.send_json(200, d["idps"])
    if r == "/components": return h.send_json(200, d["components"])
    if r == "/authentication/flows": return h.send_json(200, d["flows"])
    if r.startswith("/authentication/flows/") and r.endswith("/executions"):
        from urllib.parse import unquote
        return h.send_json(200, d["execs"].get(unquote(r.split("/")[3]), []))
    if r == "/authentication/required-actions": return h.send_json(200, d["requiredActions"])
    if r == "/events":
        types = q.get("type", []); date_from = q.get("dateFrom", ["1970-01-01"])[0]
        lo = ms(datetime.strptime(date_from, "%Y-%m-%d").replace(tzinfo=timezone.utc))
        return page([e for e in d["events"] if e["type"] in types and e["time"] >= lo])
    return h.send_json(404, {"error": "not found: " + r})

# ============================== HTTP ==============================
TOKENS = {"kc": "kc-access-token", "p1": "p1-access-token", "ol": "ol-access-token"}

class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a): pass
    def send_json(self, code, body, headers=None):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(data)))
        for k, v in (headers or {}).items(): self.send_header(k, v)
        self.end_headers(); self.wfile.write(data)
    def bearer(self, key): return self.headers.get("Authorization", "") == "Bearer " + TOKENS[key]
    def basic(self):
        a = self.headers.get("Authorization", "")
        try: return base64.b64decode(a.split(" ", 1)[1]).decode() if a.startswith("Basic ") else None
        except Exception: return None
    def do_POST(self):
        S.requests += 1
        p = urlparse(self.path).path
        body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
        if p == "/kc/realms/corp/protocol/openid-connect/token":
            f = parse_qs(body)
            if f.get("client_id") == ["x2e-collector"] and f.get("client_secret") == ["kc-secret"] and f.get("grant_type") == ["client_credentials"]:
                return self.send_json(200, {"access_token": TOKENS["kc"], "expires_in": 60, "token_type": "Bearer"})
            return self.send_json(401, {"error": "unauthorized_client", "error_description": "Invalid client or Invalid client credentials"})
        for route in POST_ROUTES:
            if route(self, p, body): return
        S.writes += 1
        self.send_json(405, {"error": "read-only mock"})
    def refuse(self): S.requests += 1; S.writes += 1; self.send_json(405, {"error": "read-only mock"})
    do_PUT = do_DELETE = do_PATCH = refuse
    def do_GET(self):
        S.requests += 1
        u = urlparse(self.path); p = u.path.rstrip("/"); q = parse_qs(u.query)
        if p.startswith("/__expected/"): return self.send_json(200, S.expected.get(p.split("/")[-1], {}))
        if p == "/__stats": return self.send_json(200, {"requests": S.requests, "writes": S.writes})
        if p.startswith("/kc/"):
            if not self.bearer("kc"): return self.send_json(401, {"error": "HTTP 401 Unauthorized"})
            return kc_route(self, p, q)
        for prefix, route in GET_ROUTES:
            if p.startswith(prefix): return route(self, p, q)
        self.send_json(404, {"error": "unknown path"})

POST_ROUTES = []
GET_ROUTES = []

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--port", type=int, default=8770); a = ap.parse_args()
    S.base = f"http://127.0.0.1:{a.port}"
    S.data["kc"] = build_keycloak()
    for build in EXTRA_BUILDERS: build()
    print("mock idps on", S.base, flush=True)
    ThreadingHTTPServer(("127.0.0.1", a.port), H).serve_forever()

EXTRA_BUILDERS = []
# ---- the other platforms are appended below this line ----
# ============================== PingFederate ==============================
def build_pingfederate():
    def acf(**kw): return {k: {"source": {"type": v[0]}, "value": v[1]} for k, v in kw.items()}
    def conn(name, entity, proto="SAML20", active=True, mappings=None, **kw):
        c = {"type": "SP", "id": "id-" + name.lower().replace(" ", "-"), "name": name, "entityId": entity, "active": active,
             "contactInfo": {"email": kw.pop("owner", None)}, "credentials": {"signingSettings": {"signingKeyPairRef": {"id": "key1"}}}}
        if proto:
            c["spBrowserSso"] = {"protocol": proto, "enabledProfiles": ["SP_INITIATED_SSO"], "signAssertions": True,
                                 "encryptionPolicy": {"encryptAssertion": kw.pop("encrypt", False)},
                                 "attributeContract": {"coreAttributes": [{"name": "SAML_SUBJECT"}], "extendedAttributes": [{"name": "email"}]},
                                 "adapterMappings": mappings or [{"idpAdapterRef": {"id": "HTMLFormAdapter"}, "attributeSources": [],
                                                                  "attributeContractFulfillment": acf(SAML_SUBJECT=("ADAPTER", "username"), email=("ADAPTER", "mail"))}]}
        c.update(kw); return c
    ldap_src = {"type": "LDAP", "dataStoreRef": {"id": "ds-ad"}, "searchFilter": "sAMAccountName=${username}"}
    jdbc_src = {"type": "JDBC", "dataStoreRef": {"id": "ds-hrdb"}, "table": "EMP"}
    conns = [
        conn("Microsoft 365", "urn:federation:MicrosoftOnline", "WSFED", wsTrust={"partnerServiceIds": ["urn:federation:MicrosoftOnline"]}),
        conn("Salesforce", "https://saml.salesforce.com", outboundProvision={"type": "Salesforce", "channels": [{"name": "users"}]}, owner="crm-team@example.com"),
        conn("Workday", "http://www.workday.com/contoso"),
        conn("Risk Engine", "https://risk.example.com/sp", encrypt=True, mappings=[{"idpAdapterRef": {"id": "HTMLFormAdapter"}, "attributeSources": [ldap_src],
             "attributeContractFulfillment": acf(SAML_SUBJECT=("ADAPTER", "username"), email=("EXPRESSION", "#this.get(\"mail\").toString().toLowerCase()"),
                                                 dept=("EXPRESSION", "#d = #this.get(\"department\"), #d != null ? #d : \"none\""), tier=("EXPRESSION", "1+1"), cn=("LDAP_DATA_STORE", "cn"))}]),
        conn("Treasury", "https://treasury.example.com/sp", mappings=[{"idpAdapterRef": {"id": "HTMLFormAdapter"}, "attributeSources": [jdbc_src, ldap_src],
             "attributeContractFulfillment": acf(SAML_SUBJECT=("ADAPTER", "username"), cost=("JDBC_DATA_STORE", "COST_CENTER"), x=("EXPRESSION", "#this.get(\"x\")"))}]),
        conn("Old Mainframe Gateway", "urn:mainframe:gw", "SAML11"),
        conn("Partner STS", "urn:partner:sts", None, wsTrust={"partnerServiceIds": ["urn:partner:sts"]}),
        conn("Retired CRM", "https://oldcrm.example.com", active=False),
        conn("Intranet", "https://intranet.example.com/sp"),
    ]
    def client(cid, name, grants, auth="SECRET", enabled=True):
        ca = {"type": auth}
        if auth == "SECRET": ca["secret"] = "PF-CLIENT-SECRET-" + cid; ca["encryptedSecret"] = "PF-ENC-" + cid
        return {"clientId": cid, "name": name, "enabled": enabled, "grantTypes": grants, "redirectUris": [], "clientAuth": ca, "description": None}
    clients = [client("web", "Customer Web", ["AUTHORIZATION_CODE", "REFRESH_TOKEN"]), client("spa", "Ops SPA", ["IMPLICIT"], "NONE"),
               client("legacy-mobile", "Legacy Mobile", ["RESOURCE_OWNER_CREDENTIALS", "REFRESH_TOKEN"]), client("batch", "Batch Jobs", ["CLIENT_CREDENTIALS"]),
               client("rs", "Resource Server", ["ACCESS_TOKEN_VALIDATION"])]
    def plugin(i, name, ref, fields=None): return {"id": i, "name": name, "pluginDescriptorRef": {"id": ref}, "configuration": {"tables": [], "fields": fields or []}}
    d = {
        "version": {"version": "12.1.3.0"},
        "serverSettings": {"federationInfo": {"baseUrl": "https://sso.contoso.example", "saml2EntityId": "contoso-pf"},
                           "emailServer": {"emailServer": "smtp.example.com", "username": "pf", "password": "PF-SMTP-PASSWORD"}},
        "/idp/spConnections": conns, "/oauth/clients": clients,
        "/idp/adapters": [plugin("HTMLFormAdapter", "HTML Form", "com.pingidentity.adapters.htmlform.idp.HtmlFormIdpAuthnAdapter"),
                          plugin("KerberosAdapter", "Kerberos", "com.pingidentity.adapters.kerberos.idp.KerberosIdpAuthnAdapter"),
                          plugin("PingIDAdapter", "PingID", "com.pingidentity.adapters.pingid.PingIDAdapter", [{"name": "PingID Properties", "encryptedValue": "PF-PINGID-PROPERTIES"}]),
                          plugin("BadgeAdapter", "Badge reader", "com.acme.adapters.BadgeAdapter")],
        "/dataStores": [{"type": "LDAP", "id": "ds-ad", "name": "Corp AD", "ldapType": "ACTIVE_DIRECTORY", "hostnames": ["dc1.corp.example.com"], "userDN": "cn=pf", "encryptedPassword": "PF-AD-BIND"},
                        {"type": "LDAP", "id": "ds-pd", "name": "Partner directory", "ldapType": "PING_DIRECTORY", "hostnames": ["pd.example.com"], "encryptedPassword": "PF-PD-BIND"},
                        {"type": "JDBC", "id": "ds-hrdb", "name": "HR database", "connectionUrl": "jdbc:oracle:thin:@hr:1521/HR", "userName": "pf", "encryptedPassword": "PF-JDBC-PASSWORD"}],
        "/authenticationSelectors": [plugin("InternalNet", "Internal network", "com.pingidentity.pf.selectors.cidr.CIDRAdapterSelector")],
        "/sp/idpConnections": [{"id": "idp1", "name": "Partner Bank", "entityId": "https://idp.partnerbank.example", "active": True}],
        "/oauth/accessTokenManagers": [plugin("jwt", "JWT tokens", "com.pingidentity.pf.access.token.management.plugins.JwtBearerAccessTokenManagementPlugin", [{"name": "Key", "encryptedValue": "PF-ATM-KEY"}]),
                                       plugin("ref", "Reference tokens", "org.sourceid.oauth20.token.plugin.impl.ReferenceBearerAccessTokenManagementPlugin")],
        "/oauth/openIdConnect/policies": [{"id": "oidc1", "name": "Default OIDC", "attributeMapping": {"attributeSources": [],
                                           "attributeContractFulfillment": acf(sub=("TOKEN", "Username"), roles=("EXPRESSION", "#this.get(\"memberOf\")"))}}],
        "/keyPairs/signing": [{"id": "key1", "subjectDN": "CN=sso.contoso.example", "expires": iso(NOW + timedelta(days=100)), "status": "VALID"},
                              {"id": "key2", "subjectDN": "CN=sso-next.contoso.example", "expires": iso(NOW + timedelta(days=800)), "status": "VALID"}],
        "/idp/tokenProcessors": [plugin("usertoken", "Username token", "com.pingidentity.pf.tokenprocessors.username.UsernameTokenProcessor")],
        "authPolicies": {"failIfNoSelection": False, "authnSelectionTrees": [
            {"name": "Internal network", "enabled": True, "rootNode": {"action": {"type": "AUTHN_SELECTOR", "authenticationSelectorRef": {"id": "InternalNet"}},
                "children": [{"action": {"type": "AUTHN_SOURCE", "context": "Yes", "authenticationSource": {"type": "IDP_ADAPTER", "sourceRef": {"id": "KerberosAdapter"}}}, "children": [{"action": {"type": "DONE", "context": "Success"}}]},
                             {"action": {"type": "CONTINUE", "context": "No"}}]}},
            {"name": "Default", "enabled": True, "rootNode": {"action": {"type": "AUTHN_SOURCE", "authenticationSource": {"type": "IDP_ADAPTER", "sourceRef": {"id": "HTMLFormAdapter"}}},
                "children": [{"action": {"type": "AUTHN_SOURCE", "context": "Success", "authenticationSource": {"type": "IDP_ADAPTER", "sourceRef": {"id": "PingIDAdapter"}}}, "children": [{"action": {"type": "DONE", "context": "Success"}}]},
                             {"action": {"type": "DONE", "context": "Fail"}}]}},
            {"name": "Old kiosk", "enabled": False, "rootNode": {"action": {"type": "AUTHN_SOURCE", "authenticationSource": {"type": "IDP_ADAPTER", "sourceRef": {"id": "BadgeAdapter"}}}}}]},
        "authServer": {"scopes": [{"name": s} for s in ("openid", "profile", "payments.read", "payments.write")], "exclusiveScopes": [], "bypassAuthorizationForApprovedGrants": False},
    }
    plan = {"urn:federation:MicrosoftOnline": (220, 90), "https://saml.salesforce.com": (70, 30), "http://www.workday.com/contoso": (50, 25),
            "https://risk.example.com/sp": (40, 15), "https://treasury.example.com/sp": (25, 10), "urn:mainframe:gw": (12, 4), "web": (60, 20), "legacy-mobile": (30, 12)}
    lines = []; usage = {}; k = 0
    for partner, (count, pool) in plan.items():
        seen = set()
        for j in range(count):
            k += 1; user = f"user{(j * 3 + len(partner)) % pool:03d}"; seen.add(user)
            when = NOW - timedelta(days=k % 60, minutes=k)
            ev = "OAuth" if partner in ("web", "legacy-mobile") else "SSO"
            lines.append(f"{when.strftime('%Y-%m-%d %H:%M:%S')},123| tid:{k}| {ev}| {user}| 10.0.0.{k % 250}| | {partner}| SAML20| sso.contoso.example| IdP| success| HTMLFormAdapter| | {20 + k % 40}")
        usage[partner] = {"signIns": count, "distinctUsers": len(seen)}
    for j in range(30):   # noise that must not be counted: failures, old lines, other events
        lines.append(f"{(NOW - timedelta(days=5)).strftime('%Y-%m-%d %H:%M:%S')},000| tid:f{j}| SSO| baduser| 10.9.9.9| | https://intranet.example.com/sp| SAML20| h| IdP| failure| HTMLFormAdapter| | 9")
        lines.append(f"{(NOW - timedelta(days=200)).strftime('%Y-%m-%d %H:%M:%S')},000| tid:o{j}| SSO| olduser| 10.9.9.9| | https://oldcrm.example.com| SAML20| h| IdP| success| HTMLFormAdapter| | 9")
        lines.append(f"{(NOW - timedelta(days=2)).strftime('%Y-%m-%d %H:%M:%S')},000| tid:a{j}| AUTHN_ATTEMPT| user001| 10.0.0.1| | | | h| IdP| success| HTMLFormAdapter| | 3")
    d["auditlog"] = "\n".join(lines) + "\n"
    S.data["pf"] = d
    S.expected["pingfederate"] = {"connections": len(conns), "clients": len(clients), "usage": usage, "counted": sum(v["signIns"] for v in usage.values()),
        "secrets": ["PF-CLIENT-SECRET", "PF-ENC-", "PF-SMTP-PASSWORD", "PF-AD-BIND", "PF-PD-BIND", "PF-JDBC-PASSWORD", "PF-PINGID-PROPERTIES", "PF-ATM-KEY", "user001", "baduser"]}

def pf_route(h, p, q):
    d = S.data["pf"]
    if p == "/__auditlog/pf":
        data = d["auditlog"].encode(); h.send_response(200); h.send_header("Content-Type", "text/plain"); h.send_header("Content-Length", str(len(data))); h.end_headers(); h.wfile.write(data); return
    if h.basic() != "auditor:pf-secret": return h.send_json(401, {"message": "Unauthorized"})
    if h.headers.get("X-XSRF-Header") != "PingFederate": return h.send_json(403, {"message": "X-XSRF-Header is required"})
    r = p[len("/pf/pf-admin-api/v1"):]
    if r == "/version": return h.send_json(200, d["version"])
    if r == "/serverSettings": return h.send_json(200, d["serverSettings"])
    if r == "/authenticationPolicies/default": return h.send_json(200, d["authPolicies"])
    if r == "/oauth/authServerSettings": return h.send_json(200, d["authServer"])
    if r == "/passwordCredentialValidators": return h.send_json(403, {"message": "Access denied for this administrative role"})
    if r in d: return h.send_json(200, {"items": d[r]})
    return h.send_json(404, {"message": "Resource not found"})

# ============================== PingOne ==============================
ENV = "env-0001"
def build_pingone():
    root = f"{S.base}/p1api/v1/environments/{ENV}"
    users = []
    for i in range(1, 151):
        u = {"id": f"p1-u-{i:03d}", "username": f"puser{i:03d}", "email": f"puser{i:03d}@example.com", "name": {"given": f"First{i}", "family": f"Last{i}"},
             "mobilePhone": "+49 160 7654321", "enabled": i <= 140, "lifecycle": {"status": "ACCOUNT_OK"}, "population": {"id": "pop-1"}, "mfaEnabled": i % 2 == 0,
             "identityProvider": {"type": "PING_ONE"}}
        if i <= 90: u["password"] = {"external": {"gateway": {"id": "gw-ad", "type": "LDAP"}}}
        elif i > 130: u["identityProvider"] = {"type": "SAML", "id": "idp-1"}
        if i % 12 == 0: pass
        elif i % 9 == 0: u["lastSignOn"] = {"at": iso(NOW - timedelta(days=200)), "remoteIp": "10.1.1.1"}
        else: u["lastSignOn"] = {"at": iso(NOW - timedelta(days=i % 30)), "remoteIp": "10.1.1.1"}
        users.append(u)
    def app(i, name, proto, typ, **kw):
        a = {"id": f"app-{i:02d}", "name": name, "enabled": True, "protocol": proto, "type": typ, "description": None}; a.update(kw); return a
    apps = [app(1, "PingOne Application Portal", "OPENID_CONNECT", "PING_ONE_PORTAL"), app(2, "PingOne Self-Service", "OPENID_CONNECT", "PING_ONE_SELF_SERVICE"),
            app(3, "Microsoft 365", "SAML", "WEB_APP", spEntityId="urn:federation:MicrosoftOnline"),
            app(4, "ServiceNow", "SAML", "WEB_APP", spEntityId="https://contoso.service-now.com", description="Owner: ITSM"),
            app(5, "Risk Portal", "SAML", "WEB_APP", spEntityId="https://risk.example.com", accessControl={"group": {"type": "ANY_GROUP", "groups": [{"id": "grp-1"}]}}),
            app(6, "Customer Web", "OPENID_CONNECT", "WEB_APP", grantTypes=["AUTHORIZATION_CODE"], tokenEndpointAuthMethod="CLIENT_SECRET_BASIC"),
            app(7, "Ops SPA", "OPENID_CONNECT", "SINGLE_PAGE_APP", grantTypes=["IMPLICIT"], tokenEndpointAuthMethod="NONE"),
            app(8, "Sync Worker", "OPENID_CONNECT", "WORKER", grantTypes=["CLIENT_CREDENTIALS"], tokenEndpointAuthMethod="CLIENT_SECRET_BASIC"),
            app(9, "Canteen Menu", "EXTERNAL_LINK", "PORTAL_LINK"), app(10, "Old Portal", "SAML", "WEB_APP", enabled=False, spEntityId="https://old.example.com"),
            app(11, "Unused Tool", "SAML", "WEB_APP", spEntityId="https://unused.example.com")]
    attrs = {"app-04": [{"name": "saml_subject", "value": "${user.username}", "mappingType": "CORE"}, {"name": "email", "value": "${user.email}", "mappingType": "CUSTOM"}],
             "app-05": [{"name": "saml_subject", "value": "${user.email}", "mappingType": "CORE"},
                        {"name": "tier", "value": "${user.department == 'Risk' ? 'gold' : 'std'}", "mappingType": "CUSTOM"},
                        {"name": "groups", "value": "${user.memberOfGroupNames}", "mappingType": "CUSTOM"}]}
    assign = {"app-03": ["sop-2"], "app-04": ["sop-3"], "app-05": ["sop-2"], "app-06": ["sop-1"]}
    acts = {"sop-1": [{"id": "a1", "type": "LOGIN", "priority": 1}],
            "sop-2": [{"id": "a2", "type": "LOGIN", "priority": 1}, {"id": "a3", "type": "MULTI_FACTOR_AUTHENTICATION", "priority": 2}],
            "sop-3": [{"id": "a4", "type": "LOGIN", "priority": 1}, {"id": "a5", "type": "MULTI_FACTOR_AUTHENTICATION", "priority": 2,
                       "condition": {"not": {"ipRange": ["203.0.113.0/24"], "contains": "${flow.request.http.remoteIp}"}}}]}
    activities = []; usage = {}; k = 0
    plan = {"app-03": (260, 100), "app-04": (90, 40), "app-05": (45, 18), "app-06": (130, 60), "app-07": (35, 10), "app-09": (20, 15)}
    for aid, (count, pool) in plan.items():
        seen = set()
        for j in range(count):
            k += 1; u = users[(j * 5 + k) % pool]; seen.add(u["id"])
            activities.append({"id": f"act-{k}", "recordedAt": iso(NOW - timedelta(days=k % 70, minutes=k)), "action": {"type": "USER.ACCESS_ALLOWED", "description": "User Access Allowed"},
                               "actors": {"client": {"id": aid, "name": aid, "type": "CLIENT"}, "user": {"id": u["id"], "name": u["username"], "type": "USER"}},
                               "resources": [{"type": "USER", "id": u["id"], "name": u["username"]}], "result": {"status": "SUCCESS"}})
        usage[aid] = {"signIns": count, "distinctUsers": len(seen)}
    S.data["p1"] = {
        "env": {"id": ENV, "name": "Contoso Workforce", "type": "PRODUCTION", "region": "EU", "license": {"id": "lic"}},
        "applications": apps, "attrs": attrs, "assign": assign, "users": users,
        "populations": [{"id": "pop-1", "name": "Employees"}],
        "groups": [{"id": "grp-1", "name": "Risk"}, {"id": "grp-2", "name": "Sales (dynamic)", "userFilter": "department eq \"Sales\""},
                   {"id": "grp-3", "name": "Managers DE", "userFilter": "title sw \"Head\" and address.countryCode eq \"DE\""}],
        "signOnPolicies": [{"id": "sop-1", "name": "Single_Factor", "default": True}, {"id": "sop-2", "name": "Multi_Factor", "default": False},
                           {"id": "sop-3", "name": "MFA outside office", "default": False}], "acts": acts,
        "identityProviders": [{"id": "idp-1", "name": "Partner SAML", "type": "SAML", "enabled": True}],
        "resources": [{"id": "res-1", "name": "openid", "type": "OPENID_CONNECT"}, {"id": "res-2", "name": "PingOne API", "type": "PING_ONE_API"},
                      {"id": "res-3", "name": "Payments API", "type": "CUSTOM", "audience": "https://api.example.com/payments"}],
        "resScopes": {"res-3": [{"name": "payments:read"}, {"name": "payments:write"}]},
        "resAttrs": {"res-3": [{"name": "sub", "value": "${user.id}"}, {"name": "limit", "value": "${user.tier == 'gold' ? 10000 : 100}"}]},
        "gateways": [{"id": "gw-ad", "name": "Corp AD gateway", "type": "LDAP", "enabled": True, "vendor": "Microsoft Active Directory", "bindDN": "cn=p1", "bindPassword": "P1-BIND-PASSWORD"},
                     {"id": "gw-rad", "name": "VPN RADIUS", "type": "RADIUS", "enabled": True, "radiusClients": [{"ip": "10.0.0.9", "sharedSecret": "P1-RADIUS-SECRET"}]}],
        "deviceAuthenticationPolicies": [{"id": "dap-1", "name": "Default", "default": True, "mobile": {"enabled": True}, "totp": {"enabled": True}, "fido2": {"enabled": True},
                                          "sms": {"enabled": True}, "voice": {"enabled": False}, "email": {"enabled": True}}],
        "activities": activities,
    }
    active = [u for u in users if u["enabled"]]
    S.expected["pingone"] = {"users": len(users), "active": len(active),
        "local_active": sum(1 for u in active if u["identityProvider"]["type"] == "PING_ONE" and "password" not in u),
        "never_active": sum(1 for u in active if "lastSignOn" not in u), "usage": usage, "activities": len(activities),
        "secrets": ["P1-BIND-PASSWORD", "P1-RADIUS-SECRET", "+49 160", "First1", "10.1.1.1"]}

def p1_route(h, p, q):
    d = S.data["p1"]
    if not h.bearer("p1"): return h.send_json(401, {"message": "Unauthorized"})
    root = f"/p1api/v1/environments/{ENV}"
    if not p.startswith(root): return h.send_json(404, {"message": "not found"})
    r = p[len(root):]
    def hal(key, items, size=50):
        start = int(q.get("cursor", [0])[0]); chunk = items[start:start + size]
        body = {"_links": {"self": {"href": S.base + p}}, "_embedded": {key: chunk}, "count": len(items), "size": len(chunk)}
        if start + size < len(items):
            keep = "&".join(f"{k}={v[0]}" for k, v in q.items() if k != "cursor").replace(" ", "%20").replace('"', "%22")
            body["_links"]["next"] = {"href": f"{S.base}{p}?{keep}{'&' if keep else ''}cursor={start + size}"}
        return h.send_json(200, body)
    if r == "": return h.send_json(200, d["env"])
    seg = r.strip("/").split("/")
    if seg == ["applications"]: return hal("applications", d["applications"])
    if len(seg) == 3 and seg[0] == "applications" and seg[2] == "attributes": return hal("attributes", d["attrs"].get(seg[1], []))
    if len(seg) == 3 and seg[0] == "applications" and seg[2] == "signOnPolicyAssignments":
        return hal("signOnPolicyAssignments", [{"id": "x", "priority": 1, "signOnPolicy": {"id": s}} for s in d["assign"].get(seg[1], [])])
    if seg == ["users"]: return hal("users", d["users"])
    if seg == ["populations"]: return h.send_json(403, {"message": "The worker application lacks the role to read populations"})
    if seg == ["groups"]: return hal("groups", d["groups"])
    if seg == ["signOnPolicies"]: return hal("signOnPolicies", d["signOnPolicies"])
    if len(seg) == 3 and seg[0] == "signOnPolicies" and seg[2] == "actions": return hal("actions", d["acts"].get(seg[1], []))
    if seg == ["identityProviders"]: return hal("identityProviders", d["identityProviders"])
    if seg == ["resources"]: return hal("resources", d["resources"])
    if len(seg) == 3 and seg[0] == "resources" and seg[2] == "scopes": return hal("scopes", d["resScopes"].get(seg[1], []))
    if len(seg) == 3 and seg[0] == "resources" and seg[2] == "attributes": return hal("attributes", d["resAttrs"].get(seg[1], []))
    if seg == ["gateways"]: return hal("gateways", d["gateways"])
    if seg == ["deviceAuthenticationPolicies"]: return hal("deviceAuthenticationPolicies", d["deviceAuthenticationPolicies"])
    if seg == ["propagation", "stores"]: return h.send_json(403, {"message": "Provisioning is not licensed"})
    if seg == ["activities"]:
        flt = q.get("filter", [""])[0]
        if "USER.ACCESS_ALLOWED" not in flt or "recordedat gt" not in flt: return h.send_json(400, {"message": "bad filter"})
        since = flt.split('"')[1]
        return hal("activities", [a for a in d["activities"] if a["recordedAt"] > since], 200)
    return h.send_json(404, {"message": "not found: " + r})

def p1_token(h, p, body):
    if p != f"/p1auth/{ENV}/as/token": return False
    ok = h.basic() == "p1-client:p1-secret" and parse_qs(body).get("grant_type") == ["client_credentials"]
    h.send_json(200, {"access_token": TOKENS["p1"], "expires_in": 3600, "token_type": "Bearer"}) if ok else h.send_json(401, {"error": "invalid_client", "error_description": "Unsupported authentication method or bad secret"})
    return True

# ============================== OneLogin ==============================
def build_onelogin():
    users = []
    for i in range(1, 231):
        u = {"id": 1000 + i, "username": f"ouser{i:03d}", "email": f"ouser{i:03d}@example.com", "firstname": f"First{i}", "lastname": f"Last{i}", "phone": "+49 151 2223334",
             "status": 1 if i <= 210 else 2, "state": 1, "directory_id": 55 if i <= 150 else None, "trusted_idp_id": 9 if 150 < i <= 170 else None,
             "department": "Sales" if i % 3 == 0 else "IT", "title": "Analyst",
             "last_login": None if i % 20 == 0 else iso(NOW - timedelta(days=150 if i % 11 == 0 else i % 25))}
        users.append(u)
    def app(i, name, method, desc, **kw):
        a = {"id": 500 + i, "connector_id": 100 + i, "name": name, "description": "", "notes": kw.pop("notes", None), "visible": True, "auth_method": method,
             "auth_method_description": desc, "provisioning": {"enabled": kw.pop("prov", False)}, "policy_id": kw.pop("policy", None), "allow_assumed_signin": False}
        a["_detail"] = kw; return a
    def param(mapping="", macro=""): return {"label": "x", "user_attribute_mappings": mapping, "user_attribute_macros": macro, "include_in_saml_assertion": True}
    apps = [app(1, "Office 365", 7, "WSFED", prov=True, policy=301),
            app(2, "Salesforce", 2, "SAML", prov=True, policy=301, notes="Owner: CRM team", parameters={"saml_username": param("email")}, configuration={"encrypt_assertion": "0"}),
            app(3, "Risk Engine", 2, "SAML", policy=302, parameters={"saml_username": param("email"), "tier": param("", "{if department == 'Risk'}gold{else}std{/if}"),
                                                                    "display": param("", "{firstname} {lastname}")}, configuration={"encrypt_assertion": "1"}),
            app(4, "Customer Portal", 8, "OpenId Connect", policy=302, sso={"client_id": "ol-portal", "client_secret": "OL-OIDC-SECRET"}),
            app(5, "Legacy Expenses", 6, "Forms Based App"), app(6, "Vendor Portal", 0, "Password", parameters={"password": {"label": "Password", "user_attribute_mappings": "", "user_attribute_macros": "", "values": "OL-SHARED-PASSWORD"}}),
            app(7, "HR Feed", 3, "API", prov=True), app(8, "Internal Wiki", 2, "SAML", enforcement_point={"resources": [{"path": "/"}], "target": "https://wiki.corp.example"}),
            app(9, "Unused App", 2, "SAML")]
    assigned = {501: 200, 502: 60, 503: 25, 504: 80, 505: 30, 506: 12, 507: 0, 508: 150, 509: 5}
    events = []; usage = {}; k = 0
    plan = {501: (240, 120), 502: (70, 30), 503: (30, 12), 504: (95, 40), 505: (22, 9), 506: (8, 4), 508: (55, 35)}
    names = {a["id"]: a["name"] for a in apps}
    for aid, (count, pool) in plan.items():
        seen = set()
        for j in range(count):
            k += 1; u = users[(j * 7 + k) % pool]; seen.add(u["id"])
            events.append({"id": 900000 + k, "created_at": iso(NOW - timedelta(days=k % 28, minutes=k)), "event_type_id": 8, "user_id": u["id"], "user_name": u["username"],
                           "app_id": aid, "app_name": names[aid], "ipaddr": "10.2.2.2"})
        usage[str(aid)] = {"signIns": count, "distinctUsers": len(seen)}
    devices = {}
    for i, u in enumerate([x for x in users if x["status"] == 1]):
        d = [] if i % 6 == 0 else [{"device_id": i, "type_display_name": "OneLogin Protect", "auth_factor_name": "OneLogin", "user_display_name": "Pixel 8"}]
        if i % 20 == 1: d.append({"device_id": 9000 + i, "type_display_name": "Yubico YubiKey", "auth_factor_name": "Yubikey", "user_display_name": "key"})
        if i % 15 == 2: d.append({"device_id": 8000 + i, "type_display_name": "OneLogin Security Questions", "auth_factor_name": "Security Questions", "user_display_name": "q"})
        devices[u["id"]] = d
    S.data["ol"] = {
        "apps": apps, "assigned": assigned, "users": users, "events": sorted(events, key=lambda e: e["id"]), "devices": devices,
        "roles": [{"id": 71, "name": "Everyone", "apps": [501, 508], "users": list(range(1001, 1211)), "admins": []}, {"id": 72, "name": "Sales", "apps": [502], "users": [1003, 1006], "admins": [1001]},
                  {"id": 73, "name": "Risk analysts", "apps": [503, 504, 505], "users": [1002], "admins": []}, {"id": 74, "name": "Empty role", "apps": [], "users": [], "admins": []}],
        "mappings": [{"id": 1, "name": "Sales department", "match": "all", "enabled": True, "position": 1, "conditions": [{"source": "department", "operator": "=", "value": "Sales"}],
                      "actions": [{"action": "add_role", "value": ["72"]}]},
                     {"id": 2, "name": "Risk in DE", "match": "all", "enabled": True, "position": 2, "conditions": [{"source": "department", "operator": "=", "value": "Risk"}, {"source": "member_of", "operator": "~", "value": "DE"}],
                      "actions": [{"action": "add_role", "value": ["73"]}]},
                     {"id": 3, "name": "Old rule", "match": "any", "enabled": False, "position": 3, "conditions": [{"source": "custom_badge", "operator": "=", "value": "x"}], "actions": [{"action": "set_status", "value": ["2"]}]}],
        "apiauth": [{"id": 31, "name": "Payments API", "description": "", "configuration": {"resource_identifier": "https://api.example.com", "audiences": ["https://api.example.com"]}}],
        "scopes": {31: [{"id": 1, "value": "payments:read"}, {"id": 2, "value": "payments:write"}]},
        "claims": {31: [{"id": 1, "label": "email", "user_attribute_mappings": "email", "user_attribute_macros": None}, {"id": 2, "label": "tier", "user_attribute_mappings": "_macro_", "user_attribute_macros": "{custom_tier}"}]},
        "hooks": [{"id": "hook-1", "type": "pre-authentication", "disabled": False, "status": "ready", "runtime": "nodejs18.x", "function": "T0wtSE9PSy1TT1VSQ0UtQ09ERQ==", "env_vars": ["RISK_API_KEY"], "packages": {"axios": "1.6.0"}},
                  {"id": "hook-2", "type": "user-migration", "disabled": True, "status": "ready", "runtime": "nodejs18.x", "function": "T0wtSE9PSy1TT1VSQ0UtQ09ERQ==", "env_vars": [], "packages": {}}],
        "riskRules": [{"id": "rr1", "name": "Block list", "type": "blacklist", "target": "location.ip", "filters": ["203.0.113.9"]}],
    }
    active = [u for u in users if u["status"] == 1]
    S.expected["onelogin"] = {"users": len(users), "active": len(active), "apps": len(apps),
        "local_active": sum(1 for u in active if not u["directory_id"] and not u["trusted_idp_id"]),
        "never_active": sum(1 for u in active if u["last_login"] is None), "usage": usage,
        "no_factor": sum(1 for v in devices.values() if not v), "assigned": {str(k): v for k, v in assigned.items()},
        "secrets": ["OL-OIDC-SECRET", "OL-SHARED-PASSWORD", "T0wtSE9PSy1TT1VSQ0UtQ09ERQ", "+49 151 222", "First1", "Pixel 8", "10.2.2.2"]}

def ol_route(h, p, q):
    d = S.data["ol"]
    if h.headers.get("Authorization", "").lower() != "bearer " + TOKENS["ol"]: return h.send_json(401, {"message": "Unauthorized"})
    r = p[len("/ol"):]
    def v2(items):
        limit = int(q.get("limit", [50])[0]); start = int(q.get("cursor", ["0"])[0]); chunk = items[start:start + limit]
        return h.send_json(200, chunk, {"After-Cursor": str(start + limit)} if start + limit < len(items) else {})
    def v1(items, size=50):
        start = int(q.get("after_cursor", ["0"])[0]); chunk = items[start:start + size]
        nxt = str(start + size) if start + size < len(items) else None
        return h.send_json(200, {"status": {"error": False, "code": 200, "type": "success"}, "pagination": {"before_cursor": None, "after_cursor": nxt}, "data": chunk})
    seg = r.strip("/").split("/")
    if seg[:2] == ["api", "2"]:
        s = seg[2:]
        if s == ["apps"]: return v2([{k: v for k, v in a.items() if k != "_detail"} for a in d["apps"]])
        if len(s) == 2 and s[0] == "apps":
            a = next((x for x in d["apps"] if str(x["id"]) == s[1]), None)
            if not a: return h.send_json(404, {"message": "not found"})
            full = {k: v for k, v in a.items() if k != "_detail"}; full.update(a["_detail"]); return h.send_json(200, full)
        if len(s) == 3 and s[0] == "apps" and s[2] == "users": return v2([{"id": 1000 + i} for i in range(1, d["assigned"].get(int(s[1]), 0) + 1)])
        if s == ["users"]:
            if int(q.get("cursor", ["0"])[0]) > 0 and "ol" not in S.throttled:
                S.throttled.add("ol"); return h.send_json(429, {"message": "rate limit reached"}, {"X-RateLimit-Limit": "5000", "X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1"})
            return v2(d["users"])
        if s == ["roles"]: return v2(d["roles"])
        if s == ["mappings"]: return v2(d["mappings"])
        if s == ["api_authorizations"]: return v2(d["apiauth"])
        if len(s) == 3 and s[0] == "api_authorizations": return v2(d[s[2]].get(int(s[1]), []))
        if s == ["hooks"]: return v2(d["hooks"])
        if s == ["risk", "rules"]: return v2(d["riskRules"])
        if len(s) == 4 and s[0] == "mfa" and s[1] == "users" and s[3] == "devices": return v2(d["devices"].get(int(s[2]), []))
    if seg[:2] == ["api", "1"]:
        s = seg[2:]
        if s == ["groups"]: return h.send_json(403, {"status": {"error": True, "code": 403}, "message": "Insufficient API credential scope"})
        if s == ["events"]:
            if q.get("event_type_id") != ["8"]: return h.send_json(400, {"message": "event_type_id"})
            since = q.get("since", ["1970"])[0]
            return v1([e for e in d["events"] if e["created_at"] >= since])
    return h.send_json(404, {"message": "not found: " + r})

def ol_token(h, p, body):
    if p != "/ol/auth/oauth2/v2/token": return False
    try: ok = h.basic() == "ol-client:ol-secret" and json.loads(body).get("grant_type") == "client_credentials"
    except Exception: ok = False
    h.send_json(200, {"access_token": TOKENS["ol"], "expires_in": 36000, "token_type": "bearer"}) if ok else h.send_json(401, {"message": "Authentication Failure"})
    return True

POST_ROUTES += [p1_token, ol_token]
GET_ROUTES += [("/__auditlog/pf", pf_route), ("/pf/", pf_route), ("/p1api/", p1_route), ("/ol/", ol_route)]
EXTRA_BUILDERS += [build_pingfederate, build_pingone, build_onelogin]


if __name__ == "__main__":
    main()
