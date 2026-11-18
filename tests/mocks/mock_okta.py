#!/usr/bin/env python3
"""
Mock Okta management API for testing the O2E Collector and Analyzer.

It serves a deterministic synthetic tenant that covers every integration
pattern the toolkit has to recognise. It is NOT an Okta emulator: it only
implements the read endpoints, paging, rate-limit headers and the two
authentication modes the Collector uses.

    python3 mock_okta.py --port 8765 [--public-key client_public.pem]

GET /__expected returns the ground truth that the tests compare against.
"""
import argparse
import base64
import json
import random
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

API_TOKEN = "mock-ssws-token"
ACCESS_TOKEN = "mock-oauth-access-token"
NOW = datetime(2026, 11, 15, 9, 0, 0, tzinfo=timezone.utc)
rng = random.Random(20261115)


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z") if dt else None


def oid(prefix, n):
    return f"{prefix}{n:017d}"


# --------------------------------------------------------------------------
# Synthetic tenant
# --------------------------------------------------------------------------
def build_tenant(base):
    t = {}
    t["org"] = {
        "id": "00o00000000000000001",
        "companyName": "Contoso Bank AG (mock)",
        "subdomain": "contoso",
        "status": "ACTIVE",
        "website": "https://example.com",
    }

    # ---- users -----------------------------------------------------------
    users = []
    departments = ["Sales", "IT", "Finance", "HR", "Operations", "Risk"]
    for i in range(1, 251):
        if i <= 180:
            provider = {"type": "ACTIVE_DIRECTORY", "name": "corp.example.com"}
        elif i <= 230:
            provider = {"type": "OKTA", "name": "OKTA"}
        else:
            provider = {"type": "ACTIVE_DIRECTORY", "name": "corp.example.com"}
        status = "ACTIVE"
        last_login = NOW - timedelta(days=rng.randint(0, 40))
        if i > 240:
            status, last_login = "DEPROVISIONED", NOW - timedelta(days=400)
        elif i > 230:
            status, last_login = "SUSPENDED", NOW - timedelta(days=200)
        elif i % 25 == 0:
            last_login = None                      # never signed in
        elif i % 10 == 0:
            last_login = NOW - timedelta(days=rng.randint(100, 300))  # stale
        login = f"user{i:03d}@example.com"
        users.append({
            "id": oid("00u", i),
            "status": status,
            "created": iso(NOW - timedelta(days=900 - i)),
            "activated": iso(NOW - timedelta(days=899 - i)),
            "lastLogin": iso(last_login),
            "lastUpdated": iso(NOW - timedelta(days=5)),
            "passwordChanged": iso(NOW - timedelta(days=60)),
            "type": {"id": "oty00000000000000001"},
            "profile": {
                "login": login,
                "email": login if i % 40 else f"alias{i:03d}@example.org",
                "firstName": f"First{i}",
                "lastName": f"Last{i}",
                "department": departments[i % len(departments)],
                "mobilePhone": f"+49 151 0000{i:04d}",
            },
            "credentials": {
                "password": {},
                "recovery_question": {"question": "Name of first pet?"},
                "provider": provider,
            },
        })
    t["users"] = users
    live = [u for u in users if u["status"] != "DEPROVISIONED"]
    active = [u for u in users if u["status"] == "ACTIVE"]

    # ---- groups and rules --------------------------------------------------
    groups = [{
        "id": oid("00g", 0), "type": "BUILT_IN",
        "profile": {"name": "Everyone", "description": "All users"},
        "_embedded": {"stats": {"usersCount": len(live), "appsCount": 3, "groupPushMappingsCount": 0}},
    }]
    for i in range(1, 21):
        gtype = "APP_GROUP" if i > 15 else "OKTA_GROUP"
        groups.append({
            "id": oid("00g", i), "type": gtype,
            "profile": {"name": f"grp-{i:02d}", "description": f"Group {i}"},
            "_embedded": {"stats": {"usersCount": 0 if i == 14 else 10 + i,
                                    "appsCount": i % 4, "groupPushMappingsCount": 1 if i in (3, 7) else 0}},
        })
    t["groups"] = groups
    rule_exprs = [
        'user.department=="Sales"',
        'user.department=="IT"',
        'String.stringContains(user.email, "@example.org")',
        'isMemberOfGroupName("grp-01") AND user.department=="Finance"',
        'Arrays.contains(user.roles, "admin")',
        'user.department=="Risk"',
    ]
    t["groupRules"] = [{
        "id": oid("0pr", i), "type": "group_rule", "name": f"rule-{i}",
        "status": "INACTIVE" if i == 6 else "ACTIVE",
        "conditions": {"expression": {"value": e, "type": "urn:okta:expression:1.0"}},
        "actions": {"assignUserToGroups": {"groupIds": [oid("00g", i)]}},
    } for i, e in enumerate(rule_exprs, start=1)]

    # ---- applications ------------------------------------------------------
    apps = []
    n = [0]

    def app(name, label, mode, status="ACTIVE", features=None, signon=None,
            creds=None, settings_app=None, oauth=None, notes=None):
        n[0] += 1
        a = {
            "id": oid("0oa", n[0]), "name": name, "label": label, "status": status,
            "created": iso(NOW - timedelta(days=700)), "lastUpdated": iso(NOW - timedelta(days=30)),
            "signOnMode": mode, "features": features or [],
            "visibility": {"hide": {"iOS": False, "web": False}},
            "credentials": creds or {"userNameTemplate": {"template": "${source.login}", "type": "BUILT_IN"},
                                     "signing": {"kid": "kid-" + str(n[0])}},
            "settings": {"app": settings_app or {}, "notes": {"admin": notes, "enduser": None}},
            "_links": {"accessPolicy": {"href": f"{base}/api/v1/policies/{oid('rst', 1 + n[0] % 3)}"}},
        }
        if signon is not None:
            a["settings"]["signOn"] = signon
        if oauth is not None:
            a["settings"]["oauthClient"] = oauth
        apps.append(a)
        return a

    def saml(acs, statements=None, name_id="${user.userName}", encrypted=False):
        s = {
            "ssoAcsUrl": acs, "audience": acs + "/metadata", "recipient": acs, "destination": acs,
            "subjectNameIdTemplate": name_id,
            "subjectNameIdFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
            "responseSigned": True, "assertionSigned": True,
            "signatureAlgorithm": "RSA_SHA256", "digestAlgorithm": "SHA256",
            "attributeStatements": statements or [],
        }
        if encrypted:
            s["assertionEncryption"] = {"enabled": True, "keyTransportAlgorithm": "RSA_OAEP"}
        return s

    # 1: Office 365, WS-Federation => starting state A
    app("office365", "Microsoft Office 365", "WS_FEDERATION",
        features=["PUSH_NEW_USERS", "PUSH_PROFILE_UPDATES", "PUSH_USER_DEACTIVATION"],
        settings_app={"domain": "example.com", "msftTenant": "contoso"}, notes="Owner: workplace team")
    # 2-11: catalogue SAML apps (names match the mock Entra gallery)
    oin = [("salesforce", "Salesforce"), ("slack", "Slack"), ("zoomus", "Zoom"), ("workday", "Workday"),
           ("servicenow_ud", "ServiceNow"), ("githubcloud", "GitHub Enterprise Cloud"),
           ("atlassian", "Atlassian Cloud"), ("boxnet", "Box"), ("docusign", "DocuSign"),
           ("amazon_aws", "AWS Account Federation")]
    for k, (nm, lb) in enumerate(oin):
        feats = ["PUSH_NEW_USERS", "PUSH_USER_DEACTIVATION", "PUSH_PROFILE_UPDATES"] if k in (0, 1, 3) else []
        if k == 3:
            feats = ["IMPORT_NEW_USERS", "IMPORT_PROFILE_UPDATES"]
        app(nm, lb, "SAML_2_0", features=feats, signon=saml(f"https://{nm}.example.net/acs"),
            notes="Owner: app team" if k % 2 == 0 else None)
    # 12-16: custom SAML apps with claims logic
    custom = [
        ("HR Portal", [{"type": "EXPRESSION", "name": "email", "values": ["user.email"]}], "${user.userName}", False),
        ("Risk Engine", [{"type": "EXPRESSION", "name": "dept", "values": ["user.department"]},
                         {"type": "EXPRESSION", "name": "upper", "values": ["String.toUpperCase(user.lastName)"]},
                         {"type": "GROUP", "name": "groups", "filterType": "REGEX", "filterValue": "grp-.*"}],
         "${user.email}", False),
        ("Treasury", [{"type": "EXPRESSION", "name": "a", "values": ["user.login"]},
                      {"type": "EXPRESSION", "name": "b", "values": ["String.substringBefore(user.email, \"@\")"]},
                      {"type": "EXPRESSION", "name": "c", "values": ["appuser.costCenter"]},
                      {"type": "EXPRESSION", "name": "d", "values": ["user.isMemberOf({'group.profile.name': 'grp-01'}) ? 'x' : 'y'"]}],
         "${fn:substringBefore(user.email, '@')}", True),
        ("Intranet", [], "${user.userName}", False),
        ("Trading Desk", [{"type": "GROUP", "name": "roles", "filterType": "STARTS_WITH", "filterValue": "grp-"}],
         "${user.userName}", False),
    ]
    for lb, st, nid, enc in custom:
        app("contoso_customsaml_" + lb.lower().replace(" ", "_"), lb, "SAML_2_0",
            signon=saml(f"https://{lb.lower().replace(' ', '')}.corp.example.com/saml", st, nid, enc))
    # 17-21: OIDC apps
    oidc = [("Customer Portal", "web", "client_secret_basic"), ("Mobile Banking", "native", "none"),
            ("Ops Dashboard", "browser", "none"), ("Batch Service", "service", "private_key_jwt"),
            ("Partner API Client", "service", "client_secret_basic")]
    for lb, atype, method in oidc:
        cid = "0oa-client-" + lb.lower().replace(" ", "-")
        oc = {"client_id": cid, "token_endpoint_auth_method": method, "autoKeyRotation": True}
        if method == "client_secret_basic":
            oc["client_secret"] = "S3cr3t-" + lb.replace(" ", "")
        app("oidc_client", lb, "OPENID_CONNECT",
            creds={"userNameTemplate": {"template": "${source.login}", "type": "BUILT_IN"}, "oauthClient": oc},
            oauth={"application_type": atype,
                   "grant_types": ["client_credentials"] if atype == "service" else ["authorization_code", "refresh_token"],
                   "redirect_uris": [] if atype == "service" else ["https://app.example.com/callback"],
                   "response_types": ["token"] if atype == "service" else ["code"]})
    # 22-25: password-vaulted (SWA) apps
    swa = [("Legacy Expenses", "AUTO_LOGIN", "EDIT_USERNAME_AND_PASSWORD"),
           ("Vendor Portal", "BROWSER_PLUGIN", "SHARED_USERNAME_AND_PASSWORD"),
           ("Travel Booking", "BROWSER_PLUGIN", "EDIT_USERNAME_AND_PASSWORD"),
           ("Old Wiki", "SECURE_PASSWORD_STORE", "ADMIN_SETS_CREDENTIALS")]
    for lb, mode, scheme in swa:
        c = {"scheme": scheme, "userNameTemplate": {"template": "${source.login}", "type": "BUILT_IN"}}
        if scheme == "SHARED_USERNAME_AND_PASSWORD":
            c["userName"] = "shared-account"
            c["password"] = {"value": "Sh4red-Pa55"}
        app("template_swa", lb, mode, creds=c)
    # 26-27: bookmarks
    app("bookmark", "Canteen Menu", "BOOKMARK")
    app("bookmark", "Facilities Desk", "BOOKMARK")
    # 28: RADIUS
    app("radius", "VPN RADIUS", "RADIUS_FOR_GENERIC_APP")
    # 29-30: inactive apps
    app("contoso_customsaml_oldcrm", "Old CRM", "SAML_2_0", status="INACTIVE", signon=saml("https://oldcrm.example.com/acs"))
    app("template_swa", "Retired Tool", "AUTO_LOGIN", status="INACTIVE",
        creds={"scheme": "EDIT_USERNAME_AND_PASSWORD"})
    t["apps"] = apps

    # ---- app assignments ---------------------------------------------------
    app_groups, app_users = {}, {}
    for idx, a in enumerate(apps):
        gids = [oid("00g", 1 + (idx + j) % 15) for j in range(idx % 3)]
        app_groups[a["id"]] = [{"id": g, "priority": j, "profile": {}} for j, g in enumerate(gids)]
        direct = [] if idx % 4 else live[: 3 + idx]
        via_group = live[40: 40 + 20 + idx * 2] if gids else []
        rows = [{"id": u["id"], "scope": "USER", "status": "ACTIVE",
                 "credentials": {"userName": u["profile"]["login"]}} for u in direct]
        rows += [{"id": u["id"], "scope": "GROUP", "status": "ACTIVE",
                  "credentials": {"userName": u["profile"]["login"]}} for u in via_group]
        app_users[a["id"]] = rows
    t["appGroups"], t["appUsers"] = app_groups, app_users

    # ---- policies ----------------------------------------------------------
    def rule(i, name, cond, actions, status="ACTIVE"):
        return {"id": oid("0pr9", i), "name": name, "status": status, "priority": i, "system": False,
                "conditions": cond, "actions": actions}

    zone_ids = [oid("nzo", i) for i in range(1, 5)]
    t["zones"] = [
        {"id": zone_ids[0], "name": "HQ Frankfurt", "type": "IP", "status": "ACTIVE", "usage": "POLICY",
         "gateways": [{"type": "CIDR", "value": "203.0.113.0/24"}], "proxies": None},
        {"id": zone_ids[1], "name": "Branch offices", "type": "IP", "status": "ACTIVE", "usage": "POLICY",
         "gateways": [{"type": "CIDR", "value": "198.51.100.0/25"}, {"type": "RANGE", "value": "192.0.2.10-192.0.2.20"}]},
        {"id": zone_ids[2], "name": "Blocked countries", "type": "DYNAMIC", "status": "ACTIVE", "usage": "BLOCKLIST",
         "locations": [{"country": "KP", "region": None}], "proxyType": "Tor"},
        {"id": zone_ids[3], "name": "Legacy VPN", "type": "IP", "status": "INACTIVE", "usage": "POLICY",
         "gateways": [{"type": "CIDR", "value": "192.0.2.128/26"}]},
    ]
    policies = []
    rules = {}

    def pol(pid, ptype, name, system=False, status="ACTIVE", rs=None):
        policies.append({"id": pid, "type": ptype, "name": name, "status": status, "system": system,
                         "priority": len(policies) + 1, "conditions": {"people": {"groups": {"include": [oid("00g", 0)]}}}})
        rules[pid] = rs or []

    pol(oid("00p", 1), "OKTA_SIGN_ON", "Default Policy", system=True, rs=[
        rule(1, "In zone, no MFA", {"network": {"connection": "ZONE", "include": [zone_ids[0], zone_ids[1]]}},
             {"signon": {"access": "ALLOW", "requireFactor": False,
                         "session": {"maxSessionIdleMinutes": 120, "maxSessionLifetimeMinutes": 720, "usePersistentCookie": False}}}),
        rule(2, "Anywhere, MFA every session", {"network": {"connection": "ANYWHERE"}},
             {"signon": {"access": "ALLOW", "requireFactor": True, "factorPromptMode": "SESSION",
                         "session": {"maxSessionIdleMinutes": 60, "maxSessionLifetimeMinutes": 480, "usePersistentCookie": False}}}),
        rule(3, "Block Tor", {"network": {"connection": "ZONE", "include": [zone_ids[2]]}}, {"signon": {"access": "DENY"}}),
    ])
    pol(oid("00p", 2), "OKTA_SIGN_ON", "Contractors", rs=[
        rule(4, "Always MFA", {"network": {"connection": "ANYWHERE"}},
             {"signon": {"access": "ALLOW", "requireFactor": True, "factorPromptMode": "ALWAYS"}}),
    ])
    pol(oid("rst", 1), "ACCESS_POLICY", "Any two factors", rs=[
        rule(5, "Catch-all", {"network": {"connection": "ANYWHERE"}},
             {"appSignOn": {"access": "ALLOW", "verificationMethod": {"factorMode": "2FA", "type": "ASSURANCE", "reauthenticateIn": "PT12H"}}}),
    ])
    pol(oid("rst", 2), "ACCESS_POLICY", "Managed device required", rs=[
        rule(6, "Managed Windows", {"device": {"registered": True, "managed": True}, "platform": {"include": [{"type": "DESKTOP", "os": {"type": "WINDOWS"}}]}},
             {"appSignOn": {"access": "ALLOW", "verificationMethod": {"factorMode": "1FA", "type": "ASSURANCE",
                            "constraints": [{"possession": {"phishingResistant": "REQUIRED"}}]}}}),
        rule(7, "Deny rest", {"network": {"connection": "ANYWHERE"}}, {"appSignOn": {"access": "DENY"}}),
    ])
    pol(oid("rst", 3), "ACCESS_POLICY", "Password only (legacy)", rs=[
        rule(8, "Catch-all", {"riskScore": {"level": "ANY"}},
             {"appSignOn": {"access": "ALLOW", "verificationMethod": {"factorMode": "1FA", "type": "ASSURANCE"}}}),
        rule(9, "High risk", {"riskScore": {"level": "HIGH"}},
             {"appSignOn": {"access": "ALLOW", "verificationMethod": {"factorMode": "2FA", "type": "ASSURANCE"}}}, status="INACTIVE"),
    ])
    pol(oid("00p", 3), "MFA_ENROLL", "Default Policy", system=True, rs=[rule(10, "Enroll at first sign-in", {}, {"enroll": {"self": "CHALLENGE"}})])
    pol(oid("00p", 4), "PASSWORD", "Default Policy", system=True, rs=[rule(11, "Default", {}, {"passwordChange": {"access": "ALLOW"}})])
    pol(oid("00p", 5), "PASSWORD", "AD password policy", rs=[rule(12, "Default", {}, {"passwordChange": {"access": "DENY"}})])
    pol(oid("00p", 6), "IDP_DISCOVERY", "Idp Discovery Policy", system=True, rs=[
        rule(13, "Partners to partner IdP", {"userIdentifier": {"type": "IDENTIFIER", "patterns": [{"matchType": "SUFFIX", "value": "partner.example"}]}},
             {"idp": {"providers": [{"type": "SAML2", "id": oid("0oi", 1)}]}}),
        rule(14, "Default", {}, {"idp": {"providers": [{"type": "OKTA"}]}}),
    ])
    pol(oid("00p", 7), "PROFILE_ENROLLMENT", "Default Policy", system=True, rs=[])
    t["policies"], t["policyRules"] = policies, rules

    # ---- identity providers, authenticators --------------------------------
    t["idps"] = [
        {"id": oid("0oi", 1), "type": "SAML2", "name": "Partner Federation", "status": "ACTIVE",
         "protocol": {"type": "SAML2", "credentials": {"trust": {"issuer": "https://idp.partner.example", "kid": "k1"}}}},
        {"id": oid("0oi", 2), "type": "GOOGLE", "name": "Google (contractors)", "status": "ACTIVE",
         "protocol": {"type": "OIDC", "credentials": {"client": {"client_id": "google-client", "client_secret": "GOCSPX-very-secret"}}}},
    ]
    t["authenticators"] = [
        {"id": oid("aut", i), "key": k, "name": nm, "type": ty, "status": st}
        for i, (k, nm, ty, st) in enumerate([
            ("okta_password", "Password", "password", "ACTIVE"),
            ("okta_verify", "Okta Verify", "app", "ACTIVE"),
            ("okta_email", "Email", "email", "ACTIVE"),
            ("phone_number", "Phone", "phone", "ACTIVE"),
            ("security_question", "Security Question", "security_question", "ACTIVE"),
            ("webauthn", "Security Key or Biometric", "security_key", "ACTIVE"),
            ("google_otp", "Google Authenticator", "app", "INACTIVE"),
            ("rsa_token", "RSA SecurID", "security_key", "ACTIVE"),
        ], start=1)]

    # ---- authorization servers --------------------------------------------
    def scopes(custom):
        base_scopes = [{"id": f"scp-sys-{s}", "name": s, "system": True} for s in ("openid", "profile", "email", "offline_access")]
        return base_scopes + [{"id": f"scp-{s}", "name": s, "system": False} for s in custom]

    def claims(custom):
        sysc = [{"id": "ocl-sub", "name": "sub", "status": "ACTIVE", "claimType": "RESOURCE", "valueType": "EXPRESSION",
                 "value": "(appuser != null) ? appuser.userName : app.clientId", "system": True}]
        return sysc + [{"id": f"ocl-{nm}", "name": nm, "status": "ACTIVE", "claimType": ct, "valueType": vt, "value": v, "system": False}
                       for nm, ct, vt, v in custom]

    t["authorizationServers"] = [
        {"id": "aus00000000000000001", "name": "default", "description": "Default", "audiences": ["api://default"],
         "issuer": f"{base}/oauth2/default", "status": "ACTIVE"},
        {"id": "aus00000000000000002", "name": "Payments API", "description": "", "audiences": ["api://payments"],
         "issuer": f"{base}/oauth2/aus00000000000000002", "status": "ACTIVE"},
        {"id": "aus00000000000000003", "name": "Old Partner API", "description": "", "audiences": ["api://partner"],
         "issuer": f"{base}/oauth2/aus00000000000000003", "status": "INACTIVE"},
    ]
    t["asScopes"] = {"aus00000000000000001": scopes([]),
                     "aus00000000000000002": scopes(["payments.read", "payments.write"]),
                     "aus00000000000000003": scopes(["partner.read"])}
    t["asClaims"] = {"aus00000000000000001": claims([]),
                     "aus00000000000000002": claims([("groups", "RESOURCE", "GROUPS", "grp-.*"),
                                                     ("costCenter", "RESOURCE", "EXPRESSION", "user.costCenter"),
                                                     ("tier", "IDENTITY", "EXPRESSION", "user.department == \"Risk\" ? \"gold\" : \"std\"")]),
                     "aus00000000000000003": claims([])}
    t["asPolicies"] = {k: [{"id": "pol-" + k[-1], "name": "Default", "status": "ACTIVE", "conditions": {"clients": {"include": ["ALL_CLIENTS"]}}}]
                       for k in t["asScopes"]}

    # ---- hooks, tokens, admins --------------------------------------------
    t["eventHooks"] = [
        {"id": "who00000000000000001", "name": "SIEM forwarder", "status": "ACTIVE",
         "events": {"type": "EVENT_TYPE", "items": ["user.session.start", "user.account.lock"]},
         "channel": {"type": "HTTP", "version": "1.0.0",
                     "config": {"uri": "https://siem.example.com/okta", "authScheme": {"type": "HEADER", "key": "Authorization", "value": "Bearer hook-secret-1"}}}},
        {"id": "who00000000000000002", "name": "HR sync trigger", "status": "ACTIVE",
         "events": {"type": "EVENT_TYPE", "items": ["user.lifecycle.create"]},
         "channel": {"type": "HTTP", "version": "1.0.0", "config": {"uri": "https://hr.example.com/hook", "authScheme": {"type": "HEADER", "key": "X-Api-Key", "value": "hook-secret-2"}}}},
    ]
    t["inlineHooks"] = [
        {"id": "cal00000000000000001", "name": "Token enrichment", "type": "com.okta.oauth2.tokens.transform", "status": "ACTIVE",
         "channel": {"type": "HTTP", "config": {"uri": "https://api.example.com/enrich", "authScheme": {"type": "HEADER", "key": "Authorization", "value": "inline-secret"}}}},
        {"id": "cal00000000000000002", "name": "Password import", "type": "com.okta.user.credential.password.import", "status": "INACTIVE",
         "channel": {"type": "HTTP", "config": {"uri": "https://legacy.example.com/pw"}}},
    ]
    t["apiTokens"] = [
        {"id": f"00T{i:017d}", "name": nm, "userId": oid("00u", uid), "clientName": cn,
         "created": iso(NOW - timedelta(days=age)), "lastUpdated": iso(NOW - timedelta(days=used)), "expiresAt": iso(NOW + timedelta(days=30))}
        for i, (nm, uid, cn, age, used) in enumerate([
            ("terraform", 1, "Terraform", 400, 1), ("hr-sync", 2, "curl", 800, 2), ("old-script", 3, "python", 1200, 190)], start=1)]
    t["adminUsers"] = {oid("00u", 1): [{"id": "ra1", "label": "Super Administrator", "type": "SUPER_ADMIN", "status": "ACTIVE", "assignmentType": "USER"}],
                       oid("00u", 2): [{"id": "ra2", "label": "Organization Administrator", "type": "ORG_ADMIN", "status": "ACTIVE", "assignmentType": "USER"}],
                       oid("00u", 3): [{"id": "ra3", "label": "Application Administrator", "type": "APP_ADMIN", "status": "ACTIVE", "assignmentType": "GROUP"},
                                       {"id": "ra4", "label": "Help Desk Administrator", "type": "HELP_DESK_ADMIN", "status": "ACTIVE", "assignmentType": "USER"}],
                       oid("00u", 4): [{"id": "ra5", "label": "Super Administrator", "type": "SUPER_ADMIN", "status": "ACTIVE", "assignmentType": "USER"}]}

    # ---- misc --------------------------------------------------------------
    t["userSchema"] = {"id": f"{base}/api/v1/meta/schemas/user/default", "name": "user",
                       "definitions": {"base": {"properties": {"login": {}, "email": {}, "firstName": {}, "lastName": {}}},
                                       "custom": {"properties": {"costCenter": {"type": "string"}, "roles": {"type": "array"}, "badgeId": {"type": "string"}}}}}
    t["mappings"] = [{"id": f"prm{i:017d}", "source": {"id": a["id"], "name": a["name"], "type": "appuser"},
                      "target": {"id": "oty00000000000000001", "name": "user", "type": "user"}} for i, a in enumerate(apps[:4], start=1)]
    t["devices"] = [{"id": f"guo{i:017d}", "status": "ACTIVE", "resourceType": "UDDevice",
                     "profile": {"displayName": f"LT-{i:04d}", "platform": "WINDOWS" if i % 3 else "MACOS", "registered": True}}
                    for i in range(1, 91)]
    t["behaviors"] = [{"id": "abc1", "name": "New Device", "type": "ANOMALOUS_DEVICE", "status": "ACTIVE"},
                      {"id": "abc2", "name": "New Country", "type": "ANOMALOUS_LOCATION", "status": "ACTIVE"}]
    t["trustedOrigins"] = [{"id": "tos1", "name": "Intranet", "origin": "https://intranet.example.com", "status": "ACTIVE"}]
    t["domains"] = {"domains": [{"id": "OcD1", "domain": "login.example.com", "validationStatus": "VERIFIED"}]}

    # ---- factors -----------------------------------------------------------
    factors = {}
    for i, u in enumerate(active):
        f = [{"id": f"opf{i}", "factorType": "push", "provider": "OKTA", "status": "ACTIVE", "profile": {"name": "Pixel"}}]
        if i % 3 == 0:
            f.append({"id": f"sms{i}", "factorType": "sms", "provider": "OKTA", "status": "ACTIVE", "profile": {"phoneNumber": "+49 151 99999999"}})
        if i % 10 == 0:
            f.append({"id": f"fwa{i}", "factorType": "webauthn", "provider": "FIDO", "status": "ACTIVE", "profile": {"authenticatorName": "YubiKey"}})
        if i % 7 == 0:
            f = []                                      # not enrolled at all
        factors[u["id"]] = f
    t["factors"] = factors

    # ---- system log --------------------------------------------------------
    events = []
    usage = {}
    unused_labels = {"Old Wiki", "Facilities Desk", "Intranet", "Old CRM", "Retired Tool", "Partner API Client"}
    k = 0
    for idx, a in enumerate(apps):
        if a["label"] in unused_labels:
            continue
        count = 400 if idx == 0 else 15 + (idx * 37) % 160
        pool = active[: 200 if idx == 0 else 5 + (idx * 13) % 90]
        seen, last = set(), None
        for _ in range(count):
            u = pool[rng.randrange(len(pool))]
            when = NOW - timedelta(days=rng.randint(0, 85), minutes=rng.randint(0, 1400))
            k += 1
            events.append({
                "uuid": f"evt-{k:07d}", "published": iso(when), "eventType": "user.authentication.sso",
                "actor": {"id": u["id"], "type": "User", "alternateId": u["profile"]["login"]},
                "outcome": {"result": "SUCCESS"},
                "target": [{"id": a["id"], "type": "AppInstance", "alternateId": a["label"], "displayName": a["label"]},
                           {"id": "0ua" + u["id"][3:], "type": "AppUser", "alternateId": u["profile"]["login"]}],
            })
            seen.add(u["id"])
            last = when if last is None or when > last else last
        usage[a["id"]] = {"signIns": count, "distinctUsers": len(seen)}
    radius_events = 0
    for j in range(60):
        u = active[j % 30]
        k += 1
        radius_events += 1
        events.append({"uuid": f"evt-{k:07d}", "published": iso(NOW - timedelta(days=j % 80, minutes=j)),
                       "eventType": "user.authentication.auth_via_radius",
                       "actor": {"id": u["id"], "type": "User", "alternateId": u["profile"]["login"]},
                       "outcome": {"result": "SUCCESS"}, "target": []})
    events.sort(key=lambda e: e["published"])
    t["logs"] = events

    # ---- ground truth for tests -------------------------------------------
    t["expected"] = {
        "users_total": len(users),
        "users_active": len(active),
        "users_deprovisioned": len(users) - len(live),
        "okta_sourced_active": sum(1 for u in active if u["credentials"]["provider"]["type"] == "OKTA"),
        "never_signed_in_active": sum(1 for u in active if u["lastLogin"] is None),
        "apps_total": len(apps),
        "apps_inactive": sum(1 for a in apps if a["status"] != "ACTIVE"),
        "apps_swa_active": sum(1 for a in apps if a["status"] == "ACTIVE" and a["signOnMode"] in ("AUTO_LOGIN", "BROWSER_PLUGIN", "SECURE_PASSWORD_STORE")),
        "apps_oidc_active": sum(1 for a in apps if a["status"] == "ACTIVE" and a["signOnMode"] == "OPENID_CONNECT"),
        "apps_saml_active": sum(1 for a in apps if a["status"] == "ACTIVE" and a["signOnMode"] == "SAML_2_0"),
        "apps_unused_active": sorted(a["label"] for a in apps if a["status"] == "ACTIVE" and a["id"] not in usage),
        "usage": usage,
        "radius_events": radius_events,
        "log_events": len(events),
        "group_rules": len(t["groupRules"]),
        "policy_rules": sum(len(v) for v in rules.values()),
        "admins": len(t["adminUsers"]),
        "factors_users_without": sum(1 for v in factors.values() if not v),
        "factors_push": sum(1 for v in factors.values() for f in v if f["factorType"] == "push"),
        "factors_webauthn": sum(1 for v in factors.values() for f in v if f["factorType"] == "webauthn"),
        "direct_assignments": {a["id"]: sum(1 for r in app_users[a["id"]] if r["scope"] == "USER") for a in apps},
        "secrets": ["S3cr3t-CustomerPortal", "S3cr3t-PartnerAPIClient", "Sh4red-Pa55", "GOCSPX-very-secret",
                    "hook-secret-1", "hook-secret-2", "inline-secret", "Name of first pet?", "+49 151"],
    }
    return t


# --------------------------------------------------------------------------
# HTTP layer
# --------------------------------------------------------------------------
class State:
    tenant = None
    base = None
    public_key = None
    requests = 0
    throttled_once = False
    seen_jti = set()
    token_requests = 0
    write_attempts = 0


def b64url_decode(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def verify_assertion(jwt, expected_aud):
    """Verify an RS256 private_key_jwt client assertion. Returns (ok, reason)."""
    try:
        h, p, s = jwt.split(".")
        header = json.loads(b64url_decode(h))
        payload = json.loads(b64url_decode(p))
    except Exception as exc:  # noqa: BLE001
        return False, f"malformed jwt: {exc}"
    if header.get("alg") != "RS256":
        return False, "alg must be RS256"
    for claim in ("iss", "sub", "aud", "exp", "jti"):
        if claim not in payload:
            return False, f"missing claim {claim}"
    if payload["iss"] != payload["sub"]:
        return False, "iss and sub must both be the client id"
    if payload["aud"] != expected_aud:
        return False, f"aud mismatch: {payload['aud']} != {expected_aud}"
    if payload["exp"] < time.time() or payload["exp"] > time.time() + 3600:
        return False, "exp out of range"
    if payload["jti"] in State.seen_jti:
        return False, "jti replayed"
    State.seen_jti.add(payload["jti"])
    if State.public_key is not None:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        try:
            State.public_key.verify(b64url_decode(s), f"{h}.{p}".encode(), padding.PKCS1v15(), hashes.SHA256())
        except Exception:  # noqa: BLE001
            return False, "bad signature"
    return True, "ok"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # keep test output quiet
        pass

    def _send(self, code, body, headers=None):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Rate-Limit-Limit", "600")
        self.send_header("X-Rate-Limit-Remaining", "599")
        self.send_header("X-Rate-Limit-Reset", str(int(time.time()) + 60))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _authorised(self):
        auth = self.headers.get("Authorization", "")
        return auth in (f"SSWS {API_TOKEN}", f"Bearer {ACCESS_TOKEN}")

    def _page(self, items, q, path, default_limit=200):
        limit = int(q.get("limit", [default_limit])[0])
        start = int(q.get("after", [0])[0])
        chunk = items[start:start + limit]
        headers = {}
        if start + limit < len(items):
            keep = "&".join(f"{k}={v[0]}" for k, v in q.items() if k not in ("after",))
            sep = "&" if keep else ""
            headers["Link"] = f'<{State.base}{path}?{keep}{sep}after={start + limit}>; rel="next"'
        self._send(200, chunk, headers)

    def do_POST(self):
        State.requests += 1
        u = urlparse(self.path)
        if u.path == "/oauth2/v1/token":
            State.token_requests += 1
            body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
            form = parse_qs(body)
            if form.get("grant_type", [""])[0] != "client_credentials":
                return self._send(400, {"error": "unsupported_grant_type"})
            if form.get("client_assertion_type", [""])[0] != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer":
                return self._send(400, {"error": "invalid_client", "error_description": "client_assertion_type"})
            ok, why = verify_assertion(form.get("client_assertion", [""])[0], f"{State.base}/oauth2/v1/token")
            if not ok:
                return self._send(401, {"error": "invalid_client", "error_description": why})
            return self._send(200, {"token_type": "Bearer", "expires_in": 3600, "access_token": ACCESS_TOKEN,
                                    "scope": form.get("scope", [""])[0]})
        State.write_attempts += 1
        self._send(405, {"errorCode": "E0000022", "errorSummary": "The mock tenant is read-only"})

    def _refuse_write(self):
        State.write_attempts += 1
        self._send(405, {"errorCode": "E0000022", "errorSummary": "The mock tenant is read-only"})

    do_PUT = do_DELETE = do_PATCH = _refuse_write

    def do_GET(self):
        State.requests += 1
        u = urlparse(self.path)
        q = parse_qs(u.query)
        p = u.path.rstrip("/")
        t = State.tenant
        if p == "/__expected":
            return self._send(200, t["expected"])
        if p == "/__stats":
            return self._send(200, {"requests": State.requests, "tokenRequests": State.token_requests,
                                    "writeAttempts": State.write_attempts})
        if not self._authorised():
            return self._send(401, {"errorCode": "E0000011", "errorSummary": "Invalid token provided"})

        seg = p.split("/")[3:] if p.startswith("/api/v1/") else []
        # one forced throttle, to prove the Collector waits and retries
        if seg[:1] == ["users"] and len(seg) == 1 and "after" in q and not State.throttled_once:
            State.throttled_once = True
            return self._send(429, {"errorCode": "E0000047", "errorSummary": "API call exceeded rate limit"},
                              {"X-Rate-Limit-Remaining": "0", "X-Rate-Limit-Reset": str(int(time.time()) + 1)})

        if seg == ["org"]:
            return self._send(200, t["org"])
        if seg == ["users"]:
            flt = q.get("filter", [""])[0]
            items = [x for x in t["users"] if x["status"] == "DEPROVISIONED"] if "DEPROVISIONED" in flt \
                else [x for x in t["users"] if x["status"] != "DEPROVISIONED"]
            return self._page(items, q, p)
        if len(seg) == 3 and seg[0] == "users" and seg[2] == "factors":
            return self._send(200, t["factors"].get(seg[1], []))
        if len(seg) == 3 and seg[0] == "users" and seg[2] == "roles":
            return self._send(200, t["adminUsers"].get(seg[1], []))
        if seg == ["iam", "assignees", "users"]:
            return self._send(200, {"value": [{"id": k} for k in t["adminUsers"]], "_links": {}})
        if seg == ["groups"]:
            return self._page(t["groups"], q, p)
        if seg == ["groups", "rules"]:
            return self._page(t["groupRules"], q, p)
        if seg == ["apps"]:
            return self._page(t["apps"], q, p, default_limit=20)
        if len(seg) == 3 and seg[0] == "apps" and seg[2] == "groups":
            return self._page(t["appGroups"].get(seg[1], []), q, p)
        if len(seg) == 3 and seg[0] == "apps" and seg[2] == "users":
            return self._page(t["appUsers"].get(seg[1], []), q, p, default_limit=50)
        if seg == ["policies"]:
            ptype = q.get("type", [""])[0]
            return self._send(200, [x for x in t["policies"] if x["type"] == ptype])
        if len(seg) == 3 and seg[0] == "policies" and seg[2] == "rules":
            return self._send(200, t["policyRules"].get(seg[1], []))
        if seg == ["authorizationServers"]:
            return self._send(200, t["authorizationServers"])
        if len(seg) == 3 and seg[0] == "authorizationServers":
            src = {"scopes": "asScopes", "claims": "asClaims", "policies": "asPolicies"}.get(seg[2])
            if src:
                return self._send(200, t[src].get(seg[1], []))
        if seg == ["logs"]:
            flt = q.get("filter", [""])[0]
            since = q.get("since", ["1970"])[0]
            items = [e for e in t["logs"] if e["published"] >= since and (e["eventType"] in flt)]
            return self._page(items, q, p, default_limit=100)
        if seg == ["meta", "schemas", "user", "default"]:
            return self._send(200, t["userSchema"])
        if seg == ["domains"]:
            return self._send(200, t["domains"])
        if seg == ["behaviors"]:                     # simulate a scope the service app was not granted
            return self._send(403, {"errorCode": "E0000006", "errorSummary": "You do not have permission to perform the requested action"})
        simple = {"zones": "zones", "idps": "idps", "authenticators": "authenticators", "eventHooks": "eventHooks",
                  "inlineHooks": "inlineHooks", "api-tokens": "apiTokens", "mappings": "mappings", "devices": "devices",
                  "behaviors": "behaviors", "trustedOrigins": "trustedOrigins"}
        if len(seg) == 1 and seg[0] in simple:
            return self._page(t[simple[seg[0]]], q, p)
        self._send(404, {"errorCode": "E0000007", "errorSummary": f"Not found: {p}"})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--public-key", help="PEM public key used to verify private_key_jwt client assertions")
    args = ap.parse_args()
    State.base = f"http://127.0.0.1:{args.port}"
    State.tenant = build_tenant(State.base)
    if args.public_key:
        from cryptography.hazmat.primitives import serialization
        with open(args.public_key, "rb") as fh:
            State.public_key = serialization.load_pem_public_key(fh.read())
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"mock okta listening on {State.base}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
