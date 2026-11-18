#!/usr/bin/env python3
"""Mock of the Microsoft Graph endpoints the Entra target connector reads. Read-only: anything but GET
(and the token POST) is refused and counted.

  POST /auth/<tenant>/oauth2/v2.0/token        client credentials (client 'graph-client' / 'graph-secret')
  GET  /graph/v1.0/organization | domains | users | applicationTemplates | servicePrincipals
  GET  /graph/v1.0/identity/conditionalAccess/policies   -> 403 (optional permission not granted)
  GET  /__stats
"""
import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

TOKEN = "mock-graph-token"


class S:
    base = ""
    requests = 0
    writes = 0


def users():
    out = []
    # Okta mock: user001..user250@example.com (241-250 deprovisioned). In this tenant: three accounts are missing, the four
    # suspended ones (237-240) were never created, user120 matches by mail only, and user200's mail is held by two accounts.
    for i in range(1, 237):
        if i in (17, 58, 199):
            continue
        mail = f"user{i:03d}@example.com"
        upn = f"u{i:03d}@contoso.onmicrosoft.com" if i in (120, 200) else mail
        out.append({"id": f"e-{i:04d}", "userPrincipalName": upn, "mail": mail, "onPremisesImmutableId": f"imm{i:04d}" if i % 5 else None,
                    "onPremisesSyncEnabled": bool(i % 5), "accountEnabled": True, "userType": "Member"})
    out.append({"id": "e-dup-200", "userPrincipalName": "shared200@contoso.onmicrosoft.com", "mail": "user200@example.com", "accountEnabled": True, "userType": "Member"})
    for prefix, n in (("kuser", 100), ("puser", 120), ("ouser", 200)):
        for i in range(1, n + 1):
            upn = f"{prefix}{i:03d}@example.com"
            out.append({"id": f"e-{prefix}-{i:04d}", "userPrincipalName": f"{prefix}{i:03d}@contoso.onmicrosoft.com" if i % 10 == 0 else upn, "mail": upn,
                        "onPremisesImmutableId": None, "onPremisesSyncEnabled": False, "accountEnabled": True, "userType": "Member"})
    out.append({"id": "e-dup", "userPrincipalName": "dup@contoso.onmicrosoft.com", "mail": "ouser010@example.com", "accountEnabled": True, "userType": "Member"})
    return out


USERS = users()
TEMPLATES = [{"id": f"t-{i}", "displayName": n, "categories": ["productivity"], "supportedSingleSignOnModes": m, "supportedProvisioningTypes": p}
             for i, (n, m, p) in enumerate([("Salesforce", ["saml", "password"], ["sync"]), ("Workday", ["saml"], ["sync"]), ("Zoom", ["saml"], ["sync"]),
                                            ("ServiceNow", ["saml"], ["sync"]), ("Slack", ["saml"], ["sync"]), ("Box", ["saml"], ["sync"]),
                                            ("Atlassian Cloud", ["saml"], ["sync"]), ("DocuSign", ["saml"], []), ("Concur", ["saml", "password"], []),
                                            ("GitHub Enterprise Cloud", ["saml"], []), ("Dropbox Business", ["saml"], []), ("LinkedIn", ["password"], [])])]
SPS = [{"id": "sp-1", "displayName": "Salesforce", "appId": "a-1", "preferredSingleSignOnMode": "saml", "accountEnabled": True},
       {"id": "sp-2", "displayName": "Entra pilot app", "appId": "a-2", "preferredSingleSignOnMode": None, "accountEnabled": True}]


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def send_json(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        S.requests += 1
        u = urlparse(self.path)
        body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
        if u.path.startswith("/auth/") and u.path.endswith("/oauth2/v2.0/token"):
            form = parse_qs(body)
            if form.get("client_id", [""])[0] != "graph-client" or form.get("client_secret", [""])[0] != "graph-secret":
                return self.send_json(401, {"error": "invalid_client", "error_description": "AADSTS7000215: Invalid client secret provided."})
            if not form.get("scope", [""])[0].endswith("/.default"):
                return self.send_json(400, {"error": "invalid_scope"})
            return self.send_json(200, {"token_type": "Bearer", "expires_in": 3599, "access_token": TOKEN})
        S.writes += 1
        self.send_json(405, {"error": {"code": "MethodNotAllowed", "message": "The mock tenant is read-only"}})

    def _refuse(self):
        S.requests += 1
        S.writes += 1
        self.send_json(405, {"error": {"code": "MethodNotAllowed", "message": "The mock tenant is read-only"}})

    do_PUT = do_PATCH = do_DELETE = _refuse

    def do_GET(self):
        S.requests += 1
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/__stats":
            return self.send_json(200, {"requests": S.requests, "writes": S.writes})
        if not u.path.startswith("/graph/v1.0/"):
            return self.send_json(404, {"error": {"code": "NotFound", "message": "Unknown path"}})
        if self.headers.get("Authorization") != f"Bearer {TOKEN}":
            return self.send_json(401, {"error": {"code": "InvalidAuthenticationToken", "message": "Access token is empty or invalid."}})
        p = u.path[len("/graph/v1.0"):]
        if p == "/organization":
            return self.send_json(200, {"value": [{"id": "tenant-0001", "displayName": "Contoso (mock tenant)", "onPremisesSyncEnabled": True,
                                                   "onPremisesLastSyncDateTime": "2026-11-17T06:00:00Z"}]})
        if p == "/domains":
            return self.send_json(200, {"value": [{"id": "example.com", "authenticationType": "Federated", "isDefault": True, "isVerified": True},
                                                  {"id": "contoso.onmicrosoft.com", "authenticationType": "Managed", "isDefault": False, "isVerified": True}]})
        if p == "/users":
            skip, size = int(q.get("$skiptoken", [0])[0]), 300
            body = {"value": USERS[skip:skip + size]}
            if skip + size < len(USERS):
                body["@odata.nextLink"] = f"{S.base}/graph/v1.0/users?$skiptoken={skip + size}"
            return self.send_json(200, body)
        if p == "/applicationTemplates":
            return self.send_json(200, {"value": TEMPLATES})
        if p == "/servicePrincipals":
            return self.send_json(200, {"value": SPS})
        if p == "/identity/conditionalAccess/policies":
            return self.send_json(403, {"error": {"code": "Forbidden", "message": "Insufficient privileges to complete the operation."}})
        self.send_json(404, {"error": {"code": "NotFound", "message": "Unknown path"}})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8780)
    a = ap.parse_args()
    S.base = f"http://127.0.0.1:{a.port}"
    ThreadingHTTPServer(("127.0.0.1", a.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
