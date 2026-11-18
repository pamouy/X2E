"""Microsoft Entra ID (the target): read-only collector through Microsoft Graph."""
from __future__ import annotations

from ..core import as_list, get
from ..httpc import HttpError
from .base import BaseConnector, ConnectorError, field

CLOUDS = {
    "global": ("https://login.microsoftonline.com", "https://graph.microsoft.com"),
    "usgov": ("https://login.microsoftonline.us", "https://graph.microsoft.us"),
    "china": ("https://login.chinacloudapi.cn", "https://microsoftgraph.chinacloudapi.cn"),
}


class Connector(BaseConnector):
    PLATFORM = "entra"
    LABEL = "Microsoft Entra ID"
    ROLE = "target"
    PERMISSIONS = ("An app registration in the target tenant with a client secret and these Microsoft Graph application permissions, admin-consented: "
                   "User.Read.All, Domain.Read.All, Organization.Read.All, Application.Read.All. Optional: Policy.Read.All for Conditional Access readiness.")
    FIELDS = [
        field("tenantId", "Tenant ID", required=True, help="Directory (tenant) ID or a verified domain"),
        field("clientId", "Application (client) ID", required=True),
        field("clientSecret", "Client secret", "secret", required=True),
        field("cloud", "Cloud", "select", default="global", options=[["global", "Global"], ["usgov", "US Government"], ["china", "China (21Vianet)"]]),
        field("authority", "Authority URL", help="Only to override the cloud default"),
        field("graphBase", "Graph URL", help="Only to override the cloud default"),
        field("allowInsecure", "Allow http (lab only)", "bool", default=False),
    ]

    def __init__(self, cfg: dict):
        super().__init__(cfg)
        cloud = CLOUDS.get(str(self.cfg["cloud"] or "global"))
        if not cloud:
            raise ConnectorError("Unknown cloud")
        self.authority = str(self.cfg["authority"] or cloud[0]).rstrip("/")
        self.graph = str(self.cfg["graphBase"] or cloud[1]).rstrip("/")
        self.tenant = self.cfg["tenantId"]
        self.client([self.authority, self.graph])

    def source_name(self) -> str:
        return f"{self.graph} tenant {self.tenant}"

    def fetch_token(self) -> tuple[str, int]:
        body = self.http.token(f"{self.authority}/{self.tenant}/oauth2/v2.0/token",
                               data={"grant_type": "client_credentials", "client_id": self.cfg["clientId"], "client_secret": self.cfg["clientSecret"],
                                     "scope": f"{self.graph}/.default"})
        return body["access_token"], int(body.get("expires_in", 3600)) - 60

    def paged(self, path: str, params: dict | None = None):
        url, seen = f"{self.graph}/v1.0{path}", set()
        while url:
            if url in seen:
                raise HttpError(None, f"Paging loop on {path}")
            seen.add(url)
            if not url.startswith(self.graph + "/"):
                raise HttpError(None, "Refusing to follow a paging link outside Microsoft Graph")
            body = self.authed_json(url, params)
            params = None
            yield from as_list(get(body, "value"))
            url = (body or {}).get("@odata.nextLink")

    def test(self) -> dict:
        org = next(iter(self.paged("/organization", {"$select": "id,displayName"})), {})
        return {"ok": True, "detail": f"Connected to tenant {org.get('displayName') or self.tenant}"}

    def collect(self, snap, files=None) -> None:
        def organization():
            org = next(iter(self.paged("/organization")), {})
            return snap.put_obj("organization", {"id": org.get("id"), "displayName": org.get("displayName"),
                                                 "onPremisesSyncEnabled": org.get("onPremisesSyncEnabled"),
                                                 "onPremisesLastSyncDateTime": org.get("onPremisesLastSyncDateTime")})

        snap.step("organization", organization)
        snap.step("domains", lambda: snap.put("domains", ({k: d.get(k) for k in ("id", "authenticationType", "isDefault", "isVerified")} for d in self.paged("/domains"))))
        snap.step("users", lambda: snap.put("users", self.paged("/users", {
            "$select": "id,userPrincipalName,mail,onPremisesImmutableId,onPremisesSyncEnabled,accountEnabled,userType", "$top": 999})))
        snap.step("applicationTemplates", lambda: snap.put("applicationTemplates", (
            {k: t.get(k) for k in ("id", "displayName", "categories", "supportedSingleSignOnModes", "supportedProvisioningTypes")}
            for t in self.paged("/applicationTemplates", {"$top": 999}))))
        snap.step("servicePrincipals", lambda: snap.put("servicePrincipals", (
            {k: s.get(k) for k in ("id", "displayName", "appId", "preferredSingleSignOnMode", "accountEnabled")}
            for s in self.paged("/servicePrincipals", {"$filter": "tags/any(t:t eq 'WindowsAzureActiveDirectoryIntegratedApp')",
                                                        "$select": "id,displayName,appId,preferredSingleSignOnMode,accountEnabled", "$top": 999}))))
        snap.step("conditionalAccessPolicies", lambda: snap.put("conditionalAccessPolicies", (
            {"displayName": p.get("displayName"), "state": p.get("state")} for p in self.paged("/identity/conditionalAccess/policies"))), optional=True)
        self.finish(snap)
