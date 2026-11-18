"""What every connector has in common."""
from __future__ import annotations

import time
from typing import Any

from ..httpc import HttpError, ReadOnlyClient, public_mode


def field(name: str, label: str, kind: str = "text", required: bool = False, default: Any = None, help: str = "",
          options: list | None = None, group: str = "") -> dict:
    """One input of a connector form. kind: text, secret, textarea-secret, number, bool, select."""
    return dict(name=name, label=label, kind=kind, required=required, default=default, help=help, options=options or [], group=group)


class ConnectorError(Exception):
    pass


class BaseConnector:
    PLATFORM = ""
    LABEL = ""
    ROLE = "source"
    FIELDS: list[dict] = []
    PERMISSIONS = ""          # shown in the UI: the read-only access the connector needs

    def __init__(self, cfg: dict):
        self.cfg = {f["name"]: cfg.get(f["name"], f["default"]) for f in self.FIELDS}
        for f in self.FIELDS:
            v = self.cfg.get(f["name"])
            if f["kind"] == "number" and v not in (None, ""):
                self.cfg[f["name"]] = int(v)
            if f["kind"] == "bool":
                self.cfg[f["name"]] = v in (True, "true", "True", 1, "1", "on")
        missing = [f["label"] for f in self.FIELDS if f["required"] and self.cfg.get(f["name"]) in (None, "")]
        if missing:
            raise ConnectorError("Missing: " + ", ".join(missing))
        self.http: ReadOnlyClient | None = None
        self._token: str | None = None
        self._expires = 0.0

    # helpers for subclasses -----------------------------------------------------------------
    def client(self, bases: list[str]) -> ReadOnlyClient:
        verify: bool | str = True
        if self.cfg.get("skipTlsVerify"):
            verify = False
        elif self.cfg.get("caBundle"):
            verify = self.cfg["caBundle"]
        self.http = ReadOnlyClient(bases, allow_insecure=bool(self.cfg.get("allowInsecure")) and not public_mode(), verify=verify)
        return self.http

    def bearer(self) -> dict:
        if not self._token or time.time() >= self._expires:
            self._token, ttl = self.fetch_token()
            self._expires = time.time() + max(5, ttl)
        return {"Authorization": f"Bearer {self._token}", "Accept": "application/json"}

    def fetch_token(self) -> tuple[str, int]:
        raise NotImplementedError

    def authed_json(self, url: str, params: dict | None = None):
        """GET with the bearer token; one silent token refresh on 401."""
        try:
            return self.http.get_json(url, self.bearer(), params)
        except HttpError as exc:
            if exc.status != 401:
                raise
            self._token = None
            return self.http.get_json(url, self.bearer(), params)

    def authed(self, url: str, params: dict | None = None):
        try:
            return self.http.get(url, self.bearer(), params)
        except HttpError as exc:
            if exc.status != 401:
                raise
            self._token = None
            return self.http.get(url, self.bearer(), params)

    # interface ---------------------------------------------------------------------------------
    def source_name(self) -> str:
        raise NotImplementedError

    def test(self) -> dict:
        """Authenticate and read one harmless object. Returns {'ok': True, 'detail': '...'}."""
        raise NotImplementedError

    def collect(self, snap, files: list[tuple[str, bytes]] | None = None) -> None:
        raise NotImplementedError

    def finish(self, snap) -> None:
        if self.http:
            snap.requests = self.http.requests
            snap.throttles = self.http.throttles
