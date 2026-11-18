"""Read-only HTTP client used by every collector.

Guarantees enforced here, not left to each collector:
  * only GET requests reach a platform API; the single exception is token(), a POST to a token endpoint;
  * requests go only to the base URLs the connector was configured with, so a paging link that points
    elsewhere cannot carry credentials to another host;
  * https is required unless the connector explicitly allows http (lab use);
  * 429 and 5xx are retried with the platform's own back-off headers.
"""
from __future__ import annotations

import ipaddress
import os
import socket
import time
from typing import Any
from urllib.parse import urlsplit

import requests


class HttpError(Exception):
    def __init__(self, status: int | None, message: str, url: str = ""):
        super().__init__(message)
        self.status = status
        self.url = url


def public_mode() -> bool:
    """True when the application is reachable from the internet (Vercel, or WORKBENCH_PUBLIC=1). Connectors then
    refuse plain http and any host that resolves to a private, loopback or link-local address, so a signed-in
    user cannot make the server call into its own network or a cloud metadata service."""
    return bool(os.environ.get("VERCEL")) or os.environ.get("WORKBENCH_PUBLIC") == "1"


def check_public_host(base: str) -> None:
    parts = urlsplit(base)
    if parts.scheme != "https":
        raise HttpError(None, f"{base} must use https on a public deployment")
    try:
        infos = socket.getaddrinfo(parts.hostname, parts.port or 443, proto=socket.IPPROTO_TCP)
    except OSError as exc:
        raise HttpError(None, f"Cannot resolve {parts.hostname}") from exc
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            raise HttpError(None, f"{parts.hostname} resolves to a non-public address. A public deployment cannot reach systems on a private network")


class ReadOnlyClient:
    def __init__(self, allowed_bases: list[str], allow_insecure: bool = False, verify: bool | str = True,
                 timeout: int = 60, max_retries: int = 5, user_agent: str = "EntraMigrationWorkbench/0.1"):
        self.allowed = [b.rstrip("/") for b in allowed_bases if b]
        for base in self.allowed:
            scheme = urlsplit(base).scheme
            if scheme not in ("https", "http"):
                raise HttpError(None, f"Not a URL: {base}")
            if scheme != "https" and not allow_insecure:
                raise HttpError(None, f"{base} must use https (or tick 'Allow http' for a lab)")
        if public_mode():
            for base in self.allowed:
                check_public_host(base)
        self.verify = verify
        self.timeout = timeout
        self.max_retries = max_retries
        self.session = requests.Session()
        self.session.headers["User-Agent"] = user_agent
        self.requests = 0
        self.throttles = 0
        self.cancelled = lambda: False

    def _check(self, url: str) -> None:
        if not any(url == b or url.startswith(b + "/") or url.startswith(b + "?") for b in self.allowed):
            raise HttpError(None, f"Refusing to send a request outside the configured host: {url.split('?')[0]}", url)

    def _send(self, method: str, url: str, **kw) -> requests.Response:
        self._check(url)
        attempt = 0
        while True:
            if self.cancelled():
                raise HttpError(None, "Cancelled")
            self.requests += 1
            try:
                resp = self.session.request(method, url, timeout=self.timeout, verify=self.verify, allow_redirects=False, **kw)
            except requests.RequestException as exc:
                attempt += 1
                if attempt > self.max_retries:
                    raise HttpError(None, f"Network error: {type(exc).__name__}: {exc}", url) from exc
                time.sleep(min(2 ** attempt, 20))
                continue
            if resp.status_code == 429 or resp.status_code >= 500:
                attempt += 1
                if attempt > self.max_retries:
                    raise HttpError(resp.status_code, f"HTTP {resp.status_code} after {self.max_retries} retries", url)
                self.throttles += 1
                time.sleep(self._backoff(resp, attempt))
                continue
            if resp.status_code >= 400:
                raise HttpError(resp.status_code, f"HTTP {resp.status_code}: {_error_text(resp)}", url)
            if 300 <= resp.status_code < 400:
                raise HttpError(resp.status_code, f"HTTP {resp.status_code}: unexpected redirect (check the base URL)", url)
            return resp

    @staticmethod
    def _backoff(resp: requests.Response, attempt: int) -> float:
        h = resp.headers
        try:
            if h.get("Retry-After"):
                return min(float(h["Retry-After"]), 120)
            if h.get("X-Rate-Limit-Reset"):                       # Okta: epoch seconds
                return max(0.5, min(float(h["X-Rate-Limit-Reset"]) - time.time() + 1, 120))
            if h.get("X-RateLimit-Reset"):                        # OneLogin: seconds until reset
                return max(0.5, min(float(h["X-RateLimit-Reset"]), 120))
        except ValueError:
            pass
        return min(2 ** attempt, 30)

    def get(self, url: str, headers: dict | None = None, params: dict | None = None) -> requests.Response:
        return self._send("GET", url, headers=headers or {}, params=params)

    def get_json(self, url: str, headers: dict | None = None, params: dict | None = None) -> Any:
        resp = self.get(url, headers, params)
        if not resp.content:
            return None
        try:
            return resp.json()
        except ValueError as exc:
            raise HttpError(resp.status_code, "The answer is not JSON (check the base URL)", url) from exc

    def token(self, url: str, data: Any = None, json_body: Any = None, headers: dict | None = None) -> dict:
        """The only POST this client can send: an OAuth token request."""
        resp = self._send("POST", url, data=data, json=json_body, headers=headers or {})
        try:
            body = resp.json()
        except ValueError as exc:
            raise HttpError(resp.status_code, "The token endpoint did not answer with JSON", url) from exc
        if not isinstance(body, dict) or not body.get("access_token"):
            raise HttpError(resp.status_code, "The token endpoint returned no access token", url)
        return body


def _error_text(resp: requests.Response) -> str:
    try:
        body = resp.json()
        if isinstance(body, dict):
            for key in ("errorSummary", "error_description", "message", "error", "errorMessage"):
                val = body.get(key)
                if isinstance(val, dict):
                    val = val.get("message") or val.get("code")
                if val:
                    return str(val)[:300]
            status = body.get("status")
            if isinstance(status, dict) and status.get("message"):
                return str(status["message"])[:300]
    except ValueError:
        pass
    return (resp.reason or "error")[:300]
