"""Connector registry: five source platforms and the Entra target."""
from . import entra, keycloak, okta, onelogin, pingfederate, pingone

MODULES = {m.Connector.PLATFORM: m for m in (okta, keycloak, pingfederate, pingone, onelogin, entra)}
SOURCES = [p for p, m in MODULES.items() if m.Connector.ROLE == "source"]


def describe() -> list[dict]:
    out = []
    for platform, mod in MODULES.items():
        c = mod.Connector
        out.append({"platform": platform, "label": c.LABEL, "role": c.ROLE, "fields": c.FIELDS, "permissions": c.PERMISSIONS,
                    "acceptsFiles": bool(getattr(c, "ACCEPTS_FILES", False))})
    return out


def secret_fields(platform: str) -> set[str]:
    return {f["name"] for f in MODULES[platform].Connector.FIELDS if f["kind"] in ("secret", "textarea-secret")}
