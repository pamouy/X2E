"""Shared helpers: safe lookups, redaction, the platform-neutral inventory model."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

SECRET_KEY = re.compile(r"(?i)(secret|password|privatekey|sharedsecret|apitoken|passphrase|credential|encryptedvalue)$")
REDACTED = "[REDACTED]"


def get(obj: Any, path: str, default: Any = None) -> Any:
    """Nested read ('a.b.c') that never raises."""
    cur = obj
    for key in path.split("."):
        if isinstance(cur, dict):
            cur = cur.get(key)
        else:
            return default
        if cur is None:
            return default
    return cur


def as_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def norm_name(name: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(name or "").lower())


def redact(obj: Any, counter: list[int] | None = None) -> Any:
    """Replace credential material by a marker, recursively and in place."""
    if isinstance(obj, dict):
        for k in list(obj.keys()):
            v = obj[k]
            if v is None:
                continue
            if SECRET_KEY.search(str(k)) and not isinstance(v, bool):
                obj[k] = REDACTED
                if counter is not None:
                    counter[0] += 1
            elif k == "authScheme" and isinstance(v, dict) and v.get("value") is not None:
                v["value"] = REDACTED          # Okta hook channel credential
                if counter is not None:
                    counter[0] += 1
                redact(v, counter)
            else:
                redact(v, counter)
    elif isinstance(obj, list):
        for item in obj:
            redact(item, counter)
    return obj


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime | None) -> str | None:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if dt else None


def parse_time(value: Any) -> datetime | None:
    """Parse the timestamp formats the five platforms return. None when not parseable."""
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        secs = value / 1000 if value > 1e11 else value
        return datetime.fromtimestamp(secs, timezone.utc)
    s = str(value).strip()
    s = re.sub(r",\d+$", "", s)
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    s = re.sub(r"(\.\d{6})\d+", r"\1", s)
    for candidate in (s, s.replace(" ", "T", 1)):
        try:
            dt = datetime.fromisoformat(candidate)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


# ---- inventory rows -----------------------------------------------------------------------------

APP_DEFAULTS = dict(
    id=None, label="", pattern="Other", kind="", status="ACTIVE", isPlatform=False, isMachine=False,
    signIns=None, distinctUsers=None, lastSignIn=None, assignedUsers=None, directAssignments=None,
    provisioning="None", complexClaims=0, groupClaims=0, customNameId=False, encrypted=False,
    usesClientSecret=False, owner=None, policy=None, flags=None, notes=None, catalogHint=None,
)

ROW_TEMPLATES = {
    "policy": dict(policyType="", policy="", rule="", status="ACTIVE", conditions="", access="ALLOW", authentication="",
                   session="", conditionalAccessBuildingBlocks="", reviewNote=""),
    "mfa": dict(method="", key="", status="ACTIVE", entraTarget="", migrationClass="User action"),
    "groupRule": dict(rule="", status="ACTIVE", expression="", target="", translation="Manual",
                      suggestedDynamicMembershipRule="", reviewNote=""),
    "automation": dict(kind="", name="", status="ACTIVE", detail="", owner="", migrationClass="Rebuild", entraTarget=""),
    "api": dict(name="", status="ACTIVE", detail="", migrationClass="Rebuild", note=""),
    "federation": dict(name="", type="", status="ACTIVE", detail=""),
    "userStore": dict(name="", type="", detail="", entraTarget="", migrationClass="Rebuild"),
    "manualCheck": dict(item="", why="", where=""),
    "zone": dict(zone="", type="", usage="", status="ACTIVE", entries=0, usedByRules=0, entraTarget=""),
    "user": dict(id=None, login=None, email=None, status="ACTIVE", source="", localPassword=False, lastLogin=None),
}


def new_app(**values: Any) -> dict:
    row = dict(APP_DEFAULTS)
    for k, v in values.items():
        if k not in row:
            raise KeyError(f"Unknown app property '{k}'")
        row[k] = v
    row["flags"] = list(row["flags"] or [])
    row["notes"] = [n for n in (row["notes"] or []) if n]
    row["id"] = None if row["id"] is None else str(row["id"])
    return row


def new_row(table: str, /, **values: Any) -> dict:
    row = dict(ROW_TEMPLATES[table])
    for k, v in values.items():
        if k not in row:
            raise KeyError(f"Unknown {table} column '{k}'")
        row[k] = v
    return row


def finding(fid: str, severity: str, area: str, title: str, count: Any, evidence: str, recommendation: str, phase: str) -> dict:
    assert severity in ("Blocker", "High", "Medium", "Info")
    return dict(id=fid, severity=severity, area=area, title=title, count=count, evidence=str(evidence or ""),
                recommendation=recommendation, phase=phase)


def dynamic_rule(attribute: str, value: str, config: dict) -> dict:
    """Suggest an Entra dynamic membership rule for a single 'attribute equals value' condition."""
    amap = config.get("attributeMap", {})
    if attribute and attribute in amap:
        return dict(translation="Auto", rule=f'(user.{amap[attribute]} -eq "{value}")', note="")
    return dict(translation="Manual", rule="", note=f"Attribute '{attribute}' has no mapped Entra attribute; likely an extension attribute")


def new_inventory(platform: str, org: str) -> dict:
    return dict(platform=platform, orgName=org, usersKnown=True, usersNote="", lastLoginKnown=False, staleActiveEstimate=None,
                users=[], factorSummary=None, usageKnown=False, usageDays=None, usageNote="", apps=[], apis=[], policies=[],
                zones=[], mfaMethods=[], groupRules=[], automations=[], federation=[], userStores=[], manualChecks=[],
                findings=[], m365Federated=False, stateEvidence=[])


DEFAULT_SCORING = {
    "staleDays": 90, "criticalUserShare": 0.25, "directAssignmentThreshold": 10, "localPasswordShareForStateC": 0.5,
    "patternBase": {"SAML": 2, "OIDC": 3, "SWA": 3, "Bookmark": 1, "SAML 1.1": 4, "WS-Fed": 4, "RADIUS": 5, "Provisioning": 2, "Other": 4},
    "modifiers": {"galleryExact": -1, "provisioningOutbound": 2, "provisioningInbound": 2, "complexClaimsFew": 1, "complexClaimsMany": 2,
                  "complexClaimsManyFrom": 3, "groupClaims": 1, "customNameId": 1, "encryptedAssertion": 1, "manyDirectAssignments": 1},
    "flagScores": {"password-grant": 2, "custom-mapper": 1, "directory-lookup": 2, "ws-trust": 3, "uma-authorization": 3,
                   "header-based": 1, "implicit-flow": 0},
    "tiers": {"lowMax": 2, "mediumMax": 4},
    "effortDays": {"calibrated": False, "Low": 0.5, "Medium": 1.5, "High": 4.0},
    "attributeMap": {"department": "department", "title": "jobTitle", "city": "city", "state": "state", "country": "country",
                     "countryCode": "country", "company": "companyName", "organization": "companyName",
                     "employeeNumber": "employeeId", "userType": "employeeType"},
}
