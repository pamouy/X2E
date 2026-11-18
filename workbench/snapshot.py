"""A snapshot: what one collector read from one platform in one run."""
from __future__ import annotations

import json
from typing import Any, Callable, Iterable

from . import __version__
from .core import iso, redact, utcnow
from .httpc import HttpError
from .vault import sha256


class Snapshot:
    def __init__(self, platform: str, source: str, options: dict | None = None,
                 progress: Callable[[str], None] | None = None):
        self.platform = platform
        self.source = source
        self.options = dict(options or {})
        self.started = utcnow()
        self.data: dict[str, Any] = {}
        self.counts: dict[str, int | None] = {}
        self.errors: list[dict] = []
        self.not_available: list[dict] = []
        self._redactions = [0]
        self._progress = progress or (lambda msg: None)
        self.requests = 0
        self.throttles = 0
        self.manifest: dict | None = None

    # ---- collecting ----------------------------------------------------------------------------
    def step(self, name: str, action: Callable[[], int | None], optional: bool = False) -> None:
        """Run one collection step. A failure never stops the run: it is recorded.
        An optional step that the platform refuses (403/404) is 'not available', not an error."""
        self._progress(name)
        try:
            n = action()
            self.counts[name] = n if n is not None else 1
        except HttpError as exc:
            if str(exc) == "Cancelled":
                raise
            self.data.pop(name, None)
            self.counts[name] = None
            if optional and exc.status in (403, 404):
                self.not_available.append({"step": name, "status": exc.status})
            else:
                self.errors.append({"step": name, "status": exc.status, "message": str(exc)})
        except Exception as exc:  # a parsing surprise must not lose the rest of the snapshot
            self.data.pop(name, None)
            self.counts[name] = None
            self.errors.append({"step": name, "status": None, "message": f"{type(exc).__name__}: {exc}"})

    def put(self, name: str, items: Iterable[Any], protect: bool = False) -> int:
        rows = []
        for item in items:
            if protect:
                redact(item, self._redactions)
            rows.append(item)
        self.data[name] = rows
        return len(rows)

    def put_obj(self, name: str, obj: Any, protect: bool = False) -> int:
        if protect:
            redact(obj, self._redactions)
        self.data[name] = obj
        return 1

    def add_error(self, step: str, status: int | None, message: str) -> None:
        self.errors.append({"step": step, "status": status, "message": message})

    # ---- reading -------------------------------------------------------------------------------
    def has(self, name: str) -> bool:
        return name in self.data

    def rows(self, name: str) -> list:
        value = self.data.get(name)
        return value if isinstance(value, list) else []

    def obj(self, name: str) -> dict:
        value = self.data.get(name)
        return value if isinstance(value, dict) else {}

    # ---- sealing -------------------------------------------------------------------------------
    def serialise(self) -> dict[str, bytes]:
        return {name: json.dumps(value, separators=(",", ":"), default=str).encode("utf-8") for name, value in self.data.items()}

    def complete(self, payloads: dict[str, bytes]) -> dict:
        finished = utcnow()
        self.manifest = {
            "tool": "Entra Migration Workbench", "toolVersion": __version__, "schemaVersion": 1,
            "platform": self.platform, "source": self.source,
            "collectedAtUtc": iso(self.started), "durationSeconds": int((finished - self.started).total_seconds()),
            "options": self.options, "requests": self.requests, "throttleWaits": self.throttles,
            "redactedValues": self._redactions[0], "counts": self.counts, "errors": self.errors,
            "notAvailable": self.not_available,
            "items": {name: {"bytes": len(blob), "sha256": sha256(blob)} for name, blob in sorted(payloads.items())},
        }
        return self.manifest

    @classmethod
    def restore(cls, manifest: dict, payloads: dict[str, bytes]) -> "Snapshot":
        """Rebuild a snapshot from storage. Refuses content that does not match the manifest."""
        snap = cls(manifest["platform"], manifest["source"], manifest.get("options"))
        for name, meta in manifest.get("items", {}).items():
            blob = payloads.get(name)
            if blob is None:
                raise ValueError(f"Snapshot item '{name}' is missing")
            if sha256(blob) != meta["sha256"]:
                raise ValueError(f"Snapshot item '{name}' does not match its manifest: it was changed after collection")
            snap.data[name] = json.loads(blob.decode("utf-8"))
        snap.manifest = manifest
        snap.counts = manifest.get("counts", {})
        snap.errors = manifest.get("errors", [])
        snap.not_available = manifest.get("notAvailable", [])
        from .core import parse_time
        snap.started = parse_time(manifest["collectedAtUtc"]) or utcnow()
        return snap
