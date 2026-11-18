"""Application logic: vault state, projects, connectors, collection runs, analyses."""
from __future__ import annotations

import base64
import contextvars
import gzip
import hashlib
import io
import json

import os
import re
import secrets
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

from . import report, vault
from .analyzer import analyse
from .collectors import MODULES, secret_fields
from .collectors.base import ConnectorError
from .core import DEFAULT_SCORING, iso, utcnow
from .httpc import HttpError
from .snapshot import Snapshot
from .store import open_store

GATES = [("G1", "Assess", "End state and scope decided"), ("G2", "Design", "Design accepted; every blocker has an owner and a decision"),
         ("G3", "Foundation", "Baseline tests green; no report-only policy would block a pilot user"),
         ("G4", "Pilot", "Pilot criteria met; one rollback performed"), ("G5", "Waves", "Every wave closed by its application owners"),
         ("G6", "Cutover", "No sign-in on the old platform for the agreed period")]
TRACK_STATUS = ["Not started", "In progress", "Switched", "Validated", "Retired", "Blocked"]
PARITY = ["", "Equivalent", "Raised", "Dropped", "Open"]
KEEP_SNAPSHOTS = 5
MAX_UPLOAD = 200 * 1024 * 1024
MAX_UNPACKED = 400 * 1024 * 1024
RUN_SILENCE = int(os.environ.get("WORKBENCH_RUN_SILENCE", "900"))      # seconds without a sign of life before a run is closed
_KEK: contextvars.ContextVar = contextvars.ContextVar("workbench_kek", default=None)


def set_request_kek(kek: bytes | None) -> None:
    """The vault key of the current request (taken from its session cookie). Never stored on the server."""
    _KEK.set(kek)
SESSION_IDLE = 30 * 60
SESSION_MAX = 12 * 3600


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def _id() -> str:
    return uuid.uuid4().hex[:16]


class Workbench:
    def __init__(self, data_dir: str | None = None, workers: int = 4, store=None, session_secret: str | None = None, threaded: bool = True):
        self.store = store or open_store(data_dir)
        self.threaded = threaded
        # Sessions are stateless: the cookie carries the vault key, sealed with this secret. Self-hosted, a random
        # secret per process is enough (a restart seals everything). Serverless, every instance needs the same one.
        self._secret = hashlib.sha256(session_secret.encode("utf-8")).digest() if session_secret else os.urandom(32)
        self._lock = threading.RLock()
        self._pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="run") if threaded else None
        self._analysis_locks: dict[str, threading.Lock] = {}
        if threaded:        # one process owns the database: whatever was in flight when it stopped can never finish
            self.store.execute("UPDATE runs SET status='interrupted', finished=? WHERE status IN ('queued','running')", (iso(utcnow()),))

    @property
    def _kek(self) -> bytes | None:
        return _KEK.get()

    def _epoch(self) -> int:
        raw = self.store.meta_get("epoch")
        return int(raw.decode()) if raw else 0

    def _issue(self, kek: bytes, created: int | None = None) -> str:
        now = int(time.time())
        body = {"k": base64.b64encode(kek).decode(), "c": created or now, "s": now, "e": self._epoch()}
        return base64.urlsafe_b64encode(vault.seal(self._secret, json.dumps(body).encode(), "session")).decode()

    def open_session(self, token: str | None) -> tuple[bytes, str] | None:
        """Check a session cookie. Returns the vault key it carries and a refreshed cookie, or None."""
        if not token:
            return None
        try:
            body = json.loads(vault.unseal(self._secret, base64.urlsafe_b64decode(token.encode()), "session"))
            kek = base64.b64decode(body["k"])
            now = time.time()
            if now - body["s"] > SESSION_IDLE or now - body["c"] > SESSION_MAX or body["e"] != self._epoch():
                return None
        except Exception:
            return None
        return kek, self._issue(kek, body["c"])

    def _reap(self) -> None:
        """A run whose worker died (function timeout, crash) never reports back: close it after a silence."""
        cut = iso(utcnow() - timedelta(seconds=RUN_SILENCE))
        self.store.execute("UPDATE runs SET status='interrupted', finished=?, step='' WHERE status IN ('queued','running') AND COALESCE(heartbeat, started) < ?",
                           (iso(utcnow()), cut))

    def _active(self, column: str, value: str) -> bool:
        assert column in ("project_id", "connector_id")
        self._reap()
        return self.store.one(f"SELECT id FROM runs WHERE {column}=? AND status IN ('queued','running') LIMIT 1", (value,)) is not None

    def execute_run(self, rid: str) -> dict:
        """Run a queued collection inside this request. In serverless mode the browser calls this right after queuing."""
        row = self.store.one("SELECT project_id FROM runs WHERE id=?", (rid,))
        if not row:
            raise ApiError(404, "No such run")
        key = self._key(row["project_id"])
        self._execute(rid, key)
        return self.run(rid)

    def _execute(self, rid: str, key: bytes) -> None:
        # the claim is atomic: of several workers that try, exactly one gets the run
        if self.store.execute("UPDATE runs SET status='running', heartbeat=? WHERE id=? AND status='queued'", (iso(utcnow()), rid)) == 1:
            self._run(rid, key)

    def _analyse_after(self, pid: str, cid: str, role: str, rid: str, key: bytes) -> None:
        if role == "target":
            self.analyse_project(pid, key)
        else:
            self.analyse_connector(pid, cid, key)

    # ---- vault and sessions ---------------------------------------------------------------------
    @property
    def initialised(self) -> bool:
        return self.store.meta_get("verifier") is not None


    @staticmethod
    def _check_passphrase(p: str) -> None:
        if not isinstance(p, str) or len(p) < 12:
            raise ApiError(400, "The passphrase needs at least 12 characters")

    def setup(self, passphrase: str) -> str:
        with self._lock:
            if self.initialised:
                raise ApiError(409, "Already set up")
            self._check_passphrase(passphrase)
            salt = os.urandom(16)
            kek = vault.derive_kek(passphrase, salt)
            self.store.meta_set("salt", salt)
            self.store.meta_set("verifier", vault.new_verifier(kek))
            set_request_kek(kek)
            self.audit(None, "vault.setup", "")
            return self._issue(kek)

    def login(self, passphrase: str) -> str:
        if not self.initialised:
            raise ApiError(409, "Not set up yet")
        now = time.time()
        raw = self.store.meta_get("fail")                 # kept in the database: it must hold across instances
        count, until = (int(raw.decode().split(":")[0]), float(raw.decode().split(":")[1])) if raw else (0, 0.0)
        if now < until:
            raise ApiError(429, f"Too many failed attempts. Try again in {int(until - now) + 1} s")
        kek = vault.derive_kek(str(passphrase or ""), self.store.meta_get("salt"))
        if not vault.check_verifier(kek, self.store.meta_get("verifier")):
            count += 1
            until = now + min(900, 30 * 2 ** (count - 5)) if count >= 5 else 0.0
            self.store.meta_set("fail", f"{count}:{until}".encode())
            self.audit(None, "login.failed", "")
            raise ApiError(401, "Wrong passphrase")
        if count:
            self.store.meta_set("fail", b"0:0")
        set_request_kek(kek)
        self.audit(None, "login", "")
        return self._issue(kek)

    def _new_session(self) -> str:
        return self._issue(self._kek)

    def session_ok(self, token: str | None) -> bool:
        return self.open_session(token) is not None

    def logout(self, token: str | None) -> None:
        """Sessions are stateless: signing out is the browser dropping its cookie."""

    def lock(self) -> None:
        """Invalidate every session everywhere. Collections that are already running keep their key until they end."""
        self.store.meta_set("epoch", str(self._epoch() + 1).encode())
        self.audit(None, "vault.lock", "")

    def change_passphrase(self, current: str, new: str) -> str:
        with self._lock:
            kek = vault.derive_kek(str(current or ""), self.store.meta_get("salt"))
            if not vault.check_verifier(kek, self.store.meta_get("verifier")):
                raise ApiError(401, "Wrong current passphrase")
            self._check_passphrase(new)
            salt = os.urandom(16)
            new_kek = vault.derive_kek(new, salt)
            stmts = [("INSERT INTO meta(key,value) VALUES('salt',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (salt,)),
                     ("INSERT INTO meta(key,value) VALUES('verifier',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (vault.new_verifier(new_kek),))]
            for row in self.store.all("SELECT id, wrapped_key FROM projects"):
                key = vault.unwrap_key(kek, row["id"], bytes(row["wrapped_key"]))
                stmts.append(("UPDATE projects SET wrapped_key=? WHERE id=?", (vault.wrap_key(new_kek, row["id"], key), row["id"])))
            self.store.transaction(stmts)
            self.store.meta_set("epoch", str(self._epoch() + 1).encode())      # every other session held the old key
            set_request_kek(new_kek)
            self.audit(None, "vault.passphrase-changed", "")
            return self._issue(new_kek)

    def audit(self, project_id: str | None, action: str, detail: str) -> None:
        self.store.execute("INSERT INTO audit(ts, project_id, action, detail) VALUES(?,?,?,?)", (iso(utcnow()), project_id, action, detail[:500]))

    # ---- projects -------------------------------------------------------------------------------
    def _key(self, project_id: str) -> bytes:
        row = self.store.one("SELECT wrapped_key FROM projects WHERE id=?", (project_id,))
        if not row:
            raise ApiError(404, "No such project")
        if self._kek is None:
            raise ApiError(401, "Locked")
        return vault.unwrap_key(self._kek, project_id, row["wrapped_key"])

    def _meta(self, project_id: str, key: bytes | None = None) -> dict:
        row = self.store.one("SELECT enc_meta, created FROM projects WHERE id=?", (project_id,))
        if not row:
            raise ApiError(404, "No such project")
        meta = vault.unseal_json(key or self._key(project_id), row["enc_meta"], f"{project_id}:meta")
        meta["id"], meta["created"] = project_id, row["created"]
        return meta

    def _save_meta(self, project_id: str, meta: dict, key: bytes) -> None:
        body = {k: meta.get(k) for k in ("name", "client", "description", "gates", "scoring")}
        self.store.execute("UPDATE projects SET enc_meta=? WHERE id=?", (vault.seal_json(key, body, f"{project_id}:meta"), project_id))

    def create_project(self, name: str, client: str = "", description: str = "") -> dict:
        name = str(name or "").strip()
        if not name:
            raise ApiError(400, "A project needs a name")
        pid, key = _id(), vault.new_project_key()
        meta = {"name": name[:120], "client": str(client or "")[:120], "description": str(description or "")[:2000],
                "gates": {g[0]: {"status": "Open", "signedBy": "", "date": "", "note": ""} for g in GATES}, "scoring": {}}
        self.store.execute("INSERT INTO projects(id, created, wrapped_key, enc_meta) VALUES(?,?,?,?)",
                           (pid, iso(utcnow()), vault.wrap_key(self._kek, pid, key), vault.seal_json(key, meta, f"{pid}:meta")))
        self.audit(pid, "project.created", "")
        return self.project(pid)

    def update_project(self, pid: str, patch: dict) -> dict:
        key = self._key(pid)
        meta = self._meta(pid, key)
        for k in ("name", "client", "description"):
            if k in patch:
                meta[k] = str(patch[k] or "")[:2000 if k == "description" else 120]
        if not meta["name"].strip():
            raise ApiError(400, "A project needs a name")
        if isinstance(patch.get("gates"), dict):
            for g, val in patch["gates"].items():
                if g in meta["gates"] and isinstance(val, dict):
                    status = val.get("status", meta["gates"][g]["status"])
                    if status not in ("Open", "Passed", "Passed with conditions", "Stopped"):
                        raise ApiError(400, "Unknown gate status")
                    meta["gates"][g] = {"status": status, "signedBy": str(val.get("signedBy", ""))[:120], "date": str(val.get("date", ""))[:20],
                                        "note": str(val.get("note", ""))[:1000]}
                    self.audit(pid, "gate.updated", f"{g}: {status}")
        rescore = False
        if "scoring" in patch:
            if not isinstance(patch["scoring"], dict):
                raise ApiError(400, "Scoring must be an object")
            _validate_scoring(patch["scoring"])
            meta["scoring"] = patch["scoring"]
            rescore = True
            self.audit(pid, "scoring.updated", "")
        self._save_meta(pid, meta, key)
        if rescore:
            self.analyse_project(pid)
        return self.project(pid)

    def delete_project(self, pid: str, confirm: str) -> None:
        meta = self._meta(pid)
        if confirm != meta["name"]:
            raise ApiError(400, "Type the project name to confirm")
        if self._active("project_id", pid):
            raise ApiError(409, "A collection is running in this project")
        self.store.delete_project(pid)
        self.audit(pid, "project.deleted", "data key destroyed")

    def projects(self) -> list[dict]:
        out = []
        for row in self.store.all("SELECT id FROM projects ORDER BY created DESC"):
            pid = row["id"]
            key = self._key(pid)
            meta = self._meta(pid, key)
            sources = self.store.all("SELECT id, platform FROM connectors WHERE project_id=? AND role='source'", (pid,))
            target = self.store.one("SELECT id FROM connectors WHERE project_id=? AND role='target'", (pid,))
            summaries = []
            for a in self.store.all("SELECT connector_id, enc_data FROM analyses WHERE project_id=?", (pid,)):
                s = vault.unseal_json(key, a["enc_data"], f"{pid}:analysis:{a['connector_id']}")["summary"]
                summaries.append({k: s.get(k) for k in ("platform", "state", "blockers", "high", "appsToMigrate", "appsToRetire", "collectedAt")})
            running = self.store.one("SELECT count(*) AS n FROM runs WHERE project_id=? AND status IN ('queued','running')", (pid,))["n"]
            gate = next((g[0] for g in GATES if meta["gates"][g[0]]["status"] not in ("Passed", "Passed with conditions")), "Done")
            out.append({"id": pid, "name": meta["name"], "client": meta["client"], "created": meta["created"], "platforms": [s["platform"] for s in sources],
                        "hasTarget": bool(target), "analyses": summaries, "running": running, "nextGate": gate})
        return out

    def project(self, pid: str) -> dict:
        key = self._key(pid)
        meta = self._meta(pid, key)
        meta["scoringDefaults"] = DEFAULT_SCORING
        meta["gateDefinitions"] = [{"id": g[0], "phase": g[1], "criterion": g[2]} for g in GATES]
        meta["connectors"] = [self._connector_view(pid, r, key) for r in self.store.all("SELECT * FROM connectors WHERE project_id=? ORDER BY role, created", (pid,))]
        meta["runs"] = self.runs(pid, limit=30)
        return meta

    # ---- connectors -----------------------------------------------------------------------------
    def _connector_row(self, pid: str, cid: str):
        row = self.store.one("SELECT * FROM connectors WHERE id=? AND project_id=?", (cid, pid))
        if not row:
            raise ApiError(404, "No such connector")
        return row

    def _connector_cfg(self, pid: str, row, key: bytes) -> dict:
        return vault.unseal_json(key, row["enc_config"], f"{pid}:connector:{row['id']}")

    def _connector_view(self, pid: str, row, key: bytes) -> dict:
        cfg = self._connector_cfg(pid, row, key)
        secret = secret_fields(row["platform"])
        shown = {k: ({"set": bool(v)} if k in secret else v) for k, v in cfg["config"].items()}
        last = self.store.one("SELECT id, status, started, finished FROM runs WHERE connector_id=? ORDER BY started DESC LIMIT 1", (row["id"],))
        analysis = self.store.one("SELECT created, run_id FROM analyses WHERE connector_id=?", (row["id"],))
        files = [{"id": f["id"], "name": vault.unseal(key, f["enc_name"], f"{pid}:file-name:{f['id']}").decode(), "size": f["size"], "created": f["created"]}
                 for f in self.store.all("SELECT id, enc_name, size, created FROM files WHERE connector_id=? ORDER BY created", (row["id"],))]
        return {"id": row["id"], "platform": row["platform"], "label": MODULES[row["platform"]].Connector.LABEL, "role": row["role"], "name": cfg["name"],
                "config": shown, "lastRun": dict(last) if last else None, "analysedAt": analysis["created"] if analysis else None, "files": files}

    def _clean_config(self, platform: str, config: dict, previous: dict | None = None) -> dict:
        mod = MODULES[platform]
        out = {}
        for f in mod.Connector.FIELDS:
            name = f["name"]
            v = config.get(name)
            if f["kind"] in ("secret", "textarea-secret"):
                if isinstance(v, dict) or v in (None, ""):      # untouched in the form: keep what is stored
                    v = (previous or {}).get(name)
            elif v is None:
                v = (previous or {}).get(name, f["default"])
            if isinstance(v, str):
                v = v.strip() if f["kind"] != "textarea-secret" else v.strip() + "\n"
            out[name] = v
        try:
            mod.Connector(out)       # validates required fields and URL rules without any network call
        except (ConnectorError, HttpError, ValueError) as exc:
            raise ApiError(400, str(exc)) from exc
        return out

    def add_connector(self, pid: str, platform: str, name: str, config: dict) -> dict:
        if platform not in MODULES:
            raise ApiError(400, "Unknown platform")
        key = self._key(pid)
        role = MODULES[platform].Connector.ROLE
        if role == "target" and self.store.one("SELECT id FROM connectors WHERE project_id=? AND role='target'", (pid,)):
            raise ApiError(409, "This project already has a target tenant")
        cid = _id()
        body = {"name": str(name or MODULES[platform].Connector.LABEL)[:80], "config": self._clean_config(platform, config or {})}
        self.store.execute("INSERT INTO connectors(id, project_id, platform, role, created, enc_config) VALUES(?,?,?,?,?,?)",
                           (cid, pid, platform, role, iso(utcnow()), vault.seal_json(key, body, f"{pid}:connector:{cid}")))
        self.audit(pid, "connector.added", f"{platform} {cid}")
        return self._connector_view(pid, self._connector_row(pid, cid), key)

    def update_connector(self, pid: str, cid: str, name: str | None, config: dict | None) -> dict:
        key = self._key(pid)
        row = self._connector_row(pid, cid)
        body = self._connector_cfg(pid, row, key)
        if name is not None:
            body["name"] = str(name)[:80] or body["name"]
        if config is not None:
            body["config"] = self._clean_config(row["platform"], config, body["config"])
        self.store.execute("UPDATE connectors SET enc_config=? WHERE id=?", (vault.seal_json(key, body, f"{pid}:connector:{cid}"), cid))
        self.audit(pid, "connector.updated", f"{row['platform']} {cid}")
        return self._connector_view(pid, self._connector_row(pid, cid), key)

    def delete_connector(self, pid: str, cid: str) -> None:
        self._connector_row(pid, cid)
        if self._active("connector_id", cid):
            raise ApiError(409, "A collection is running on this connector")
        run_ids = [r["id"] for r in self.store.all("SELECT id FROM runs WHERE connector_id=?", (cid,))]
        stmts = [("DELETE FROM blobs WHERE run_id=?", (r,)) for r in run_ids]
        stmts += [("DELETE FROM runs WHERE connector_id=?", (cid,)), ("DELETE FROM analyses WHERE connector_id=?", (cid,)),
                  ("DELETE FROM files WHERE connector_id=?", (cid,)), ("DELETE FROM kv WHERE project_id=? AND key LIKE ?", (pid, f"%:{cid}")),
                  ("DELETE FROM connectors WHERE id=?", (cid,))]
        self.store.transaction(stmts)
        self.audit(pid, "connector.deleted", cid)

    def _instance(self, pid: str, cid: str, key: bytes):
        row = self._connector_row(pid, cid)
        cfg = self._connector_cfg(pid, row, key)
        try:
            return row, MODULES[row["platform"]].Connector(cfg["config"])
        except (ConnectorError, HttpError) as exc:
            raise ApiError(400, str(exc)) from exc

    def test_connector(self, pid: str, cid: str) -> dict:
        key = self._key(pid)
        row, con = self._instance(pid, cid, key)
        try:
            result = con.test()
        except (HttpError, ConnectorError) as exc:
            result = {"ok": False, "detail": str(exc)}
        except Exception as exc:
            result = {"ok": False, "detail": f"{type(exc).__name__}: {exc}"}
        self.audit(pid, "connector.tested", f"{row['platform']} {cid}: {'ok' if result['ok'] else 'failed'}")
        return result

    # ---- uploaded files (PingFederate audit logs) -----------------------------------------------
    def add_file(self, pid: str, cid: str, name: str, data: bytes) -> dict:
        key = self._key(pid)
        row = self._connector_row(pid, cid)
        if not getattr(MODULES[row["platform"]].Connector, "ACCEPTS_FILES", False):
            raise ApiError(400, "This connector does not take files")
        if len(data) > MAX_UPLOAD:
            raise ApiError(413, "File too large (200 MB at most per file)")
        fid = _id()
        safe = re.sub(r"[^A-Za-z0-9._ -]", "_", os.path.basename(name or "audit.log"))[:120] or "audit.log"
        self.store.execute("INSERT INTO files(id, project_id, connector_id, created, size, enc_name, enc_data) VALUES(?,?,?,?,?,?,?)",
                           (fid, pid, cid, iso(utcnow()), len(data), vault.seal(key, safe.encode(), f"{pid}:file-name:{fid}"),
                            vault.seal(key, data, f"{pid}:file:{fid}")))
        self.audit(pid, "file.added", f"{cid} {len(data)} bytes")
        return {"id": fid, "name": safe, "size": len(data)}

    def delete_file(self, pid: str, cid: str, fid: str) -> None:
        self._key(pid)
        self.store.execute("DELETE FROM files WHERE id=? AND connector_id=? AND project_id=?", (fid, cid, pid))
        self.audit(pid, "file.deleted", f"{cid} {fid}")

    # ---- runs -----------------------------------------------------------------------------------
    def start_collection(self, pid: str, cid: str) -> dict:
        key = self._key(pid)
        row, _con = self._instance(pid, cid, key)            # a broken configuration is refused before anything is queued
        if self._active("connector_id", cid):
            raise ApiError(409, "A collection is already running on this connector")
        rid, now = _id(), iso(utcnow())
        self.store.execute("INSERT INTO runs(id, project_id, connector_id, platform, role, status, started, heartbeat) VALUES(?,?,?,?,?,?,?,?)",
                           (rid, pid, cid, row["platform"], row["role"], "queued", now, now))
        self.audit(pid, "collection.started", f"{row['platform']} {cid} run {rid}")
        if self.threaded:
            self._pool.submit(self._execute, rid, key)
        return self.run(rid)

    def start_all(self, pid: str) -> list[dict]:
        self._key(pid)
        rows = self.store.all("SELECT id FROM connectors WHERE project_id=? ORDER BY role DESC, created", (pid,))   # target first
        if not rows:
            raise ApiError(400, "Add a connector first")
        return [self.start_collection(pid, r["id"]) for r in rows]

    def cancel_run(self, rid: str) -> None:
        row = self.store.one("SELECT project_id FROM runs WHERE id=?", (rid,))
        if not row:
            raise ApiError(404, "No such run")
        self._key(row["project_id"])
        if self.store.execute("UPDATE runs SET status='cancelled', finished=? WHERE id=? AND status='queued'", (iso(utcnow()), rid)) == 1:
            return                                           # nobody had picked it up yet
        if self.store.execute("UPDATE runs SET cancel=1 WHERE id=? AND status='running'", (rid,)) != 1:
            raise ApiError(409, "This run is not active")

    def _run(self, rid: str, key: bytes) -> None:
        row = self.store.one("SELECT * FROM runs WHERE id=?", (rid,))
        pid, cid, platform, role = row["project_id"], row["connector_id"], row["platform"], row["role"]
        steps = [0]
        tick = [0.0, 0.0, False]                            # last cancel check, last heartbeat, cancelled

        def progress(step: str) -> None:
            steps[0] += 1
            tick[1] = time.time()
            self.store.execute("UPDATE runs SET step=?, steps_done=?, heartbeat=? WHERE id=?", (step[:80], steps[0], iso(utcnow()), rid))

        def cancelled() -> bool:
            now = time.time()
            if now - tick[0] > 1.0:
                tick[0] = now
                r = self.store.one("SELECT cancel FROM runs WHERE id=?", (rid,))
                tick[2] = bool(r and r["cancel"])
                if now - tick[1] > 30:                       # a long step still shows that the worker is alive
                    tick[1] = now
                    self.store.execute("UPDATE runs SET heartbeat=? WHERE id=?", (iso(utcnow()), rid))
            return tick[2]

        status, error, snap = "done", None, None
        try:
            _crow, con = self._instance(pid, cid, key)
            files = []
            for f in self.store.all("SELECT id, enc_name, enc_data FROM files WHERE connector_id=?", (cid,)):
                name = vault.unseal(key, f["enc_name"], f"{pid}:file-name:{f['id']}").decode()
                data = vault.unseal(key, f["enc_data"], f"{pid}:file:{f['id']}")
                if name.endswith(".gz"):
                    data = gzip.GzipFile(fileobj=io.BytesIO(data)).read(MAX_UNPACKED + 1)
                    if len(data) > MAX_UNPACKED:
                        raise ApiError(413, f"{name} unpacks to more than {MAX_UNPACKED // 2 ** 20} MB")
                files.append((name, data))
            options = {k: v for k, v in con.cfg.items() if k in ("logDays", "eventDays", "activityDays", "includeFactors", "includeUserCredentials", "skipAppAssignments")}
            snap = Snapshot(con.LABEL, con.source_name(), options, progress)
            con.http.cancelled = cancelled
            con.collect(snap, files or None)
        except HttpError as exc:
            status, error = ("cancelled", None) if str(exc) == "Cancelled" else ("failed", str(exc))
        except ApiError as exc:
            status, error = "failed", str(exc)
        except Exception as exc:  # a connector bug must end the run, not the worker
            status, error = "failed", f"{type(exc).__name__}: {exc}"
        try:
            if status == "done" and snap.errors and not any(snap.counts.values()):      # every step failed (typically: authentication)
                status, error = "failed", snap.errors[0]["message"]
            if status == "done":
                payloads = snap.serialise()
                manifest = snap.complete(payloads)
                stmts = [("INSERT INTO blobs(run_id, name, project_id, enc_data) VALUES(?,?,?,?)", (rid, name, pid, vault.seal(key, blob, f"{pid}:blob:{rid}:{name}")))
                         for name, blob in payloads.items()]
                stmts.append(("UPDATE runs SET enc_manifest=?, step='analysing', heartbeat=? WHERE id=?",
                              (vault.seal_json(key, manifest, f"{pid}:manifest:{rid}"), iso(utcnow()), rid)))
                self.store.transaction(stmts)
                self._prune(cid)
                self.audit(pid, "collection.finished", f"{platform} run {rid}: {manifest['requests']} requests, {len(manifest['errors'])} step errors")
                self._analyse_after(pid, cid, role, rid, key)
            else:
                log = {"error": error, "stepErrors": snap.errors if snap else []}
                self.store.execute("UPDATE runs SET enc_log=? WHERE id=?", (vault.seal_json(key, log, f"{pid}:log:{rid}"), rid))
                self.audit(pid, f"collection.{status}", f"{platform} run {rid}")
        except Exception as exc:
            status = "failed"
            self.store.execute("UPDATE runs SET enc_log=? WHERE id=?", (vault.seal_json(key, {"error": f"{type(exc).__name__}: {exc}", "stepErrors": []}, f"{pid}:log:{rid}"), rid))
        # last write: whoever polls sees a finished run only when everything is stored and analysed
        self.store.execute("UPDATE runs SET status=?, finished=?, step='' WHERE id=?", (status, iso(utcnow()), rid))

    def _prune(self, cid: str) -> None:
        done = self.store.all("SELECT id FROM runs WHERE connector_id=? AND enc_manifest IS NOT NULL ORDER BY started DESC", (cid,))
        for r in done[KEEP_SNAPSHOTS:]:
            self.store.execute("DELETE FROM blobs WHERE run_id=?", (r["id"],))

    def _run_view(self, row, key: bytes) -> dict:
        out = {"id": row["id"], "project": row["project_id"], "connector": row["connector_id"], "platform": row["platform"], "role": row["role"],
               "status": row["status"], "started": row["started"], "finished": row["finished"], "step": row["step"] or "",
               "stepsDone": row["steps_done"] or 0, "error": None}
        if row["enc_log"] is not None:
            out["error"] = vault.unseal_json(key, row["enc_log"], f"{row['project_id']}:log:{row['id']}").get("error")
        return out

    def run(self, rid: str) -> dict:
        self._reap()
        row = self.store.one("SELECT * FROM runs WHERE id=?", (rid,))
        if not row:
            raise ApiError(404, "No such run")
        return self._run_view(row, self._key(row["project_id"]))

    def runs(self, pid: str, limit: int = 30) -> list[dict]:
        key = self._key(pid)
        self._reap()
        out = []
        for row in self.store.all("SELECT * FROM runs WHERE project_id=? ORDER BY started DESC, id LIMIT ?", (pid, limit)):
            item = self._run_view(row, key)
            item["manifest"] = None
            if row["enc_manifest"] is not None and row["status"] == "done":
                m = vault.unseal_json(key, row["enc_manifest"], f"{pid}:manifest:{row['id']}")
                item["manifest"] = {k: m.get(k) for k in ("source", "collectedAtUtc", "durationSeconds", "requests", "throttleWaits", "redactedValues", "counts", "errors", "notAvailable")}
            out.append(item)
        return out

    # ---- snapshots and analyses -----------------------------------------------------------------
    def _load_snapshot(self, pid: str, rid: str, key: bytes) -> Snapshot:
        row = self.store.one("SELECT enc_manifest FROM runs WHERE id=? AND project_id=?", (rid, pid))
        if not row or not row["enc_manifest"]:
            raise ApiError(404, "No snapshot for this run")
        manifest = vault.unseal_json(key, row["enc_manifest"], f"{pid}:manifest:{rid}")
        payloads = {b["name"]: vault.unseal(key, b["enc_data"], f"{pid}:blob:{rid}:{b['name']}") for b in self.store.all("SELECT name, enc_data FROM blobs WHERE run_id=?", (rid,))}
        return Snapshot.restore(manifest, payloads)

    def _latest_run(self, cid: str) -> str | None:
        """The newest run of a connector whose snapshot is stored (manifest and items are written in one transaction)."""
        row = self.store.one("SELECT r.id FROM runs r WHERE r.connector_id=? AND r.enc_manifest IS NOT NULL "
                             "AND EXISTS(SELECT 1 FROM blobs b WHERE b.run_id=r.id) ORDER BY r.started DESC LIMIT 1", (cid,))
        return row["id"] if row else None

    def _kv(self, pid: str, k: str, key: bytes) -> dict:
        row = self.store.one("SELECT enc_value FROM kv WHERE project_id=? AND key=?", (pid, k))
        return vault.unseal_json(key, row["enc_value"], f"{pid}:kv:{k}") if row else {}

    def _kv_set(self, pid: str, k: str, value: dict, key: bytes) -> None:
        self.store.execute("INSERT INTO kv(project_id, key, enc_value) VALUES(?,?,?) ON CONFLICT(project_id, key) DO UPDATE SET enc_value=excluded.enc_value",
                           (pid, k, vault.seal_json(key, value, f"{pid}:kv:{k}")))

    def analyse_connector(self, pid: str, cid: str, key: bytes | None = None) -> bool:
        key = key or self._key(pid)
        row = self._connector_row(pid, cid)
        if row["role"] != "source":
            return False
        rid = self._latest_run(cid)
        if not rid:
            return False
        with self._analysis_locks.setdefault(cid, threading.Lock()):
            snap = self._load_snapshot(pid, rid, key)
            target = self.store.one("SELECT id FROM connectors WHERE project_id=? AND role='target'", (pid,))
            trid = self._latest_run(target["id"]) if target else None
            entra = self._load_snapshot(pid, trid, key) if trid else None
            meta = self._meta(pid, key)
            result = analyse(snap, MODULES[row["platform"]].normalize, entra, meta.get("scoring") or {}, self._kv(pid, f"tracking:{cid}", key))
            prev = self.store.one("SELECT run_id, enc_data FROM analyses WHERE connector_id=?", (cid,))
            drift = None
            if prev:
                old = vault.unseal_json(key, prev["enc_data"], f"{pid}:analysis:{cid}")
                if prev["run_id"] != rid:
                    before = {a["appId"]: a["label"] for a in old["apps"]}
                    after = {a["appId"]: a["label"] for a in result["apps"]}
                    drift = {"comparedWith": old["summary"]["collectedAt"], "added": sorted(after[k] for k in after.keys() - before.keys()),
                             "removed": sorted(before[k] for k in before.keys() - after.keys()),
                             "blockersBefore": old["summary"]["blockers"], "blockersNow": result["summary"]["blockers"]}
                else:
                    drift = old.get("drift")
            result["drift"] = drift
            result["runId"], result["targetRunId"] = rid, trid
            self.store.execute("INSERT INTO analyses(connector_id, project_id, run_id, target_run_id, created, enc_data) VALUES(?,?,?,?,?,?) "
                               "ON CONFLICT(connector_id) DO UPDATE SET run_id=excluded.run_id, target_run_id=excluded.target_run_id, created=excluded.created, enc_data=excluded.enc_data",
                               (cid, pid, rid, trid, iso(utcnow()), vault.seal_json(key, result, f"{pid}:analysis:{cid}")))
        return True

    def analyse_project(self, pid: str, key: bytes | None = None) -> int:
        key = key or self._key(pid)
        n = 0
        for row in self.store.all("SELECT id FROM connectors WHERE project_id=? AND role='source'", (pid,)):
            n += 1 if self.analyse_connector(pid, row["id"], key) else 0
        self.audit(pid, "analysis.run", f"{n} source(s)")
        return n

    def analysis(self, pid: str, cid: str) -> dict:
        key = self._key(pid)
        self._connector_row(pid, cid)
        row = self.store.one("SELECT enc_data, created FROM analyses WHERE connector_id=? AND project_id=?", (cid, pid))
        if not row:
            raise ApiError(404, "Not analysed yet: run a collection first")
        a = vault.unseal_json(key, row["enc_data"], f"{pid}:analysis:{cid}")
        checks = self._kv(pid, f"checks:{cid}", key)
        for r in a["tables"]["manualChecks"]:
            c = checks.get("manual:" + r["item"], {})
            r["done"], r["answer"] = bool(c.get("done")), c.get("answer", "")
        for r in a["tables"]["policies"]:
            c = checks.get("policy:" + "|".join((r["policyType"], r["policy"], r["rule"])), {})
            r["parity"], r["decision"] = c.get("parity", ""), c.get("decision", "")
        a["trackStatuses"], a["parityValues"] = TRACK_STATUS, PARITY
        return a

    def set_tracking(self, pid: str, cid: str, app_id: str, patch: dict) -> None:
        key = self._key(pid)
        self._connector_row(pid, cid)
        track = self._kv(pid, f"tracking:{cid}", key)
        cur = track.get(app_id, {})
        if "status" in patch:
            if patch["status"] not in TRACK_STATUS:
                raise ApiError(400, "Unknown status")
            cur["status"] = patch["status"]
        if "wave" in patch:
            if patch["wave"] not in ("", None, "1", "2", "3", "4", "5", "6", "7", "R"):
                raise ApiError(400, "Unknown wave")
            cur["wave"] = patch["wave"] or ""
        for k in ("owner", "note"):
            if k in patch:
                cur[k] = str(patch[k] or "")[:500]
        track[app_id] = cur
        self._kv_set(pid, f"tracking:{cid}", track, key)
        self.audit(pid, "app.tracked", f"{cid} {app_id[:60]}: {cur.get('status', '')}")
        self.analyse_connector(pid, cid, key)

    def set_check(self, pid: str, cid: str, kind: str, ident: str, patch: dict) -> None:
        key = self._key(pid)
        self._connector_row(pid, cid)
        if kind not in ("manual", "policy"):
            raise ApiError(400, "Unknown check type")
        checks = self._kv(pid, f"checks:{cid}", key)
        cur = checks.get(f"{kind}:{ident}", {})
        if kind == "manual":
            if "done" in patch:
                cur["done"] = bool(patch["done"])
            if "answer" in patch:
                cur["answer"] = str(patch["answer"] or "")[:4000]
        else:
            if "parity" in patch:
                if patch["parity"] not in PARITY:
                    raise ApiError(400, "Unknown parity value")
                cur["parity"] = patch["parity"]
            if "decision" in patch:
                cur["decision"] = str(patch["decision"] or "")[:2000]
        checks[f"{kind}:{ident}"] = cur
        self._kv_set(pid, f"checks:{cid}", checks, key)
        self.audit(pid, f"check.{kind}", cid)

    # ---- exports --------------------------------------------------------------------------------
    def export(self, pid: str, cid: str, fmt: str) -> tuple[bytes, str, str]:
        a = self.analysis(pid, cid)
        meta = self._meta(pid)
        stem = re.sub(r"[^A-Za-z0-9]+", "-", f"{meta['name']}-{a['summary']['platform']}").strip("-").lower()
        self.audit(pid, "export", f"{cid} {fmt}")
        if fmt == "xlsx":
            return report.workbook(a, meta["name"]), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", f"{stem}-assessment.xlsx"
        if fmt == "md":
            return report.findings_report(a, meta["name"]).encode(), "text/markdown; charset=utf-8", f"{stem}-findings.md"
        if fmt == "json":
            import json
            return json.dumps(a, indent=2, default=str).encode(), "application/json", f"{stem}-analysis.json"
        raise ApiError(400, "Unknown format")

    def evidence(self, pid: str) -> tuple[bytes, str]:
        key = self._key(pid)
        meta = self._meta(pid, key)
        items = []
        for row in self.store.all("SELECT * FROM connectors WHERE project_id=? ORDER BY role, created", (pid,)):
            rid = self._latest_run(row["id"])
            if not rid:
                continue
            manifest = vault.unseal_json(key, self.store.one("SELECT enc_manifest FROM runs WHERE id=?", (rid,))["enc_manifest"], f"{pid}:manifest:{rid}")
            analysis = None
            if row["role"] == "source" and self.store.one("SELECT 1 FROM analyses WHERE connector_id=?", (row["id"],)):
                analysis = self.analysis(pid, row["id"])
            items.append({"folder": f"{row['role']}-{row['platform']}-{row['id'][:6]}", "manifest": manifest, "analysis": analysis})
        audit = [dict(r) for r in self.store.all("SELECT ts, action, detail FROM audit WHERE project_id=? ORDER BY id", (pid,))]
        self.audit(pid, "export", "evidence pack")
        stem = re.sub(r"[^A-Za-z0-9]+", "-", meta["name"]).strip("-").lower()
        return report.evidence_pack(meta, items, audit), f"{stem}-evidence.zip"

    def audit_trail(self, pid: str, limit: int = 200) -> list[dict]:
        self._key(pid)
        return [dict(r) for r in self.store.all("SELECT ts, action, detail FROM audit WHERE project_id=? ORDER BY id DESC LIMIT ?", (pid, limit))]


def _validate_scoring(s: dict) -> None:
    allowed = set(DEFAULT_SCORING)
    for k, v in s.items():
        if k not in allowed:
            raise ApiError(400, f"Unknown scoring setting '{k}'")
        ref = DEFAULT_SCORING[k]
        if isinstance(ref, dict):
            if not isinstance(v, dict):
                raise ApiError(400, f"'{k}' must be an object")
            for kk, vv in v.items():
                if k != "attributeMap" and kk not in ref:
                    raise ApiError(400, f"Unknown setting '{k}.{kk}'")
                if k == "attributeMap":
                    if not isinstance(vv, str) or not re.match(r"^[A-Za-z0-9_]+$", vv):
                        raise ApiError(400, "Attribute names: letters, digits and underscore only")
                elif not isinstance(vv, (int, float, bool)):
                    raise ApiError(400, f"'{k}.{kk}' must be a number")
        elif not isinstance(v, (int, float)) or isinstance(v, bool):
            raise ApiError(400, f"'{k}' must be a number")
