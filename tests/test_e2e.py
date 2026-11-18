"""End-to-end tests: the real application against the mock tenants.

Run:  python -m pytest tests -q
The mocks are started on free local ports. Nothing leaves the machine.
"""
import io
import json
import os
import socket
import gzip
import subprocess
import sys
import time
import zipfile
from pathlib import Path

import pytest
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from openpyxl import load_workbook

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from workbench.main import create_app  # noqa: E402

H = {"x-workbench": "1"}
PASS = "correct horse battery staple"


MODE = os.environ.get("WB_TEST_MODE", "server")            # server | serverless
DB = os.environ.get("WB_TEST_DB", "sqlite")                # sqlite | postgres
PG_ADMIN = os.environ.get("WB_TEST_PG", "postgresql://wb@127.0.0.1:55432/postgres")
SECRET = "test-session-secret"


def client(app, cookies=None) -> TestClient:
    """https, because the serverless session cookie is Secure."""
    c = TestClient(app, base_url="https://testserver")
    for k, v in (cookies or {}).items():
        c.cookies.set(k, v)
    return c


def make_app(data, serverless=None, secret=None):
    serverless = (MODE == "serverless") if serverless is None else serverless
    return create_app(str(data), serverless=serverless, session_secret=secret or (SECRET if serverless else None), setup_code="SETUP123")


def unlock(env):
    """Give this test thread the vault key of the signed-in session, as the request middleware does."""
    from workbench.service import set_request_kek
    kek = env["app"].state.wb.open_session(env["c"].cookies.get("wb_session"))[0]
    set_request_kek(kek)
    return kek


def raw_dump(env) -> bytes:
    """Everything the database holds, as bytes: the files of SQLite, or every value of every table in Postgres."""
    store = env["app"].state.wb.store
    if store.backend == "sqlite":
        return b"".join(f.read_bytes() for f in Path(env["data"]).iterdir())
    out = []
    for t in ("meta", "projects", "connectors", "files", "runs", "blobs", "analyses", "kv", "audit"):
        for row in store.all(f"SELECT * FROM {t}"):
            out += [v if isinstance(v, bytes) else str(v).encode() for v in dict(row).values()]
    return b"\n".join(out)


def kick(c, runs):
    """Serverless mode: a queued run starts when a signed-in client asks for it, as the web UI does."""
    if MODE != "serverless":
        return []
    import threading
    cookies = {"wb_session": c.cookies.get("wb_session")}
    threads = [threading.Thread(target=lambda r=r: client(c.app, cookies).post(f"/api/runs/{r['id']}/execute", headers=H), daemon=True) for r in runs]
    for t in threads:
        t.start()
    return threads


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_port(port: int) -> None:
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"mock on port {port} did not start")


@pytest.fixture(scope="session")
def mocks(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("keys")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    pub = tmp / "pub.pem"
    pub.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    ports = {"okta": free_port(), "idps": free_port(), "graph": free_port()}
    procs = [subprocess.Popen([sys.executable, str(ROOT / "tests/mocks/mock_okta.py"), "--port", str(ports["okta"]), "--public-key", str(pub)]),
             subprocess.Popen([sys.executable, str(ROOT / "tests/mocks/mock_idps.py"), "--port", str(ports["idps"])]),
             subprocess.Popen([sys.executable, str(ROOT / "tests/mocks/mock_graph.py"), "--port", str(ports["graph"])])]
    for p in ports.values():
        wait_port(p)
    okta, idps, graph = (f"http://127.0.0.1:{ports[k]}" for k in ("okta", "idps", "graph"))
    yield {
        "okta_url": okta, "idps_url": idps, "graph_url": graph, "pem": pem,
        "okta": {"orgUrl": okta, "authMode": "oauth", "clientId": "0oaSERVICE", "privateKey": pem, "includeFactors": True, "allowInsecure": True},
        "okta_ssws": {"orgUrl": okta, "authMode": "ssws", "apiToken": "mock-ssws-token", "allowInsecure": True, "logDays": 0},
        "keycloak": {"baseUrl": idps + "/kc", "realm": "corp", "clientId": "x2e-collector", "clientSecret": "kc-secret", "includeUserCredentials": True, "allowInsecure": True},
        "pingfederate": {"adminUrl": idps + "/pf", "username": "auditor", "password": "pf-secret", "allowInsecure": True},
        "pingone": {"environmentId": "env-0001", "clientId": "p1-client", "clientSecret": "p1-secret", "apiBase": idps + "/p1api", "authBase": idps + "/p1auth", "allowInsecure": True},
        "onelogin": {"baseUrl": idps + "/ol", "clientId": "ol-client", "clientSecret": "ol-secret", "includeFactors": True, "allowInsecure": True},
        "entra": {"tenantId": "contoso", "clientId": "graph-client", "clientSecret": "graph-secret", "authority": graph + "/auth", "graphBase": graph + "/graph", "allowInsecure": True},
    }
    for p in procs:
        p.terminate()


@pytest.fixture(scope="session")
def env(tmp_path_factory, mocks):
    data = tmp_path_factory.mktemp("data")
    if DB == "postgres":
        import psycopg
        name = f"wbtest_{os.getpid()}_{int(time.time())}"
        with psycopg.connect(PG_ADMIN, autocommit=True) as admin:
            admin.execute(f"CREATE DATABASE {name} ENCODING 'UTF8' TEMPLATE template0")
        os.environ["WORKBENCH_DATABASE_URL"] = PG_ADMIN.rsplit("/", 1)[0] + "/" + name
    app = make_app(data)
    c = client(app)
    st = c.get("/api/state").json()
    assert (st["initialised"], st["signedIn"], st["mode"], st["database"]) == (False, False, MODE, DB)
    return {"app": app, "c": c, "data": data, "projects": {}, "pass": PASS}


def wait_runs(c, runs, timeout=180, kicked=False):
    if not kicked:
        kick(c, runs)
    end = time.time() + timeout
    out = {}
    for r in runs:
        while True:
            st = c.get(f"/api/runs/{r['id']}").json()
            if st["status"] not in ("queued", "running"):
                out[r["id"]] = st
                break
            assert time.time() < end, f"run {r['id']} still {st['status']} at step {st['step']}"
            time.sleep(0.2)
    return out


def make_project(c, mocks, name, platforms, files=None):
    p = c.post("/api/projects", json={"name": name, "client": f"{name} client GmbH"}, headers=H).json()
    ids = {}
    for plat in platforms + ["entra"]:
        cfg_key = plat
        r = c.post(f"/api/projects/{p['id']}/connectors", json={"platform": plat.split("_")[0], "name": plat, "config": mocks[cfg_key]}, headers=H)
        assert r.status_code == 200, r.text
        ids[plat] = r.json()["id"]
    for plat, blob in (files or {}).items():
        r = c.post(f"/api/projects/{p['id']}/connectors/{ids[plat]}/files", files={"file": ("audit.log.gz", gzip.compress(blob))}, headers=H)
        assert r.status_code == 200, r.text
    return p["id"], ids


# ---- access control -----------------------------------------------------------------------------

def test_01_setup_and_access_control(env):
    c, app = env["c"], env["app"]
    assert c.get("/api/projects").status_code == 401                                   # nothing without a session
    assert c.post("/api/setup", json={"setupCode": "WRONG", "passphrase": PASS}, headers=H).status_code == 403
    assert c.post("/api/setup", json={"setupCode": app.state.setup_code, "passphrase": "short"}, headers=H).status_code == 400
    assert c.post("/api/setup", json={"setupCode": app.state.setup_code, "passphrase": PASS}).status_code == 403   # no custom header: refused
    r = c.post("/api/setup", json={"setupCode": app.state.setup_code, "passphrase": PASS}, headers=H)
    assert r.status_code == 200 and "httponly" in r.headers["set-cookie"].lower() and "samesite=strict" in r.headers["set-cookie"].lower()
    assert c.post("/api/setup", json={"setupCode": "", "passphrase": PASS}, headers=H).status_code == 409          # only once
    assert c.get("/api/projects").json() == []
    assert c.post("/api/projects", json={"name": "x"}).status_code == 403              # state change without the header
    anon = client(app)
    assert anon.get("/api/projects").status_code == 401
    assert anon.post("/api/login", json={"passphrase": "wrong passphrase 123"}, headers=H).status_code == 401
    page = c.get("/")
    assert page.status_code == 200 and "frame-ancestors 'none'" in page.headers["content-security-policy"]
    assert c.get("/static/../service.py").status_code == 404
    names = [p["platform"] for p in c.get("/api/platforms").json()]
    assert names == ["okta", "keycloak", "pingfederate", "pingone", "onelogin", "entra"]


def test_02_connector_validation(env, mocks):
    c = env["c"]
    pid = c.post("/api/projects", json={"name": "validation"}, headers=H).json()["id"]
    bad = c.post(f"/api/projects/{pid}/connectors", json={"platform": "okta", "config": {"orgUrl": "http://okta.example", "authMode": "ssws", "apiToken": "t"}}, headers=H)
    assert bad.status_code == 400 and "https" in bad.json()["error"]                    # http only with the explicit lab switch
    assert c.post(f"/api/projects/{pid}/connectors", json={"platform": "keycloak", "config": {"baseUrl": "https://kc.example"}}, headers=H).status_code == 400
    assert c.post(f"/api/projects/{pid}/connectors", json={"platform": "nope", "config": {}}, headers=H).status_code == 400
    ok = c.post(f"/api/projects/{pid}/connectors", json={"platform": "keycloak", "config": {**mocks["keycloak"], "clientSecret": "wrong"}}, headers=H).json()
    assert ok["config"]["clientSecret"] == {"set": True}                                # the API never returns a secret
    t = c.post(f"/api/projects/{pid}/connectors/{ok['id']}/test", headers=H).json()
    assert t["ok"] is False and "401" in t["detail"]
    upd = c.put(f"/api/projects/{pid}/connectors/{ok['id']}", json={"config": {**mocks["keycloak"], "clientSecret": None, "eventDays": 30}}, headers=H).json()
    assert upd["config"]["eventDays"] == 30 and upd["config"]["clientSecret"] == {"set": True}      # empty secret keeps the stored one
    assert c.post(f"/api/projects/{pid}/connectors/{ok['id']}/test", headers=H).json()["ok"] is False
    c.put(f"/api/projects/{pid}/connectors/{ok['id']}", json={"config": {**mocks["keycloak"]}}, headers=H)
    assert c.post(f"/api/projects/{pid}/connectors/{ok['id']}/test", headers=H).json() == {"ok": True, "detail": "Connected to realm corp"}
    e1 = c.post(f"/api/projects/{pid}/connectors", json={"platform": "entra", "config": mocks["entra"]}, headers=H)
    assert e1.status_code == 200
    assert c.post(f"/api/projects/{pid}/connectors", json={"platform": "entra", "config": mocks["entra"]}, headers=H).status_code == 409    # one target per project
    assert c.post(f"/api/projects/{pid}/connectors/{e1.json()['id']}/files", files={"file": ("a.log", b"x")}, headers=H).status_code == 400
    assert c.request("DELETE", f"/api/projects/{pid}", json={"confirm": "wrong"}, headers=H).status_code == 400
    assert c.request("DELETE", f"/api/projects/{pid}", json={"confirm": "validation"}, headers=H).status_code == 200
    assert c.get(f"/api/projects/{pid}").status_code == 404


# ---- five platforms, four projects, in parallel -------------------------------------------------

def test_03_parallel_projects(env, mocks):
    c = env["c"]
    audit_log = requests.get(mocks["idps_url"] + "/__auditlog/pf").content
    plan = {"okta": ["okta"], "keycloak": ["keycloak"], "ping": ["pingfederate", "pingone"], "onelogin": ["onelogin"]}
    runs = []
    for name, plats in plan.items():
        pid, ids = make_project(c, mocks, name, plats, {"pingfederate": audit_log} if name == "ping" else None)
        env["projects"][name] = {"id": pid, "ids": ids}
        r = c.post(f"/api/projects/{pid}/collect", headers=H)
        assert r.status_code == 200, r.text
        runs += r.json()
    assert len(runs) == 9
    live = [c.get(f"/api/runs/{r['id']}").json()["status"] for r in runs]
    assert sum(s in ("queued", "running") for s in live) >= 4                         # really in parallel
    dup = c.post(f"/api/projects/{env['projects']['okta']['id']}/connectors/{env['projects']['okta']['ids']['okta']}/collect", headers=H)
    assert dup.status_code == 409
    done = wait_runs(c, runs)
    assert all(d["status"] == "done" for d in done.values()), done
    home = {p["name"]: p for p in c.get("/api/projects").json()}
    assert home["ping"]["platforms"] == ["pingfederate", "pingone"] and len(home["ping"]["analyses"]) == 2
    assert all(home[n]["hasTarget"] and home[n]["running"] == 0 for n in plan)


def analysis(env, project, platform):
    p = env["projects"][project]
    r = env["c"].get(f"/api/projects/{p['id']}/analysis/{p['ids'][platform]}")
    assert r.status_code == 200, r.text
    return r.json()


def by_id(a):
    return {x["appId"]: x for x in a["apps"]}


def ids(a):
    return [f["id"] for f in a["findings"]]


def test_04_okta(env, mocks):
    a = analysis(env, "okta", "okta")
    exp = requests.get(mocks["okta_url"] + "/__expected").json()
    s, idn = a["summary"], a["identity"]
    assert s["platform"] == "Okta" and s["apps"] == exp["apps_total"] == 30
    assert idn["active"] == exp["users_active"] and idn["total"] == exp["users_total"]
    assert idn["localPasswordActive"] == exp["okta_sourced_active"] and idn["neverSignedInActive"] == exp["never_signed_in_active"]
    apps = by_id(a)
    for app_id, u in exp["usage"].items():
        assert (apps[app_id]["signIns"], apps[app_id]["distinctUsers"]) == (u["signIns"], u["distinctUsers"])
    retire = {x["label"] for x in a["apps"] if x["wave"] == "R"}
    machine = {x["label"] for x in a["apps"] if "No interactive sign-in" in x["notes"]}
    assert "Partner API Client" in machine and not (machine & retire)                  # a machine client without sign-ins is not "unused"
    assert set(exp["apps_unused_active"]) - machine <= retire
    assert len(retire) == len(set(exp["apps_unused_active"]) - machine) + exp["apps_inactive"]
    assert a["state"]["state"] == "A" and a["state"]["mixed"] is True
    assert any("federated domain(s): example.com" in e for e in a["state"]["evidence"])
    m = idn["matching"]
    assert m == {"compared": 240, "byUpn": 231, "byMail": 1, "ambiguous": 1, "unmatched": 7}
    assert len(a["unmatched"]) == 8 and {u["login"] for u in a["unmatched"]} >= {"user017@example.com", "user200@example.com", "user240@example.com"}
    for f in ("ID-01", "ID-02", "ID-03", "APP-01", "APP-03", "APP-04", "AUT-01", "AUT-03", "POL-01", "POL-03", "ADM-01", "MFA-03", "MAN-01", "APP-07"):
        assert f in ids(a), f
    assert "COL-01" not in ids(a) and "COL-03" not in ids(a)
    assert a["summary"]["notAvailable"] == ["behaviors"]                                # 403 on an optional step is not an error
    assert a["factorSummary"]["usersChecked"] == 230
    assert a["target"]["tenant"] == "Contoso (mock tenant)" and a["target"]["conditionalAccess"] is None
    sf = next(x for x in a["apps"] if x["label"] == "Salesforce")
    assert sf["galleryMatch"] == "exact" and sf["existsInEntra"] is True
    waves = {w["wave"]: w["apps"] for w in a["waves"]}
    assert waves["P"] == 1 and sum(waves.values()) == 30
    assert a["summary"]["effortCalibrated"] is False


def test_05_keycloak(env, mocks):
    a = analysis(env, "keycloak", "keycloak")
    exp = requests.get(mocks["idps_url"] + "/__expected/keycloak").json()
    assert a["identity"]["active"] == exp["active"] and a["identity"]["localPasswordActive"] == exp["local_password_active"]
    assert a["identity"]["staleActive"] == exp["active"] - exp["distinct_login_users"]
    apps = by_id(a)
    for cid, u in exp["usage"].items():
        if cid in apps and not apps[cid]["label"] == "batch":
            assert apps[cid]["distinctUsers"] == u["distinctUsers"], cid
    assert apps["urn:federation:MicrosoftOnline"]["wave"] == "P"
    for f in ("KC-02", "KC-03", "KC-04", "KC-06", "FLG-01", "FLG-02", "STO-01", "ID-01", "POL-01", "COL-01"):
        assert f in ids(a), f
    col = [f for f in a["findings"] if f["id"] == "COL-01"]
    assert len(col) == 1 and "roles" in col[0]["title"]                                 # the mock refuses /roles: reported, not hidden
    assert all(x["pattern"] in ("SAML", "OIDC") for x in a["apps"])
    assert not any(x["label"] in ("account", "admin-cli", "broker") for x in a["apps"])


def test_06_pingfederate(env, mocks):
    a = analysis(env, "ping", "pingfederate")
    exp = requests.get(mocks["idps_url"] + "/__expected/pingfederate").json()
    assert a["summary"]["apps"] == exp["connections"] + exp["clients"]
    assert a["identity"]["known"] is False and a["summary"]["activeUsers"] is None
    apps = by_id(a)
    for pid, u in exp["usage"].items():
        assert (apps[pid]["signIns"], apps[pid]["distinctUsers"]) == (u["signIns"], u["distinctUsers"]), pid
    assert a["summary"]["usageKnown"] is True
    for f in ("PF-01", "PF-03", "FLG-01", "FLG-03", "FLG-04", "FLG-05", "APP-03", "STO-01", "AUT-01"):
        assert f in ids(a), f
    sts = [x for x in a["apps"] if "ws-trust" in x["flags"]]
    assert sts and all(x["wave"] != "R" or x["retireReason"] == "Inactive on the source platform" for x in sts if x["signIns"] == 0 and x["status"] == "ACTIVE")


def test_07_pingone(env, mocks):
    a = analysis(env, "ping", "pingone")
    exp = requests.get(mocks["idps_url"] + "/__expected/pingone").json()
    idn = a["identity"]
    assert (idn["total"], idn["active"], idn["localPasswordActive"], idn["neverSignedInActive"]) == (exp["users"], exp["active"], exp["local_active"], exp["never_active"])
    apps = by_id(a)
    for app_id, u in exp["usage"].items():
        assert (apps[app_id]["signIns"], apps[app_id]["distinctUsers"]) == (u["signIns"], u["distinctUsers"])
    for f in ("P1-01", "ID-01", "POL-01", "GRP-01", "COL-01"):
        assert f in ids(a), f
    assert not any(x["kind"].startswith("PING_ONE") for x in a["apps"])


def test_08_onelogin(env, mocks):
    a = analysis(env, "onelogin", "onelogin")
    exp = requests.get(mocks["idps_url"] + "/__expected/onelogin").json()
    idn = a["identity"]
    assert (idn["total"], idn["active"], idn["localPasswordActive"], idn["neverSignedInActive"]) == (exp["users"], exp["active"], exp["local_active"], exp["never_active"])
    assert a["summary"]["apps"] == exp["apps"] and a["factorSummary"]["usersWithoutFactor"] == exp["no_factor"]
    apps = by_id(a)
    for app_id, u in exp["usage"].items():
        assert (apps[app_id]["signIns"], apps[app_id]["distinctUsers"]) == (u["signIns"], u["distinctUsers"])
    for app_id, n in exp["assigned"].items():
        assert apps[app_id]["assignedUsers"] == n
    for f in ("OL-01", "OL-02", "AUT-01", "FLG-06", "APP-01", "ID-03"):
        assert f in ids(a), f
    prov = [x for x in a["apps"] if x["pattern"] == "Provisioning"]
    assert prov and all(x["wave"] != "R" for x in prov)                               # provisioning-only connectors are not "unused"
    assert all(r["authentication"] == "Unknown" for r in a["tables"]["policies"] if r["policyType"] == "App policy")


# ---- guarantees ---------------------------------------------------------------------------------

def test_09_read_only(env, mocks):
    okta = requests.get(mocks["okta_url"] + "/__stats").json()
    assert okta["writeAttempts"] == 0 and okta["tokenRequests"] >= 1                    # OAuth with private_key_jwt was used
    assert requests.get(mocks["idps_url"] + "/__stats").json()["writes"] == 0
    assert requests.get(mocks["graph_url"] + "/__stats").json()["writes"] == 0


def test_10_nothing_readable_at_rest(env, mocks):
    """Neither connector credentials, nor collected data, nor project names are readable in the database file."""
    raw = raw_dump(env)
    needles = ["mock-ssws-token", "kc-secret", "pf-secret", "p1-secret", "ol-secret", "graph-secret", "BEGIN PRIVATE KEY", PASS,
               "user001@example.com", "kuser001", "Salesforce", "Contoso Bank", "okta client GmbH", "urn:federation:MicrosoftOnline", "audit.log"]
    for n in needles:
        assert n.encode() not in raw, f"'{n}' is readable in the data directory"
    assert env["app"].state.wb.store.one("SELECT count(*) AS n FROM blobs")["n"] > 60
    kek = unlock(env)                                                                   # the vault key exists in the session cookie only
    import base64
    assert kek not in raw and base64.b64encode(kek) not in raw and SECRET.encode() not in raw


def test_11_secrets_redacted_in_snapshots(env, mocks):
    """Decrypt every stored snapshot and look for the secrets the mocks planted in their configuration."""
    from workbench import vault
    wb = env["app"].state.wb
    unlock(env)
    planted = {"okta": requests.get(mocks["okta_url"] + "/__expected").json().get("secrets", [])}
    for plat in ("keycloak", "pingfederate", "pingone", "onelogin"):
        planted[plat] = requests.get(f"{mocks['idps_url']}/__expected/{plat}").json()["secrets"]       # credentials and personal data the collector must not keep
    assert sum(len(v) for v in planted.values()) > 25
    seen = 0
    for row in wb.store.all("SELECT b.run_id, b.name, b.project_id, b.enc_data, r.platform FROM blobs b JOIN runs r ON r.id=b.run_id"):
        key = wb._key(row["project_id"])
        text = vault.unseal(key, row["enc_data"], f"{row['project_id']}:blob:{row['run_id']}:{row['name']}").decode()
        seen += 1
        for secret in planted.get(row["platform"], []):
            assert secret not in text, f"{secret} found in {row['platform']}/{row['name']}"
    assert seen > 60
    for name in ("okta", "keycloak", "ping", "onelogin"):
        for r in env["c"].get(f"/api/projects/{env['projects'][name]['id']}/runs").json():
            assert r["manifest"]["redactedValues"] >= 0
    okta_run = [r for r in env["c"].get(f"/api/projects/{env['projects']['okta']['id']}/runs").json() if r["platform"] == "okta"][0]
    assert okta_run["manifest"]["redactedValues"] >= 5


def test_12_project_isolation_and_tamper_detection(env):
    from workbench import vault
    wb = env["app"].state.wb
    unlock(env)
    a, b = env["projects"]["okta"]["id"], env["projects"]["keycloak"]["id"]
    row = wb.store.one("SELECT run_id, name, enc_data FROM blobs WHERE project_id=? LIMIT 1", (a,))
    with pytest.raises(vault.VaultError):
        vault.unseal(wb._key(b), row["enc_data"], f"{a}:blob:{row['run_id']}:{row['name']}")           # another project's key does not open it
    with pytest.raises(vault.VaultError):
        vault.unseal(wb._key(a), row["enc_data"], f"{a}:blob:{row['run_id']}:other")                    # nor does it open when moved
    # a blob swapped inside the same project fails the manifest check
    other = wb.store.one("SELECT name, enc_data FROM blobs WHERE run_id=? AND name!=? LIMIT 1", (row["run_id"], row["name"]))
    good = vault.unseal(wb._key(a), other["enc_data"], f"{a}:blob:{row['run_id']}:{other['name']}")
    wb.store.execute("UPDATE blobs SET enc_data=? WHERE run_id=? AND name=?", (vault.seal(wb._key(a), good + b" ", f"{a}:blob:{row['run_id']}:{other['name']}"), row["run_id"], other["name"]))
    with pytest.raises(ValueError, match="does not match its manifest"):
        wb._load_snapshot(a, row["run_id"], wb._key(a))
    wb.store.execute("UPDATE blobs SET enc_data=? WHERE run_id=? AND name=?", (other["enc_data"], row["run_id"], other["name"]))
    wb._load_snapshot(a, row["run_id"], wb._key(a))


def test_13_tracking_checks_gates_scoring(env):
    c = env["c"]
    p = env["projects"]["okta"]
    pid, cid = p["id"], p["ids"]["okta"]
    a = c.get(f"/api/projects/{pid}/analysis/{cid}").json()
    app = next(x for x in a["apps"] if x["wave"] == "2")
    no_owner_before = next(f["count"] for f in a["findings"] if f["id"] == "APP-07")
    assert c.put(f"/api/projects/{pid}/tracking/{cid}", json={"appId": app["appId"], "status": "nonsense"}, headers=H).status_code == 400
    r = c.put(f"/api/projects/{pid}/tracking/{cid}", json={"appId": app["appId"], "owner": "Jana Novak", "status": "Validated", "wave": "3", "note": "moved"}, headers=H)
    assert r.status_code == 200
    a2 = c.get(f"/api/projects/{pid}/analysis/{cid}").json()
    moved = next(x for x in a2["apps"] if x["appId"] == app["appId"])
    assert (moved["wave"], moved["proposedWave"], moved["owner"], moved["trackStatus"]) == ("3", "2", "Jana Novak", "Validated")
    assert next(f["count"] for f in a2["findings"] if f["id"] == "APP-07") == no_owner_before - 1
    assert next(w for w in a2["waves"] if w["wave"] == "3")["done"] == 1
    pol = a2["tables"]["policies"][0]
    key = "|".join((pol["policyType"], pol["policy"], pol["rule"]))
    assert c.put(f"/api/projects/{pid}/checks/{cid}", json={"kind": "policy", "id": key, "parity": "Raised", "decision": "CA-01 require MFA"}, headers=H).status_code == 200
    man = a2["tables"]["manualChecks"][0]["item"]
    assert c.put(f"/api/projects/{pid}/checks/{cid}", json={"kind": "manual", "id": man, "done": True, "answer": "12 flows exported"}, headers=H).status_code == 200
    a3 = c.get(f"/api/projects/{pid}/analysis/{cid}").json()
    assert (a3["tables"]["policies"][0]["parity"], a3["tables"]["policies"][0]["decision"]) == ("Raised", "CA-01 require MFA")
    assert a3["tables"]["manualChecks"][0]["done"] is True
    g = c.patch(f"/api/projects/{pid}", json={"gates": {"G1": {"status": "Passed", "signedBy": "Sponsor", "date": "2026-11-17"}}}, headers=H).json()
    assert g["gates"]["G1"]["status"] == "Passed"
    assert next(x for x in c.get("/api/projects").json() if x["id"] == pid)["nextGate"] == "G2"
    assert c.patch(f"/api/projects/{pid}", json={"scoring": {"bogus": 1}}, headers=H).status_code == 400
    before = a3["summary"]["effortDays"]
    assert c.patch(f"/api/projects/{pid}", json={"scoring": {"effortDays": {"calibrated": True, "Low": 1, "Medium": 3, "High": 8}}}, headers=H).status_code == 200
    a4 = c.get(f"/api/projects/{pid}/analysis/{cid}").json()
    assert a4["summary"]["effortCalibrated"] is True and a4["summary"]["effortDays"] > before
    assert next(x for x in a4["apps"] if x["appId"] == app["appId"])["owner"] == "Jana Novak"           # decisions survive a re-analysis


def test_14_exports(env):
    c = env["c"]
    p = env["projects"]["ping"]
    pid = p["id"]
    x = c.get(f"/api/projects/{pid}/export/{p['ids']['pingfederate']}/xlsx")
    assert x.status_code == 200
    wb = load_workbook(io.BytesIO(x.content))
    for sheet in ("Summary", "Findings", "Waves", "Apps", "Policies", "MfaMethods", "UserStores", "ManualChecks"):
        assert sheet in wb.sheetnames, sheet
    assert wb["Apps"].max_row == 15 and wb["Findings"].max_row > 15
    md = c.get(f"/api/projects/{pid}/export/{p['ids']['pingone']}/md").text
    assert md.startswith("# Migration assessment: PingOne to Entra ID") and "| P1-01 | Blocker |" in md
    z = zipfile.ZipFile(io.BytesIO(c.get(f"/api/projects/{pid}/evidence").content))
    names = z.namelist()
    assert "project.json" in names and "audit-trail.json" in names and sum(n.endswith("manifest.json") for n in names) == 3
    assert sum(n.endswith("assessment.xlsx") for n in names) == 2
    manifest = json.loads(z.read(next(n for n in names if n.startswith("source-pingfederate") and n.endswith("manifest.json"))))
    assert manifest["options"]["auditLogFiles"] == 1 and all(len(v["sha256"]) == 64 for v in manifest["items"].values())
    trail = json.loads(z.read("audit-trail.json"))
    assert any(t["action"] == "collection.finished" for t in trail) and not any("secret" in (t["detail"] or "") for t in trail)


def test_15_second_snapshot_shows_drift_and_old_snapshots_are_pruned(env, mocks):
    c = env["c"]
    pid = c.post("/api/projects", json={"name": "drift"}, headers=H).json()["id"]
    cid = c.post(f"/api/projects/{pid}/connectors", json={"platform": "pingone", "config": mocks["pingone"]}, headers=H).json()["id"]
    for _ in range(2):
        wait_runs(c, [c.post(f"/api/projects/{pid}/connectors/{cid}/collect", headers=H).json()])
    a = c.get(f"/api/projects/{pid}/analysis/{cid}").json()
    assert a["drift"] == {"comparedWith": a["drift"]["comparedWith"], "added": [], "removed": [], "blockersBefore": a["summary"]["blockers"], "blockersNow": a["summary"]["blockers"]}
    assert "COL-03" in [f["id"] for f in a["findings"]]                                 # no target in this project: said, not assumed
    assert a["apps"][0]["galleryMatch"] == "unknown"
    for _ in range(5):
        wait_runs(c, [c.post(f"/api/projects/{pid}/connectors/{cid}/collect", headers=H).json()])
    wb = env["app"].state.wb
    kept = wb.store.one("SELECT count(DISTINCT run_id) AS n FROM blobs WHERE project_id=?", (pid,))["n"]
    assert kept == 5 and len(c.get(f"/api/projects/{pid}/runs").json()) == 7
    env["projects"]["drift"] = {"id": pid}


def test_16_failed_collection_is_reported(env, mocks):
    c = env["c"]
    pid = c.post("/api/projects", json={"name": "failing"}, headers=H).json()["id"]
    cid = c.post(f"/api/projects/{pid}/connectors", json={"platform": "onelogin", "config": {**mocks["onelogin"], "clientSecret": "wrong"}}, headers=H).json()["id"]
    run = c.post(f"/api/projects/{pid}/connectors/{cid}/collect", headers=H).json()
    st = wait_runs(c, [run])[run["id"]]
    assert st["status"] == "failed" and "401" in st["error"]
    assert c.get(f"/api/projects/{pid}/analysis/{cid}").status_code == 404
    listed = c.get(f"/api/projects/{pid}/runs").json()[0]
    assert listed["status"] == "failed" and "401" in listed["error"]
    # credentials are never sent to a host the connector was not configured for
    from workbench.httpc import HttpError, ReadOnlyClient
    client = ReadOnlyClient(["https://tenant.example.com"])
    with pytest.raises(HttpError, match="outside the configured host"):
        client.get("https://tenant.example.com.evil.test/api")
    with pytest.raises(HttpError, match="outside the configured host"):
        client.get("https://evil.test/?u=https://tenant.example.com/")
    assert not hasattr(client, "post") and not hasattr(client, "put") and not hasattr(client, "delete")


def test_17_delete_project_destroys_its_key(env):
    c = env["c"]
    wb = env["app"].state.wb
    pid = env["projects"]["drift"]["id"]
    assert wb.store.one("SELECT count(*) AS n FROM blobs WHERE project_id=?", (pid,))["n"] > 0
    assert c.request("DELETE", f"/api/projects/{pid}", json={"confirm": "drift"}, headers=H).status_code == 200
    for t in ("projects", "connectors", "runs", "blobs", "analyses", "kv", "files"):
        col = "id" if t == "projects" else "project_id"
        assert wb.store.one(f"SELECT count(*) AS n FROM {t} WHERE {col}=?", (pid,))["n"] == 0, t
    assert c.get(f"/api/projects/{pid}").status_code == 404
    assert len(c.get(f"/api/projects/{env['projects']['okta']['id']}/analysis/{env['projects']['okta']['ids']['okta']}").json()["apps"]) == 30


def test_18_passphrase_change_restart_and_lock(env):
    c = env["c"]
    new = "another long passphrase 42"
    assert c.post("/api/passphrase", json={"current": "wrong", "new": new}, headers=H).status_code == 401
    assert c.post("/api/passphrase", json={"current": PASS, "new": "short"}, headers=H).status_code == 400
    before = c.cookies.get("wb_session")
    assert c.post("/api/passphrase", json={"current": PASS, "new": new}, headers=H).status_code == 200
    okta = env["projects"]["okta"]
    assert c.get(f"/api/projects/{okta['id']}/analysis/{okta['ids']['okta']}").status_code == 200
    assert client(env["app"], {"wb_session": before}).get("/api/projects").status_code == 401      # sessions holding the old key are dead
    # a second instance on the same database: a restarted process (server mode) or another function instance (serverless)
    app2 = make_app(env["data"])
    st = client(app2).get("/api/state").json()
    assert st["initialised"] is True and st["signedIn"] is False and app2.state.setup_code is None
    carried = client(app2, {"wb_session": c.cookies.get("wb_session")}).get("/api/projects").status_code
    assert carried == (200 if MODE == "serverless" else 401)     # serverless: any instance reads the cookie; server: a restart seals everything
    c2 = client(app2)
    assert c2.get("/api/projects").status_code == 401
    assert c2.post("/api/login", json={"passphrase": PASS}, headers=H).status_code == 401           # the old passphrase is dead
    assert c2.post("/api/login", json={"passphrase": new}, headers=H).status_code == 200
    names = sorted(p["name"] for p in c2.get("/api/projects").json())
    assert names == ["failing", "keycloak", "okta", "onelogin", "ping"]
    a = c2.get(f"/api/projects/{okta['id']}/analysis/{okta['ids']['okta']}").json()
    assert a["summary"]["apps"] == 30 and a["tables"]["policies"][0]["parity"] == "Raised"
    assert c2.post("/api/lock", headers=H).status_code == 200
    assert c2.get("/api/projects").status_code == 401
    if MODE == "serverless":
        assert c.get("/api/projects").status_code == 401            # lock ends every session on every instance
    for _ in range(5):
        assert c2.post("/api/login", json={"passphrase": "guess guess guess"}, headers=H).status_code == 401
    assert c2.post("/api/login", json={"passphrase": new}, headers=H).status_code == 429               # throttled after five failures
    assert client(env["app"]).post("/api/login", json={"passphrase": new}, headers=H).status_code == 429   # the throttle is shared, not per instance
    app2.state.wb.store.meta_set("fail", b"0:0")
    assert c.post("/api/login", json={"passphrase": new}, headers=H).status_code == 200
    env["pass"] = new


def test_19_cancel_a_running_collection(env, mocks):
    c = env["c"]
    pid = c.post("/api/projects", json={"name": "cancel"}, headers=H).json()["id"]
    cid = c.post(f"/api/projects/{pid}/connectors", json={"platform": "okta", "config": mocks["okta"]}, headers=H).json()["id"]
    run = c.post(f"/api/projects/{pid}/connectors/{cid}/collect", headers=H).json()
    kick(c, [run])
    time.sleep(1.5)
    assert c.get(f"/api/runs/{run['id']}").json()["status"] == "running"
    assert c.post(f"/api/runs/{run['id']}/cancel", headers=H).status_code == 200
    st = wait_runs(c, [run], kicked=True)[run["id"]]
    assert st["status"] == "cancelled"
    assert c.get(f"/api/projects/{pid}/analysis/{cid}").status_code == 404                 # a cancelled run leaves no half snapshot
    assert env["app"].state.wb.store.one("SELECT count(*) AS n FROM blobs WHERE project_id=?", (pid,))["n"] == 0
    assert c.post(f"/api/runs/{run['id']}/cancel", headers=H).status_code == 409
    queued = c.post(f"/api/projects/{pid}/connectors/{cid}/collect", headers=H).json()
    if MODE == "serverless":                                                                # nobody picked it up yet: cancelled at once
        assert c.post(f"/api/runs/{queued['id']}/cancel", headers=H).status_code == 200
        assert c.get(f"/api/runs/{queued['id']}").json()["status"] == "cancelled"
        assert c.post(f"/api/runs/{queued['id']}/execute", headers=H).json()["status"] == "cancelled"
    else:
        c.post(f"/api/runs/{queued['id']}/cancel", headers=H)
        wait_runs(c, [queued])


def test_20_instances_share_nothing_but_the_database(env, mocks):
    """The serverless property: any instance can serve any request. Two instances, one database, no shared memory."""
    x, y = make_app(env["data"], serverless=True, secret="shared"), make_app(env["data"], serverless=True, secret="shared")
    cx = client(x)
    assert cx.post("/api/login", json={"passphrase": env["pass"]}, headers=H).status_code == 200
    cy = client(y, {"wb_session": cx.cookies.get("wb_session")})
    assert "Secure" in cx.post("/api/login", json={"passphrase": env["pass"]}, headers=H).headers["set-cookie"]
    pid = cx.post("/api/projects", json={"name": "two instances"}, headers=H).json()["id"]
    cid = cy.post(f"/api/projects/{pid}/connectors", json={"platform": "pingone", "config": mocks["pingone"]}, headers=H).json()["id"]
    run = cx.post(f"/api/projects/{pid}/connectors/{cid}/collect", headers=H).json()
    assert run["status"] == "queued" and cy.get(f"/api/runs/{run['id']}").json()["status"] == "queued"   # serverless: nothing runs by itself
    done = cy.post(f"/api/runs/{run['id']}/execute", headers=H).json()                                    # queued on X, executed on Y
    assert done["status"] == "done" and cx.get(f"/api/runs/{run['id']}").json()["status"] == "done"
    assert cy.post(f"/api/runs/{run['id']}/execute", headers=H).json()["status"] == "done"                # a second worker finds nothing to do
    assert cx.get(f"/api/projects/{pid}/analysis/{cid}").json()["summary"]["apps"] == 9                   # read on X
    z = make_app(env["data"], serverless=True, secret="another secret")
    assert client(z, {"wb_session": cx.cookies.get("wb_session")}).get("/api/projects").status_code == 401
    # a worker that dies (function timeout) leaves a run that never reports back: it is closed after a silence
    stuck = cx.post(f"/api/projects/{pid}/connectors/{cid}/collect", headers=H).json()
    x.state.wb.store.execute("UPDATE runs SET status='running', heartbeat='2020-01-01T00:00:00Z' WHERE id=?", (stuck["id"],))
    assert cy.get(f"/api/runs/{stuck['id']}").json()["status"] == "interrupted"
    assert cx.post(f"/api/projects/{pid}/connectors/{cid}/collect", headers=H).status_code == 200         # and no longer blocks the connector
    assert cx.request("DELETE", f"/api/projects/{pid}", json={"confirm": "two instances"}, headers=H).status_code == 409
    for r in cx.get(f"/api/projects/{pid}/runs").json():
        if r["status"] == "queued":
            cx.post(f"/api/runs/{r['id']}/cancel", headers=H)
    assert cx.request("DELETE", f"/api/projects/{pid}", json={"confirm": "two instances"}, headers=H).status_code == 200


def test_21_public_deployment_rules(env, monkeypatch):
    """On a public deployment connectors refuse plain http and hosts on private networks."""
    from workbench.collectors import MODULES
    from workbench.httpc import HttpError, ReadOnlyClient
    monkeypatch.setenv("WORKBENCH_PUBLIC", "1")
    for base, why in (("http://tenant.example.com", "https"), ("https://localhost", "non-public"), ("https://127.0.0.1:9999", "non-public"),
                      ("https://169.254.169.254", "non-public"), ("https://10.1.2.3", "non-public"), ("https://[::1]", "non-public")):
        with pytest.raises(HttpError, match=why):
            ReadOnlyClient([base])
    with pytest.raises(HttpError, match="https"):                                           # the lab switch is ignored
        MODULES["keycloak"].Connector({"baseUrl": "http://kc.example.com", "realm": "r", "clientId": "c", "clientSecret": "s", "allowInsecure": True})
    c = env["c"]
    pid = c.post("/api/projects", json={"name": "public"}, headers=H).json()["id"]
    r = c.post(f"/api/projects/{pid}/connectors", json={"platform": "pingfederate", "config": {"adminUrl": "https://127.0.0.1:9999", "username": "a", "password": "b"}}, headers=H)
    assert r.status_code == 400 and "non-public" in r.json()["error"]
    monkeypatch.delenv("WORKBENCH_PUBLIC")
    not_configured = create_app(str(env["data"]), serverless=True, session_secret=None)
    r = client(not_configured).get("/api/state")
    assert r.status_code == 503 and "WORKBENCH_SESSION_SECRET" in r.json()["error"]
