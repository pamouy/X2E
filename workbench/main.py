"""HTTP API and static web UI.

Two modes, one code base:
  server      one long-lived process (container, VM). SQLite by default, collections in background threads.
  serverless  short-lived instances (Vercel). Postgres, stateless sessions, collections inside a request.
"""
from __future__ import annotations

import os
import secrets
from pathlib import Path

from fastapi import FastAPI, File, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, Response

from . import __version__
from .collectors import describe
from .service import ApiError, Workbench, set_request_kek
from .store import StoreError, open_store

STATIC = Path(__file__).parent / "static"
COOKIE = "wb_session"
PUBLIC = {"/api/state", "/api/setup", "/api/login", "/api/logout"}
NO_REFRESH = PUBLIC | {"/api/lock", "/api/passphrase"}


def create_app(data_dir: str | None = None, serverless: bool | None = None, session_secret: str | None = None,
               setup_code: str | None = None, store=None) -> FastAPI:
    if serverless is None:
        serverless = bool(os.environ.get("VERCEL")) or os.environ.get("WORKBENCH_MODE") == "serverless"
    session_secret = session_secret or os.environ.get("WORKBENCH_SESSION_SECRET")
    setup_code = setup_code or os.environ.get("WORKBENCH_SETUP_CODE")
    app = FastAPI(title="Entra Migration Workbench", version=__version__, docs_url=None, redoc_url=None, openapi_url=None)
    problem = None
    wb = None
    if serverless and not session_secret:
        problem = "WORKBENCH_SESSION_SECRET is not set. Every instance needs the same secret to read session cookies."
    else:
        try:
            wb = Workbench(data_dir, workers=int(os.environ.get("WORKBENCH_WORKERS", "4")), store=store or open_store(data_dir),
                           session_secret=session_secret, threaded=not serverless)
        except StoreError as exc:
            problem = str(exc)
    app.state.wb = wb
    app.state.setup_code = None
    if wb and not wb.initialised:
        if setup_code:
            app.state.setup_code = setup_code.strip().upper()
        elif not serverless:
            app.state.setup_code = secrets.token_hex(4).upper()
            print(f"\n  Entra Migration Workbench: first start.\n  Setup code: {app.state.setup_code}\n  Open the web UI and enter it to set the passphrase.\n", flush=True)
    secure_cookie = serverless or os.environ.get("WORKBENCH_COOKIE_SECURE", "0") == "1"
    if os.environ.get("WORKBENCH_COOKIE_SECURE") == "0":
        secure_cookie = False

    @app.exception_handler(ApiError)
    async def api_error(_req: Request, exc: ApiError):
        return JSONResponse({"error": str(exc)}, status_code=exc.status)

    @app.middleware("http")
    async def guard(request: Request, call_next):
        path = request.url.path
        session = None
        if path.startswith("/api/"):
            if problem:
                return JSONResponse({"error": f"Not configured: {problem}"}, status_code=503)
            if request.method not in ("GET", "HEAD") and request.headers.get("x-workbench") != "1":
                return JSONResponse({"error": "Missing request header"}, status_code=403)       # blocks cross-site form posts
            session = wb.open_session(request.cookies.get(COOKIE))
            set_request_kek(session[0] if session else None)
            if path not in PUBLIC and not session:
                return JSONResponse({"error": "Sign in first"}, status_code=401)
        response = await call_next(request)
        if session and path not in NO_REFRESH and response.status_code < 500:
            set_cookie(response, session[1])                                                     # sliding idle timeout
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Robots-Tag"] = "noindex, nofollow"
        response.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        if path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    def set_cookie(resp: Response, token: str) -> Response:
        resp.set_cookie(COOKIE, token, httponly=True, samesite="strict", secure=secure_cookie, path="/")
        return resp

    def drop_cookie(resp: Response) -> Response:
        resp.delete_cookie(COOKIE, path="/", httponly=True, samesite="strict", secure=secure_cookie)
        return resp

    async def body(request: Request) -> dict:
        try:
            data = await request.json()
        except Exception as exc:
            raise ApiError(400, "The request body is not JSON") from exc
        if not isinstance(data, dict):
            raise ApiError(400, "The request body must be an object")
        return data

    # ---- session ------------------------------------------------------------------------------
    @app.get("/api/state")
    def state(request: Request):
        signed_in = wb.open_session(request.cookies.get(COOKIE)) is not None
        return {"version": __version__, "initialised": wb.initialised, "unlocked": signed_in, "signedIn": signed_in,
                "mode": "serverless" if serverless else "server", "database": wb.store.backend}

    @app.post("/api/setup")
    async def setup(request: Request):
        data = await body(request)
        if wb.initialised:
            raise ApiError(409, "Already set up")
        if not app.state.setup_code:
            raise ApiError(403, "Setup is disabled: set WORKBENCH_SETUP_CODE in the environment and redeploy")
        if not secrets.compare_digest(str(data.get("setupCode", "")).strip().upper(), app.state.setup_code):
            raise ApiError(403, "Wrong setup code")
        token = wb.setup(data.get("passphrase", ""))
        app.state.setup_code = None
        return set_cookie(JSONResponse({"ok": True}), token)

    @app.post("/api/login")
    async def login(request: Request):
        data = await body(request)
        return set_cookie(JSONResponse({"ok": True}), wb.login(data.get("passphrase", "")))

    @app.post("/api/logout")
    async def logout():
        return drop_cookie(JSONResponse({"ok": True}))

    @app.post("/api/lock")
    def lock():
        wb.lock()
        return drop_cookie(JSONResponse({"ok": True}))

    @app.post("/api/passphrase")
    async def passphrase(request: Request):
        data = await body(request)
        return set_cookie(JSONResponse({"ok": True}), wb.change_passphrase(data.get("current", ""), data.get("new", "")))

    @app.get("/api/platforms")
    async def platforms():
        return describe()

    # ---- projects -----------------------------------------------------------------------------
    @app.get("/api/projects")
    def projects():
        return wb.projects()

    @app.post("/api/projects")
    async def create_project(request: Request):
        data = await body(request)
        return wb.create_project(data.get("name", ""), data.get("client", ""), data.get("description", ""))

    @app.get("/api/projects/{pid}")
    def project(pid: str):
        return wb.project(pid)

    @app.patch("/api/projects/{pid}")
    async def update_project(pid: str, request: Request):
        return wb.update_project(pid, await body(request))

    @app.delete("/api/projects/{pid}")
    async def delete_project(pid: str, request: Request):
        wb.delete_project(pid, (await body(request)).get("confirm", ""))
        return {"ok": True}

    @app.get("/api/projects/{pid}/audit")
    def audit(pid: str):
        return wb.audit_trail(pid)

    # ---- connectors ---------------------------------------------------------------------------
    @app.post("/api/projects/{pid}/connectors")
    async def add_connector(pid: str, request: Request):
        data = await body(request)
        return wb.add_connector(pid, data.get("platform", ""), data.get("name", ""), data.get("config") or {})

    @app.put("/api/projects/{pid}/connectors/{cid}")
    async def update_connector(pid: str, cid: str, request: Request):
        data = await body(request)
        return wb.update_connector(pid, cid, data.get("name"), data.get("config"))

    @app.delete("/api/projects/{pid}/connectors/{cid}")
    def delete_connector(pid: str, cid: str):
        wb.delete_connector(pid, cid)
        return {"ok": True}

    @app.post("/api/projects/{pid}/connectors/{cid}/test")
    def test_connector(pid: str, cid: str):
        return wb.test_connector(pid, cid)

    @app.post("/api/projects/{pid}/connectors/{cid}/files")
    async def add_file(pid: str, cid: str, file: UploadFile = File(...)):
        return wb.add_file(pid, cid, file.filename or "audit.log", await file.read())

    @app.delete("/api/projects/{pid}/connectors/{cid}/files/{fid}")
    def delete_file(pid: str, cid: str, fid: str):
        wb.delete_file(pid, cid, fid)
        return {"ok": True}

    # ---- runs and analyses --------------------------------------------------------------------
    @app.post("/api/projects/{pid}/connectors/{cid}/collect")
    def collect(pid: str, cid: str):
        return wb.start_collection(pid, cid)

    @app.post("/api/projects/{pid}/collect")
    def collect_all(pid: str):
        return wb.start_all(pid)

    @app.get("/api/projects/{pid}/runs")
    def runs(pid: str):
        return wb.runs(pid)

    @app.get("/api/runs/{rid}")
    def run(rid: str):
        return wb.run(rid)

    @app.post("/api/runs/{rid}/execute")
    def execute(rid: str):
        """Serverless mode: the collection runs inside this request and ends with it. Server mode: answers at once,
        because a background thread already has the run."""
        return wb.execute_run(rid)

    @app.post("/api/runs/{rid}/cancel")
    def cancel(rid: str):
        wb.cancel_run(rid)
        return {"ok": True}

    @app.post("/api/projects/{pid}/analyse")
    def analyse(pid: str):
        return {"analysed": wb.analyse_project(pid)}

    @app.get("/api/projects/{pid}/analysis/{cid}")
    def analysis(pid: str, cid: str):
        return wb.analysis(pid, cid)

    @app.put("/api/projects/{pid}/tracking/{cid}")
    async def tracking(pid: str, cid: str, request: Request):
        data = await body(request)
        wb.set_tracking(pid, cid, str(data.get("appId", "")), data)
        return {"ok": True}

    @app.put("/api/projects/{pid}/checks/{cid}")
    async def checks(pid: str, cid: str, request: Request):
        data = await body(request)
        wb.set_check(pid, cid, str(data.get("kind", "")), str(data.get("id", "")), data)
        return {"ok": True}

    @app.get("/api/projects/{pid}/export/{cid}/{fmt}")
    def export(pid: str, cid: str, fmt: str):
        blob, mime, name = wb.export(pid, cid, fmt)
        return Response(blob, media_type=mime, headers={"Content-Disposition": f'attachment; filename="{name}"'})

    @app.get("/api/projects/{pid}/evidence")
    def evidence(pid: str):
        blob, name = wb.evidence(pid)
        return Response(blob, media_type="application/zip", headers={"Content-Disposition": f'attachment; filename="{name}"'})

    # ---- web UI -------------------------------------------------------------------------------
    @app.get("/")
    async def index():
        return FileResponse(STATIC / "index.html", headers={"Cache-Control": "no-cache"})

    @app.get("/static/{name}")
    async def static(name: str):
        target = (STATIC / name).resolve()
        if target.parent != STATIC.resolve() or not target.is_file():
            return JSONResponse({"error": "Not found"}, status_code=404)
        return FileResponse(target, headers={"Cache-Control": "no-cache"})

    @app.get("/healthz")
    async def healthz():
        return {"ok": problem is None, "mode": "serverless" if serverless else "server"}

    return app


def run() -> None:
    import uvicorn
    host = os.environ.get("WORKBENCH_HOST", "127.0.0.1")
    port = int(os.environ.get("WORKBENCH_PORT", "8080"))
    cert, key = os.environ.get("WORKBENCH_TLS_CERT"), os.environ.get("WORKBENCH_TLS_KEY")
    uvicorn.run(create_app(), host=host, port=port, ssl_certfile=cert, ssl_keyfile=key, log_level="warning", server_header=False)


if __name__ == "__main__":
    run()
