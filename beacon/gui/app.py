"""Scoped evidence console. Local by default; remote API requires a bearer token."""
from __future__ import annotations

import hmac
import os
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict
from starlette.middleware.trustedhost import TrustedHostMiddleware

from beacon.assurance.bedrock import make_judge
from beacon.assurance.evaluation import evaluate_control, list_receipts, rules_for
from beacon.assurance.index import load_evidence_ledger
from beacon.config import load_settings
from beacon.errors import BeaconError
from beacon.plugins.spec import CollectContext
from beacon.push import write_pack
from beacon.scf.engine import collect_all, collect_named, collect_target
from beacon.scf.objective_catalog import objectives
from beacon.scope.store import list_scopes, load_scope
from beacon.workspace import freshness, system_status, validation

STATIC_DIR = Path(__file__).resolve().parent / "static"
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "[::1]", "::1", "testserver"})


class CollectBody(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    target: str | None = None
    plugin: str | None = None
    scope_id: str | None = None
    live: bool = False


class EvaluateBody(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    scope_id: str
    control_ref: str
    judge: Literal["none", "jev", "bedrock"] = "none"


def create_app() -> FastAPI:
    app = FastAPI(title="Beacon", version="0.1.0")
    token = os.environ.get("BEACON_API_TOKEN", "")
    hosts = [host.strip() for host in os.environ.get("BEACON_ALLOWED_HOSTS", "localhost,127.0.0.1,[::1],testserver").split(",") if host.strip()]
    # `beacon serve` checks the bind address; this also covers an app started by another ASGI server.
    if not token and any(host not in LOOPBACK_HOSTS for host in hosts):
        raise BeaconError("E_AUTH", "a non-loopback BEACON_ALLOWED_HOSTS entry requires BEACON_API_TOKEN")
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=hosts)

    @app.middleware("http")
    async def protect(request: Request, call_next):
        if request.url.path.startswith("/api/"):
            if token and not hmac.compare_digest(request.headers.get("authorization", "").encode(), f"Bearer {token}".encode()):
                return JSONResponse({"ok": False, "code": "E_AUTH", "error": "Bearer token required"}, status_code=401)
            origin = request.headers.get("origin")
            if origin and urlsplit(origin).netloc != request.headers.get("host"):
                return JSONResponse({"ok": False, "code": "E_ORIGIN"}, status_code=403)
            if request.method not in {"GET", "HEAD", "OPTIONS"} and request.headers.get("x-beacon-request") != "1":
                return JSONResponse({"ok": False, "code": "E_CSRF"}, status_code=403)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(BeaconError)
    async def beacon_error(_request, exc):
        return JSONResponse({"ok": False, "code": exc.code, "error": str(exc)}, status_code=400)

    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.get("/")
    def index():
        return FileResponse(STATIC_DIR / "index.html")

    @app.get("/api/dashboard")
    def dashboard():
        settings = load_settings()
        return {"status": system_status(settings), "freshness": freshness(settings),
                "pages": ["dashboard", "assessment", "freshness", "validation", "push", "system"]}

    @app.get("/api/freshness")
    def api_freshness():
        return {"items": freshness(load_settings())}

    @app.get("/api/validation")
    def api_validation():
        return validation(load_settings())

    @app.get("/api/system")
    def api_system():
        return system_status(load_settings())

    @app.get("/api/scopes")
    def api_scopes():
        return {"scopes": list_scopes(load_settings())}

    @app.get("/api/objectives")
    def api_objectives(control: str):
        return {"objectives": objectives(control.upper()), "rules": rules_for(control.upper())}

    @app.get("/api/ledger")
    def api_ledger(scope_id: str | None = None):
        return load_evidence_ledger(load_settings(), scope_id=scope_id).model_dump(mode="json")

    @app.get("/api/receipts")
    def api_receipts(scope_id: str | None = None):
        return {"receipts": list_receipts(load_settings(), scope_id=scope_id)}

    @app.post("/api/evaluate")
    def api_evaluate(payload: EvaluateBody):
        settings = load_settings()
        scope = load_scope(settings, payload.scope_id)
        return evaluate_control(settings, scope_id=payload.scope_id, control_ref=payload.control_ref.upper(),
                                judge=make_judge(payload.judge, scope))

    @app.post("/api/push")
    def api_push():
        result = write_pack(load_settings(), None)
        return {"ok": True, "path": str(result.path), "remote": result.remote}

    @app.post("/api/collect")
    def api_collect(payload: CollectBody):
        settings = load_settings()
        ctx = CollectContext(target=payload.target, live=payload.live)
        if payload.plugin:
            return collect_named(settings, payload.plugin, ctx, scope_id=payload.scope_id)
        if payload.target:
            return collect_target(settings, payload.target, ctx, scope_id=payload.scope_id)
        return collect_all(settings, ctx, scope_id=payload.scope_id)

    return app
