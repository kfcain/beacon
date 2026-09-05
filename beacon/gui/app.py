"""FastAPI GUI: Dashboard, Freshness, Validation, Push, System."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from beacon.config import load_settings
from beacon.errors import BeaconError
from beacon.plugins.spec import CollectContext
from beacon.push import write_pack
from beacon.scf.engine import collect_all, collect_target
from beacon.workspace import freshness, system_status, validation

STATIC_DIR = Path(__file__).resolve().parent / "static"


class CollectBody(BaseModel):
    target: str | None = None
    live: bool | None = None


def create_app() -> FastAPI:
    app = FastAPI(title="Beacon", version="0.1.0")
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    @app.get("/api/dashboard")
    def api_dashboard() -> JSONResponse:
        status = system_status(load_settings())
        fresh = freshness(load_settings())
        return JSONResponse(
            {
                "status": status,
                "freshness": fresh,
                "pages": ["dashboard", "freshness", "validation", "push", "system"],
            }
        )

    @app.get("/api/freshness")
    def api_freshness() -> JSONResponse:
        return JSONResponse({"items": freshness(load_settings())})

    @app.get("/api/validation")
    def api_validation() -> JSONResponse:
        return JSONResponse(validation(load_settings()))

    @app.post("/api/push")
    def api_push() -> JSONResponse:
        try:
            path = write_pack(load_settings(), None)
        except BeaconError as exc:
            return JSONResponse({"ok": False, "code": exc.code, "error": str(exc)}, status_code=400)
        return JSONResponse({"ok": True, "path": str(path)})

    @app.get("/api/system")
    def api_system() -> JSONResponse:
        return JSONResponse(system_status(load_settings()))

    @app.post("/api/collect")
    def api_collect(payload: CollectBody = CollectBody()) -> JSONResponse:
        settings = load_settings()
        target = payload.target
        ctx = CollectContext(target=target, live=payload.live)
        try:
            if target:
                result = collect_target(settings, str(target), ctx, checkpoint=True)
            else:
                result = collect_all(settings, ctx, checkpoint=True)
        except BeaconError as exc:
            return JSONResponse({"ok": False, "code": exc.code, "error": str(exc)}, status_code=400)
        return JSONResponse(result)

    return app
