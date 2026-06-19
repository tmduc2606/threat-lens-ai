from __future__ import annotations
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from .config import get_settings
from .database import engine
from .models.base import Base
# IMPORTANT:
# Importing the models package ensures SQLAlchemy registers every table
# before Base.metadata.create_all() runs.
from . import models as _models  # noqa: F401

from .routers.feedback import router as feedback_router
from .routers.health import router as health_router
from .routers.intel import router as intel_router
from .routers.modeling import router as modeling_router
from .routers.recent import router as recent_router
from .routers.scan import router as scan_router
from .routers.search import router as search_router
from .routers.tips import router as tips_router
from .routers.admin import router as admin_router

settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    version="2.0.0",
    description=(
        "ThreatLensAI backend for a VirusTotal-style scan interface. "
        "Supports IP, domain, CVE, and OTX pulse lookups, plus joblib model plug-ins."
    ),
)

allow_origins = ["*"] if settings.cors_origins == ["*"] else settings.cors_origins

app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(health_router, prefix="/api")
app.include_router(scan_router, prefix="/api")
app.include_router(search_router, prefix="/api")
app.include_router(intel_router, prefix="/api")
app.include_router(recent_router, prefix="/api")
app.include_router(feedback_router, prefix="/api")
app.include_router(modeling_router, prefix="/api")
app.include_router(tips_router, prefix="/api")
app.include_router(admin_router, prefix="/api")


@app.on_event("startup")
def on_startup():
    # Ensures all tables from backend/app/models are created.
    Base.metadata.create_all(bind=engine)


# Serve frontend static files (HTML, JS, CSS) at /
# API routes are registered first (with /api prefix), so they take precedence.
frontend_path = Path(__file__).resolve().parent.parent.parent / "frontend"
if frontend_path.is_dir():
    app.mount(
        "/",
        StaticFiles(directory=str(frontend_path), html=True),
        name="frontend",
    )