from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import health, scans
from app.core.config import settings
from app.core.logging import configure_logging, get_logger
from app.db.session import init_db


@asynccontextmanager
async def lifespan(_: FastAPI):
    configure_logging()
    init_db()
    get_logger(__name__).info(
        "application_started",
        extra={"mode": settings.default_scan_mode, "database_url": settings.database_url},
    )
    yield


app = FastAPI(
    title="App Security Audit API",
    version="0.1.0",
    description="API read-only para avaliacao de seguranca e performance em Linux.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["Authorization", "Content-Type", "X-API-Token", "Accept", "Origin"],
)

app.include_router(health.router, prefix="/api/v1", tags=["health"])
app.include_router(scans.router, prefix="/api/v1", tags=["scans"])


@app.get("/")
def root() -> dict:
    return {
        "service": "App Security Audit API",
        "status": "ok",
        "docs": "/docs",
        "health": "/api/v1/health",
        "scans": "/api/v1/scans",
    }
