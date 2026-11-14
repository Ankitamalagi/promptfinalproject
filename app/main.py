"""
Prompt Injection Security Gateway - Main FastAPI Application.

This is the entry point for the gateway service. It creates the FastAPI app,
configures routes, and sets up middleware.
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, FileResponse

from app.core.config import get_settings
from app.audit.database import init_db
from app.api import health, scan, chat, config, logs


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events - startup and shutdown."""
    # Startup: initialize database tables
    print("Starting Prompt Injection Security Gateway...")
    init_db()
    yield
    # Shutdown: cleanup
    print("Shutting down...")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    settings = get_settings()

    app = FastAPI(
        title="Prompt Injection Security Gateway",
        description=(
            "A security middleware that analyzes untrusted text before "
            "optionally forwarding to an LLM provider."
        ),
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # Include API routers
    app.include_router(health.router, prefix="/api", tags=["Health"])
    app.include_router(scan.router, prefix="/api", tags=["Scan"])
    app.include_router(chat.router, prefix="/api", tags=["Chat"])
    app.include_router(config.router, prefix="/api", tags=["Config"])
    app.include_router(logs.router, prefix="/api", tags=["Logs"])

    # Mount static files for dashboard
    app.mount("/static", StaticFiles(directory="app/static"), name="static")

    # Dashboard endpoint
    @app.get("/dashboard", include_in_schema=False)
    async def dashboard():
        return FileResponse("app/static/index.html")

    # Root endpoint - redirect to docs and dashboard
    @app.get("/", include_in_schema=False)
    async def root():
        return JSONResponse(
            content={
                "name": "Prompt Injection Security Gateway",
                "version": "0.1.0",
                "dashboard": "/dashboard",
                "docs": "/docs",
                "health": "/api/health",
            }
        )

    return app


# Create the app instance
app = create_app()


if __name__ == "__main__":
    import uvicorn

    settings = get_settings()
    uvicorn.run(
        "app.main:app",
        host=settings.app_host,
        port=settings.app_port,
        reload=settings.app_env == "development",
    )