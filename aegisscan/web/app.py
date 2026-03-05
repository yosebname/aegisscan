"""
FastAPI application factory and configuration.

Handles application initialization, CORS setup, static files, templates,
and database lifecycle management.
"""

from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Callable

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from aegisscan.web.routes import router


def create_app(config: dict[str, Any] | None = None) -> FastAPI:
    """
    Create and configure the FastAPI application.

    Args:
        config: Configuration dictionary with optional keys:
            - allowed_origins: List of allowed CORS origins (default: localhost:3000, :5000)
            - debug: Enable debug mode (default: False)
            - database_url: Database connection URL
            - scan_timeout: Scan operation timeout in seconds (default: 3600)

    Returns:
        Configured FastAPI application instance.
    """
    config = config or {}

    # Extract configuration with sensible defaults
    allowed_origins = config.get("allowed_origins", ["http://localhost:3000", "http://localhost:5000"])
    debug = config.get("debug", False)
    database_url = config.get("database_url", "sqlite:///./aegisscan.db")
    scan_timeout = config.get("scan_timeout", 3600)

    # Define lifespan event handlers
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        """
        Manage application lifespan events.

        Handles startup and shutdown operations, including database initialization.
        """
        # Startup
        app.state.database_url = database_url
        app.state.scan_timeout = scan_timeout
        # Database initialization would happen here if needed
        # await init_database(database_url)

        yield

        # Shutdown
        # Cleanup would happen here (close DB connections, etc.)
        pass

    # Create FastAPI application
    app = FastAPI(
        title="AegisScan Web UI",
        description="Network security scanning and vulnerability assessment platform",
        version="1.0.0",
        lifespan=lifespan,
        debug=debug,
    )

    # Configure CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Setup static files directory
    static_dir = Path(__file__).parent / "static"
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    # Setup template directory
    templates_dir = Path(__file__).parent / "templates"
    if templates_dir.exists():
        app.state.templates = Jinja2Templates(directory=str(templates_dir))

    # Include API routers
    app.include_router(router)

    return app
