"""
AegisScan Web UI Module

Provides FastAPI application and routes for the AegisScan network security scanning tool.
"""

__version__ = "1.0.0"
__all__ = ["create_app"]

from aegisscan.web.app import create_app
