"""Database module for AegisScan.

Provides SQLAlchemy ORM models and session management for scan data persistence.
Supports SQLite (development) and PostgreSQL (production) backends.
"""

from aegisscan.db.database import DatabaseManager
from aegisscan.db.models import (
    Base,
    ScanRun,
    Host,
    Port,
    Service,
    Banner,
    TLSCert,
    NmapObservation,
    ExternalObservation,
    DiffFinding,
)

__all__ = [
    "Base",
    "DatabaseManager",
    "ScanRun",
    "Host",
    "Port",
    "Service",
    "Banner",
    "TLSCert",
    "NmapObservation",
    "ExternalObservation",
    "DiffFinding",
]
