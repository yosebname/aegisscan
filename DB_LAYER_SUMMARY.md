# AegisScan Database Layer Implementation

## Overview
Production-quality database layer for AegisScan vulnerability scanning platform, built with SQLAlchemy ORM supporting SQLite (development) and PostgreSQL (production).

## File Structure

```
aegisscan/
├── __init__.py              # Package initialization with version info
└── db/
    ├── __init__.py          # Database module exports
    ├── models.py            # SQLAlchemy ORM models (9 entities)
    └── database.py          # Session management & CRUD operations
```

## File Details

### 1. `aegisscan/__init__.py`
**Purpose:** Main package initialization with version tracking

**Contents:**
- Version string: `1.0.0`
- Author attribution
- License declaration
- Clean package exports via `__all__`

### 2. `aegisscan/db/__init__.py`
**Purpose:** Database module exports for clean imports

**Exports:**
- `DatabaseManager` - Connection & session management
- All 9 ORM models (ScanRun, Host, Port, Service, Banner, TLSCert, NmapObservation, ExternalObservation, DiffFinding)
- `Base` - SQLAlchemy declarative base

**Usage:**
```python
from aegisscan.db import DatabaseManager, Host, Port
```

## Data Models (9 entities)

### Core Entities

#### 1. **ScanRun**
Represents a single vulnerability scan execution.

| Field | Type | Notes |
|-------|------|-------|
| id | Integer | Primary key, indexed |
| start_time | DateTime | Indexed, defaults to UTC now |
| end_time | DateTime | Nullable, indexed |
| targets | JSON | Scan target specifications |
| config_hash | String(64) | SHA256 hash, indexed for deduplication |
| engine_version | String(32) | Scanning engine version |
| status | String(32) | pending/running/completed/failed, indexed |

**Relationships:**
- Has many NmapObservation (cascade delete)
- Has many DiffFinding (cascade delete)

**Indexes:**
- Composite: (status, start_time)
- Single: config_hash

---

#### 2. **Host**
Discovered network host with metadata.

| Field | Type | Notes |
|-------|------|-------|
| id | Integer | Primary key, indexed |
| ip | String(45) | Unique, indexed (IPv4/IPv6) |
| hostname | String(255) | Nullable, indexed |
| tags | JSON | Custom metadata tags |
| first_seen | DateTime | Indexed, temporal tracking |
| last_seen | DateTime | Indexed, temporal tracking |

**Relationships:**
- Has many Port (cascade delete)
- Has many Service (cascade delete)
- Has many Banner (cascade delete)
- Has many TLSCert (cascade delete)
- Has many NmapObservation (cascade delete)
- Has many ExternalObservation (cascade delete)

**Indexes:**
- Composite: (ip, last_seen)
- Single: hostname

---

#### 3. **Port**
Open or filtered port on a host.

| Field | Type | Notes |
|-------|------|-------|
| id | Integer | Primary key |
| host_id | Integer | FK to Host, indexed |
| port_number | Integer | Indexed (1-65535) |
| protocol | String(8) | tcp/udp, indexed |
| state_connect | String(32) | Connection test state |
| state_syn | String(32) | SYN scan state |
| rtt_ms | Float | Millisecond latency |
| first_seen | DateTime | Indexed |
| last_seen | DateTime | Indexed |

**Relationships:**
- Belongs to Host

**Indexes:**
- Composite: (host_id, port_number, protocol) - unique constraint
- Composite: (host_id, port_number, protocol) - regular index
- Single: last_seen

---

#### 4. **Service**
Detected service running on host:port.

| Field | Type | Notes |
|-------|------|-------|
| id | Integer | Primary key |
| host_id | Integer | FK to Host, indexed |
| port_number | Integer | Indexed |
| detected_service | String(128) | Service name, indexed |
| product | String(255) | Software product, indexed |
| version | String(128) | Product version |
| confidence | Float | Detection confidence (0-1) |
| source | String(64) | nmap/banner_grab/etc, indexed |

**Relationships:**
- Belongs to Host

**Indexes:**
- Composite: (host_id, port_number)
- Composite: (product, version)

---

#### 5. **Banner**
Raw service banner/greeting data.

| Field | Type | Notes |
|-------|------|-------|
| id | Integer | Primary key |
| host_id | Integer | FK to Host, indexed |
| port_number | Integer | Indexed |
| raw_banner | Text | Complete banner text |
| parsed_fields | JSON | Extracted structured fields |
| collected_at | DateTime | Indexed, collection timestamp |

**Relationships:**
- Belongs to Host

**Indexes:**
- Composite: (host_id, port_number)
- Single: collected_at

---

#### 6. **TLSCert**
TLS/SSL certificate extracted from service.

| Field | Type | Notes |
|-------|------|-------|
| id | Integer | Primary key |
| host_id | Integer | FK to Host, indexed |
| port_number | Integer | Indexed |
| sni | String(255) | Server Name Indication, indexed |
| subject | Text | Certificate subject DN |
| issuer | Text | Certificate issuer DN |
| not_before | DateTime | Validity start, indexed |
| not_after | DateTime | Validity end, indexed |
| san_list | JSON | Subject Alternative Names |
| fingerprint_sha256 | String(64) | Unique, indexed |
| serial_number | String(128) | Indexed |
| sig_algorithm | String(64) | Signature algorithm |

**Relationships:**
- Belongs to Host

**Indexes:**
- Composite: (host_id, port_number)
- Composite: (subject) - for CN/SAN searches
- Single: not_after - for expiration tracking
- Single: fingerprint_sha256 - unique constraint

---

#### 7. **NmapObservation**
Nmap-specific service and NSE script observations.

| Field | Type | Notes |
|-------|------|-------|
| id | Integer | Primary key |
| host_id | Integer | FK to Host, indexed |
| port_number | Integer | Indexed |
| nmap_service | String(128) | Nmap detected service |
| nmap_version | String(128) | Nmap version detection |
| scripts_summary | JSON | NSE script output summaries |
| scan_run_id | Integer | FK to ScanRun, indexed |

**Relationships:**
- Belongs to Host
- Belongs to ScanRun

**Indexes:**
- Composite: (host_id, port_number)
- Single: scan_run_id

---

#### 8. **ExternalObservation**
Multi-source external intelligence (Shodan, Censys, etc).

| Field | Type | Notes |
|-------|------|-------|
| id | Integer | Primary key |
| source | String(64) | Data source, indexed |
| host_id | Integer | FK to Host, indexed |
| port_number | Integer | Indexed |
| service | String(128) | Detected service |
| banner | Text | Service banner |
| last_seen | DateTime | Indexed, last observation |
| raw_data | JSON | Complete raw observation |

**Relationships:**
- Belongs to Host

**Indexes:**
- Composite: (source, host_id, port_number)
- Single: last_seen

---

#### 9. **DiffFinding**
Change/difference detected between scans.

| Field | Type | Notes |
|-------|------|-------|
| id | Integer | Primary key |
| scan_run_id | Integer | FK to ScanRun, indexed |
| finding_type | String(64) | new_port/closed_port/etc, indexed |
| severity | String(32) | critical/high/medium/low, indexed |
| summary | Text | Human-readable summary |
| evidence | JSON | Supporting evidence data |
| created_at | DateTime | Creation timestamp, indexed |

**Relationships:**
- Belongs to ScanRun

**Indexes:**
- Single: scan_run_id
- Single: severity
- Single: finding_type

---

## DatabaseManager Class

### Initialization
```python
db = DatabaseManager(
    database_url="sqlite:///aegisscan.db",  # or PostgreSQL
    echo=False,  # SQL logging
    pool_size=10,  # Connection pool (PostgreSQL)
    max_overflow=20  # Overflow connections
)
db.create_tables()
```

### Key Features

1. **Multi-Database Support**
   - SQLite with WAL mode, ForeignKey constraints, optimized pragmas
   - PostgreSQL with connection pooling, recycling, pre-ping

2. **Session Management**
   - Context manager for automatic commit/rollback
   - Exception handling with logging
   - Automatic session cleanup

3. **CRUD Operations**

#### Host Operations
```python
# Create or update (upsert)
host = db.create_or_update_host(
    ip="192.168.1.100",
    hostname="web-server.local",
    tags={"environment": "prod", "team": "infra"}
)

# Retrieve
host = db.get_host_by_ip("192.168.1.100")

# List with pagination
hosts = db.list_hosts(limit=100, offset=0)
```

#### Port Operations
```python
# Create or update (upsert)
port = db.create_or_update_port(
    host_id=1,
    port_number=443,
    protocol="tcp",
    state_connect="open",
    state_syn="open",
    rtt_ms=25.5
)

# Query
ports = db.get_ports_by_host(host_id=1)
open_ports = db.get_open_ports(host_id=1, protocol="tcp")
```

#### Service Operations
```python
service = db.create_service(
    host_id=1,
    port_number=443,
    detected_service="https",
    product="nginx",
    version="1.24.0",
    confidence=0.95,
    source="nmap"
)

services = db.get_services_by_host(host_id=1)
```

#### ScanRun Operations
```python
# Create scan run
scan = db.create_scan_run(
    targets={"networks": ["192.168.1.0/24"]},
    config_hash="abc123def456...",
    engine_version="1.0.0",
    status="pending"
)

# Update status
db.update_scan_run_status(scan.id, "running")
db.update_scan_run_status(scan.id, "completed")

# List
scans = db.list_scan_runs(status="completed", limit=10)
```

#### Certificate Operations
```python
cert = db.create_tls_cert(
    host_id=1,
    port_number=443,
    subject="CN=example.com,O=Example Inc",
    issuer="CN=Let's Encrypt Authority",
    not_before=datetime(2024, 1, 1),
    not_after=datetime(2025, 1, 1),
    fingerprint_sha256="abc123def456...",
    serial_number="12345678",
    sig_algorithm="sha256WithRSAEncryption",
    sni="example.com",
    san_list=["example.com", "www.example.com"]
)

certs = db.get_tls_certs_by_host(host_id=1)
```

#### Banner Operations
```python
banner = db.create_banner(
    host_id=1,
    port_number=22,
    raw_banner="SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
    parsed_fields={"protocol": "SSH-2.0", "software": "OpenSSH_8.2p1"}
)
```

#### Observation Operations
```python
# Nmap observations
nmap_obs = db.create_nmap_observation(
    host_id=1,
    port_number=443,
    nmap_service="https",
    nmap_version="nginx 1.24.0",
    scripts_summary={"ssl-cert": "..."},
    scan_run_id=1
)

# External observations (Shodan, Censys, etc)
ext_obs = db.create_external_observation(
    source="shodan",
    host_id=1,
    port_number=443,
    service="nginx",
    banner="Server: nginx",
    raw_data={"vulnerability": "log4shell"}
)
```

#### DiffFinding Operations
```python
finding = db.create_diff_finding(
    scan_run_id=1,
    finding_type="new_port",
    severity="high",
    summary="New HTTPS service detected on port 443",
    evidence={"port": 443, "protocol": "tcp", "service": "https"}
)

findings = db.get_diff_findings_by_scan(scan_run_id=1, severity="critical")
```

## Production Features

1. **Type Safety**
   - Full type hints (PEP 484)
   - Mapped columns for IDE autocomplete
   - TypeVar for generic operations

2. **Documentation**
   - Comprehensive docstrings (Google style)
   - Parameter descriptions with types
   - Return value documentation
   - Usage examples in class docstrings

3. **Error Handling**
   - SQLAlchemy exception catching
   - Structured logging with levels
   - Rollback on transaction failure
   - Automatic session cleanup

4. **Performance**
   - Strategic indexes on all FK relationships
   - Composite indexes for common queries
   - Connection pooling (PostgreSQL)
   - SQLite optimization pragmas (WAL mode, cache)

5. **Data Integrity**
   - Foreign key constraints (SQLite enabled)
   - Unique constraints where appropriate
   - Cascade deletes for parent-child relationships
   - Temporal tracking (first_seen, last_seen)

6. **Scalability**
   - Extensible to PostgreSQL
   - Connection pooling configuration
   - Pagination support in list operations
   - Efficient upsert patterns

## Import Examples

```python
# Option 1: Import from db module (recommended)
from aegisscan.db import DatabaseManager, Host, Port, Service

# Option 2: Import directly from submodules
from aegisscan.db.database import DatabaseManager
from aegisscan.db.models import Host, Port, Service

# Option 3: Use Base for custom models
from aegisscan.db.models import Base
```

## Schema Statistics

| Metric | Value |
|--------|-------|
| Total Entities | 9 |
| Total Relationships | 17 |
| Total Indexes | 31 |
| Foreign Keys | 12 |
| Unique Constraints | 3 |
| JSON Columns | 9 |

## Next Steps

1. Add migrations using Alembic for schema versioning
2. Implement query caching layer for read-heavy operations
3. Add backup/restore utilities
4. Create data export formats (JSON, CSV)
5. Implement audit logging for sensitive operations
6. Add connection pooling tests
7. Create sample data loaders for testing
