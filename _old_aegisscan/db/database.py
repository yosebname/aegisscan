"""Database session management and CRUD operations for AegisScan.

Provides DatabaseManager for connection pooling, schema initialization,
and helper methods for common CRUD operations with upsert logic.
"""

import logging
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Dict, Generator, List, Optional, Type, TypeVar

from sqlalchemy import create_engine, event, select
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from aegisscan.db.models import (
    Base,
    Banner,
    DiffFinding,
    ExternalObservation,
    Host,
    NmapObservation,
    Port,
    ScanRun,
    Service,
    TLSCert,
)

logger = logging.getLogger(__name__)

T = TypeVar("T")


class DatabaseManager:
    """Manages database connections, schema, and common CRUD operations.
    
    Provides high-level database operations with connection pooling,
    automatic schema creation, and upsert logic for common entities.
    """

    def __init__(
        self,
        database_url: str = "sqlite:///aegisscan.db",
        echo: bool = False,
        pool_size: int = 10,
        max_overflow: int = 20,
    ) -> None:
        """Initialize database manager with connection settings.
        
        Args:
            database_url: SQLAlchemy database URL. Defaults to SQLite.
            echo: Enable SQL logging if True.
            pool_size: Connection pool size (minimum connections).
            max_overflow: Maximum overflow connections beyond pool_size.
        """
        self.database_url = database_url
        self.echo = echo
        self.pool_size = pool_size
        self.max_overflow = max_overflow
        
        self.engine: Optional[Engine] = None
        self.SessionLocal: Optional[sessionmaker] = None
        
        self._initialize_engine()

    def _initialize_engine(self) -> None:
        """Create engine with appropriate configuration based on database type."""
        engine_kwargs: Dict[str, Any] = {
            "echo": self.echo,
        }
        
        # Configure based on database type
        if self.database_url.startswith("sqlite"):
            # SQLite specific configuration
            engine_kwargs["connect_args"] = {"check_same_thread": False}
            engine_kwargs["pool_pre_ping"] = True
        else:
            # PostgreSQL and other databases
            engine_kwargs["pool_size"] = self.pool_size
            engine_kwargs["max_overflow"] = self.max_overflow
            engine_kwargs["pool_pre_ping"] = True
            engine_kwargs["pool_recycle"] = 3600
        
        self.engine = create_engine(self.database_url, **engine_kwargs)
        self.SessionLocal = sessionmaker(bind=self.engine, expire_on_commit=False)
        
        # Register SQLite pragmas for better performance
        if self.database_url.startswith("sqlite"):
            self._configure_sqlite()
        
        logger.info(f"Database engine initialized: {self.database_url}")

    def _configure_sqlite(self) -> None:
        """Configure SQLite for optimal performance."""
        if not self.engine:
            return
        
        @event.listens_for(Engine, "connect")
        def set_sqlite_pragma(dbapi_conn: Any, connection_record: Any) -> None:
            cursor = dbapi_conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.execute("PRAGMA cache_size=-64000")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    def create_tables(self) -> None:
        """Create all database tables based on ORM models.
        
        Raises:
            RuntimeError: If engine is not initialized.
        """
        if not self.engine:
            raise RuntimeError("Database engine not initialized")
        
        try:
            Base.metadata.create_all(self.engine)
            logger.info("Database schema initialized successfully")
        except SQLAlchemyError as e:
            logger.error(f"Failed to create tables: {e}")
            raise

    def drop_tables(self) -> None:
        """Drop all database tables. USE WITH CAUTION."""
        if not self.engine:
            raise RuntimeError("Database engine not initialized")
        
        logger.warning("Dropping all database tables")
        Base.metadata.drop_all(self.engine)

    @contextmanager
    def get_session(self) -> Generator[Session, None, None]:
        """Context manager for database sessions.
        
        Yields:
            SQLAlchemy Session instance.
            
        Raises:
            RuntimeError: If SessionLocal is not initialized.
        """
        if not self.SessionLocal:
            raise RuntimeError("Database session factory not initialized")
        
        session = self.SessionLocal()
        try:
            yield session
            session.commit()
        except SQLAlchemyError as e:
            session.rollback()
            logger.error(f"Database error: {e}")
            raise
        finally:
            session.close()

    # ===== Host CRUD Operations =====

    def create_or_update_host(
        self,
        ip: str,
        hostname: Optional[str] = None,
        tags: Optional[Dict[str, Any]] = None,
    ) -> Host:
        """Create or update a host with upsert logic.
        
        Args:
            ip: Host IP address (unique identifier).
            hostname: Optional hostname/FQDN.
            tags: Optional custom tags dictionary.
            
        Returns:
            Host instance (created or updated).
        """
        if tags is None:
            tags = {}
        
        with self.get_session() as session:
            stmt = select(Host).where(Host.ip == ip)
            host = session.execute(stmt).scalar_one_or_none()
            
            if host:
                # Update existing host
                if hostname:
                    host.hostname = hostname
                host.tags = {**host.tags, **tags}
                host.last_seen = datetime.utcnow()
                logger.debug(f"Updated host: {ip}")
            else:
                # Create new host
                host = Host(
                    ip=ip,
                    hostname=hostname,
                    tags=tags,
                    first_seen=datetime.utcnow(),
                    last_seen=datetime.utcnow(),
                )
                session.add(host)
                logger.debug(f"Created new host: {ip}")
            
            session.flush()
            return host

    def get_host_by_ip(self, ip: str) -> Optional[Host]:
        """Retrieve a host by IP address.
        
        Args:
            ip: Host IP address.
            
        Returns:
            Host instance or None if not found.
        """
        with self.get_session() as session:
            stmt = select(Host).where(Host.ip == ip)
            return session.execute(stmt).scalar_one_or_none()

    def list_hosts(self, limit: int = 100, offset: int = 0) -> List[Host]:
        """List all hosts with pagination.
        
        Args:
            limit: Maximum number of results.
            offset: Number of results to skip.
            
        Returns:
            List of Host instances.
        """
        with self.get_session() as session:
            stmt = select(Host).limit(limit).offset(offset)
            return session.execute(stmt).scalars().all()

    # ===== Port CRUD Operations =====

    def create_or_update_port(
        self,
        host_id: int,
        port_number: int,
        protocol: str = "tcp",
        state_connect: Optional[str] = None,
        state_syn: Optional[str] = None,
        rtt_ms: Optional[float] = None,
    ) -> Port:
        """Create or update a port with upsert logic.
        
        Args:
            host_id: Foreign key to host.
            port_number: Port number (0-65535).
            protocol: Protocol (tcp/udp).
            state_connect: Connection test state.
            state_syn: SYN scan state.
            rtt_ms: Round-trip time in milliseconds.
            
        Returns:
            Port instance (created or updated).
        """
        with self.get_session() as session:
            stmt = select(Port).where(
                (Port.host_id == host_id)
                & (Port.port_number == port_number)
                & (Port.protocol == protocol)
            )
            port = session.execute(stmt).scalar_one_or_none()
            
            if port:
                # Update existing port
                if state_connect:
                    port.state_connect = state_connect
                if state_syn:
                    port.state_syn = state_syn
                if rtt_ms is not None:
                    port.rtt_ms = rtt_ms
                port.last_seen = datetime.utcnow()
                logger.debug(f"Updated port: {host_id}:{port_number}/{protocol}")
            else:
                # Create new port
                port = Port(
                    host_id=host_id,
                    port_number=port_number,
                    protocol=protocol,
                    state_connect=state_connect,
                    state_syn=state_syn,
                    rtt_ms=rtt_ms,
                    first_seen=datetime.utcnow(),
                    last_seen=datetime.utcnow(),
                )
                session.add(port)
                logger.debug(f"Created port: {host_id}:{port_number}/{protocol}")
            
            session.flush()
            return port

    def get_ports_by_host(self, host_id: int) -> List[Port]:
        """Retrieve all ports for a given host.
        
        Args:
            host_id: Host ID.
            
        Returns:
            List of Port instances.
        """
        with self.get_session() as session:
            stmt = select(Port).where(Port.host_id == host_id)
            return session.execute(stmt).scalars().all()

    def get_open_ports(self, host_id: int, protocol: str = "tcp") -> List[Port]:
        """Retrieve open ports for a host.
        
        Args:
            host_id: Host ID.
            protocol: Protocol filter (default: tcp).
            
        Returns:
            List of open Port instances.
        """
        with self.get_session() as session:
            stmt = select(Port).where(
                (Port.host_id == host_id)
                & (Port.protocol == protocol)
                & (Port.state_connect.in_(["open", "open|filtered"]))
            )
            return session.execute(stmt).scalars().all()

    # ===== Service CRUD Operations =====

    def create_service(
        self,
        host_id: int,
        port_number: int,
        detected_service: str,
        product: Optional[str] = None,
        version: Optional[str] = None,
        confidence: float = 0.0,
        source: str = "unknown",
    ) -> Service:
        """Create a service record.
        
        Args:
            host_id: Foreign key to host.
            port_number: Associated port number.
            detected_service: Service name/type.
            product: Software product name.
            version: Software version.
            confidence: Detection confidence (0-1).
            source: Detection source (nmap, banner_grab, etc).
            
        Returns:
            Service instance.
        """
        with self.get_session() as session:
            service = Service(
                host_id=host_id,
                port_number=port_number,
                detected_service=detected_service,
                product=product,
                version=version,
                confidence=confidence,
                source=source,
            )
            session.add(service)
            session.flush()
            logger.debug(f"Created service: {host_id}:{port_number}/{detected_service}")
            return service

    def get_services_by_host(self, host_id: int) -> List[Service]:
        """Retrieve all services for a host.
        
        Args:
            host_id: Host ID.
            
        Returns:
            List of Service instances.
        """
        with self.get_session() as session:
            stmt = select(Service).where(Service.host_id == host_id)
            return session.execute(stmt).scalars().all()

    # ===== ScanRun CRUD Operations =====

    def create_scan_run(
        self,
        targets: Dict[str, Any],
        config_hash: str,
        engine_version: str,
        status: str = "pending",
    ) -> ScanRun:
        """Create a new scan run record.
        
        Args:
            targets: Target specifications (IPs, CIDR blocks, etc).
            config_hash: SHA256 hash of scan configuration.
            engine_version: Version of scanning engine.
            status: Initial scan status (pending/running/completed/failed).
            
        Returns:
            ScanRun instance.
        """
        with self.get_session() as session:
            scan_run = ScanRun(
                targets=targets,
                config_hash=config_hash,
                engine_version=engine_version,
                status=status,
                start_time=datetime.utcnow(),
            )
            session.add(scan_run)
            session.flush()
            logger.info(f"Created scan run: {scan_run.id}")
            return scan_run

    def get_scan_run(self, scan_run_id: int) -> Optional[ScanRun]:
        """Retrieve a scan run by ID.
        
        Args:
            scan_run_id: Scan run ID.
            
        Returns:
            ScanRun instance or None if not found.
        """
        with self.get_session() as session:
            stmt = select(ScanRun).where(ScanRun.id == scan_run_id)
            return session.execute(stmt).scalar_one_or_none()

    def update_scan_run_status(
        self,
        scan_run_id: int,
        status: str,
        end_time: Optional[datetime] = None,
    ) -> Optional[ScanRun]:
        """Update scan run status and end time.
        
        Args:
            scan_run_id: Scan run ID.
            status: New status.
            end_time: Completion time (defaults to current time if provided).
            
        Returns:
            Updated ScanRun instance or None if not found.
        """
        with self.get_session() as session:
            stmt = select(ScanRun).where(ScanRun.id == scan_run_id)
            scan_run = session.execute(stmt).scalar_one_or_none()
            
            if scan_run:
                scan_run.status = status
                if end_time:
                    scan_run.end_time = end_time
                elif status in ["completed", "failed"]:
                    scan_run.end_time = datetime.utcnow()
                logger.info(f"Updated scan run {scan_run_id} status to {status}")
            
            return scan_run

    def list_scan_runs(
        self,
        status: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[ScanRun]:
        """List scan runs with optional filtering.
        
        Args:
            status: Filter by status (optional).
            limit: Maximum number of results.
            offset: Number of results to skip.
            
        Returns:
            List of ScanRun instances.
        """
        with self.get_session() as session:
            stmt = select(ScanRun)
            
            if status:
                stmt = stmt.where(ScanRun.status == status)
            
            stmt = stmt.order_by(ScanRun.start_time.desc()).limit(limit).offset(offset)
            return session.execute(stmt).scalars().all()

    # ===== Certificate CRUD Operations =====

    def create_tls_cert(
        self,
        host_id: int,
        port_number: int,
        subject: str,
        issuer: str,
        not_before: datetime,
        not_after: datetime,
        fingerprint_sha256: str,
        serial_number: str,
        sig_algorithm: str,
        sni: Optional[str] = None,
        san_list: Optional[List[str]] = None,
    ) -> TLSCert:
        """Create a TLS certificate record.
        
        Args:
            host_id: Foreign key to host.
            port_number: Associated port number.
            subject: Certificate subject DN.
            issuer: Certificate issuer DN.
            not_before: Validity start date.
            not_after: Validity end date.
            fingerprint_sha256: SHA256 fingerprint (unique).
            serial_number: Certificate serial number.
            sig_algorithm: Signature algorithm.
            sni: Optional Server Name Indication.
            san_list: Optional list of Subject Alternative Names.
            
        Returns:
            TLSCert instance.
        """
        if san_list is None:
            san_list = []
        
        with self.get_session() as session:
            tls_cert = TLSCert(
                host_id=host_id,
                port_number=port_number,
                sni=sni,
                subject=subject,
                issuer=issuer,
                not_before=not_before,
                not_after=not_after,
                san_list=san_list,
                fingerprint_sha256=fingerprint_sha256,
                serial_number=serial_number,
                sig_algorithm=sig_algorithm,
            )
            session.add(tls_cert)
            session.flush()
            logger.debug(f"Created TLS cert: {host_id}:{port_number}")
            return tls_cert

    def get_tls_certs_by_host(self, host_id: int) -> List[TLSCert]:
        """Retrieve all TLS certificates for a host.
        
        Args:
            host_id: Host ID.
            
        Returns:
            List of TLSCert instances.
        """
        with self.get_session() as session:
            stmt = select(TLSCert).where(TLSCert.host_id == host_id)
            return session.execute(stmt).scalars().all()

    # ===== Banner CRUD Operations =====

    def create_banner(
        self,
        host_id: int,
        port_number: int,
        raw_banner: str,
        parsed_fields: Optional[Dict[str, Any]] = None,
    ) -> Banner:
        """Create a banner record.
        
        Args:
            host_id: Foreign key to host.
            port_number: Associated port number.
            raw_banner: Raw banner data.
            parsed_fields: Optional parsed field dictionary.
            
        Returns:
            Banner instance.
        """
        if parsed_fields is None:
            parsed_fields = {}
        
        with self.get_session() as session:
            banner = Banner(
                host_id=host_id,
                port_number=port_number,
                raw_banner=raw_banner,
                parsed_fields=parsed_fields,
                collected_at=datetime.utcnow(),
            )
            session.add(banner)
            session.flush()
            return banner

    # ===== Observation CRUD Operations =====

    def create_nmap_observation(
        self,
        host_id: int,
        port_number: int,
        nmap_service: Optional[str] = None,
        nmap_version: Optional[str] = None,
        scripts_summary: Optional[Dict[str, Any]] = None,
        scan_run_id: Optional[int] = None,
    ) -> NmapObservation:
        """Create an nmap observation record.
        
        Args:
            host_id: Foreign key to host.
            port_number: Associated port number.
            nmap_service: Nmap detected service.
            nmap_version: Nmap version detection.
            scripts_summary: NSE script output summary.
            scan_run_id: Optional associated scan run.
            
        Returns:
            NmapObservation instance.
        """
        if scripts_summary is None:
            scripts_summary = {}
        
        with self.get_session() as session:
            obs = NmapObservation(
                host_id=host_id,
                port_number=port_number,
                nmap_service=nmap_service,
                nmap_version=nmap_version,
                scripts_summary=scripts_summary,
                scan_run_id=scan_run_id,
            )
            session.add(obs)
            session.flush()
            return obs

    def create_external_observation(
        self,
        source: str,
        host_id: int,
        port_number: int,
        service: Optional[str] = None,
        banner: Optional[str] = None,
        raw_data: Optional[Dict[str, Any]] = None,
    ) -> ExternalObservation:
        """Create an external observation record.
        
        Args:
            source: Data source (shodan, certs.io, etc).
            host_id: Foreign key to host.
            port_number: Associated port number.
            service: Detected service.
            banner: Service banner data.
            raw_data: Raw observation data.
            
        Returns:
            ExternalObservation instance.
        """
        if raw_data is None:
            raw_data = {}
        
        with self.get_session() as session:
            obs = ExternalObservation(
                source=source,
                host_id=host_id,
                port_number=port_number,
                service=service,
                banner=banner,
                raw_data=raw_data,
                last_seen=datetime.utcnow(),
            )
            session.add(obs)
            session.flush()
            return obs

    # ===== Diff Finding CRUD Operations =====

    def create_diff_finding(
        self,
        scan_run_id: int,
        finding_type: str,
        severity: str,
        summary: str,
        evidence: Optional[Dict[str, Any]] = None,
    ) -> DiffFinding:
        """Create a diff finding record.
        
        Args:
            scan_run_id: Associated scan run.
            finding_type: Type of change (new_port, closed_port, etc).
            severity: Severity level (critical/high/medium/low).
            summary: Human-readable summary.
            evidence: Supporting evidence data.
            
        Returns:
            DiffFinding instance.
        """
        if evidence is None:
            evidence = {}
        
        with self.get_session() as session:
            finding = DiffFinding(
                scan_run_id=scan_run_id,
                finding_type=finding_type,
                severity=severity,
                summary=summary,
                evidence=evidence,
                created_at=datetime.utcnow(),
            )
            session.add(finding)
            session.flush()
            logger.info(f"Created diff finding: {finding_type} ({severity})")
            return finding

    def get_diff_findings_by_scan(
        self,
        scan_run_id: int,
        severity: Optional[str] = None,
    ) -> List[DiffFinding]:
        """Retrieve diff findings for a scan run.
        
        Args:
            scan_run_id: Scan run ID.
            severity: Optional severity filter.
            
        Returns:
            List of DiffFinding instances.
        """
        with self.get_session() as session:
            stmt = select(DiffFinding).where(DiffFinding.scan_run_id == scan_run_id)
            
            if severity:
                stmt = stmt.where(DiffFinding.severity == severity)
            
            return session.execute(stmt).scalars().all()
