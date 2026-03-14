"""데이터 모델: scan_runs, hosts, ports, services, banners, tls_certs, nmap_observations, external_observations, diff_findings."""
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    JSON,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    start_time: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    end_time: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    targets: Mapped[str] = mapped_column(Text)  # JSON or comma-separated
    config_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    engine_versions: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON
    scan_type: Mapped[str] = mapped_column(String(32), default="connect")  # connect | syn | both

    ports: Mapped[list["Port"]] = relationship("Port", back_populates="scan_run", cascade="all, delete-orphan")
    diff_findings: Mapped[list["DiffFinding"]] = relationship(
        "DiffFinding", back_populates="scan_run", cascade="all, delete-orphan"
    )


class Host(Base):
    __tablename__ = "hosts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ip: Mapped[str] = mapped_column(String(45), unique=True, index=True)
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    tags: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON array

    ports: Mapped[list["Port"]] = relationship("Port", back_populates="host", cascade="all, delete-orphan")
    services: Mapped[list["Service"]] = relationship("Service", back_populates="host", cascade="all, delete-orphan")
    banners: Mapped[list["Banner"]] = relationship("Banner", back_populates="host", cascade="all, delete-orphan")
    tls_certs: Mapped[list["TLSCert"]] = relationship("TLSCert", back_populates="host", cascade="all, delete-orphan")
    nmap_observations: Mapped[list["NmapObservation"]] = relationship(
        "NmapObservation", back_populates="host", cascade="all, delete-orphan"
    )
    external_observations: Mapped[list["ExternalObservation"]] = relationship(
        "ExternalObservation", back_populates="host", cascade="all, delete-orphan"
    )
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(
        "Vulnerability", back_populates="host", cascade="all, delete-orphan"
    )
    web_findings: Mapped[list["WebFinding"]] = relationship(
        "WebFinding", back_populates="host", cascade="all, delete-orphan"
    )


class Port(Base):
    __tablename__ = "ports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id"), index=True)
    scan_run_id: Mapped[Optional[int]] = mapped_column(ForeignKey("scan_runs.id"), nullable=True, index=True)
    port: Mapped[int] = mapped_column(Integer)
    proto: Mapped[str] = mapped_column(String(8), default="tcp")
    state_connect: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)  # open | closed | filtered
    state_syn: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    rtt_ms: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    first_seen: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    host: Mapped["Host"] = relationship("Host", back_populates="ports")
    scan_run: Mapped[Optional["ScanRun"]] = relationship("ScanRun", back_populates="ports")

    __table_args__ = (Index("ix_ports_host_port", "host_id", "port", unique=True),)


class Service(Base):
    __tablename__ = "services"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id"), index=True)
    port: Mapped[int] = mapped_column(Integer)
    detected_service: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    product: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    version: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    host: Mapped["Host"] = relationship("Host", back_populates="services")

    __table_args__ = (Index("ix_services_host_port", "host_id", "port", unique=True),)


class Banner(Base):
    __tablename__ = "banners"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id"), index=True)
    port: Mapped[int] = mapped_column(Integer)
    raw_banner: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    parsed_fields: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON
    timestamp: Mapped[Optional[datetime]] = mapped_column(DateTime, default=datetime.utcnow)

    host: Mapped["Host"] = relationship("Host", back_populates="banners")

    __table_args__ = (Index("ix_banners_host_port", "host_id", "port"),)


class TLSCert(Base):
    __tablename__ = "tls_certs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id"), index=True)
    port: Mapped[int] = mapped_column(Integer)
    sni: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    subject: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    issuer: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    not_before: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    not_after: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    san_list: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON array
    fingerprint_sha256: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    signature_algorithm: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    host: Mapped["Host"] = relationship("Host", back_populates="tls_certs")

    __table_args__ = (Index("ix_tls_certs_host_port", "host_id", "port"),)


class NmapObservation(Base):
    __tablename__ = "nmap_observations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id"), index=True)
    port: Mapped[int] = mapped_column(Integer)
    nmap_service: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    nmap_version: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    scripts_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON

    host: Mapped["Host"] = relationship("Host", back_populates="nmap_observations")

    __table_args__ = (Index("ix_nmap_observations_host_port", "host_id", "port"),)


class ExternalObservation(Base):
    __tablename__ = "external_observations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    source: Mapped[str] = mapped_column(String(32))  # shodan | censys | ...
    host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id"), index=True)
    port: Mapped[int] = mapped_column(Integer)
    service: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    banner: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    raw_data: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON

    host: Mapped["Host"] = relationship("Host", back_populates="external_observations")

    __table_args__ = (Index("ix_external_observations_host_port_source", "host_id", "port", "source"),)


class DiffFinding(Base):
    __tablename__ = "diff_findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_run_id: Mapped[Optional[int]] = mapped_column(ForeignKey("scan_runs.id"), nullable=True, index=True)
    finding_type: Mapped[str] = mapped_column(String(64))  # connect_syn_mismatch | shadow_exposure | ...
    severity: Mapped[str] = mapped_column(String(16))  # low | medium | high | critical
    summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    evidence_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    host_id: Mapped[Optional[int]] = mapped_column(ForeignKey("hosts.id"), nullable=True)
    port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    scan_run: Mapped[Optional["ScanRun"]] = relationship("ScanRun", back_populates="diff_findings")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id"), index=True)
    port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    cve_id: Mapped[str] = mapped_column(String(32), index=True)
    source: Mapped[str] = mapped_column(String(32), default="shodan")
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    epss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    epss_percentile: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    severity: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    discovered_at: Mapped[Optional[datetime]] = mapped_column(DateTime, default=datetime.utcnow)

    host: Mapped["Host"] = relationship("Host", back_populates="vulnerabilities")

    __table_args__ = (Index("ix_vulns_host_cve", "host_id", "cve_id", unique=True),)


class WebFinding(Base):
    __tablename__ = "web_findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id"), index=True)
    port: Mapped[int] = mapped_column(Integer)
    finding_type: Mapped[str] = mapped_column(String(64))
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    matched_pattern: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    evidence: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    screenshot_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    scan_run_id: Mapped[Optional[int]] = mapped_column(ForeignKey("scan_runs.id"), nullable=True, index=True)
    discovered_at: Mapped[Optional[datetime]] = mapped_column(DateTime, default=datetime.utcnow)

    host: Mapped["Host"] = relationship("Host", back_populates="web_findings")

    __table_args__ = (Index("ix_web_findings_host_port_type", "host_id", "port", "finding_type"),)
