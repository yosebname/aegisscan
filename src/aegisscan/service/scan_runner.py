"""스캔 실행 오케스트레이션: Connect/SYN → DB 저장 → Enrichment."""
import asyncio
import hashlib
import json
import logging
from datetime import datetime
from typing import List, Optional, Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..data.models import (
    Banner,
    DiffFinding,
    Host,
    NmapObservation,
    Port,
    ScanRun,
    Service,
    TLSCert,
)
from ..scanner.connect_scanner import ConnectScanner, ConnectScanResult, ConnectScanSummary
from ..scanner.syn_scanner import SynScanner, SynScanResult, SynScanSummary, compare_connect_syn
from ..enrichment.banner import BannerGrabber
from ..enrichment.tls_inspector import TLSInspector

logger = logging.getLogger(__name__)


def _config_hash(targets: Sequence[str], ports: str | List[int], timeout: float, rate: Optional[float]) -> str:
    h = hashlib.sha256()
    h.update(json.dumps({"targets": list(targets), "ports": str(ports), "timeout": timeout, "rate": rate}, sort_keys=True).encode())
    return h.hexdigest()[:16]


async def _get_or_create_host(session: AsyncSession, ip: str, hostname: Optional[str] = None) -> Host:
    r = await session.execute(select(Host).where(Host.ip == ip))
    host = r.scalar_one_or_none()
    if host is None:
        host = Host(ip=ip, hostname=hostname)
        session.add(host)
        await session.flush()
    elif hostname and not host.hostname:
        host.hostname = hostname
    return host


async def save_connect_results(
    session: AsyncSession,
    scan_run_id: int,
    summary: ConnectScanSummary,
) -> None:
    now = datetime.utcnow()
    for r in summary.results:
        if r.state not in ("open", "closed", "filtered"):
            continue
        host = await _get_or_create_host(session, r.host)
        port_row = await session.execute(
            select(Port).where(Port.host_id == host.id, Port.port == r.port)
        )
        p = port_row.scalar_one_or_none()
        if p is None:
            p = Port(
                host_id=host.id,
                scan_run_id=scan_run_id,
                port=r.port,
                proto="tcp",
                state_connect=r.state,
                rtt_ms=r.rtt_ms,
                first_seen=now,
                last_seen=now,
            )
            session.add(p)
        else:
            p.state_connect = r.state
            p.rtt_ms = r.rtt_ms or p.rtt_ms
            p.last_seen = now
            if p.scan_run_id is None:
                p.scan_run_id = scan_run_id
    await session.flush()


async def save_syn_results(
    session: AsyncSession,
    scan_run_id: int,
    summary: SynScanSummary,
) -> None:
    if not summary.results:
        return
    now = datetime.utcnow()
    for r in summary.results:
        host = await _get_or_create_host(session, r.host)
        port_row = await session.execute(
            select(Port).where(Port.host_id == host.id, Port.port == r.port)
        )
        p = port_row.scalar_one_or_none()
        if p is None:
            p = Port(
                host_id=host.id,
                scan_run_id=scan_run_id,
                port=r.port,
                proto="tcp",
                state_syn=r.state,
                first_seen=now,
                last_seen=now,
            )
            session.add(p)
        else:
            p.state_syn = r.state
            p.last_seen = now
    await session.flush()


async def run_enrichment(
    session: AsyncSession,
    open_host_ports: List[tuple],
    banner_timeout: float = 3.0,
    tls_timeout: float = 5.0,
) -> None:
    """open_host_ports: [(host_ip, port), ...]"""
    banner_grabber = BannerGrabber(timeout=banner_timeout)
    tls_inspector = TLSInspector(timeout=tls_timeout)
    for host_ip, port in open_host_ports:
        host_r = await session.execute(select(Host).where(Host.ip == host_ip))
        host = host_r.scalar_one_or_none()
        if not host:
            continue
        # Banner
        banner_result = await banner_grabber.grab(host_ip, port)
        if banner_result:
            parsed = json.dumps(banner_result.parsed_fields) if banner_result.parsed_fields else None
            session.add(Banner(host_id=host.id, port=port, raw_banner=banner_result.raw_banner, parsed_fields=parsed))
            if banner_result.service_hint:
                sr = await session.execute(select(Service).where(Service.host_id == host.id, Service.port == port))
                svc = sr.scalar_one_or_none()
                if not svc:
                    session.add(Service(host_id=host.id, port=port, detected_service=banner_result.service_hint, confidence=0.8))
        # TLS for common HTTPS ports
        if port in (443, 8443, 9443):
            tls_info = await tls_inspector.inspect(host_ip, port, sni=host_ip)
            if tls_info:
                san_json = json.dumps(tls_info.san_list) if tls_info.san_list else None
                session.add(TLSCert(
                    host_id=host.id,
                    port=port,
                    sni=tls_info.sni,
                    subject=tls_info.subject,
                    issuer=tls_info.issuer,
                    not_before=tls_info.not_before,
                    not_after=tls_info.not_after,
                    san_list=san_json,
                    fingerprint_sha256=tls_info.fingerprint_sha256,
                    signature_algorithm=tls_info.signature_algorithm,
                ))
        await session.flush()


class ScanRunner:
    """전체 스캔 플로우: Connect(+ SYN) → DB 저장 → 불일치 분석 → Enrichment."""

    def __init__(
        self,
        session: AsyncSession,
        timeout: float = 3.0,
        retries: int = 2,
        rate_per_sec: Optional[float] = None,
        do_enrichment: bool = True,
    ):
        self.session = session
        self.timeout = timeout
        self.retries = retries
        self.rate_per_sec = rate_per_sec
        self.do_enrichment = do_enrichment

    async def run(
        self,
        targets: Sequence[str],
        ports: str | List[int],
        run_syn: bool = False,
        run_connect: bool = True,
    ) -> int:
        """스캔 실행 후 ScanRun id 반환."""
        config_hash = _config_hash(targets, ports, self.timeout, self.rate_per_sec)
        scan_run = ScanRun(
            targets=json.dumps(list(targets)),
            config_hash=config_hash,
            scan_type="both" if (run_connect and run_syn) else ("syn" if run_syn else "connect"),
        )
        self.session.add(scan_run)
        await self.session.flush()
        scan_run_id = scan_run.id

        connect_summary: Optional[ConnectScanSummary] = None
        syn_summary: Optional[SynScanSummary] = None

        if run_connect:
            scanner = ConnectScanner(timeout=self.timeout, retries=self.retries, rate_per_sec=self.rate_per_sec)
            connect_summary = await scanner.scan(targets=targets, ports=ports)
            await save_connect_results(self.session, scan_run_id, connect_summary)

        if run_syn and SynScanner.is_available():
            syn_scanner = SynScanner(timeout=self.timeout, rate_per_sec=self.rate_per_sec)
            syn_summary = await syn_scanner.scan(targets=targets, ports=ports)
            await save_syn_results(self.session, scan_run_id, syn_summary)

        if connect_summary and syn_summary:
            mismatches = compare_connect_syn(connect_summary.results, syn_summary.results)
            for m in mismatches:
                host = await _get_or_create_host(self.session, m["host"])
                self.session.add(DiffFinding(
                    scan_run_id=scan_run_id,
                    finding_type="connect_syn_mismatch",
                    severity="medium",
                    summary=f"{m['host']}:{m['port']} connect={m['state_connect']} syn={m['state_syn']}",
                    evidence_json=json.dumps(m),
                    host_id=host.id,
                    port=m.get("port"),
                ))
            await self.session.flush()

        open_host_ports = []
        if connect_summary:
            for r in connect_summary.results:
                if r.state == "open":
                    open_host_ports.append((r.host, r.port))

        if self.do_enrichment and open_host_ports:
            await run_enrichment(
                self.session,
                open_host_ports[:200],
                banner_timeout=self.timeout,
                tls_timeout=5.0,
            )

        scan_run.end_time = datetime.utcnow()
        await self.session.flush()
        return scan_run_id
