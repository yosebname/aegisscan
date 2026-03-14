"""스캔 실행 오케스트레이션: Connect/SYN → DB 저장 → Enrichment."""
import asyncio
import hashlib
import json
import logging
from datetime import datetime
from pathlib import Path
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
    WebFinding,
)
from ..scanner.connect_scanner import ConnectScanner, ConnectScanResult, ConnectScanSummary
from ..scanner.syn_scanner import SynScanner, SynScanResult, SynScanSummary, compare_connect_syn
from ..enrichment.banner import BannerGrabber, BANNER_GRABBERS
from ..enrichment.tls_inspector import TLSInspector
from ..enrichment.web_analyzer import analyze_http_target, WebAnalysisReport

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
    on_enrich=None,
    on_progress=None,
) -> int:
    """open_host_ports: [(host_ip, port), ...]. 반환: 수집 건수."""
    banner_grabber = BannerGrabber(timeout=banner_timeout)
    tls_inspector = TLSInspector(timeout=tls_timeout)
    count = 0
    total = len(open_host_ports)
    for idx, (host_ip, port) in enumerate(open_host_ports):
        if on_progress:
            on_progress(idx + 1, total, "Enriching")
        host_r = await session.execute(select(Host).where(Host.ip == host_ip))
        host = host_r.scalar_one_or_none()
        if not host:
            continue
        banner_result = await banner_grabber.grab(host_ip, port)
        if banner_result:
            parsed = json.dumps(banner_result.parsed_fields) if banner_result.parsed_fields else None
            session.add(Banner(host_id=host.id, port=port, raw_banner=banner_result.raw_banner, parsed_fields=parsed))
            if banner_result.service_hint:
                sr = await session.execute(select(Service).where(Service.host_id == host.id, Service.port == port))
                svc = sr.scalar_one_or_none()
                if not svc:
                    session.add(Service(host_id=host.id, port=port, detected_service=banner_result.service_hint, confidence=0.8))
            detail = banner_result.raw_banner.split("\n")[0][:60] if banner_result.raw_banner else ""
            if on_enrich:
                on_enrich(host_ip, port, "Banner", f"{banner_result.service_hint or 'tcp'} — {detail}")
            count += 1
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
                subj = tls_info.subject or "unknown"
                if on_enrich:
                    on_enrich(host_ip, port, "TLS", f"subject={subj[:40]} expires={tls_info.not_after}")
                count += 1
        await session.flush()
    return count


HTTP_PORTS = set(BANNER_GRABBERS.keys()) & {80, 443, 8080, 8443}


async def run_web_analysis(
    session: AsyncSession,
    open_http_ports: List[tuple],
    scan_run_id: Optional[int] = None,
    screenshot_dir: Optional[Path] = None,
    take_screenshots: bool = True,
    on_enrich=None,
    on_progress=None,
) -> List[dict]:
    """HTTP open 포트에 대해 웹 보안 분석 수행, 결과를 DB에 저장."""
    from pathlib import Path as _P

    if screenshot_dir is None:
        screenshot_dir = _P("screenshots")
    screenshot_dir.mkdir(parents=True, exist_ok=True)

    all_findings: List[dict] = []
    total = len(open_http_ports)

    for idx, (host_ip, port) in enumerate(open_http_ports):
        if on_progress:
            on_progress(idx + 1, total, "Web analysis")

        host_r = await session.execute(select(Host).where(Host.ip == host_ip))
        host = host_r.scalar_one_or_none()
        if not host:
            continue

        def _on_finding(f):
            if on_enrich:
                label = {"admin_exposure": "Admin", "info_leak": "InfoLeak", "dir_listing": "DirList"}.get(f.finding_type, "Web")
                screenshot_note = " [screenshot]" if f.screenshot_path else ""
                on_enrich(f.host, f.port, label, f"{f.evidence[:60]}{screenshot_note}")

        report = await analyze_http_target(
            host_ip, port,
            screenshot_dir=screenshot_dir,
            take_screenshots=take_screenshots,
            on_finding=_on_finding,
        )

        for f in report.findings:
            session.add(WebFinding(
                host_id=host.id,
                port=f.port,
                finding_type=f.finding_type,
                severity=f.severity,
                url=f.url,
                matched_pattern=f.matched_pattern,
                evidence=f.evidence,
                screenshot_path=f.screenshot_path,
                scan_run_id=scan_run_id,
            ))
            all_findings.append({
                "host": f.host, "port": f.port,
                "finding_type": f.finding_type, "severity": f.severity,
                "url": f.url, "evidence": f.evidence,
                "screenshot_path": f.screenshot_path,
            })

        await session.flush()

    return all_findings


class ScanRunner:
    """전체 스캔 플로우: Connect(+ SYN) → DB 저장 → 불일치 분석 → Enrichment."""

    def __init__(
        self,
        session: AsyncSession,
        timeout: float = 3.0,
        retries: int = 2,
        rate_per_sec: Optional[float] = None,
        do_enrichment: bool = True,
        on_progress=None,
        on_phase=None,
        on_enrich=None,
    ):
        self.session = session
        self.timeout = timeout
        self.retries = retries
        self.rate_per_sec = rate_per_sec
        self.do_enrichment = do_enrichment
        self._on_progress = on_progress  # (current, total, label)
        self._on_phase = on_phase        # (phase_name)
        self._on_enrich = on_enrich      # (host, port, kind, detail)

    def _notify_progress(self, current, total, label="Scanning"):
        if self._on_progress:
            self._on_progress(current, total, label)

    def _notify_phase(self, phase):
        if self._on_phase:
            self._on_phase(phase)

    def _notify_enrich(self, host, port, kind, detail):
        if self._on_enrich:
            self._on_enrich(host, port, kind, detail)

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
            self._notify_phase("connect_scan")
            scanner = ConnectScanner(timeout=self.timeout, retries=self.retries, rate_per_sec=self.rate_per_sec)
            connect_summary = await scanner.scan(targets=targets, ports=ports)
            await save_connect_results(self.session, scan_run_id, connect_summary)

        if run_syn and SynScanner.is_available():
            self._notify_phase("syn_scan")
            syn_scanner = SynScanner(timeout=self.timeout, rate_per_sec=self.rate_per_sec)
            syn_summary = await syn_scanner.scan(targets=targets, ports=ports)
            await save_syn_results(self.session, scan_run_id, syn_summary)

        mismatches = []
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

        enriched_count = 0
        if self.do_enrichment and open_host_ports:
            self._notify_phase("enrichment")
            enriched_count = await run_enrichment(
                self.session,
                open_host_ports[:200],
                banner_timeout=self.timeout,
                tls_timeout=5.0,
                on_enrich=self._on_enrich,
                on_progress=self._on_progress,
            )

        web_findings: List[dict] = []
        if self.do_enrichment and open_host_ports:
            http_ports = [(h, p) for h, p in open_host_ports if p in (80, 443, 8080, 8443, 9443, 3000, 5000, 8000, 8888)]
            if not http_ports:
                http_ports = [(h, p) for h, p in open_host_ports][:10]
            if http_ports:
                self._notify_phase("web_analysis")
                web_findings = await run_web_analysis(
                    self.session,
                    http_ports[:50],
                    scan_run_id=scan_run_id,
                    take_screenshots=True,
                    on_enrich=self._on_enrich,
                    on_progress=self._on_progress,
                )

        scan_run.end_time = datetime.utcnow()
        await self.session.flush()

        self._scan_result = {
            "connect_summary": connect_summary,
            "syn_summary": syn_summary,
            "mismatches": len(mismatches),
            "enriched_count": enriched_count,
            "web_findings": web_findings,
        }
        return scan_run_id
