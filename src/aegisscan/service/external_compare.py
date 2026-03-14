"""내부 스캔 vs 외부 관측 비교 → Shadow exposure 등 DiffFinding 생성."""
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..data.models import DiffFinding, ExternalObservation, Host, Port, Vulnerability
from ..external.base import ExternalConnector, ExternalObservationRecord
from ..external.epss_client import query_epss, epss_severity

logger = logging.getLogger(__name__)


@dataclass
class ExternalCompareResult:
    diff_count: int = 0
    cve_count: int = 0
    epss_queried: int = 0
    high_epss_cves: List[Dict] = field(default_factory=list)


async def run_external_compare(
    session: AsyncSession,
    connector: ExternalConnector,
    host_ips: List[str],
    scan_run_id: Optional[int] = None,
) -> int:
    """
    외부 관측 조회 후 DB에 저장하고, 내부 open 포트와 비교해
    '외부에만 노출된 포트'(shadow exposure) 등을 DiffFinding으로 기록.
    반환: 생성된 DiffFinding 수.
    """
    count = 0
    for ip in host_ips:
        records = await connector.query_host(ip)
        if not records:
            continue
        host_r = await session.execute(select(Host).where(Host.ip == ip))
        host = host_r.scalar_one_or_none()
        if not host:
            host = Host(ip=ip)
            session.add(host)
            await session.flush()
        internal_ports = set()
        internal_r = await session.execute(select(Port.port).where(Port.host_id == host.id, Port.state_connect == "open"))
        for row in internal_r:
            internal_ports.add(row[0])
        external_ports = {r.port for r in records}
        for r in records:
            session.add(ExternalObservation(
                source=r.source,
                host_id=host.id,
                port=r.port,
                service=r.service,
                banner=r.banner,
                last_seen=datetime.utcnow(),
                raw_data=json.dumps(r.raw_data) if r.raw_data else None,
            ))
        shadow = external_ports - internal_ports
        if shadow:
            for port in list(shadow)[:50]:
                session.add(DiffFinding(
                    scan_run_id=scan_run_id,
                    finding_type="shadow_exposure",
                    severity="high",
                    summary=f"{ip}:{port} is visible externally but not open in internal scan",
                    evidence_json=json.dumps({"ip": ip, "port": port, "source": connector.source_name}),
                    host_id=host.id,
                    port=port,
                ))
                count += 1
        await session.flush()
    return count


async def run_external_compare_with_cve(
    session: AsyncSession,
    connector: ExternalConnector,
    host_ips: List[str],
    scan_run_id: Optional[int] = None,
    fetch_epss: bool = True,
    on_progress=None,
) -> ExternalCompareResult:
    """
    외부 관측 + CVE 추출 + EPSS 점수 조회를 통합 수행.
    기존 run_external_compare의 기능을 포함하며, CVE/EPSS를 추가로 처리.
    """
    result = ExternalCompareResult()
    all_cve_ids: List[str] = []
    cve_host_map: Dict[str, List[dict]] = {}

    for idx, ip in enumerate(host_ips):
        if on_progress:
            on_progress(idx + 1, len(host_ips), "External query")

        records = await connector.query_host(ip)
        if not records:
            continue

        host_r = await session.execute(select(Host).where(Host.ip == ip))
        host = host_r.scalar_one_or_none()
        if not host:
            host = Host(ip=ip)
            session.add(host)
            await session.flush()

        internal_ports = set()
        internal_r = await session.execute(
            select(Port.port).where(Port.host_id == host.id, Port.state_connect == "open")
        )
        for row in internal_r:
            internal_ports.add(row[0])

        external_ports = {r.port for r in records}

        for r in records:
            session.add(ExternalObservation(
                source=r.source,
                host_id=host.id,
                port=r.port,
                service=r.service,
                banner=r.banner,
                last_seen=datetime.utcnow(),
                raw_data=json.dumps(r.raw_data) if r.raw_data else None,
            ))

            for cve_id in r.vulns:
                all_cve_ids.append(cve_id)
                cve_host_map.setdefault(cve_id, []).append({
                    "host_id": host.id, "ip": ip, "port": r.port,
                })

        shadow = external_ports - internal_ports
        if shadow:
            for port in list(shadow)[:50]:
                session.add(DiffFinding(
                    scan_run_id=scan_run_id,
                    finding_type="shadow_exposure",
                    severity="high",
                    summary=f"{ip}:{port} is visible externally but not open in internal scan",
                    evidence_json=json.dumps({"ip": ip, "port": port, "source": connector.source_name}),
                    host_id=host.id,
                    port=port,
                ))
                result.diff_count += 1

        await session.flush()

    unique_cves = sorted(set(all_cve_ids))
    result.cve_count = len(unique_cves)

    epss_results = {}
    if fetch_epss and unique_cves:
        logger.info("Querying EPSS for %d unique CVEs...", len(unique_cves))
        epss_results = await query_epss(unique_cves)
        result.epss_queried = len(epss_results)

    for cve_id in unique_cves:
        epss = epss_results.get(cve_id)
        epss_score = epss.epss_score if epss else None
        epss_pct = epss.percentile if epss else None
        sev = epss_severity(epss_score) if epss_score is not None else None

        for loc in cve_host_map.get(cve_id, []):
            existing = await session.execute(
                select(Vulnerability).where(
                    Vulnerability.host_id == loc["host_id"],
                    Vulnerability.cve_id == cve_id,
                )
            )
            if existing.scalar_one_or_none():
                continue

            session.add(Vulnerability(
                host_id=loc["host_id"],
                port=loc["port"],
                cve_id=cve_id,
                source=connector.source_name,
                epss_score=epss_score,
                epss_percentile=epss_pct,
                severity=sev,
            ))

            if epss_score is not None and epss_score >= 0.1:
                result.high_epss_cves.append({
                    "cve_id": cve_id,
                    "ip": loc["ip"],
                    "port": loc["port"],
                    "epss_score": epss_score,
                    "percentile": epss_pct,
                    "severity": sev,
                })

            if sev in ("high", "critical"):
                session.add(DiffFinding(
                    scan_run_id=scan_run_id,
                    finding_type="high_epss_cve",
                    severity=sev,
                    summary=f"{loc['ip']}:{loc['port']} — {cve_id} (EPSS={epss_score:.4f}, top {epss_pct:.1%})",
                    evidence_json=json.dumps({
                        "cve_id": cve_id, "ip": loc["ip"], "port": loc["port"],
                        "epss_score": epss_score, "percentile": epss_pct,
                    }),
                    host_id=loc["host_id"],
                    port=loc["port"],
                ))
                result.diff_count += 1

    await session.flush()
    return result
