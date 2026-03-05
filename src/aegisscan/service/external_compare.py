"""내부 스캔 vs 외부 관측 비교 → Shadow exposure 등 DiffFinding 생성."""
import json
import logging
from datetime import datetime
from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..data.models import DiffFinding, ExternalObservation, Host, Port
from ..external.base import ExternalConnector, ExternalObservationRecord

logger = logging.getLogger(__name__)


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
        # Shadow: 외부에만 보이는 포트
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
