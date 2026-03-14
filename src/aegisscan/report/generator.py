"""HTML/PDF 리포트 생성 (Jinja2)."""
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from jinja2 import Environment, PackageLoader, select_autoescape

from ..data.models import Host, Port, ScanRun, Service, Banner, TLSCert, DiffFinding


def _make_session(db_url: str):
    engine = create_async_engine(db_url)
    return engine, async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def _fetch_report_data(
    db_url: str,
    scan_run_id: Optional[int] = None,
) -> Dict[str, Any]:
    engine, factory = _make_session(db_url)
    async with factory() as session:
        if scan_run_id:
            run_r = await session.execute(select(ScanRun).where(ScanRun.id == scan_run_id))
            run = run_r.scalar_one_or_none()
            if not run:
                raise ValueError(f"Scan run not found: {scan_run_id}")

            port_filter = Port.scan_run_id == scan_run_id
            diff_filter = DiffFinding.scan_run_id == scan_run_id
        else:
            port_filter = True
            diff_filter = True

        hosts_r = await session.execute(select(func.count(Host.id)))
        ports_open_r = await session.execute(
            select(func.count(Port.id)).where(and_(Port.state_connect == "open", port_filter))
        )
        findings_r = await session.execute(
            select(func.count(DiffFinding.id)).where(diff_filter)
        )
        runs_r = await session.execute(
            select(ScanRun).order_by(ScanRun.start_time.desc()).limit(5)
        )
        findings_list_r = await session.execute(
            select(DiffFinding).where(diff_filter).order_by(DiffFinding.id.desc()).limit(50)
        )
        tls_r = await session.execute(
            select(TLSCert, Host.ip).join(Host, TLSCert.host_id == Host.id).limit(100)
        )
        top_ports_r = await session.execute(
            select(Port.port, func.count(Port.id))
            .where(and_(Port.state_connect == "open", port_filter))
            .group_by(Port.port)
            .order_by(func.count(Port.id).desc())
            .limit(20)
        )
        data = {
            "scan_run_id": scan_run_id,
            "total_hosts": hosts_r.scalar() or 0,
            "open_ports_count": ports_open_r.scalar() or 0,
            "findings_count": findings_r.scalar() or 0,
            "scan_runs": [
                {"id": r.id, "start_time": str(r.start_time), "scan_type": r.scan_type}
                for r in runs_r.scalars().all()
            ],
            "findings": [
                {"finding_type": f.finding_type, "severity": f.severity, "summary": f.summary}
                for f in findings_list_r.scalars().all()
            ],
            "tls_certs": [
                {"host_ip": ip, "port": t.port, "not_after": str(t.not_after) if t.not_after else None}
                for t, ip in tls_r.all()
            ],
            "top_ports": [{"port": p, "count": c} for p, c in top_ports_r.all()],
            "generated_at": datetime.utcnow().isoformat(),
        }
    await engine.dispose()
    return data


def _render_html(data: Dict[str, Any]) -> str:
    env = Environment(
        loader=PackageLoader("aegisscan", "templates"),
        autoescape=select_autoescape(),
    )
    template = env.get_template("report.html")
    return template.render(**data)


async def generate_html_report(output_path: Path, database_url: str) -> None:
    data = await _fetch_report_data(database_url)
    html = _render_html(data)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")


async def generate_scan_run_report(
    output_path: Path,
    database_url: str,
    scan_run_id: int,
) -> None:
    data = await _fetch_report_data(database_url, scan_run_id=scan_run_id)
    html = _render_html(data)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")
