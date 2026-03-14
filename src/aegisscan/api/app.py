"""FastAPI 앱: 대시보드·검색·필터."""
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Depends, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..data.session import get_engine, get_session_factory, init_db
from ..data.models import Host, Port, ScanRun, Service, Banner, TLSCert, DiffFinding, ExternalObservation, Vulnerability, WebFinding


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db(get_settings().database_url)
    yield
    # cleanup if needed


def create_app() -> FastAPI:
    app = FastAPI(title="AegisScan", description="Attack Surface 통합 분석", version="0.1.0", lifespan=lifespan)
    return app


app = create_app()


async def get_db():
    engine = get_engine(get_settings().database_url)
    factory = get_session_factory(engine)
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


@app.get("/api/scan-runs", response_model=list)
async def list_scan_runs(db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(ScanRun).order_by(ScanRun.start_time.desc()).limit(100))
    runs = r.scalars().all()
    return [{"id": x.id, "start_time": str(x.start_time), "targets": x.targets, "scan_type": x.scan_type} for x in runs]


@app.get("/api/hosts", response_model=list)
async def list_hosts(
    db: AsyncSession = Depends(get_db),
    tag: str | None = None,
    search: str | None = Query(None, description="IP or hostname filter"),
):
    q = select(Host)
    if search:
        from sqlalchemy import or_
        q = q.where(or_(Host.ip.contains(search), Host.hostname.contains(search)))
    r = await db.execute(q.order_by(Host.ip).limit(500))
    hosts = r.scalars().all()
    return [{"id": h.id, "ip": h.ip, "hostname": h.hostname} for h in hosts]


@app.get("/api/hosts/{host_id}/ports", response_model=list)
async def list_host_ports(host_id: int, db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(Port).where(Port.host_id == host_id))
    ports = r.scalars().all()
    return [
        {
            "port": p.port,
            "state_connect": p.state_connect,
            "state_syn": p.state_syn,
            "rtt_ms": p.rtt_ms,
        }
        for p in ports
    ]


@app.get("/api/open-ports-top", response_model=list)
async def open_ports_top(db: AsyncSession = Depends(get_db), limit: int = 20):
    r = await db.execute(
        select(Port.port, func.count(Port.id).label("cnt"))
        .where(Port.state_connect == "open")
        .group_by(Port.port)
        .order_by(func.count(Port.id).desc())
        .limit(limit)
    )
    return [{"port": row[0], "count": row[1]} for row in r.all()]


@app.get("/api/diff-findings", response_model=list)
async def list_diff_findings(
    db: AsyncSession = Depends(get_db),
    finding_type: str | None = None,
    severity: str | None = None,
):
    q = select(DiffFinding)
    if finding_type:
        q = q.where(DiffFinding.finding_type == finding_type)
    if severity:
        q = q.where(DiffFinding.severity == severity)
    r = await db.execute(q.order_by(DiffFinding.id.desc()).limit(200))
    findings = r.scalars().all()
    return [
        {
            "id": f.id,
            "finding_type": f.finding_type,
            "severity": f.severity,
            "summary": f.summary,
            "host_id": f.host_id,
            "port": f.port,
        }
        for f in findings
    ]


@app.get("/api/tls-expiring", response_model=list)
async def tls_expiring(db: AsyncSession = Depends(get_db), days: int = 30):
    from datetime import timedelta
    from sqlalchemy import and_
    threshold = __import__("datetime").datetime.utcnow() + timedelta(days=days)
    r = await db.execute(
        select(TLSCert, Host.ip)
        .join(Host, TLSCert.host_id == Host.id)
        .where(and_(TLSCert.not_after != None, TLSCert.not_after <= threshold))
        .limit(100)
    )
    rows = r.all()
    return [{"host_ip": row[1], "port": row[0].port, "not_after": str(row[0].not_after)} for row in rows]


@app.get("/api/vulnerabilities", response_model=list)
async def list_vulnerabilities(
    db: AsyncSession = Depends(get_db),
    severity: str | None = None,
    min_epss: float | None = Query(None, description="Minimum EPSS score filter"),
    limit: int = 100,
):
    q = select(Vulnerability, Host.ip).join(Host, Vulnerability.host_id == Host.id)
    if severity:
        q = q.where(Vulnerability.severity == severity)
    if min_epss is not None:
        q = q.where(Vulnerability.epss_score >= min_epss)
    q = q.order_by(Vulnerability.epss_score.desc().nullslast()).limit(limit)
    r = await db.execute(q)
    return [
        {
            "id": v.id,
            "host_ip": ip,
            "port": v.port,
            "cve_id": v.cve_id,
            "source": v.source,
            "epss_score": v.epss_score,
            "epss_percentile": v.epss_percentile,
            "severity": v.severity,
            "cvss_score": v.cvss_score,
            "discovered_at": str(v.discovered_at) if v.discovered_at else None,
        }
        for v, ip in r.all()
    ]


@app.get("/api/vulnerabilities/summary", response_model=dict)
async def vuln_summary(db: AsyncSession = Depends(get_db)):
    total_r = await db.execute(select(func.count(Vulnerability.id)))
    critical_r = await db.execute(
        select(func.count(Vulnerability.id)).where(Vulnerability.severity == "critical")
    )
    high_r = await db.execute(
        select(func.count(Vulnerability.id)).where(Vulnerability.severity == "high")
    )
    unique_cve_r = await db.execute(
        select(func.count(func.distinct(Vulnerability.cve_id)))
    )
    return {
        "total_vulnerabilities": total_r.scalar() or 0,
        "unique_cves": unique_cve_r.scalar() or 0,
        "critical_count": critical_r.scalar() or 0,
        "high_count": high_r.scalar() or 0,
    }


@app.get("/api/web-findings", response_model=list)
async def list_web_findings(
    db: AsyncSession = Depends(get_db),
    finding_type: str | None = None,
    severity: str | None = None,
    limit: int = 100,
):
    q = select(WebFinding, Host.ip).join(Host, WebFinding.host_id == Host.id)
    if finding_type:
        q = q.where(WebFinding.finding_type == finding_type)
    if severity:
        q = q.where(WebFinding.severity == severity)
    q = q.order_by(WebFinding.id.desc()).limit(limit)
    r = await db.execute(q)
    return [
        {
            "id": wf.id,
            "host_ip": ip,
            "port": wf.port,
            "finding_type": wf.finding_type,
            "severity": wf.severity,
            "url": wf.url,
            "matched_pattern": wf.matched_pattern,
            "evidence": wf.evidence,
            "screenshot_path": wf.screenshot_path,
            "has_screenshot": wf.screenshot_path is not None,
            "discovered_at": str(wf.discovered_at) if wf.discovered_at else None,
        }
        for wf, ip in r.all()
    ]


@app.get("/api/web-findings/summary", response_model=dict)
async def web_findings_summary(db: AsyncSession = Depends(get_db)):
    total_r = await db.execute(select(func.count(WebFinding.id)))
    admin_r = await db.execute(
        select(func.count(WebFinding.id)).where(WebFinding.finding_type == "admin_exposure")
    )
    info_r = await db.execute(
        select(func.count(WebFinding.id)).where(WebFinding.finding_type == "info_leak")
    )
    dir_r = await db.execute(
        select(func.count(WebFinding.id)).where(WebFinding.finding_type == "dir_listing")
    )
    ss_r = await db.execute(
        select(func.count(WebFinding.id)).where(WebFinding.screenshot_path != None)
    )
    return {
        "total": total_r.scalar() or 0,
        "admin_exposure": admin_r.scalar() or 0,
        "info_leak": info_r.scalar() or 0,
        "dir_listing": dir_r.scalar() or 0,
        "screenshots": ss_r.scalar() or 0,
    }


@app.get("/api/screenshots/{filename}")
async def get_screenshot(filename: str):
    ss_dir = Path("screenshots")
    filepath = ss_dir / filename
    if filepath.exists() and filepath.suffix == ".png":
        return FileResponse(filepath, media_type="image/png")
    return HTMLResponse("Not found", status_code=404)


@app.get("/api/stats", response_model=dict)
async def stats(db: AsyncSession = Depends(get_db)):
    hosts_r = await db.execute(select(func.count(Host.id)))
    ports_r = await db.execute(select(func.count(Port.id)).where(Port.state_connect == "open"))
    findings_r = await db.execute(select(func.count(DiffFinding.id)))
    vulns_r = await db.execute(select(func.count(Vulnerability.id)))
    web_r = await db.execute(select(func.count(WebFinding.id)))
    return {
        "total_hosts": hosts_r.scalar() or 0,
        "open_ports_count": ports_r.scalar() or 0,
        "diff_findings_count": findings_r.scalar() or 0,
        "vulnerabilities_count": vulns_r.scalar() or 0,
        "web_findings_count": web_r.scalar() or 0,
    }


# 정적 파일(대시보드 HTML)
STATIC_DIR = Path(__file__).parent / "static"


@app.get("/", response_class=HTMLResponse)
async def dashboard():
    html = Path(__file__).parent / "static" / "index.html"
    if html.exists():
        return FileResponse(html)
    return HTMLResponse("<h1>AegisScan</h1><p>Dashboard: place index.html in api/static/</p><p><a href='/docs'>API Docs</a></p>")


def mount_static():
    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


mount_static()
