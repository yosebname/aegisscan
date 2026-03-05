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
from ..data.models import Host, Port, ScanRun, Service, Banner, TLSCert, DiffFinding, ExternalObservation


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


@app.get("/api/stats", response_model=dict)
async def stats(db: AsyncSession = Depends(get_db)):
    hosts_r = await db.execute(select(func.count(Host.id)))
    ports_r = await db.execute(select(func.count(Port.id)).where(Port.state_connect == "open"))
    findings_r = await db.execute(select(func.count(DiffFinding.id)))
    return {
        "total_hosts": hosts_r.scalar() or 0,
        "open_ports_count": ports_r.scalar() or 0,
        "diff_findings_count": findings_r.scalar() or 0,
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
