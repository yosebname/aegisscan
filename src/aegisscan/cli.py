"""CLI: 스캔 실행, Nmap 임포트, 외부 비교, 리포트, 웹 대시보드."""
import argparse
import asyncio
import logging
import sys
from pathlib import Path
from typing import Optional

from aegisscan import __version__
from aegisscan.config import get_settings
from aegisscan.data.session import get_engine, get_session_factory, init_db
from aegisscan.console import (
    print_banner, info, warn, error, success, header,
    progress_bar, print_scan_config, print_results_table,
    print_summary, print_enrichment_detail, c, C,
)

logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")
logger = logging.getLogger(__name__)


def cmd_scan(args):
    from aegisscan.service.scan_runner import ScanRunner

    print_banner()

    targets = [t.strip() for t in args.targets.split(",") if t.strip()]
    if not targets:
        error("대상이 비어 있습니다. 예: --targets 192.168.1.0/24 또는 10.0.0.1")
        return 1
    if not getattr(args, "i_own_or_am_authorized", False):
        error(
            "스캔은 허가된 자산에만 수행하세요.\n"
            "         확인 시 --i-own-or-am-authorized 를 추가하세요."
        )
        return 1

    scan_type = "both" if args.syn else "connect"
    print_scan_config(targets, args.ports, scan_type, args.timeout)

    def on_phase(phase):
        labels = {
            "connect_scan": "Initiating Connect scan...",
            "syn_scan": "Initiating SYN scan...",
            "enrichment": "Enriching open ports (Banner/TLS)...",
        }
        header(labels.get(phase, phase))

    def on_progress(current, total, label="Progress"):
        progress_bar(current, total, label)

    def on_enrich(host, port, kind, detail):
        print_enrichment_detail(host, port, kind, detail)

    async def _run():
        await init_db(get_settings().database_url)
        engine = get_engine(get_settings().database_url)
        factory = get_session_factory(engine)
        async with factory() as session:
            runner = ScanRunner(
                session,
                timeout=args.timeout,
                retries=args.retries,
                rate_per_sec=args.rate,
                do_enrichment=args.enrich,
                on_progress=on_progress,
                on_phase=on_phase,
                on_enrich=on_enrich,
            )
            scan_run_id = await runner.run(
                targets=targets,
                ports=args.ports,
                run_connect=True,
                run_syn=args.syn,
            )
            await session.commit()

            result_info = getattr(runner, "_scan_result", {})
            connect_summary = result_info.get("connect_summary")
            syn_summary = result_info.get("syn_summary")
            mismatches = result_info.get("mismatches", 0)
            enriched_count = result_info.get("enriched_count", 0)

            if connect_summary:
                print_results_table(connect_summary.results)

            summary = connect_summary or syn_summary
            if summary:
                success("Scan completed!")
                print_summary(
                    total_hosts=summary.total_hosts,
                    total_ports=summary.total_ports_checked,
                    open_count=summary.open_count,
                    closed_count=summary.closed_count,
                    filtered_count=summary.filtered_count,
                    duration=summary.duration_sec,
                    scan_run_id=scan_run_id,
                    enriched_count=enriched_count,
                    mismatches=mismatches,
                )
            else:
                success("Scan completed!")
                info(f"Scan run ID: {scan_run_id}")

        return 0

    return asyncio.run(_run())


def cmd_import_nmap(args):
    from aegisscan.importer.nmap_xml import NmapXMLImporter

    print_banner()

    async def _run():
        await init_db(get_settings().database_url)
        data = NmapXMLImporter.parse(args.file)
        normalized = NmapXMLImporter.to_normalized(data)
        info(f"Nmap XML 파싱: 호스트 {c(str(len(data)), C.BOLD)}, 항목 {c(str(len(normalized)), C.BOLD)}")
        engine = get_engine(get_settings().database_url)
        factory = get_session_factory(engine)
        from sqlalchemy import select
        from aegisscan.data.models import Host, Port, NmapObservation

        async with factory() as session:
            for i, row in enumerate(normalized):
                progress_bar(i + 1, len(normalized), "Importing")
                host_r = await session.execute(select(Host).where(Host.ip == row["host"]))
                host = host_r.scalar_one_or_none()
                if not host:
                    host = Host(ip=row["host"], hostname=row.get("hostname"))
                    session.add(host)
                    await session.flush()
                port_r = await session.execute(
                    select(Port).where(Port.host_id == host.id, Port.port == row["port"])
                )
                if port_r.scalar_one_or_none() is None:
                    session.add(Port(
                        host_id=host.id, port=row["port"],
                        proto=row.get("proto", "tcp"), state_connect="open",
                    ))
                    await session.flush()
                session.add(NmapObservation(
                    host_id=host.id, port=row["port"],
                    nmap_service=row.get("nmap_service"),
                    nmap_version=row.get("nmap_version"),
                    scripts_summary=row.get("scripts_summary"),
                ))
            await session.commit()
        success("Nmap 임포트 완료.")
        return 0

    return asyncio.run(_run())


def cmd_external(args):
    from aegisscan.service.external_compare import run_external_compare
    from aegisscan.external.shodan_connector import ShodanConnector
    from aegisscan.external.censys_connector import CensysConnector

    print_banner()

    async def _run():
        await init_db(get_settings().database_url)
        engine = get_engine(get_settings().database_url)
        factory = get_session_factory(engine)
        from sqlalchemy import select
        from aegisscan.data.models import Host

        async with factory() as session:
            r = await session.execute(select(Host.ip).limit(args.limit))
            ips = [row[0] for row in r.all()]
        if not ips:
            warn("호스트가 없습니다. 먼저 스캔을 실행하세요.")
            return 0
        info(f"호스트 {c(str(len(ips)), C.BOLD)}개 대상 외부 조회 ({args.source})")
        connector = ShodanConnector() if args.source == "shodan" else CensysConnector()
        async with factory() as session:
            n = await run_external_compare(session, connector, ips, scan_run_id=None)
            await session.commit()
        success(f"외부 비교 완료. DiffFinding {c(str(n), C.BOLD)} 건")
        return 0

    return asyncio.run(_run())


def _resolve_scan_run_id(raw_id: Optional[str]) -> Optional[int]:
    if raw_id is None:
        return None
    try:
        return int(raw_id)
    except ValueError:
        pass
    clean = raw_id.replace("scan_", "")
    import sqlite3
    try:
        db_path = get_settings().database_url.replace("sqlite+aiosqlite:///", "").replace("sqlite:///", "")
        conn = sqlite3.connect(db_path)
        row = conn.execute(
            "SELECT id FROM scan_runs WHERE config_hash = ? ORDER BY id DESC LIMIT 1", (clean,),
        ).fetchone()
        if row is None:
            row = conn.execute(
                "SELECT id FROM scan_runs WHERE config_hash LIKE ? ORDER BY id DESC LIMIT 1",
                (f"%{clean[:8]}%",),
            ).fetchone()
        conn.close()
        if row:
            return row[0]
    except Exception:
        pass
    return None


def cmd_report(args):
    from aegisscan.report.generator import generate_html_report, generate_scan_run_report

    print_banner()
    scan_run_id = _resolve_scan_run_id(getattr(args, "scan_run", None))
    fmt = getattr(args, "format", "html")
    output_raw = args.output

    if output_raw and Path(output_raw).is_dir():
        out = Path(output_raw) / f"report_{scan_run_id or 'all'}.{fmt}"
    else:
        out = Path(output_raw or f"reports/report.{fmt}")

    out.parent.mkdir(parents=True, exist_ok=True)
    info(f"Generating {c(fmt.upper(), C.BOLD)} report...")

    if scan_run_id:
        asyncio.run(generate_scan_run_report(out, get_settings().database_url, scan_run_id))
    else:
        asyncio.run(generate_html_report(out, get_settings().database_url))

    success(f"Report generated: {c(str(out), C.CYAN)}")
    return 0


def cmd_serve(args):
    print_banner()
    try:
        import uvicorn
    except ImportError:
        error("uvicorn이 필요합니다: pip install uvicorn")
        return 1

    asyncio.run(init_db(get_settings().database_url))
    info(f"Starting web dashboard on {c(f'http://{args.host}:{args.port}', C.CYAN + C.BOLD)}")
    uvicorn.run(
        "aegisscan.api.app:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info",
    )
    return 0


def main():
    parser = argparse.ArgumentParser(
        prog="aegisscan",
        description="AegisScan: Professional Network Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  aegisscan scan --targets 192.168.1.0/24 --ports 1-1024 --i-own-or-am-authorized
  aegisscan scan --targets 10.0.0.1 --ports 22,80,443 --syn --i-own-or-am-authorized
  aegisscan report --scan-run 1 --format html -o report.html
  aegisscan serve --port 8000
        """,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Connect(+ SYN) 스캔 실행")
    p_scan.add_argument("--targets", required=True, help="대상 IP/대역 (쉼표 구분)")
    p_scan.add_argument("--ports", default="1-1024", help="포트 범위 (기본: 1-1024)")
    p_scan.add_argument("--timeout", type=float, default=3.0)
    p_scan.add_argument("--retries", type=int, default=2)
    p_scan.add_argument("--rate", type=float, default=None, help="초당 요청 제한")
    p_scan.add_argument("--syn", action="store_true", help="SYN 스캔 추가 (권한 필요)")
    p_scan.add_argument("--no-enrich", dest="enrich", action="store_false", default=True, help="배너/TLS 수집 생략")
    p_scan.add_argument("--i-own-or-am-authorized", action="store_true", help="허가된 자산임을 확인")
    p_scan.set_defaults(func=cmd_scan)

    p_imp = sub.add_parser("import-nmap", help="Nmap XML 결과 임포트")
    p_imp.add_argument("file", type=Path, help="Nmap XML 파일 경로")
    p_imp.set_defaults(func=cmd_import_nmap)

    p_ext = sub.add_parser("external", help="외부 관측 비교 (Shodan/Censys)")
    p_ext.add_argument("--source", choices=["shodan", "censys"], required=True)
    p_ext.add_argument("--limit", type=int, default=50, help="조회할 호스트 수")
    p_ext.set_defaults(func=cmd_external)

    p_rep = sub.add_parser("report", help="HTML 리포트 생성")
    p_rep.add_argument("--scan-run", default=None, help="스캔 실행 ID")
    p_rep.add_argument("--format", choices=["html", "pdf"], default="html", help="출력 형식")
    p_rep.add_argument("--output", "-o", default=None, help="출력 경로")
    p_rep.set_defaults(func=cmd_report)

    p_serve = sub.add_parser("serve", help="웹 대시보드 시작")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8000)
    p_serve.add_argument("--reload", action="store_true", help="자동 리로드")
    p_serve.set_defaults(func=cmd_serve)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main() or 0)
