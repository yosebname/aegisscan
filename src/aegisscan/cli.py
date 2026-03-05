"""CLI: 스캔 실행, Nmap 임포트, 리포트 출력."""
import argparse
import asyncio
import logging
import sys
from pathlib import Path

from aegisscan.config import get_settings
from aegisscan.data.session import get_engine, get_session_factory, init_db
from aegisscan.scanner.connect_scanner import ConnectScanner
from aegisscan.scanner.syn_scanner import SynScanner
from aegisscan.service.scan_runner import ScanRunner
from aegisscan.importer.nmap_xml import NmapXMLImporter
from aegisscan.service.external_compare import run_external_compare
from aegisscan.external.shodan_connector import ShodanConnector
from aegisscan.external.censys_connector import CensysConnector

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger(__name__)


def cmd_scan(args):
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
            )
            targets = [t.strip() for t in args.targets.split(",") if t.strip()]
            if not targets:
                logger.error("대상이 비어 있습니다. 예: --targets 192.168.1.0/24 또는 10.0.0.1")
                return 1
            if not getattr(args, "i_own_or_am_authorized", False):
                logger.warning("스캔은 허가된 자산에만 수행하세요. 확인 시 --i-own-or-am-authorized 를 추가하세요.")
                return 1
            scan_run_id = await runner.run(
                targets=targets,
                ports=args.ports,
                run_connect=True,
                run_syn=args.syn,
            )
            await session.commit()
            logger.info("스캔 완료. scan_run_id=%s", scan_run_id)
        return 0

    return asyncio.run(_run())


def cmd_import_nmap(args):
    async def _run():
        await init_db(get_settings().database_url)
        data = NmapXMLImporter.parse(args.file)
        normalized = NmapXMLImporter.to_normalized(data)
        logger.info("Nmap XML 파싱: 호스트 %s, 항목 %s", len(data), len(normalized))
        engine = get_engine(get_settings().database_url)
        factory = get_session_factory(engine)
        from sqlalchemy import select
        from aegisscan.data.models import Host, Port, NmapObservation

        async with factory() as session:
            for row in normalized:
                host_r = await session.execute(select(Host).where(Host.ip == row["host"]))
                host = host_r.scalar_one_or_none()
                if not host:
                    host = Host(ip=row["host"], hostname=row.get("hostname"))
                    session.add(host)
                    await session.flush()
                port_r = await session.execute(select(Port).where(Port.host_id == host.id, Port.port == row["port"]))
                if port_r.scalar_one_or_none() is None:
                    session.add(Port(host_id=host.id, port=row["port"], proto=row.get("proto", "tcp"), state_connect="open"))
                    await session.flush()
                session.add(NmapObservation(
                    host_id=host.id,
                    port=row["port"],
                    nmap_service=row.get("nmap_service"),
                    nmap_version=row.get("nmap_version"),
                    scripts_summary=row.get("scripts_summary"),
                ))
            await session.commit()
        logger.info("Nmap 임포트 완료.")
        return 0

    return asyncio.run(_run())


def cmd_external(args):
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
            logger.warning("호스트가 없습니다. 먼저 스캔을 실행하세요.")
            return 0
        connector = None
        if args.source == "shodan":
            connector = ShodanConnector()
        elif args.source == "censys":
            connector = CensysConnector()
        if not connector:
            logger.error("--source shodan | censys 필요")
            return 1
        async with factory() as session:
            n = await run_external_compare(session, connector, ips, scan_run_id=None)
            logger.info("외부 비교 완료. DiffFinding %s 건", n)
        return 0

    return asyncio.run(_run())


def cmd_report(args):
    from aegisscan.report.generator import generate_html_report
    out = Path(args.output or "reports/report.html")
    out.parent.mkdir(parents=True, exist_ok=True)
    asyncio.run(generate_html_report(out, get_settings().database_url))
    logger.info("리포트 저장: %s", out)
    return 0


def main():
    parser = argparse.ArgumentParser(description="AegisScan: 포트 스캔 기반 공격표면 분석")
    sub = parser.add_subparsers(dest="command", required=True)

    # scan
    p_scan = sub.add_parser("scan", help="Connect(+ SYN) 스캔 실행")
    p_scan.add_argument("--targets", required=True, help="대상 IP/대역 (쉼표 구분, 예: 192.168.1.0/24,10.0.0.1)")
    p_scan.add_argument("--ports", default="1-1024", help="포트 범위 (기본: 1-1024)")
    p_scan.add_argument("--timeout", type=float, default=3.0)
    p_scan.add_argument("--retries", type=int, default=2)
    p_scan.add_argument("--rate", type=float, default=None, help="초당 요청 제한")
    p_scan.add_argument("--syn", action="store_true", help="SYN 스캔 추가 (권한 필요)")
    p_scan.add_argument("--no-enrich", dest="enrich", action="store_false", default=True, help="배너/TLS 수집 생략")
    p_scan.add_argument("--i-own-or-am-authorized", action="store_true", help="허가된 자산임을 확인하고 스캔 실행")
    p_scan.set_defaults(func=cmd_scan)

    # import-nmap
    p_imp = sub.add_parser("import-nmap", help="Nmap XML 결과 임포트")
    p_imp.add_argument("file", type=Path, help="Nmap XML 파일 경로")
    p_imp.set_defaults(func=cmd_import_nmap)

    # external
    p_ext = sub.add_parser("external", help="외부 관측 비교 (Shodan/Censys)")
    p_ext.add_argument("--source", choices=["shodan", "censys"], required=True)
    p_ext.add_argument("--limit", type=int, default=50, help="조회할 호스트 수")
    p_ext.set_defaults(func=cmd_external)

    # report
    p_rep = sub.add_parser("report", help="HTML 리포트 생성")
    p_rep.add_argument("--output", "-o", default="reports/report.html")
    p_rep.set_defaults(func=cmd_report)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main() or 0)
