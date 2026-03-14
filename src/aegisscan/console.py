"""터미널 컬러 출력, ASCII 배너, 프로그레스 바, 결과 테이블."""
import sys
import time
from typing import List, Optional

from aegisscan import __version__

SUPPORTS_COLOR = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


class C:
    """ANSI 컬러 코드."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    UNDERLINE = "\033[4m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"


def c(text: str, color: str) -> str:
    if not SUPPORTS_COLOR:
        return text
    return f"{color}{text}{C.RESET}"


def print_banner():
    banner = rf"""
{c(r"    ___    _____ ____ ___ ____ ____   ____   ____  _   _", C.BOLD + C.CYAN)}
{c(r"   /   |  / ____/ ___/_ _/ __/ __/  / __/  / ___// | / /", C.BOLD + C.CYAN)}
{c(r"  / /| | / __/ / / __ / /\__ \\__ \  / /    / /__ /  |/ / ", C.BOLD + C.CYAN)}
{c(r" / ___ |/ /___/ /_/ // /___/ /__/ / / /___ / /___/ /|  /  ", C.BOLD + C.CYAN)}
{c(r"/_/  |_/_____/\____/___/____/____/  \____/ \____/_/ |_/   ", C.BOLD + C.CYAN)}

{c("Professional Network Security Scanner", C.BOLD + C.WHITE)}
{c(f"Version {__version__}", C.DIM)}
"""
    print(banner)


def info(msg: str):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"{c(f'[{ts}]', C.CYAN)} {c('INFO', C.GREEN)}     {msg}")


def warn(msg: str):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"{c(f'[{ts}]', C.CYAN)} {c('WARN', C.YELLOW)}     {msg}")


def error(msg: str):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"{c(f'[{ts}]', C.CYAN)} {c('ERROR', C.RED)}    {msg}")


def success(msg: str):
    print(f"\n{c(msg, C.BOLD + C.GREEN)}")


def header(msg: str):
    print(f"\n{c(msg, C.BOLD + C.BLUE)}")


def progress_bar(current: int, total: int, label: str = "Progress", width: int = 40):
    if total <= 0:
        return
    pct = min(current / total, 1.0)
    filled = int(pct * width)
    bar = "█" * filled + "░" * (width - filled)
    pct_str = f"{int(pct * 100)}%"
    print(f"\r{label}: [{c(bar, C.CYAN)}] {pct_str} ({current}/{total})", end="", flush=True)
    if current >= total:
        print()


def print_scan_config(targets: list, ports: str, scan_type: str, timeout: float, concurrency: int = 500):
    info(f"Loaded {c(str(len(targets)), C.BOLD)} target(s)")
    info(
        f"Starting scan: {c(str(len(targets)), C.BOLD)} target(s), "
        f"ports={c(ports, C.YELLOW)}, type={c(scan_type, C.YELLOW)}, "
        f"concurrency={c(str(concurrency), C.YELLOW)}"
    )


def print_results_table(
    results: list,
    show_closed: bool = False,
    max_rows: int = 60,
):
    """스캔 결과를 테이블로 출력."""
    if show_closed:
        display = results[:max_rows]
    else:
        display = [r for r in results if r.state == "open"][:max_rows]

    if not display:
        info("열린 포트가 발견되지 않았습니다.")
        return

    header("Scan Results")
    hdr = f"  {'HOST':<20} {'PORT':<8} {'STATE':<12} {'RTT(ms)':<10} {'SERVICE':<15}"
    print(c(hdr, C.BOLD + C.WHITE))
    print(c("  " + "─" * 68, C.DIM))

    for r in display:
        state_color = C.GREEN if r.state == "open" else (C.RED if r.state == "closed" else C.YELLOW)
        rtt = f"{r.rtt_ms:.1f}" if r.rtt_ms else "-"
        svc = getattr(r, "service_hint", "") or ""
        print(
            f"  {r.host:<20} {r.port:<8} {c(r.state, state_color):<22} {rtt:<10} {svc:<15}"
        )


def print_summary(
    total_hosts: int,
    total_ports: int,
    open_count: int,
    closed_count: int,
    filtered_count: int,
    duration: float,
    scan_run_id,
    enriched_count: int = 0,
    mismatches: int = 0,
):
    header("Summary")
    print(f"  Hosts scanned    : {c(str(total_hosts), C.BOLD)}")
    print(f"  Ports checked    : {c(str(total_ports), C.BOLD)}")
    print(f"  Open             : {c(str(open_count), C.GREEN + C.BOLD)}")
    print(f"  Closed           : {c(str(closed_count), C.DIM)}")
    print(f"  Filtered         : {c(str(filtered_count), C.YELLOW)}")
    if enriched_count:
        print(f"  Banners/TLS      : {c(str(enriched_count), C.CYAN)} collected")
    if mismatches:
        print(f"  Connect≠SYN      : {c(str(mismatches), C.RED + C.BOLD)} mismatch(es)")
    print(f"  Duration         : {c(f'{duration:.2f}s', C.BOLD)}")
    print(f"  Scan run ID      : {c(str(scan_run_id), C.CYAN + C.BOLD)}")
    print()


def print_enrichment_detail(host: str, port: int, kind: str, detail: str):
    kind_c = C.MAGENTA if kind == "TLS" else C.BLUE
    print(f"    {c('▸', kind_c)} {host}:{port} [{c(kind, kind_c)}] {detail}")


def print_cve_table(cve_list: list, max_rows: int = 40):
    """CVE/EPSS 결과 테이블 출력. 각 항목은 dict(cve_id, ip, port, epss_score, percentile, severity)."""
    if not cve_list:
        info("CVE가 발견되지 않았습니다.")
        return

    sorted_cves = sorted(cve_list, key=lambda x: x.get("epss_score", 0) or 0, reverse=True)
    display = sorted_cves[:max_rows]

    header("CVE / EPSS Analysis")
    hdr_line = f"  {'CVE ID':<20} {'HOST':<18} {'PORT':<7} {'EPSS':<10} {'PERCENTILE':<12} {'SEVERITY':<10}"
    print(c(hdr_line, C.BOLD + C.WHITE))
    print(c("  " + "─" * 78, C.DIM))

    for item in display:
        sev = item.get("severity", "?")
        sev_color = {
            "critical": C.RED + C.BOLD,
            "high": C.RED,
            "medium": C.YELLOW,
            "low": C.GREEN,
        }.get(sev, C.DIM)

        epss = item.get("epss_score")
        epss_str = f"{epss:.4f}" if epss is not None else "-"
        pct = item.get("percentile")
        pct_str = f"{pct:.1%}" if pct is not None else "-"

        print(
            f"  {c(item.get('cve_id', '?'), C.CYAN):<30} "
            f"{item.get('ip', '?'):<18} "
            f"{str(item.get('port', '?')):<7} "
            f"{epss_str:<10} "
            f"{pct_str:<12} "
            f"{c(sev, sev_color)}"
        )

    if len(sorted_cves) > max_rows:
        info(f"... 외 {len(sorted_cves) - max_rows}건 생략")


def print_cve_summary(cve_count: int, epss_queried: int, high_count: int):
    """CVE/EPSS 요약 출력."""
    header("CVE/EPSS Summary")
    print(f"  Unique CVEs found : {c(str(cve_count), C.BOLD)}")
    print(f"  EPSS scores fetched: {c(str(epss_queried), C.BOLD)}")
    if high_count:
        print(f"  High EPSS (≥0.1)  : {c(str(high_count), C.RED + C.BOLD)}")
    else:
        print(f"  High EPSS (≥0.1)  : {c('0', C.GREEN)}")
    print()


def print_web_findings_table(findings: list, max_rows: int = 30):
    """웹 보안 분석 결과 테이블. 각 항목은 dict(finding_type, host, port, url, evidence, severity, screenshot_path)."""
    if not findings:
        return

    header("Web Security Findings")
    type_labels = {
        "admin_exposure": "Admin Page",
        "info_leak": "Info Leak",
        "dir_listing": "Dir Listing",
    }
    hdr_line = f"  {'TYPE':<14} {'HOST:PORT':<22} {'SEVERITY':<10} {'EVIDENCE':<40} {'SCREENSHOT'}"
    print(c(hdr_line, C.BOLD + C.WHITE))
    print(c("  " + "─" * 95, C.DIM))

    display = findings[:max_rows]
    for f in display:
        sev = f.get("severity", "medium")
        sev_color = {"high": C.RED + C.BOLD, "critical": C.RED + C.BOLD, "medium": C.YELLOW, "low": C.GREEN}.get(sev, C.DIM)
        type_label = type_labels.get(f.get("finding_type", ""), f.get("finding_type", "?"))
        type_color = {
            "admin_exposure": C.RED,
            "info_leak": C.YELLOW,
            "dir_listing": C.MAGENTA,
        }.get(f.get("finding_type", ""), C.WHITE)
        hp = f"{f.get('host', '?')}:{f.get('port', '?')}"
        ev = (f.get("evidence", "") or "")[:40]
        ss = c("✓ captured", C.GREEN) if f.get("screenshot_path") else c("—", C.DIM)
        print(
            f"  {c(type_label, type_color):<24} {hp:<22} {c(sev, sev_color):<20} {ev:<40} {ss}"
        )

    if len(findings) > max_rows:
        info(f"... 외 {len(findings) - max_rows}건 생략")


def print_web_findings_summary(total: int, screenshots: int, by_type: Optional[dict] = None):
    """웹 보안 분석 요약."""
    if total == 0:
        return
    header("Web Security Summary")
    print(f"  Total findings   : {c(str(total), C.RED + C.BOLD)}")
    print(f"  Screenshots      : {c(str(screenshots), C.CYAN)}")
    if by_type:
        for t, cnt in by_type.items():
            label = {"admin_exposure": "Admin Page", "info_leak": "Info Leak", "dir_listing": "Dir Listing"}.get(t, t)
            print(f"    {label:<16}: {c(str(cnt), C.BOLD)}")
    print()
