"""웹 보안 분석기: 관리자 페이지 노출, 정보 누출, 디렉터리 리스팅 탐지 + 스크린샷."""
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional

import httpx

logger = logging.getLogger(__name__)

ADMIN_PATHS = [
    "/admin", "/admin/", "/administrator", "/login", "/signin",
    "/manage", "/manager", "/management",
    "/setup", "/install", "/config", "/configuration",
    "/wp-admin", "/wp-login.php",
    "/phpmyadmin", "/phpMyAdmin", "/pma",
    "/cpanel", "/webmail",
    "/admin/login", "/admin/dashboard",
    "/console", "/dashboard",
]

ADMIN_PATH_KEYWORDS = re.compile(
    r"/(admin|login|signin|manage|manager|setup|install|config|console|dashboard|cpanel|phpmyadmin|webmail)",
    re.IGNORECASE,
)

INFO_LEAK_PATTERNS = [
    re.compile(r"Apache/[\d.]+", re.IGNORECASE),
    re.compile(r"nginx/[\d.]+", re.IGNORECASE),
    re.compile(r"PHP/[\d.]+", re.IGNORECASE),
    re.compile(r"Microsoft-IIS/[\d.]+", re.IGNORECASE),
    re.compile(r"OpenSSL/[\d.\w]+", re.IGNORECASE),
    re.compile(r"(Ubuntu|Debian|CentOS|Red\s*Hat|Fedora)", re.IGNORECASE),
    re.compile(r"at\s+/var/www/", re.IGNORECASE),
    re.compile(r"at\s+/home/\w+/", re.IGNORECASE),
    re.compile(r"at\s+/usr/share/", re.IGNORECASE),
    re.compile(r"/(var|home|usr|etc|opt)/[\w/]+\.\w+", re.IGNORECASE),
    re.compile(r"X-Powered-By:\s*\S+", re.IGNORECASE),
    re.compile(r"Server:\s*(Apache|nginx|IIS|Tomcat|Jetty|Express)/[\d.]+", re.IGNORECASE),
    re.compile(r"Traceback \(most recent call last\)", re.IGNORECASE),
    re.compile(r"(Fatal error|Warning|Notice):.*in\s+/", re.IGNORECASE),
    re.compile(r"Stack Trace:|StackTrace", re.IGNORECASE),
]

DIR_LISTING_PATTERNS = [
    re.compile(r"<title>\s*Index of\s*/", re.IGNORECASE),
    re.compile(r"<title>\s*Directory listing for\s*/", re.IGNORECASE),
    re.compile(r"<h1>\s*Index of\s*/", re.IGNORECASE),
    re.compile(r"Name\s*</a>.*Last modified\s*</a>.*Size\s*</a>", re.IGNORECASE | re.DOTALL),
    re.compile(r"Parent Directory", re.IGNORECASE),
]

FINDING_TYPES = {
    "admin_exposure": "관리자 페이지 노출",
    "info_leak": "서버 정보 누출",
    "dir_listing": "디렉터리 리스팅",
}


@dataclass
class WebFindingResult:
    finding_type: str
    severity: str
    url: str
    host: str
    port: int
    matched_pattern: str
    evidence: str
    screenshot_path: Optional[str] = None


@dataclass
class WebAnalysisReport:
    findings: List[WebFindingResult] = field(default_factory=list)
    screenshots_taken: int = 0


async def _take_screenshot(url: str, output_path: Path, timeout: int = 15000) -> bool:
    """Playwright로 스크린샷 캡처. 실패 시 False 반환."""
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        logger.debug("playwright not installed, skipping screenshot")
        return False

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            ctx = await browser.new_context(
                ignore_https_errors=True,
                viewport={"width": 1280, "height": 900},
            )
            page = await ctx.new_page()
            await page.goto(url, wait_until="domcontentloaded", timeout=timeout)
            await page.wait_for_timeout(500)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            await page.screenshot(path=str(output_path), full_page=False)
            await browser.close()
        return True
    except Exception as e:
        logger.debug("Screenshot failed for %s: %s", url, e)
        return False


def _build_url(host: str, port: int, path: str = "/") -> str:
    scheme = "https" if port in (443, 8443, 9443) else "http"
    return f"{scheme}://{host}:{port}{path}"


def _classify_severity(finding_type: str, evidence: str) -> str:
    if finding_type == "admin_exposure":
        return "high"
    if finding_type == "dir_listing":
        return "high"
    if finding_type == "info_leak":
        for kw in ("Traceback", "Fatal error", "Stack Trace", "/var/www/", "/home/"):
            if kw.lower() in evidence.lower():
                return "high"
        return "medium"
    return "medium"


async def analyze_http_target(
    host: str,
    port: int,
    screenshot_dir: Path,
    http_timeout: float = 5.0,
    take_screenshots: bool = True,
    on_finding: Optional[Callable] = None,
) -> WebAnalysisReport:
    """단일 host:port에 대해 3가지 웹 보안 패턴을 분석."""
    report = WebAnalysisReport()
    base_url = _build_url(host, port)
    ts = str(int(time.time()))

    async with httpx.AsyncClient(timeout=http_timeout, verify=False, follow_redirects=True) as client:
        # --- 1. Admin page probing ---
        for path in ADMIN_PATHS:
            url = f"{base_url}{path}"
            try:
                r = await client.get(url)
                if r.status_code in (200, 301, 302, 401, 403):
                    body_lower = r.text.lower() if r.text else ""
                    is_real_page = (
                        r.status_code == 200
                        and len(r.text or "") > 200
                        and any(kw in body_lower for kw in (
                            "login", "password", "username", "sign in", "admin",
                            "dashboard", "관리", "로그인",
                        ))
                    ) or r.status_code in (401, 403)

                    if is_real_page:
                        evidence_text = f"HTTP {r.status_code} at {path}"
                        if r.status_code in (401, 403):
                            evidence_text += " (authentication required)"

                        screenshot_file = None
                        if take_screenshots:
                            fname = f"{host}_{port}_admin_{path.strip('/').replace('/', '_')}_{ts}.png"
                            ss_path = screenshot_dir / fname
                            if await _take_screenshot(url, ss_path):
                                screenshot_file = str(ss_path)
                                report.screenshots_taken += 1

                        finding = WebFindingResult(
                            finding_type="admin_exposure",
                            severity="high",
                            url=url,
                            host=host,
                            port=port,
                            matched_pattern=f"Admin path: {path}",
                            evidence=evidence_text,
                            screenshot_path=screenshot_file,
                        )
                        report.findings.append(finding)
                        if on_finding:
                            on_finding(finding)
            except Exception:
                continue

        # --- 2 & 3. Info leak + Directory listing on root and common paths ---
        check_paths = ["/", "/index.html", "/test", "/info.php", "/phpinfo.php", "/server-status"]
        for path in check_paths:
            url = f"{base_url}{path}"
            try:
                r = await client.get(url)
                if r.status_code != 200:
                    continue
                body = r.text or ""
                headers_str = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
                full_text = headers_str + "\n" + body

                # Info leak
                leaked = []
                for pat in INFO_LEAK_PATTERNS:
                    m = pat.search(full_text)
                    if m:
                        leaked.append(m.group(0)[:120])
                if leaked:
                    evidence_text = "; ".join(leaked[:5])
                    sev = _classify_severity("info_leak", evidence_text)

                    screenshot_file = None
                    if take_screenshots:
                        fname = f"{host}_{port}_infoleak_{path.strip('/') or 'root'}_{ts}.png"
                        ss_path = screenshot_dir / fname
                        if await _take_screenshot(url, ss_path):
                            screenshot_file = str(ss_path)
                            report.screenshots_taken += 1

                    finding = WebFindingResult(
                        finding_type="info_leak",
                        severity=sev,
                        url=url,
                        host=host,
                        port=port,
                        matched_pattern="Server/version/path disclosure",
                        evidence=evidence_text,
                        screenshot_path=screenshot_file,
                    )
                    report.findings.append(finding)
                    if on_finding:
                        on_finding(finding)

                # Directory listing
                for pat in DIR_LISTING_PATTERNS:
                    if pat.search(body):
                        screenshot_file = None
                        if take_screenshots:
                            fname = f"{host}_{port}_dirlist_{path.strip('/') or 'root'}_{ts}.png"
                            ss_path = screenshot_dir / fname
                            if await _take_screenshot(url, ss_path):
                                screenshot_file = str(ss_path)
                                report.screenshots_taken += 1

                        finding = WebFindingResult(
                            finding_type="dir_listing",
                            severity="high",
                            url=url,
                            host=host,
                            port=port,
                            matched_pattern=pat.pattern[:80],
                            evidence=f"Directory listing detected at {path}",
                            screenshot_path=screenshot_file,
                        )
                        report.findings.append(finding)
                        if on_finding:
                            on_finding(finding)
                        break
            except Exception:
                continue

    return report
