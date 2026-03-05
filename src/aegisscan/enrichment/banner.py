"""배너 그랩: HTTP, SSH, FTP, SMTP, Redis 등 초기 응답 수집."""
import asyncio
import logging
import re
from dataclasses import dataclass
from typing import Optional, Dict, Any

import httpx

logger = logging.getLogger(__name__)


@dataclass
class BannerResult:
    raw_banner: str
    parsed_fields: Optional[Dict[str, Any]] = None
    service_hint: Optional[str] = None


async def grab_http(host: str, port: int, timeout: float = 3.0, paths: Optional[list] = None) -> Optional[BannerResult]:
    """HTTP/HTTPS: status line, Server 헤더, 선택 path."""
    paths = paths or ["/", "/health"]
    scheme = "https" if port == 443 else "http"
    base = f"{scheme}://{host}:{port}"
    lines = []
    parsed = {"status": None, "headers": {}, "paths": {}}
    try:
        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            for path in paths[:3]:
                try:
                    r = await client.get(base + path)
                    if path == "/":
                        parsed["status"] = f"{r.status_code} {r.reason_phrase}"
                        for k, v in r.headers.items():
                            if k.lower() in ("server", "x-powered-by", "content-type"):
                                parsed["headers"][k] = v
                    parsed["paths"][path] = r.status_code
                    lines.append(f"GET {path} -> {r.status_code}")
                except Exception as e:
                    parsed["paths"][path] = str(e)
        raw = "\n".join(lines) if lines else parsed.get("status") or ""
        if parsed.get("headers"):
            raw += "\n" + "\n".join(f"{k}: {v}" for k, v in parsed["headers"].items())
        return BannerResult(raw_banner=raw, parsed_fields=parsed, service_hint="http")
    except Exception as e:
        logger.debug("HTTP banner %s:%s %s", host, port, e)
        return None


async def grab_ssh(host: str, port: int, timeout: float = 3.0) -> Optional[BannerResult]:
    """SSH: 버전 문자열 한 줄."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        line = (await asyncio.wait_for(reader.readline(), timeout=2.0)).decode("utf-8", errors="replace").strip()
        writer.close()
        await writer.wait_closed()
        if line:
            return BannerResult(raw_banner=line, parsed_fields={"version_line": line}, service_hint="ssh")
        return None
    except Exception as e:
        logger.debug("SSH banner %s:%s %s", host, port, e)
        return None


async def grab_generic(host: str, port: int, timeout: float = 3.0, max_bytes: int = 1024) -> Optional[BannerResult]:
    """일반 TCP: 최대 N바이트 읽기."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        data = await asyncio.wait_for(reader.read(max_bytes), timeout=2.0)
        writer.close()
        await writer.wait_closed()
        raw = data.decode("utf-8", errors="replace").strip()
        raw = re.sub(r"\s+", " ", raw)[:500]
        if raw:
            return BannerResult(raw_banner=raw, service_hint="tcp")
        return None
    except Exception as e:
        logger.debug("Generic banner %s:%s %s", host, port, e)
        return None


# 포트별 그랩 함수 매핑
BANNER_GRABBERS = {
    80: grab_http,
    443: grab_http,
    8080: grab_http,
    8443: grab_http,
    22: grab_ssh,
    21: grab_generic,
    25: grab_generic,
    6379: grab_generic,
    3306: grab_generic,
    5432: grab_generic,
}


class BannerGrabber:
    """열린 포트에 대해 배너 수집."""

    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout

    async def grab(self, host: str, port: int) -> Optional[BannerResult]:
        grabber = BANNER_GRABBERS.get(port, grab_generic)
        return await grabber(host, port, timeout=self.timeout)
