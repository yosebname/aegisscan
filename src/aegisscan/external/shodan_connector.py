"""Shodan API 연동 (플러그인). API 키 필요."""
import logging
from typing import List, Optional

import httpx

from .base import ExternalConnector, ExternalObservationRecord

logger = logging.getLogger(__name__)


class ShodanConnector(ExternalConnector):
    @property
    def source_name(self) -> str:
        return "shodan"

    def __init__(self, api_key: Optional[str] = None):
        from ..config import get_settings
        self.api_key = api_key or get_settings().shodan_api_key
        self.base_url = "https://api.shodan.io"

    async def query_host(self, ip: str) -> List[ExternalObservationRecord]:
        if not self.api_key:
            logger.warning("Shodan API key not set")
            return []
        out: List[ExternalObservationRecord] = []
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                r = await client.get(
                    f"{self.base_url}/shodan/host/{ip}",
                    params={"key": self.api_key},
                )
                if r.status_code != 200:
                    return []
                data = r.json()

                host_vulns: List[str] = data.get("vulns", [])

                for port_data in data.get("data", []):
                    port_vulns = port_data.get("vulns", {})
                    cve_list: List[str] = []
                    if isinstance(port_vulns, dict):
                        cve_list = [k for k in port_vulns if k.startswith("CVE-")]
                    elif isinstance(port_vulns, list):
                        cve_list = [v for v in port_vulns if isinstance(v, str) and v.startswith("CVE-")]

                    if not cve_list and host_vulns:
                        cve_list = [v for v in host_vulns if isinstance(v, str) and v.startswith("CVE-")]

                    out.append(ExternalObservationRecord(
                        source=self.source_name,
                        ip=ip,
                        port=port_data.get("port", 0),
                        service=port_data.get("product") or port_data.get("_shodan", {}).get("module"),
                        banner=port_data.get("data", "")[:500] if isinstance(port_data.get("data"), str) else None,
                        raw_data=port_data,
                        vulns=cve_list,
                    ))
        except Exception as e:
            logger.debug("Shodan query %s: %s", ip, e)
        return out
