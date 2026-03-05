"""Censys API 연동 (플러그인). API ID/Secret 필요."""
import base64
import logging
from typing import List, Optional

import httpx

from .base import ExternalConnector, ExternalObservationRecord

logger = logging.getLogger(__name__)


class CensysConnector(ExternalConnector):
    @property
    def source_name(self) -> str:
        return "censys"

    def __init__(self, api_id: Optional[str] = None, api_secret: Optional[str] = None):
        from ..config import get_settings
        s = get_settings()
        self.api_id = api_id or s.censys_api_id
        self.api_secret = api_secret or s.censys_api_secret
        self.base_url = "https://search.censys.io/api/v2/hosts"

    def _auth_header(self) -> str:
        if not self.api_id or not self.api_secret:
            return ""
        raw = f"{self.api_id}:{self.api_secret}"
        return "Basic " + base64.b64encode(raw.encode()).decode()

    async def query_host(self, ip: str) -> List[ExternalObservationRecord]:
        if not self.api_id or not self.api_secret:
            logger.warning("Censys API credentials not set")
            return []
        out = []
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                r = await client.get(
                    f"{self.base_url}/{ip}",
                    headers={"Authorization": self._auth_header()},
                )
                if r.status_code != 200:
                    return []
                data = r.json().get("result", {}).get("services", [])
                for svc in data:
                    out.append(ExternalObservationRecord(
                        source=self.source_name,
                        ip=ip,
                        port=svc.get("port", 0),
                        service=svc.get("service_name") or svc.get("name"),
                        banner=svc.get("banner"),
                        raw_data=svc,
                    ))
        except Exception as e:
            logger.debug("Censys query %s: %s", ip, e)
        return out
