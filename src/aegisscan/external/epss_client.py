"""FIRST.org EPSS (Exploit Prediction Scoring System) API 클라이언트.

EPSS API: https://api.first.org/data/v1/epss
- 인증 불필요 (공개 API)
- 배치 조회 지원 (쉼표 구분 CVE 목록)
"""
import logging
from dataclasses import dataclass
from typing import Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)

EPSS_API_URL = "https://api.first.org/data/v1/epss"
BATCH_SIZE = 100


@dataclass
class EPSSResult:
    cve_id: str
    epss_score: float
    percentile: float


async def query_epss(cve_ids: List[str], timeout: float = 15.0) -> Dict[str, EPSSResult]:
    """CVE 목록에 대한 EPSS 점수를 배치 조회하여 dict로 반환."""
    if not cve_ids:
        return {}

    unique = sorted(set(cve_ids))
    results: Dict[str, EPSSResult] = {}

    for i in range(0, len(unique), BATCH_SIZE):
        batch = unique[i : i + BATCH_SIZE]
        cve_param = ",".join(batch)
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                r = await client.get(EPSS_API_URL, params={"cve": cve_param})
                if r.status_code != 200:
                    logger.warning("EPSS API returned %d for batch starting %s", r.status_code, batch[0])
                    continue
                data = r.json()
                for entry in data.get("data", []):
                    cve = entry.get("cve", "")
                    try:
                        score = float(entry.get("epss", 0))
                        pct = float(entry.get("percentile", 0))
                    except (ValueError, TypeError):
                        continue
                    results[cve] = EPSSResult(cve_id=cve, epss_score=score, percentile=pct)
        except Exception as e:
            logger.debug("EPSS batch query error: %s", e)

    return results


def epss_severity(score: float) -> str:
    """EPSS 점수를 기반으로 위험도 레이블 반환."""
    if score >= 0.7:
        return "critical"
    if score >= 0.4:
        return "high"
    if score >= 0.1:
        return "medium"
    return "low"
