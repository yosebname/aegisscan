"""외부 관측 플러그인 베이스."""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ExternalObservationRecord:
    source: str
    ip: str
    port: int
    service: Optional[str] = None
    banner: Optional[str] = None
    raw_data: Optional[dict] = None
    vulns: List[str] = field(default_factory=list)


class ExternalConnector(ABC):
    """Shodan/Censys 등 외부 데이터 소스 플러그인 인터페이스."""

    @property
    @abstractmethod
    def source_name(self) -> str:
        pass

    @abstractmethod
    async def query_host(self, ip: str) -> List[ExternalObservationRecord]:
        """호스트 IP에 대한 공개 포트/서비스 정보 조회."""
        pass
