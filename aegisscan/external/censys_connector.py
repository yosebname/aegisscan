"""Censys threat intelligence API connector."""

import asyncio
import json
import logging
import time
from base64 import b64encode
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

try:
    import aiohttp
except ImportError:
    aiohttp = None

from .base import ExternalIntelConnector

logger = logging.getLogger(__name__)


@dataclass
class CensysService:
    """Represents a service discovered by Censys."""

    port: int
    protocol: str
    banner: Optional[str] = None
    timestamp: Optional[datetime] = None
    tls_cert_sha256: Optional[str] = None


@dataclass
class CensysHostResult:
    """Result of a Censys host lookup."""

    ip: str
    services: List[CensysService] = field(default_factory=list)
    tls_certs: List[Dict[str, Any]] = field(default_factory=list)
    autonomous_system: Optional[Dict[str, Any]] = None
    location: Optional[Dict[str, Any]] = None
    last_seen: Optional[datetime] = None
    raw_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "ip": self.ip,
            "services": [
                {
                    "port": s.port,
                    "protocol": s.protocol,
                    "banner": s.banner,
                    "timestamp": s.timestamp.isoformat() if s.timestamp else None,
                }
                for s in self.services
            ],
            "tls_certs": self.tls_certs,
            "autonomous_system": self.autonomous_system,
            "location": self.location,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
        }


class CensysConnector(ExternalIntelConnector):
    """Connector for Censys threat intelligence API.

    Accesses Censys API v2 to retrieve host data. Implements rate limiting,
    response caching, and authentication via API ID and secret.

    Attributes:
        api_id: Censys API ID (optional)
        api_secret: Censys API secret (optional)
        cache_ttl: Cache time-to-live in seconds (default: 3600)
        rate_limit: Delay between requests in seconds (default: 0.2)
    """

    BASE_URL = "https://api.censys.io/v2"
    RATE_LIMIT = 0.2  # 5 requests per second (Censys tier 1 limit)

    def __init__(
        self,
        api_id: Optional[str] = None,
        api_secret: Optional[str] = None,
        cache_ttl: int = 3600,
        rate_limit: float = RATE_LIMIT,
    ):
        """Initialize Censys connector.

        Args:
            api_id: Censys API ID (optional)
            api_secret: Censys API secret (optional)
            cache_ttl: Cache time-to-live in seconds
            rate_limit: Delay between API requests in seconds
        """
        enabled = (
            api_id is not None
            and api_secret is not None
            and len(api_id) > 0
            and len(api_secret) > 0
        )
        super().__init__("censys", enabled=enabled)

        self.api_id = api_id
        self.api_secret = api_secret
        self.cache_ttl = cache_ttl
        self.rate_limit = rate_limit
        self._cache: Dict[str, tuple[CensysHostResult, float]] = {}
        self._last_request_time = 0.0
        self._session: Optional[aiohttp.ClientSession] = None
        self._auth_header = self._create_auth_header() if enabled else None

    async def __aenter__(self):
        """Async context manager entry."""
        if not self.enabled:
            return self
        if aiohttp and not self._session:
            self._session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self._session:
            await self._session.close()
            self._session = None

    async def health_check(self) -> bool:
        """Check if Censys connector is operational."""
        if not self.enabled:
            return False

        if not aiohttp:
            self.logger.warning("aiohttp not available, cannot verify Censys API")
            return False

        try:
            await self._apply_rate_limit()
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.BASE_URL}/account",
                    headers={"Authorization": self._auth_header},
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as resp:
                    return resp.status == 200
        except Exception as e:
            self.logger.error(f"Censys health check failed: {e}")
            return False

    async def lookup_host(self, ip: str) -> Optional[CensysHostResult]:
        """Look up a single host on Censys.

        Args:
            ip: IP address to look up

        Returns:
            CensysHostResult or None if lookup fails

        Raises:
            ValueError: If IP address is invalid
        """
        if not self.enabled:
            self.logger.debug("Censys connector disabled, skipping lookup")
            return None

        if not self._is_valid_ip(ip):
            raise ValueError(f"Invalid IP address: {ip}")

        # Check cache
        cached = self._get_from_cache(ip)
        if cached:
            return cached

        result = await self._lookup_host_api(ip)

        if result:
            self._cache[ip] = (result, time.time())

        return result

    async def lookup_multiple(self, ips: List[str]) -> List[CensysHostResult]:
        """Look up multiple hosts on Censys.

        Processes IPs sequentially with rate limiting. Returns partial results
        if some lookups fail.

        Args:
            ips: List of IP addresses to look up

        Returns:
            List of CensysHostResult objects (may be partial)
        """
        if not self.enabled:
            self.logger.debug("Censys connector disabled, skipping batch lookup")
            return []

        results = []
        for ip in ips:
            try:
                result = await self.lookup_host(ip)
                if result:
                    results.append(result)
            except (ValueError, Exception) as e:
                self.logger.warning(f"Failed to lookup {ip}: {e}")

        return results

    async def _lookup_host_api(self, ip: str) -> Optional[CensysHostResult]:
        """Look up host via Censys API v2.

        Args:
            ip: IP address to look up

        Returns:
            CensysHostResult or None if lookup fails
        """
        if not aiohttp:
            self.logger.error("aiohttp not available for Censys API calls")
            return None

        if not self._session:
            self._session = aiohttp.ClientSession()

        await self._apply_rate_limit()

        try:
            async with self._session.get(
                f"{self.BASE_URL}/hosts/{ip}",
                headers={"Authorization": self._auth_header},
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return self._parse_response(ip, data)
                elif resp.status == 401:
                    self.logger.error("Invalid Censys API credentials")
                    self.enabled = False
                    return None
                elif resp.status == 404:
                    self.logger.debug(f"IP {ip} not found in Censys")
                    return None
                elif resp.status == 429:
                    self.logger.warning(f"Censys rate limit exceeded for {ip}")
                    # Back off rate limiting
                    self.rate_limit *= 1.5
                    return None
                else:
                    self.logger.warning(f"Censys API returned {resp.status}: {resp.reason}")
                    return None
        except asyncio.TimeoutError:
            self.logger.error(f"Censys API timeout for {ip}")
            return None
        except Exception as e:
            self.logger.error(f"Error looking up {ip} with Censys API: {e}")
            return None

    def _parse_response(
        self, ip: str, data: Dict[str, Any]
    ) -> Optional[CensysHostResult]:
        """Parse response from Censys API v2.

        Args:
            ip: IP address
            data: JSON response data

        Returns:
            CensysHostResult or None
        """
        try:
            result = CensysHostResult(ip=ip, raw_data=data)

            # Parse services
            services = data.get("services", [])
            for service in services:
                port = service.get("port")
                protocol = service.get("protocol", "tcp")
                banner = service.get("banner")
                timestamp_str = service.get("timestamp")

                timestamp = None
                if timestamp_str:
                    try:
                        timestamp = datetime.fromisoformat(
                            timestamp_str.replace("Z", "+00:00")
                        )
                    except (ValueError, AttributeError):
                        pass

                censys_service = CensysService(
                    port=port,
                    protocol=protocol,
                    banner=banner,
                    timestamp=timestamp,
                    tls_cert_sha256=service.get("tls", {}).get("certificate_sha256"),
                )
                result.services.append(censys_service)

            # Parse autonomous system info
            asn_info = data.get("autonomous_system", {})
            if asn_info:
                result.autonomous_system = {
                    "asn": asn_info.get("asn"),
                    "name": asn_info.get("name"),
                    "routed_prefix": asn_info.get("routed_prefix"),
                }

            # Parse location info
            location_info = data.get("location", {})
            if location_info:
                result.location = {
                    "continent": location_info.get("continent"),
                    "country": location_info.get("country"),
                    "timezone": location_info.get("timezone"),
                    "coordinates": location_info.get("coordinates"),
                }

            # Parse last seen
            last_seen_str = data.get("last_updated_at")
            if last_seen_str:
                try:
                    result.last_seen = datetime.fromisoformat(
                        last_seen_str.replace("Z", "+00:00")
                    )
                except (ValueError, AttributeError):
                    pass

            # Parse TLS certificates
            tls_data = data.get("tls", {})
            certs = tls_data.get("certificates", [])
            for cert in certs:
                cert_dict = {
                    "sha256": cert.get("sha256"),
                    "not_before": cert.get("not_before"),
                    "not_after": cert.get("not_after"),
                    "subject": cert.get("subject"),
                    "issuer": cert.get("issuer"),
                    "public_key_algorithm": cert.get("public_key_algorithm"),
                }
                result.tls_certs.append(cert_dict)

            return result
        except Exception as e:
            self.logger.error(f"Error parsing Censys response for {ip}: {e}")
            return None

    def _create_auth_header(self) -> str:
        """Create HTTP Basic auth header for Censys API.

        Returns:
            Authorization header value
        """
        if not self.api_id or not self.api_secret:
            return ""

        credentials = f"{self.api_id}:{self.api_secret}"
        encoded = b64encode(credentials.encode()).decode()
        return f"Basic {encoded}"

    def _get_from_cache(self, ip: str) -> Optional[CensysHostResult]:
        """Get cached result if available and not expired.

        Args:
            ip: IP address

        Returns:
            Cached result or None if not in cache or expired
        """
        if ip not in self._cache:
            return None

        result, timestamp = self._cache[ip]
        if time.time() - timestamp > self.cache_ttl:
            del self._cache[ip]
            return None

        return result

    async def _apply_rate_limit(self) -> None:
        """Apply rate limiting based on last request time."""
        elapsed = time.time() - self._last_request_time
        if elapsed < self.rate_limit:
            await asyncio.sleep(self.rate_limit - elapsed)
        self._last_request_time = time.time()

    @staticmethod
    def _is_valid_ip(ip: str) -> bool:
        """Check if string is a valid IP address.

        Args:
            ip: String to validate

        Returns:
            True if valid IPv4 or IPv6 address
        """
        import ipaddress

        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def clear_cache(self) -> None:
        """Clear the response cache."""
        self._cache.clear()
        self.logger.debug("Censys cache cleared")

    async def close(self) -> None:
        """Close async session."""
        if self._session:
            await self._session.close()
            self._session = None
