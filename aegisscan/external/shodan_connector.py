"""Shodan threat intelligence API connector."""

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

try:
    import aiohttp
except ImportError:
    aiohttp = None

try:
    import shodan
except ImportError:
    shodan = None

from .base import ExternalIntelConnector

logger = logging.getLogger(__name__)


@dataclass
class ShodanHostResult:
    """Result of a Shodan host lookup."""

    ip: str
    ports: List[int] = field(default_factory=list)
    services: List[Dict[str, Any]] = field(default_factory=list)
    banners: List[Dict[str, Any]] = field(default_factory=list)
    vulns: List[str] = field(default_factory=list)
    last_update: Optional[datetime] = None
    org: Optional[str] = None
    isp: Optional[str] = None
    os: Optional[str] = None
    raw_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "ip": self.ip,
            "ports": self.ports,
            "services": self.services,
            "banners": self.banners,
            "vulns": self.vulns,
            "last_update": self.last_update.isoformat() if self.last_update else None,
            "org": self.org,
            "isp": self.isp,
            "os": self.os,
        }


class ShodanConnector(ExternalIntelConnector):
    """Connector for Shodan threat intelligence API.

    Supports both the official shodan library (if available) and direct
    REST API access via aiohttp. Implements rate limiting, response caching,
    and graceful degradation when API keys are missing.

    Attributes:
        api_key: Shodan API key (optional)
        cache_ttl: Cache time-to-live in seconds (default: 3600)
        rate_limit: Delay between requests in seconds (default: 1.0 for free tier)
    """

    BASE_URL = "https://api.shodan.io"
    FREE_TIER_RATE_LIMIT = 1.0  # 1 request per second for free tier

    def __init__(
        self,
        api_key: Optional[str] = None,
        cache_ttl: int = 3600,
        rate_limit: float = FREE_TIER_RATE_LIMIT,
    ):
        """Initialize Shodan connector.

        Args:
            api_key: Shodan API key (optional)
            cache_ttl: Cache time-to-live in seconds
            rate_limit: Delay between API requests in seconds
        """
        enabled = api_key is not None and len(api_key) > 0
        super().__init__("shodan", enabled=enabled)

        self.api_key = api_key
        self.cache_ttl = cache_ttl
        self.rate_limit = rate_limit
        self._cache: Dict[str, tuple[ShodanHostResult, float]] = {}
        self._last_request_time = 0.0
        self._session: Optional[aiohttp.ClientSession] = None

        if enabled and shodan:
            self.logger.debug("Shodan library available, will use official API")
        elif enabled:
            self.logger.debug("Shodan library not available, using REST API")

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
        """Check if Shodan connector is operational."""
        if not self.enabled:
            return False

        if not aiohttp:
            self.logger.warning("aiohttp not available, cannot verify Shodan API")
            return False

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.BASE_URL}/api/info",
                    params={"key": self.api_key},
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as resp:
                    return resp.status == 200
        except Exception as e:
            self.logger.error(f"Shodan health check failed: {e}")
            return False

    async def lookup_host(self, ip: str) -> Optional[ShodanHostResult]:
        """Look up a single host on Shodan.

        Args:
            ip: IP address to look up

        Returns:
            ShodanHostResult or None if lookup fails

        Raises:
            ValueError: If IP address is invalid
        """
        if not self.enabled:
            self.logger.debug("Shodan connector disabled, skipping lookup")
            return None

        if not self._is_valid_ip(ip):
            raise ValueError(f"Invalid IP address: {ip}")

        # Check cache
        cached = self._get_from_cache(ip)
        if cached:
            return cached

        # Apply rate limiting
        await self._apply_rate_limit()

        result = None
        if shodan:
            result = await self._lookup_with_library(ip)
        elif aiohttp:
            result = await self._lookup_with_rest_api(ip)
        else:
            self.logger.error("Neither shodan library nor aiohttp available")

        if result:
            self._cache[ip] = (result, time.time())

        return result

    async def lookup_multiple(self, ips: List[str]) -> List[ShodanHostResult]:
        """Look up multiple hosts on Shodan.

        Processes IPs sequentially with rate limiting. Returns partial results
        if some lookups fail.

        Args:
            ips: List of IP addresses to look up

        Returns:
            List of ShodanHostResult objects (may be partial)
        """
        if not self.enabled:
            self.logger.debug("Shodan connector disabled, skipping batch lookup")
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

    async def _lookup_with_library(self, ip: str) -> Optional[ShodanHostResult]:
        """Look up host using official shodan library.

        Args:
            ip: IP address to look up

        Returns:
            ShodanHostResult or None if lookup fails
        """
        try:
            api = shodan.Shodan(self.api_key)
            data = await asyncio.to_thread(api.host, ip)
            return self._parse_library_response(ip, data)
        except shodan.APIError as e:
            self.logger.error(f"Shodan API error for {ip}: {e}")
            if "invalid API key" in str(e).lower():
                self.enabled = False
            return None
        except Exception as e:
            self.logger.error(f"Error looking up {ip} with Shodan library: {e}")
            return None

    async def _lookup_with_rest_api(self, ip: str) -> Optional[ShodanHostResult]:
        """Look up host using Shodan REST API via aiohttp.

        Args:
            ip: IP address to look up

        Returns:
            ShodanHostResult or None if lookup fails
        """
        if not self._session:
            self._session = aiohttp.ClientSession()

        try:
            async with self._session.get(
                f"{self.BASE_URL}/shodan/host/{ip}",
                params={"key": self.api_key},
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return self._parse_rest_response(ip, data)
                elif resp.status == 401:
                    self.logger.error("Invalid Shodan API key")
                    self.enabled = False
                    return None
                elif resp.status == 404:
                    self.logger.debug(f"IP {ip} not found in Shodan")
                    return None
                else:
                    self.logger.warning(f"Shodan API returned {resp.status}: {resp.reason}")
                    return None
        except asyncio.TimeoutError:
            self.logger.error(f"Shodan API timeout for {ip}")
            return None
        except Exception as e:
            self.logger.error(f"Error looking up {ip} with Shodan REST API: {e}")
            return None

    def _parse_library_response(
        self, ip: str, data: Dict[str, Any]
    ) -> Optional[ShodanHostResult]:
        """Parse response from official shodan library.

        Args:
            ip: IP address
            data: Response data from library

        Returns:
            ShodanHostResult or None
        """
        try:
            result = ShodanHostResult(
                ip=ip,
                ports=data.get("ports", []),
                org=data.get("org"),
                isp=data.get("isp"),
                os=data.get("os"),
                raw_data=data,
            )

            # Parse banners/services
            for banner in data.get("data", []):
                service = {
                    "port": banner.get("port"),
                    "protocol": banner.get("_shodan", {}).get("module"),
                    "banner": banner.get("data", ""),
                    "timestamp": banner.get("timestamp"),
                }
                result.banners.append(service)
                result.services.append(service)

            # Parse vulns
            vulns = data.get("vulns", {})
            result.vulns = list(vulns.keys()) if vulns else []

            # Parse last update
            last_update = data.get("last_update")
            if last_update:
                try:
                    result.last_update = datetime.fromisoformat(
                        last_update.replace("Z", "+00:00")
                    )
                except (ValueError, AttributeError):
                    pass

            return result
        except Exception as e:
            self.logger.error(f"Error parsing Shodan library response for {ip}: {e}")
            return None

    def _parse_rest_response(
        self, ip: str, data: Dict[str, Any]
    ) -> Optional[ShodanHostResult]:
        """Parse response from Shodan REST API.

        Args:
            ip: IP address
            data: JSON response data

        Returns:
            ShodanHostResult or None
        """
        try:
            result = ShodanHostResult(
                ip=ip,
                ports=data.get("ports", []),
                org=data.get("org"),
                isp=data.get("isp"),
                os=data.get("os"),
                raw_data=data,
            )

            # Parse banners/services
            for banner in data.get("data", []):
                service = {
                    "port": banner.get("port"),
                    "protocol": banner.get("_shodan", {}).get("module"),
                    "banner": banner.get("data", ""),
                    "timestamp": banner.get("timestamp"),
                }
                result.banners.append(service)
                result.services.append(service)

            # Parse vulns
            vulns = data.get("vulns", {})
            result.vulns = list(vulns.keys()) if vulns else []

            # Parse last update
            last_update = data.get("last_update")
            if last_update:
                try:
                    result.last_update = datetime.fromisoformat(
                        last_update.replace("Z", "+00:00")
                    )
                except (ValueError, AttributeError):
                    pass

            return result
        except Exception as e:
            self.logger.error(f"Error parsing Shodan REST response for {ip}: {e}")
            return None

    def _get_from_cache(self, ip: str) -> Optional[ShodanHostResult]:
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
        self.logger.debug("Shodan cache cleared")

    async def close(self) -> None:
        """Close async session."""
        if self._session:
            await self._session.close()
            self._session = None
