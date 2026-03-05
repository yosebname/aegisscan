"""Abstract base class for external intelligence connectors."""

from abc import ABC, abstractmethod
from typing import Any, Optional
import logging

logger = logging.getLogger(__name__)


class ExternalIntelConnector(ABC):
    """Abstract base class for external intelligence data sources.

    All external connectors should inherit from this class and implement
    the required methods. Connectors are plugin-style and should gracefully
    handle missing credentials.
    """

    def __init__(self, name: str, enabled: bool = False):
        """Initialize connector.

        Args:
            name: Connector name (e.g., 'shodan', 'censys')
            enabled: Whether connector is operational with valid credentials
        """
        self.name = name
        self.enabled = enabled
        self.logger = logging.getLogger(f"{__name__}.{name}")

    @abstractmethod
    async def lookup_host(self, ip: str) -> Optional[Any]:
        """Look up intelligence for a single host.

        Args:
            ip: IP address to look up

        Returns:
            Host result object or None if lookup fails/unavailable

        Raises:
            NotImplementedError: Must be implemented by subclass
        """
        pass

    @abstractmethod
    async def lookup_multiple(self, ips: list[str]) -> list[Any]:
        """Look up intelligence for multiple hosts.

        Args:
            ips: List of IP addresses to look up

        Returns:
            List of host result objects (may be partial)

        Raises:
            NotImplementedError: Must be implemented by subclass
        """
        pass

    async def health_check(self) -> bool:
        """Check if connector is healthy and operational.

        Returns:
            True if connector is ready to use
        """
        return self.enabled

    def __str__(self) -> str:
        """Return string representation."""
        return f"{self.name} (enabled={self.enabled})"
