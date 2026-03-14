"""External intelligence connector module for AegisScan.

Provides plugin-style connectors to external threat intelligence services
like Shodan and Censys.
"""

from .base import ExternalIntelConnector
from .shodan_connector import ShodanConnector, ShodanHostResult
from .censys_connector import CensysConnector, CensysHostResult

__all__ = [
    "ExternalIntelConnector",
    "ShodanConnector",
    "ShodanHostResult",
    "CensysConnector",
    "CensysHostResult",
]
