"""Nmap XML format importer for AegisScan.

Parses Nmap scan results in XML format and converts them to internal database
format. Handles edge cases including missing fields, partial scans, and
different Nmap versions.
"""

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any
import logging

logger = logging.getLogger(__name__)


@dataclass
class NmapScript:
    """Represents an Nmap NSE script result."""

    id: str
    output: str


@dataclass
class NmapPort:
    """Represents a port discovered by Nmap."""

    port_id: int
    protocol: str
    state: str
    service_name: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    extra_info: Optional[str] = None
    scripts: List[NmapScript] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "port": self.port_id,
            "protocol": self.protocol,
            "state": self.state,
            "service": self.service_name,
            "product": self.product,
            "version": self.version,
            "extra_info": self.extra_info,
            "scripts": [{"id": s.id, "output": s.output} for s in self.scripts],
        }


@dataclass
class NmapHost:
    """Represents a host discovered by Nmap."""

    ip: str
    hostname: Optional[str] = None
    status: str = "unknown"
    ports: List[NmapPort] = field(default_factory=list)
    os_matches: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "status": self.status,
            "ports": [p.to_dict() for p in self.ports],
            "os_matches": self.os_matches,
        }


@dataclass
class NmapScanResult:
    """Represents complete Nmap scan results."""

    scanner: str = "nmap"
    args: str = ""
    start_time: Optional[datetime] = None
    hosts: List[NmapHost] = field(default_factory=list)
    stats: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "scanner": self.scanner,
            "args": self.args,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "hosts": [h.to_dict() for h in self.hosts],
            "stats": self.stats,
        }


class NmapImporter:
    """Parser for Nmap XML output format.

    Handles multiple Nmap versions and gracefully manages missing/malformed data.
    """

    def __init__(self):
        """Initialize the Nmap importer."""
        self.logger = logging.getLogger(__name__)

    def parse_file(self, filepath: str) -> NmapScanResult:
        """Parse an Nmap XML output file.

        Args:
            filepath: Path to the Nmap XML file

        Returns:
            NmapScanResult: Parsed scan results

        Raises:
            FileNotFoundError: If file does not exist
            ET.ParseError: If XML is malformed
        """
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Nmap file not found: {filepath}")

        try:
            with open(path, "r", encoding="utf-8") as f:
                xml_content = f.read()
            return self.parse_string(xml_content)
        except ET.ParseError as e:
            self.logger.error(f"Failed to parse Nmap XML file {filepath}: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Error reading Nmap file {filepath}: {e}")
            raise

    def parse_string(self, xml_string: str) -> NmapScanResult:
        """Parse Nmap XML from string.

        Args:
            xml_string: XML content as string

        Returns:
            NmapScanResult: Parsed scan results

        Raises:
            ET.ParseError: If XML is malformed
        """
        try:
            root = ET.fromstring(xml_string)
        except ET.ParseError as e:
            self.logger.error(f"Failed to parse Nmap XML: {e}")
            raise

        result = NmapScanResult()

        # Parse scan metadata
        self._parse_metadata(root, result)

        # Parse hosts
        for host_elem in root.findall(".//host"):
            host = self._parse_host(host_elem)
            if host:
                result.hosts.append(host)

        # Parse statistics
        self._parse_stats(root, result)

        return result

    def _parse_metadata(self, root: ET.Element, result: NmapScanResult) -> None:
        """Extract scan metadata from root element.

        Args:
            root: Root XML element
            result: NmapScanResult to populate
        """
        # Get scanner info
        nmaprun = root
        result.scanner = "nmap"
        result.args = nmaprun.get("args", "")

        # Parse start time
        start_str = nmaprun.get("start")
        if start_str:
            try:
                result.start_time = datetime.utcfromtimestamp(int(start_str))
            except (ValueError, TypeError):
                self.logger.warning(f"Could not parse start time: {start_str}")

    def _parse_host(self, host_elem: ET.Element) -> Optional[NmapHost]:
        """Parse a single host element.

        Args:
            host_elem: Host XML element

        Returns:
            NmapHost or None if host has no addresses
        """
        # Extract IP address
        ip = None
        for addr in host_elem.findall("address[@addrtype='ipv4']"):
            ip = addr.get("addr")
            break

        if not ip:
            # Try IPv6
            for addr in host_elem.findall("address[@addrtype='ipv6']"):
                ip = addr.get("addr")
                break

        if not ip:
            self.logger.warning("Host element found without IP address")
            return None

        host = NmapHost(ip=ip)

        # Extract hostname
        for hostnames_elem in host_elem.findall("hostnames"):
            for hostname_elem in hostnames_elem.findall("hostname"):
                hostname = hostname_elem.get("name")
                if hostname:
                    host.hostname = hostname
                    break

        # Extract host status
        for status_elem in host_elem.findall("status"):
            state = status_elem.get("state", "unknown")
            host.status = state

        # Extract ports
        for ports_elem in host_elem.findall("ports"):
            for port_elem in ports_elem.findall("port"):
                port = self._parse_port(port_elem)
                if port:
                    host.ports.append(port)

        # Extract OS information
        for osmatch in host_elem.findall("os/osmatch"):
            os_data = {
                "name": osmatch.get("name", ""),
                "accuracy": osmatch.get("accuracy", "0"),
                "cpes": [],
            }

            for cpe_elem in osmatch.findall("cpe"):
                cpe_text = cpe_elem.text
                if cpe_text:
                    os_data["cpes"].append(cpe_text)

            host.os_matches.append(os_data)

        return host

    def _parse_port(self, port_elem: ET.Element) -> Optional[NmapPort]:
        """Parse a single port element.

        Args:
            port_elem: Port XML element

        Returns:
            NmapPort or None if port data is invalid
        """
        try:
            port_id = int(port_elem.get("portid", 0))
            protocol = port_elem.get("protocol", "tcp")
        except (ValueError, TypeError):
            self.logger.warning("Invalid port element data")
            return None

        if port_id == 0:
            return None

        port = NmapPort(port_id=port_id, protocol=protocol)

        # Extract port state
        for state_elem in port_elem.findall("state"):
            port.state = state_elem.get("state", "unknown")
            port.reason = state_elem.get("reason", "")

        # Extract service information
        for service_elem in port_elem.findall("service"):
            port.service_name = service_elem.get("name", port.service_name)
            port.product = service_elem.get("product", port.product)
            port.version = service_elem.get("version", port.version)
            port.extra_info = service_elem.get("extrainfo", port.extra_info)

        # Extract NSE script results
        for script_elem in port_elem.findall("script"):
            script_id = script_elem.get("id")
            script_output = script_elem.get("output", "")
            if script_id:
                port.scripts.append(NmapScript(id=script_id, output=script_output))

        return port

    def _parse_stats(self, root: ET.Element, result: NmapScanResult) -> None:
        """Extract scan statistics.

        Args:
            root: Root XML element
            result: NmapScanResult to populate
        """
        for runstats in root.findall(".//runstats"):
            for finished in runstats.findall("finished"):
                result.stats["finish_time"] = finished.get("timestr")
                try:
                    result.stats["finish_timestamp"] = int(finished.get("time", 0))
                except ValueError:
                    pass
                result.stats["elapsed"] = finished.get("elapsed")
                result.stats["summary"] = finished.get("summary", "")

            for hosts in runstats.findall("hosts"):
                result.stats["total_hosts"] = int(hosts.get("total", 0))
                result.stats["up_hosts"] = int(hosts.get("up", 0))
                result.stats["down_hosts"] = int(hosts.get("down", 0))

    def normalize_to_db(
        self, nmap_result: NmapScanResult, db_manager: Any, scan_run_id: str
    ) -> Dict[str, Any]:
        """Convert Nmap results to internal database format.

        Args:
            nmap_result: Parsed Nmap results
            db_manager: Database manager instance for schema validation
            scan_run_id: Identifier for this scan run

        Returns:
            Dictionary in database schema format
        """
        normalized = {
            "scan_run_id": scan_run_id,
            "scanner": nmap_result.scanner,
            "scanner_args": nmap_result.args,
            "scan_timestamp": nmap_result.start_time.isoformat()
            if nmap_result.start_time
            else None,
            "statistics": nmap_result.stats,
            "assets": [],
        }

        for host in nmap_result.hosts:
            asset = {
                "ip_address": host.ip,
                "hostname": host.hostname,
                "host_status": host.status,
                "discovered_services": [],
                "os_candidates": [],
                "last_scanned": nmap_result.start_time.isoformat()
                if nmap_result.start_time
                else None,
            }

            # Convert ports to services
            for port in host.ports:
                service = {
                    "port": port.port_id,
                    "protocol": port.protocol,
                    "state": port.state,
                    "service_name": port.service_name,
                    "product": port.product,
                    "version": port.version,
                    "extra_info": port.extra_info,
                    "scripts": [
                        {"name": s.id, "output": s.output} for s in port.scripts
                    ],
                }
                asset["discovered_services"].append(service)

            # Convert OS matches
            for os_match in host.os_matches:
                asset["os_candidates"].append(
                    {
                        "name": os_match.get("name"),
                        "accuracy": os_match.get("accuracy"),
                        "cpes": os_match.get("cpes", []),
                    }
                )

            normalized["assets"].append(asset)

        return normalized

    def merge_with_scan(
        self,
        nmap_data: NmapScanResult,
        internal_scan_data: Dict[str, Any],
        priority_rules: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Merge new Nmap data with existing internal scan data.

        Applies priority rules to determine which version of conflicting
        information to keep.

        Args:
            nmap_data: New Nmap scan results
            internal_scan_data: Existing internal scan data
            priority_rules: Dict mapping field names to priority strategy:
                - "newest": keep most recent timestamp
                - "nmap": always use nmap value
                - "internal": always use internal value
                - "merge": combine both values (for lists)

        Returns:
            Merged scan data
        """
        if priority_rules is None:
            priority_rules = {
                "hostname": "merge",
                "services": "merge",
                "os_info": "newest",
            }

        merged = internal_scan_data.copy()

        # Merge assets by IP
        internal_assets_by_ip = {
            asset["ip_address"]: asset for asset in merged.get("assets", [])
        }

        for nmap_host in nmap_data.hosts:
            ip = nmap_host.ip
            if ip in internal_assets_by_ip:
                internal_asset = internal_assets_by_ip[ip]

                # Merge hostname
                if priority_rules.get("hostname") == "merge":
                    if nmap_host.hostname and nmap_host.hostname != internal_asset.get(
                        "hostname"
                    ):
                        if internal_asset.get("hostname"):
                            hostnames = {internal_asset["hostname"]}
                            hostnames.add(nmap_host.hostname)
                            internal_asset["alternate_hostnames"] = list(hostnames)
                        else:
                            internal_asset["hostname"] = nmap_host.hostname

                # Merge services
                if priority_rules.get("services") == "merge":
                    self._merge_services(internal_asset, nmap_host)

                # Update OS info based on priority
                if priority_rules.get("os_info") == "newest":
                    if nmap_data.start_time and (
                        not internal_asset.get("last_scanned")
                        or nmap_data.start_time.isoformat()
                        > internal_asset.get("last_scanned")
                    ):
                        internal_asset["os_candidates"] = [
                            {
                                "name": os.get("name"),
                                "accuracy": os.get("accuracy"),
                                "cpes": os.get("cpes", []),
                            }
                            for os in nmap_host.os_matches
                        ]
                        internal_asset["last_scanned"] = nmap_data.start_time.isoformat()
            else:
                # New host
                new_asset = {
                    "ip_address": ip,
                    "hostname": nmap_host.hostname,
                    "host_status": nmap_host.status,
                    "discovered_services": [
                        {
                            "port": p.port_id,
                            "protocol": p.protocol,
                            "state": p.state,
                            "service_name": p.service_name,
                            "product": p.product,
                            "version": p.version,
                            "extra_info": p.extra_info,
                        }
                        for p in nmap_host.ports
                    ],
                    "os_candidates": [
                        {
                            "name": os.get("name"),
                            "accuracy": os.get("accuracy"),
                            "cpes": os.get("cpes", []),
                        }
                        for os in nmap_host.os_matches
                    ],
                    "last_scanned": nmap_data.start_time.isoformat()
                    if nmap_data.start_time
                    else None,
                }
                merged.setdefault("assets", []).append(new_asset)

        return merged

    @staticmethod
    def _merge_services(
        internal_asset: Dict[str, Any], nmap_host: NmapHost
    ) -> None:
        """Merge service/port information into asset.

        Args:
            internal_asset: Internal asset dict to update
            nmap_host: Nmap host with new service data
        """
        internal_services = {
            (s["port"], s["protocol"]): s
            for s in internal_asset.get("discovered_services", [])
        }

        for nmap_port in nmap_host.ports:
            key = (nmap_port.port_id, nmap_port.protocol)
            if key in internal_services:
                internal_service = internal_services[key]
                # Update service details if more specific
                if nmap_port.product and not internal_service.get("product"):
                    internal_service["product"] = nmap_port.product
                if nmap_port.version and not internal_service.get("version"):
                    internal_service["version"] = nmap_port.version
                # Update state to most recent
                internal_service["state"] = nmap_port.state
            else:
                # New service
                new_service = {
                    "port": nmap_port.port_id,
                    "protocol": nmap_port.protocol,
                    "state": nmap_port.state,
                    "service_name": nmap_port.service_name,
                    "product": nmap_port.product,
                    "version": nmap_port.version,
                    "extra_info": nmap_port.extra_info,
                }
                internal_asset.setdefault("discovered_services", []).append(
                    new_service
                )
