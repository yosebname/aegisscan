"""Nmap XML 결과 파싱 및 정규화."""
import json
import logging
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def parse_nmap_xml(path: str | Path) -> List[Dict[str, Any]]:
    """
    Nmap XML 파일 파싱.
    반환: [ {"host": "1.2.3.4", "ports": [ {"port": 80, "state": "open", "service": "http", "version": "...", "scripts": [...] } ] }, ... ]
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(str(path))
    tree = ET.parse(path)
    root = tree.getroot()

    results = []
    for host_elem in root.findall(".//host"):
        status = host_elem.find("status")
        if status is not None and status.get("state") == "down":
            continue
        addr = host_elem.find("address[@addrtype='ipv4']")
        if addr is None:
            addr = host_elem.find("address[@addrtype='ipv6']")
        if addr is None:
            continue
        ip = addr.get("addr")
        if not ip:
            continue
        hostnames = [e.get("name") for e in host_elem.findall("hostnames/hostname") if e.get("name")]

        ports_list = []
        for port_elem in host_elem.findall("ports/port"):
            proto = port_elem.get("protocol", "tcp")
            port_id = port_elem.get("port")
            if not port_id:
                continue
            try:
                port_num = int(port_id)
            except ValueError:
                continue
            state_elem = port_elem.find("state")
            state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"
            svc_elem = port_elem.find("service")
            service_name = svc_elem.get("name") if svc_elem is not None else None
            product = svc_elem.get("product") if svc_elem is not None else None
            version = svc_elem.get("version") if svc_elem is not None else None
            scripts = []
            for script_elem in port_elem.findall("script"):
                scripts.append({
                    "id": script_elem.get("id"),
                    "output": script_elem.get("output"),
                })
            ports_list.append({
                "port": port_num,
                "proto": proto,
                "state": state,
                "service": service_name,
                "product": product,
                "version": version,
                "scripts": scripts,
            })
        results.append({
            "host": ip,
            "hostnames": hostnames,
            "ports": ports_list,
        })
    return results


class NmapXMLImporter:
    """Nmap XML 파싱 후 DB 정규화 스키마로 변환."""

    @staticmethod
    def parse(path: str | Path) -> List[Dict[str, Any]]:
        return parse_nmap_xml(path)

    @staticmethod
    def to_normalized(nmap_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        내부 스키마용 정규화.
        hosts + nmap_observations 형태로 반환.
        """
        out = []
        for h in nmap_results:
            host_ip = h["host"]
            hostnames = h.get("hostnames", [])
            for p in h.get("ports", []):
                if p.get("state") != "open":
                    continue
                out.append({
                    "host": host_ip,
                    "hostname": hostnames[0] if hostnames else None,
                    "port": p["port"],
                    "proto": p.get("proto", "tcp"),
                    "nmap_service": p.get("service"),
                    "nmap_version": p.get("version") or p.get("product"),
                    "scripts_summary": json.dumps(p.get("scripts", [])) if p.get("scripts") else None,
                })
        return out
