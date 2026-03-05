"""TLS 인증서 수집: SNI, CN/SAN, 발급자, 유효기간, 서명 알고리즘."""
import asyncio
import logging
import ssl
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, List

logger = logging.getLogger(__name__)


@dataclass
class TLSInfo:
    sni: Optional[str]
    subject: Optional[str]
    issuer: Optional[str]
    not_before: Optional[datetime]
    not_after: Optional[datetime]
    san_list: List[str]
    fingerprint_sha256: Optional[str]
    signature_algorithm: Optional[str]


def _peer_cert_to_tls_info(peer_cert: Optional[dict], sni: Optional[str]) -> Optional[TLSInfo]:
    if not peer_cert:
        return None
    subject = peer_cert.get("subject")
    issuer = peer_cert.get("issuer")

    def fmt_name(name):
        if isinstance(name, (list, tuple)):
            parts = []
            for t in name:
                if isinstance(t, (list, tuple)) and len(t) == 2:
                    parts.append(f"{t[0]}={t[1]}")
                else:
                    parts.append(str(t))
            return ", ".join(parts)
        return str(name) if name else None

    not_before = peer_cert.get("notBefore")
    not_after = peer_cert.get("notAfter")
    if isinstance(not_before, str):
        try:
            not_before = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
        except Exception:
            not_before = None
    if isinstance(not_after, str):
        try:
            not_after = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        except Exception:
            not_after = None
    san: List[str] = []
    ext = peer_cert.get("subjectAltName", ())
    if ext:
        for part in ext:
            if isinstance(part, (list, tuple)) and len(part) == 2 and part[0] == "DNS":
                san.append(part[1])
    fingerprint = peer_cert.get("fingerprint_sha256", "").replace(":", "").lower() if isinstance(
        peer_cert.get("fingerprint_sha256"), str
    ) else None
    return TLSInfo(
        sni=sni,
        subject=fmt_name(subject) if subject else None,
        issuer=fmt_name(issuer) if issuer else None,
        not_before=not_before,
        not_after=not_after,
        san_list=san,
        fingerprint_sha256=fingerprint,
        signature_algorithm=peer_cert.get("signature_algorithm") if isinstance(peer_cert.get("signature_algorithm"), str) else None,
    )


async def get_tls_info(host: str, port: int, sni: Optional[str] = None, timeout: float = 5.0) -> Optional[TLSInfo]:
    """TLS 핸드셰이크 후 인증서 정보 반환."""
    import socket
    sni = sni or host
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def sync_connect():
        sock = socket.create_connection((host, port), timeout=timeout)
        try:
            ssock = ctx.wrap_socket(sock, server_hostname=sni)
            cert_der = ssock.getpeercert()
            cert_bin = ssock.getpeercert(binary_form=True)
            if cert_der and cert_bin:
                import hashlib
                cert_der["fingerprint_sha256"] = hashlib.sha256(cert_bin).hexdigest()
            ssock.close()
            return cert_der
        finally:
            sock.close()

    try:
        loop = asyncio.get_event_loop()
        cert = await asyncio.wait_for(
            loop.run_in_executor(None, sync_connect),
            timeout=timeout + 2,
        )
        return _peer_cert_to_tls_info(cert, sni)
    except Exception as e:
        logger.debug("TLS %s:%s %s", host, port, e)
        return None


class TLSInspector:
    """TLS 인증서 수집 래퍼."""

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    async def inspect(self, host: str, port: int, sni: Optional[str] = None) -> Optional[TLSInfo]:
        return await get_tls_info(host, port, sni=sni, timeout=self.timeout)
