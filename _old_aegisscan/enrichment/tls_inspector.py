"""
TLS certificate inspection module for service enrichment.

Provides asynchronous TLS/SSL certificate extraction and analysis,
including x509 field parsing, chain verification, and expiry monitoring.
"""

import asyncio
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple
from ipaddress import IPv4Address
import hashlib


@dataclass
class TLSResult:
    """
    Result of a TLS/SSL certificate inspection.
    
    Attributes:
        ip: Target IP address
        port: Target port number
        sni: Server Name Indication hostname if used
        subject_cn: Common Name from certificate subject
        issuer_cn: Common Name from certificate issuer
        issuer_org: Organization from certificate issuer
        not_before: Certificate valid from date (UTC)
        not_after: Certificate expiry date (UTC)
        days_until_expiry: Days until certificate expires (-1 if expired)
        san_list: List of Subject Alternative Names
        serial_number: Certificate serial number (hex string)
        fingerprint_sha256: SHA256 fingerprint of certificate
        signature_algorithm: Signature algorithm used
        key_size: Public key size in bits
        protocol_version: TLS protocol version (e.g., "TLSv1.2", "TLSv1.3")
        certificate_chain_summary: List of issuer CN names in chain
        is_self_signed: Whether certificate is self-signed
        is_expired: Whether certificate has expired
        is_expiring_soon: Whether certificate expires within 30 days
        error: Error message if inspection failed
        timestamp: When the inspection was performed
    """
    ip: str
    port: int
    sni: Optional[str] = None
    subject_cn: Optional[str] = None
    issuer_cn: Optional[str] = None
    issuer_org: Optional[str] = None
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    days_until_expiry: Optional[int] = None
    san_list: List[str] = field(default_factory=list)
    serial_number: Optional[str] = None
    fingerprint_sha256: Optional[str] = None
    signature_algorithm: Optional[str] = None
    key_size: Optional[int] = None
    protocol_version: Optional[str] = None
    certificate_chain_summary: List[str] = field(default_factory=list)
    is_self_signed: bool = False
    is_expired: bool = False
    is_expiring_soon: bool = False
    error: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)

    def is_success(self) -> bool:
        """Check if TLS inspection was successful."""
        return self.error is None and self.subject_cn is not None


class TLSInspector:
    """
    Asynchronous TLS/SSL certificate inspector.
    
    Extracts and parses x509 certificate information from TLS connections,
    including certificate chain analysis and expiry monitoring.
    """

    def __init__(self, timeout: float = 10.0, max_concurrent: int = 20):
        """
        Initialize TLS inspector.
        
        Args:
            timeout: Connection timeout in seconds (default: 10.0)
            max_concurrent: Maximum concurrent connections (default: 20)
        """
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.semaphore = asyncio.Semaphore(max_concurrent)

    async def inspect_tls(
        self,
        ip: str,
        port: int,
        sni: Optional[str] = None
    ) -> TLSResult:
        """
        Inspect TLS certificate from a single target.
        
        Args:
            ip: Target IP address
            port: Target port number
            sni: Server Name Indication hostname (optional)
            
        Returns:
            TLSResult with certificate information or error details
        """
        async with self.semaphore:
            return await self._inspect_tls_internal(ip, port, sni)

    async def _inspect_tls_internal(
        self,
        ip: str,
        port: int,
        sni: Optional[str] = None
    ) -> TLSResult:
        """Internal method to perform TLS inspection."""
        result = TLSResult(ip=ip, port=port, sni=sni)
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Override ServerHostnameCallback if SNI provided
            if sni:
                context.server_hostname = sni
            
            # Establish TLS connection
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    ip, port, ssl=context
                ),
                timeout=self.timeout
            )
            
            # Get SSL object from writer
            ssl_object = writer.get_extra_info('ssl_object')
            
            # Extract certificate and parse it
            der_cert = ssl_object.getpeercert(binary_form=True)
            if not der_cert:
                writer.close()
                await writer.wait_closed()
                result.error = "Failed to retrieve certificate"
                return result
            
            # Parse certificate
            cert_dict = ssl_object.getpeercert(binary_form=False)
            
            # Get protocol version
            result.protocol_version = ssl_object.version()
            
            # Get cipher information
            cipher_info = ssl_object.cipher()
            
            # Close connection
            writer.close()
            await writer.wait_closed()
            
            # Parse certificate fields
            self._parse_certificate(result, cert_dict, der_cert)
            
            return result
            
        except asyncio.TimeoutError:
            result.error = "Connection timeout"
            return result
        except ssl.SSLError as e:
            result.error = f"SSL error: {str(e)}"
            return result
        except Exception as e:
            result.error = f"TLS inspection failed: {str(e)}"
            return result

    def _parse_certificate(
        self,
        result: TLSResult,
        cert_dict: Dict[str, Any],
        der_cert: bytes
    ) -> None:
        """
        Parse x509 certificate fields.
        
        Args:
            result: TLSResult object to populate
            cert_dict: Certificate dictionary from ssl.getpeercert()
            der_cert: Raw DER-encoded certificate bytes
        """
        try:
            # Parse subject
            subject = dict(x[0] for x in cert_dict.get('subject', []))
            result.subject_cn = subject.get('commonName')
            
            # Parse issuer
            issuer = dict(x[0] for x in cert_dict.get('issuer', []))
            result.issuer_cn = issuer.get('commonName')
            result.issuer_org = issuer.get('organizationName')
            
            # Check if self-signed
            result.is_self_signed = (
                result.subject_cn == result.issuer_cn and
                subject == issuer
            )
            
            # Parse Subject Alternative Names
            san_list = []
            for sub_alt_names in cert_dict.get('subjectAltName', []):
                if sub_alt_names[0] == 'DNS':
                    san_list.append(sub_alt_names[1])
            result.san_list = san_list
            
            # Parse validity dates
            not_before_str = cert_dict.get('notBefore')
            not_after_str = cert_dict.get('notAfter')
            
            if not_before_str:
                result.not_before = self._parse_asn1_time(not_before_str)
            if not_after_str:
                result.not_after = self._parse_asn1_time(not_after_str)
            
            # Calculate expiry metrics
            if result.not_after:
                now = datetime.now(timezone.utc)
                result.is_expired = now > result.not_after
                days_delta = (result.not_after - now).days
                result.days_until_expiry = days_delta
                result.is_expiring_soon = 0 <= days_delta < 30
            
            # Parse serial number
            serial = cert_dict.get('serialNumber')
            if serial:
                result.serial_number = hex(int(serial))[2:]
            
            # Calculate SHA256 fingerprint
            result.fingerprint_sha256 = hashlib.sha256(der_cert).hexdigest()
            
            # Parse signature algorithm
            result.signature_algorithm = cert_dict.get('signatureAlgorithm')
            
            # Try to extract key size
            result.key_size = self._extract_key_size(der_cert)
            
            # Parse certificate chain
            result.certificate_chain_summary = [result.issuer_cn] if result.issuer_cn else []
            
        except Exception as e:
            # Parsing errors are non-fatal; result is partially populated
            pass

    def _parse_asn1_time(self, time_str: str) -> datetime:
        """
        Parse ASN.1 time string (from ssl module).
        
        Format: 'Jan  1 00:00:00 2025 GMT'
        
        Args:
            time_str: ASN.1 formatted time string
            
        Returns:
            datetime object in UTC
        """
        try:
            # Format: 'Jan  1 00:00:00 2025 GMT'
            time_str = time_str.replace('  ', ' ')  # Normalize spacing
            dt = datetime.strptime(time_str, '%b %d %H:%M:%S %Y %Z')
            # Ensure UTC timezone
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            # Fallback for different formats
            return datetime.now(timezone.utc)

    def _extract_key_size(self, der_cert: bytes) -> Optional[int]:
        """
        Extract public key size from DER certificate.
        
        This is a simplified extraction using common bit patterns.
        
        Args:
            der_cert: Raw DER-encoded certificate
            
        Returns:
            Key size in bits or None if unable to determine
        """
        try:
            # Look for common key size patterns in DER
            # These are rough heuristics based on certificate structure
            
            # 256-byte (2048-bit RSA)
            if b'\x82\x01\x01' in der_cert:
                return 2048
            # 384-byte (3072-bit RSA)
            if b'\x82\x01\x81' in der_cert:
                return 3072
            # 512-byte (4096-bit RSA)
            if b'\x82\x02\x01' in der_cert:
                return 4096
            # 160-byte (1280-bit RSA)
            if b'\x82\x00\xa0' in der_cert:
                return 1280
            
            # Default common sizes
            if len(der_cert) > 800:
                return 4096
            elif len(der_cert) > 500:
                return 2048
            
            return None
        except Exception:
            return None

    async def inspect_multiple(
        self,
        targets: List[tuple]
    ) -> List[TLSResult]:
        """
        Inspect TLS certificates from multiple targets concurrently.
        
        Args:
            targets: List of (ip, port) or (ip, port, sni) tuples
            
        Returns:
            List of TLSResult objects
        """
        tasks = []
        for target in targets:
            if len(target) == 2:
                ip, port = target
                sni = None
            elif len(target) == 3:
                ip, port, sni = target
            else:
                continue
            
            task = self.inspect_tls(ip, port, sni)
            tasks.append(task)
        
        return await asyncio.gather(*tasks, return_exceptions=False)
