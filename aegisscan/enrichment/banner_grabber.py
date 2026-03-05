"""
Asynchronous banner grabbing module for service identification.

Provides protocol-specific banner extraction and parsing capabilities
for common network services (HTTP, SSH, FTP, SMTP, Redis, MySQL, etc.)
with automatic protocol detection based on port numbers.
"""

import asyncio
import socket
import ssl
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Any
from enum import Enum
import re


class Protocol(str, Enum):
    """Common network protocols."""
    HTTP = "http"
    HTTPS = "https"
    SSH = "ssh"
    FTP = "ftp"
    SMTP = "smtp"
    REDIS = "redis"
    MYSQL = "mysql"
    GENERIC = "generic"


class PortMapping(Enum):
    """Default protocol ports for auto-detection."""
    HTTP = 80
    HTTPS = 443
    SSH = 22
    FTP = 21
    SMTP = 25
    REDIS = 6379
    MYSQL = 3306


@dataclass
class BannerResult:
    """
    Result of a banner grab operation.
    
    Attributes:
        ip: Target IP address
        port: Target port number
        protocol: Detected or specified protocol
        raw_banner: Raw bytes received from service
        parsed_fields: Dictionary of parsed protocol-specific fields
        error: Error message if grab failed, None if successful
        timestamp: When the grab was performed
    """
    ip: str
    port: int
    protocol: str
    raw_banner: Optional[bytes] = None
    parsed_fields: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)

    def is_success(self) -> bool:
        """Check if banner grab was successful."""
        return self.error is None and self.raw_banner is not None

    def decode_banner_safe(self) -> str:
        """Safely decode banner bytes to string, replacing invalid chars."""
        if not self.raw_banner:
            return ""
        return self.raw_banner.decode('utf-8', errors='replace').strip()


class ProtocolHandler(ABC):
    """
    Abstract base class for protocol-specific banner handlers.
    
    Each handler implements protocol-specific logic for connecting,
    sending commands, and parsing responses.
    """

    def __init__(self, timeout: float = 5.0):
        """
        Initialize protocol handler.
        
        Args:
            timeout: Connection timeout in seconds
        """
        self.timeout = timeout

    @abstractmethod
    async def grab_banner(self, ip: str, port: int) -> BannerResult:
        """
        Grab banner from the service.
        
        Args:
            ip: Target IP address
            port: Target port number
            
        Returns:
            BannerResult with parsed data or error information
        """
        pass

    @staticmethod
    def _safe_decode(data: bytes, encoding: str = 'utf-8') -> str:
        """Safely decode bytes, replacing invalid characters."""
        return data.decode(encoding, errors='replace')


class HTTPHandler(ProtocolHandler):
    """Handler for HTTP banners."""

    async def grab_banner(self, ip: str, port: int) -> BannerResult:
        """Grab HTTP banner by sending GET request."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=self.timeout
            )
            
            # Send HTTP GET request
            request = b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\nConnection: close\r\n\r\n"
            writer.write(request)
            await writer.drain()
            
            # Read response
            response = await asyncio.wait_for(
                reader.read(4096),
                timeout=self.timeout
            )
            
            writer.close()
            await writer.wait_closed()
            
            parsed = self._parse_http(response)
            return BannerResult(
                ip=ip,
                port=port,
                protocol=Protocol.HTTP.value,
                raw_banner=response,
                parsed_fields=parsed
            )
        except asyncio.TimeoutError:
            return BannerResult(
                ip=ip, port=port,
                protocol=Protocol.HTTP.value,
                error="Connection timeout"
            )
        except Exception as e:
            return BannerResult(
                ip=ip, port=port,
                protocol=Protocol.HTTP.value,
                error=f"HTTP grab failed: {str(e)}"
            )

    def _parse_http(self, response: bytes) -> Dict[str, Any]:
        """Parse HTTP response headers."""
        try:
            text = self._safe_decode(response)
            lines = text.split('\r\n')
            
            parsed = {}
            
            # Parse status line
            if lines:
                status_parts = lines[0].split()
                if len(status_parts) >= 2:
                    parsed['status_code'] = status_parts[1]
                    if len(status_parts) >= 3:
                        parsed['status_text'] = ' '.join(status_parts[2:])
            
            # Parse headers
            for line in lines[1:]:
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip()
                    value = value.strip()
                    
                    # Store relevant headers
                    if key.lower() == 'server':
                        parsed['server'] = value
                    elif key.lower() == 'x-powered-by':
                        parsed['x_powered_by'] = value
                    elif key.lower() == 'content-type':
                        parsed['content_type'] = value
            
            return parsed
        except Exception:
            return {}


class HTTPSHandler(HTTPHandler):
    """Handler for HTTPS banners."""

    async def grab_banner(self, ip: str, port: int) -> BannerResult:
        """Grab HTTPS banner over TLS connection."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=context),
                timeout=self.timeout
            )
            
            # Send HTTP GET request
            request = b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\nConnection: close\r\n\r\n"
            writer.write(request)
            await writer.drain()
            
            # Read response
            response = await asyncio.wait_for(
                reader.read(4096),
                timeout=self.timeout
            )
            
            writer.close()
            await writer.wait_closed()
            
            parsed = self._parse_http(response)
            return BannerResult(
                ip=ip,
                port=port,
                protocol=Protocol.HTTPS.value,
                raw_banner=response,
                parsed_fields=parsed
            )
        except asyncio.TimeoutError:
            return BannerResult(
                ip=ip, port=port,
                protocol=Protocol.HTTPS.value,
                error="Connection timeout"
            )
        except Exception as e:
            return BannerResult(
                ip=ip, port=port,
                protocol=Protocol.HTTPS.value,
                error=f"HTTPS grab failed: {str(e)}"
            )


class SSHHandler(ProtocolHandler):
    """Handler for SSH version strings."""

    async def grab_banner(self, ip: str, port: int) -> BannerResult:
        """Grab SSH version string."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=self.timeout
            )
            
            # SSH sends version string immediately
            banner = await asyncio.wait_for(
                reader.readline(),
                timeout=self.timeout
            )
            
            writer.close()
            await writer.wait_closed()
            
            parsed = self._parse_ssh(banner)
            return BannerResult(
                ip=ip,
                port=port,
                protocol=Protocol.SSH.value,
                raw_banner=banner,
                parsed_fields=parsed
            )
        except asyncio.TimeoutError:
            return BannerResult(
                ip=ip, port=port,
                protocol=Protocol.SSH.value,
                error="Connection timeout"
            )
        except Exception as e:
            return BannerResult(
                ip=ip, port=port,
                protocol=Protocol.SSH.value,
                error=f"SSH grab failed: {str(e)}"
            )

    def _parse_ssh(self, banner: bytes) -> Dict[str, Any]:
        """Parse SSH protocol version string."""
        try:
            text = self._safe_decode(banner)
            if text.startswith('SSH-'):
                parts = text.split('-')
                if len(parts) >= 3:
                    return {
                        'protocol_version': parts[1],
                        'software': '-'.join(parts[2:]).strip()
                    }
            return {}
        except Exception:
            return {}


class FTPHandler(ProtocolHandler):
    """Handler for FTP banners."""

    async def grab_banner(self, ip: str, port: int) -> BannerResult:
        """Grab FTP 220 welcome banner."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=self.timeout
            )
            
            # FTP sends 220 banner immediately
            banner = await asyncio.wait_for(
                reader.readline(),
                timeout=self.timeout
            )
            
            writer.close()
            await writer.wait_closed()
            
            parsed = self._parse_ftp(banner)
            return BannerResult(
                ip=ip,
                port=port,
                protocol=Protocol.FTP.value,
                raw_banner=banner,
                parsed_fields=parsed
            )
        except asyncio.TimeoutError:
            return BannerResult(
                ip=ip, port=port,
                protocol=Protocol.FTP.value,
                error="Connection timeout"
            )
        except Exception as e:
            return BannerResult(
                ip=ip, port=port,
                protocol=Protocol.FTP.value,
                error=f"FTP grab failed: {str(e)}"
            )

    def _parse_ftp(self, banner: bytes) -> Dict[str, Any]:
        """Parse FTP response code and message."""
        try:
            text = self._safe_decode(banner)
            match = re.match(r'(\d{3})\s+(.*)', text)
            if match:
                return {
                    'response_code': match.group(1),
                    'message': match.group(2).strip()
                }
            return {}
        except Exception:
            return {}


class SMTPHandler(ProtocolHandler):
    """Handler for SMTP banners."""

    async def grab_banner(self, ip: str, port: int) -> BannerResult:
        """Grab SMTP 220 welcome banner."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=self.timeout
            )
            
            # SMTP sends 220 banner immediately
            banner = await asyncio.wait_for(
                reader.readline(),
                timeout=self.timeout
            )
            
            writer.close()
            await writer.wait_closed()
            
            parsed = self._parse_smtp(banner)
            return BannerResult(
                ip=ip,
                port=port,
                protocol=Protocol.SMTP.value,
                raw_banner=banner,
                parsed_fields=parsed
            )
        except asyncio.TimeoutError:
            return BannerResult(
                ip=ip, port=port,
                protocol=Protocol.SMTP.value,
                error="Connection timeout"
            )
        except Exception as e:
            return BannerResult(
                ip=ip, port=port,
                protocol=Protocol.SMTP.value,
                error=f"SMTP grab failed: {str(e)}"
            )

    def _parse_smtp(self, banner: bytes) -> Dict[str, Any]:
        """Parse SMTP response code and message."""
        try:
            text = self._safe_decode(banner)
            match = re.match(r'(\d{3})\s+(.*)', text)
            if match:
                return {
                    'response_code': match.group(1),
                    'message': match.group(2).strip()
                }
            return {}
        except Exception:
            return {}


class RedisHandler(ProtocolHandler):
    """Handler for Redis banners."""

    async def grab_banner(self, ip: str, port: int) -> BannerResult:
        """Grab Redis server info via PING."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=self.timeout
            )
            
            # Send PING command
            writer.write(b"*1\r\n$4\r\nPING\r\n")
            await writer.drain()
            
            # Read response
            banner = await asyncio.wait_for(
                reader.readline(),
                timeout=self.timeout
            )
            
            writer.close()
            await writer.wait_closed()
            
            parsed = self._parse_redis(banner)
            return BannerResult(
                ip=ip,
                port=port,
                protocol=Protocol.REDIS.value,
                raw_banner=banner,
                parsed_fields=parsed
            )
        except asyncio.TimeoutError:
            return BannerResult(
                ip=ip, port=port,
                protocol=Protocol.REDIS.value,
                error="Connection timeout"
            )
        except Exception as e:
            return BannerResult(
                ip=ip, port=port,
                protocol=Protocol.REDIS.value,
                error=f"Redis grab failed: {str(e)}"
            )

    def _parse_redis(self, banner: bytes) -> Dict[str, Any]:
        """Parse Redis response."""
        try:
            text = self._safe_decode(banner)
            if text.startswith('+PONG'):
                return {'response': 'PONG', 'authenticated': False}
            elif text.startswith('-'):
                return {'error': text.strip()}
            return {'response': text.strip()}
        except Exception:
            return {}


class MySQLHandler(ProtocolHandler):
    """Handler for MySQL handshake packets."""

    async def grab_banner(self, ip: str, port: int) -> BannerResult:
        """Grab MySQL server version from handshake packet."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=self.timeout
            )
            
            # MySQL sends handshake packet immediately
            banner = await asyncio.wait_for(
                reader.read(256),
                timeout=self.timeout
            )
            
            writer.close()
            await writer.wait_closed()
            
            parsed = self._parse_mysql(banner)
            return BannerResult(
                ip=ip,
                port=port,
                protocol=Protocol.MYSQL.value,
                raw_banner=banner,
                parsed_fields=parsed
            )
        except asyncio.TimeoutError:
            return BannerResult(
                ip=ip, port=port,
                protocol=Protocol.MYSQL.value,
                error="Connection timeout"
            )
        except Exception as e:
            return BannerResult(
                ip=ip, port=port,
                protocol=Protocol.MYSQL.value,
                error=f"MySQL grab failed: {str(e)}"
            )

    def _parse_mysql(self, packet: bytes) -> Dict[str, Any]:
        """Parse MySQL handshake packet."""
        try:
            if len(packet) < 10:
                return {}
            
            # MySQL handshake format:
            # 1 byte protocol version
            # null-terminated string: server version
            # 4 bytes: connection ID
            # 8 bytes: auth plugin data part 1
            # 1 byte: filler
            # 2 bytes: capability flags
            # etc.
            
            protocol_version = packet[0]
            # Find null terminator for version string
            null_idx = packet.find(b'\x00', 1)
            if null_idx > 1:
                version_str = packet[1:null_idx].decode('utf-8', errors='replace')
                return {
                    'protocol_version': protocol_version,
                    'server_version': version_str
                }
            return {}
        except Exception:
            return {}


class GenericHandler(ProtocolHandler):
    """Generic handler for unknown protocols."""

    async def grab_banner(self, ip: str, port: int) -> BannerResult:
        """Read first N bytes as generic banner."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=self.timeout
            )
            
            # Read first chunk
            banner = await asyncio.wait_for(
                reader.read(1024),
                timeout=self.timeout
            )
            
            writer.close()
            await writer.wait_closed()
            
            return BannerResult(
                ip=ip,
                port=port,
                protocol=Protocol.GENERIC.value,
                raw_banner=banner
            )
        except asyncio.TimeoutError:
            return BannerResult(
                ip=ip, port=port,
                protocol=Protocol.GENERIC.value,
                error="Connection timeout"
            )
        except Exception as e:
            return BannerResult(
                ip=ip, port=port,
                protocol=Protocol.GENERIC.value,
                error=f"Generic grab failed: {str(e)}"
            )


class BannerGrabber:
    """
    Asynchronous banner grabber for service identification.
    
    Supports multiple protocols with automatic detection based on port numbers.
    Implements concurrent grabbing with configurable concurrency control.
    """

    # Protocol -> Handler mapping
    PROTOCOL_HANDLERS = {
        Protocol.HTTP: HTTPHandler,
        Protocol.HTTPS: HTTPSHandler,
        Protocol.SSH: SSHHandler,
        Protocol.FTP: FTPHandler,
        Protocol.SMTP: SMTPHandler,
        Protocol.REDIS: RedisHandler,
        Protocol.MYSQL: MySQLHandler,
        Protocol.GENERIC: GenericHandler,
    }

    # Port -> Protocol auto-detection mapping
    PORT_PROTOCOL_MAP = {
        80: Protocol.HTTP,
        443: Protocol.HTTPS,
        22: Protocol.SSH,
        21: Protocol.FTP,
        25: Protocol.SMTP,
        6379: Protocol.REDIS,
        3306: Protocol.MYSQL,
    }

    def __init__(
        self,
        timeout: float = 5.0,
        max_concurrent: int = 50,
        protocol_hint: Optional[str] = None
    ):
        """
        Initialize banner grabber.
        
        Args:
            timeout: Connection timeout in seconds (default: 5.0)
            max_concurrent: Maximum concurrent connections (default: 50)
            protocol_hint: Default protocol if not detected from port
        """
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.protocol_hint = protocol_hint
        self.semaphore = asyncio.Semaphore(max_concurrent)

    def _detect_protocol(
        self,
        port: int,
        protocol_hint: Optional[str] = None
    ) -> str:
        """
        Detect protocol from port number or use hint.
        
        Args:
            port: Target port number
            protocol_hint: Optional protocol hint
            
        Returns:
            Detected or hinted protocol name
        """
        if protocol_hint:
            return protocol_hint.lower()
        
        # Check port mapping
        for port_num, protocol in self.PORT_PROTOCOL_MAP.items():
            if port == port_num:
                return protocol.value
        
        # Fall back to generic
        return Protocol.GENERIC.value

    async def grab_banner(
        self,
        ip: str,
        port: int,
        protocol_hint: Optional[str] = None
    ) -> BannerResult:
        """
        Grab banner from a single target.
        
        Args:
            ip: Target IP address
            port: Target port number
            protocol_hint: Optional protocol hint for detection
            
        Returns:
            BannerResult with banner data or error information
        """
        async with self.semaphore:
            protocol = self._detect_protocol(port, protocol_hint)
            handler_class = self.PROTOCOL_HANDLERS.get(
                Protocol(protocol),
                GenericHandler
            )
            handler = handler_class(timeout=self.timeout)
            return await handler.grab_banner(ip, port)

    async def grab_banners(self, targets: List[tuple]) -> List[BannerResult]:
        """
        Grab banners from multiple targets concurrently.
        
        Args:
            targets: List of (ip, port) or (ip, port, protocol_hint) tuples
            
        Returns:
            List of BannerResult objects
        """
        tasks = []
        for target in targets:
            if len(target) == 2:
                ip, port = target
                protocol_hint = None
            elif len(target) == 3:
                ip, port, protocol_hint = target
            else:
                continue
            
            task = self.grab_banner(ip, port, protocol_hint)
            tasks.append(task)
        
        return await asyncio.gather(*tasks, return_exceptions=False)
