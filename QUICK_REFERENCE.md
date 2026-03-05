# AegisScan Importer & External Connectors - Quick Reference

## File Locations

```
/sessions/loving-wonderful-mayer/mnt/ohreo/aegisscan/aegisscan/
├── importer/
│   ├── __init__.py           (20 lines)
│   └── nmap_importer.py      (528 lines)
└── external/
    ├── __init__.py           (17 lines)
    ├── base.py               (69 lines)
    ├── shodan_connector.py   (419 lines)
    └── censys_connector.py   (411 lines)

Total: 1,464 lines of production-grade Python
```

## Nmap Importer API

### Parse Nmap XML
```python
from aegisscan.importer import NmapImporter

importer = NmapImporter()

# From file
result = importer.parse_file("scan.xml")

# From string
result = importer.parse_string(xml_content)

# Inspect results
for host in result.hosts:
    print(f"{host.ip}: {host.status}")
    for port in host.ports:
        print(f"  {port.port_id}/{port.protocol}: {port.state}")
```

### Convert to Database Format
```python
# Normalize for storage
normalized = importer.normalize_to_db(result, db_manager, "scan_123")

# Result structure:
# {
#   "scan_run_id": "scan_123",
#   "scanner": "nmap",
#   "scanner_args": "-sV -O",
#   "scan_timestamp": "2026-03-05T...",
#   "assets": [
#     {
#       "ip_address": "192.168.1.1",
#       "hostname": "router.local",
#       "discovered_services": [...],
#       "os_candidates": [...]
#     }
#   ]
# }
```

### Merge with Existing Data
```python
# Priority rules control merge behavior
priority_rules = {
    "hostname": "merge",      # Combine all hostnames
    "services": "merge",      # Add new services, update existing
    "os_info": "newest"       # Use most recent scan's OS data
}

merged = importer.merge_with_scan(
    nmap_result,
    existing_scan_data,
    priority_rules
)
```

## Shodan Connector API

### Basic Usage
```python
from aegisscan.external import ShodanConnector

# Initialize (gracefully disables if no key)
connector = ShodanConnector(api_key="YOUR_KEY_HERE")

# Or use context manager
async with ShodanConnector(api_key="YOUR_KEY_HERE") as connector:
    result = await connector.lookup_host("8.8.8.8")
    
    if result:
        print(f"Ports: {result.ports}")
        print(f"Vulns: {result.vulns}")
        print(f"Org: {result.org}")
```

### Batch Lookup
```python
ips = ["8.8.8.8", "1.1.1.1", "208.67.222.222"]
results = await connector.lookup_multiple(ips)

for result in results:
    print(f"{result.ip}: {len(result.banners)} banners found")
```

### Features
- Rate limiting: 1 req/sec (free tier)
- Caching: 3600s TTL (configurable)
- Dual backend: Official library or REST API
- Auto-disabled if invalid credentials
- Error recovery with logging

## Censys Connector API

### Basic Usage
```python
from aegisscan.external import CensysConnector

# Initialize with API credentials
connector = CensysConnector(api_id="YOUR_ID", api_secret="YOUR_SECRET")

async with CensysConnector(api_id="...", api_secret="...") as connector:
    result = await connector.lookup_host("8.8.8.8")
    
    if result:
        print(f"Services: {len(result.services)}")
        print(f"TLS Certs: {len(result.tls_certs)}")
        print(f"ASN: {result.autonomous_system.get('asn')}")
        print(f"Country: {result.location.get('country')}")
```

### Batch Lookup
```python
results = await connector.lookup_multiple(ips)

for result in results:
    for service in result.services:
        print(f"{result.ip}:{service.port}/{service.protocol}")
```

### Features
- Rate limiting: 5 req/sec (0.2s delay)
- Caching: 3600s TTL (configurable)
- API v2 with HTTP Basic auth
- Auto backoff on rate limit (429)
- TLS certificate extraction
- Geographic location data
- Autonomous system info

## Plugin Architecture

Both connectors follow plugin pattern:

```python
# Initialize without credentials
shodan = ShodanConnector()  # enabled=False
censys = CensysConnector()  # enabled=False

if not shodan.enabled:
    print("Shodan Intel not available")
else:
    result = await shodan.lookup_host("8.8.8.8")
```

## Error Handling

### Nmap Importer
```python
try:
    result = importer.parse_file("nonexistent.xml")
except FileNotFoundError as e:
    print(f"File not found: {e}")
except Exception as e:
    print(f"Parse error: {e}")
```

### External Connectors
```python
try:
    result = await connector.lookup_host("invalid-ip")
except ValueError as e:
    print(f"Invalid IP: {e}")

# Invalid credentials disable connector
if not connector.enabled:
    print("Connector disabled - check API credentials")
```

## Data Serialization

All result classes have `.to_dict()` for JSON export:

```python
result = await shodan.lookup_host("8.8.8.8")
json_data = result.to_dict()
print(json.dumps(json_data, indent=2))
```

## Performance Tips

1. **Batch Operations**: Use `lookup_multiple()` instead of loops
2. **Caching**: Enabled by default, use `clear_cache()` to refresh
3. **Rate Limiting**: Automatic, respects API tier limits
4. **Async**: Use with asyncio for concurrent lookups

```python
# Fast: Concurrent lookups
async def batch_lookup():
    tasks = [
        connector.lookup_host(ip) for ip in ips
    ]
    results = await asyncio.gather(*tasks)
    return results
```

## Logging

Enable debug logging to see detailed operations:

```python
import logging
logging.basicConfig(level=logging.DEBUG)

# Now see detailed logs from:
# - aegisscan.importer.nmap_importer
# - aegisscan.external.shodan
# - aegisscan.external.censys
# - aegisscan.external.base
```

## Type Hints

Full type hints for IDE support:

```python
from aegisscan.importer import NmapImporter, NmapScanResult

importer: NmapImporter = NmapImporter()
result: NmapScanResult = importer.parse_file("scan.xml")

from aegisscan.external import ShodanConnector, ShodanHostResult
from typing import Optional

connector: ShodanConnector = ShodanConnector(api_key="xxx")
result: Optional[ShodanHostResult] = await connector.lookup_host("8.8.8.8")
```

## Configuration

### Rate Limiting
```python
# Custom rate limits
shodan = ShodanConnector(api_key="xxx", rate_limit=2.0)  # 0.5 req/sec
censys = CensysConnector(api_id="xxx", api_secret="yyy", rate_limit=0.5)  # 2 req/sec
```

### Caching
```python
# Longer cache TTL
shodan = ShodanConnector(api_key="xxx", cache_ttl=7200)  # 2 hours

# Clear cache
shodan.clear_cache()
```

## Production Deployment

1. **Use environment variables for credentials**:
```python
import os

api_key = os.getenv("SHODAN_API_KEY")
connector = ShodanConnector(api_key=api_key)
```

2. **Check connector health**:
```python
if await connector.health_check():
    print("Connector ready")
```

3. **Handle partial failures gracefully**:
```python
results = await connector.lookup_multiple(ips)  # Returns only successful lookups
if not results:
    print("No results found")
```

4. **Clean up resources**:
```python
async with connector:
    # Use connector
    pass
# Automatically closes session
```
