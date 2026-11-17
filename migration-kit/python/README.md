# Efflux v3 Python Client

Zero-dependency Python client for the Efflux v3 API. Uses only the Python standard library.

## Requirements

- Python 3.9+
- No third-party packages required for basic HTTP usage

## Quick Start

```python
from efflux_v3 import EffluxV3Client, ScanRequest

client = EffluxV3Client(api_key="your-api-key")

# Create a scan
response = client.create_scan(ScanRequest(
    hosts=["10.0.0.0/24"],
    ports=["top_100"],
    fingerprint=True,
    tags=["production"],
))
job_id = response.data.job_id

# Wait until the job leaves "pending" / "in progress" (polls every 5s, timeout 1 hour)
job = client.wait_for_job(job_id)
if not job.is_complete:                      # "canceled" or "rejected"
    raise SystemExit(f"Job ended {job.status}")

# Get results — wrapped like every v3 resource, so take .data
report = client.get_scan_results(job_id).data
for host, host_status in report.scan_results.items():
    for port, result in host_status.ports.items():
        if result.open:
            print(f"{host}:{port} — {result.service}")
```

## v2 → v3 Key Changes

| What you changed | Details |
|---|---|
| `fingerprint=2` (int) | → `fingerprint=True` (bool) |
| `checks_opts={...}` | → `checks_options={...}` (renamed, simplified) |
| `callback.start_url` | → `callback.start.url` (nested) |
| `response["job_id"]` | → `response.data.job_id` (envelope) |
| `response["results"]` | → `get_scan_results(id).data.scan_results` (separate endpoint, 404 until complete) |
| `response["domain_info"]` | → `report.domain_results` (DNS now under `.dns_info`) |
| `for r in response["url_info"]` | → `for url, r in report.url_results.items()` |
| `port["certificate"]` | → `port.certificates.certificate` (+ `chain`, `tls_version`) |
| `port["ssh_collection"]` | → `port.collection["ssh"]` |
| `port["checks"]` | → `report.checks_by_port()[(host, port)]` |
| `http["requested_url"]` | → `http.url` |
| `http["security_headers"]`, `http["other_headers"]` | → `http.headers`; `http.split_headers()` rebuilds the split |
| `job["status"] == "running"` | → `job.is_running` (`"pending"` or `"in progress"`) |
| `GET /scans?count=50` | → `list_scans(page=1, limit=50)` |
| `POST /scans/repeat/{id}` | → `repeat_scan(id)` |
| `GET /scans/{id}/subscribe` | → `wait_for_job(id)` or WebSocket |

## Error Handling

```python
from efflux_v3.exceptions import (
    EffluxJobRejectedError, # 400 — job rejected (bare RequestResults body; see .errors, .rejected)
    EffluxValidationError,  # 400
    EffluxAuthError,        # 401, 403
    EffluxNotFoundError,    # 404
    EffluxRateLimitError,   # 429
    EffluxAPIError,         # any other 4xx/5xx
)

try:
    response = client.create_scan(request)
except EffluxValidationError as e:
    print(e.detail)             # human-readable error
    print(e.fields)             # {field: message} dict
except EffluxRateLimitError as e:
    print(e.retry_after_seconds)
    print(e.reset_at)
except EffluxAPIError as e:
    print(f"HTTP {e.status_code}: {e.detail}")
```

## Module Structure

```
efflux_v3/
├── __init__.py      — public exports
├── client.py        — EffluxV3Client (all API methods)
├── models.py        — all typed dataclass models
└── exceptions.py    — typed exception hierarchy

examples/
└── migrate_scans.py — side-by-side v2/v3 migration examples
```

## Running Examples

```bash
export EFFLUX_API_KEY=your-key-here
python examples/migrate_scans.py
```
