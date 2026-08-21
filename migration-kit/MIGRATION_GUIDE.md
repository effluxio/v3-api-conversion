# Efflux API v2 → v3 Migration Guide

This guide covers everything you need to migrate from the v2 `/scans` API to v3, plus a complete reference for all v3 capabilities.

---

## Quick Reference: What Changed

| Area | v2 | v3 |
|---|---|---|
| Base URL | `https://api.effluxio.com/api/v2` | `https://api.efflux.io/v3` |
| Response format | Raw object | Wrapped in `{ data, links }` |
| List responses | Raw array | `{ data: [...], pagination: {...} }` |
| Error format | `{ error: "message" }` | RFC 7807 Problem Details |
| `fingerprint` type | integer (0, 1, 2) | boolean |
| Checks options field | `checks_opts` | `checks_options` |
| Checks options detail | 7 fields (include/exclude IDs, targets) | 3 fields (severity + cves_only) |
| Callback format | Flat fields | Nested `{start, success, fail}` objects |
| Get results | `GET /scans/{id}` returns everything | Split: job status vs. `/results` vs. `/summary` |
| JobReport result map | `results` | `scan_results` |
| JobReport domain map | `domain_info` | `domain_results` |
| JobReport URL data | `url_info` (array) | `url_results` (map, keyed by URL) |
| Check results | Nested in `PortStatus` | Also at top-level `check_results` array in JobReport |
| Repeat job | `POST /scans/repeat/{job_id}` | `POST /scans/{job_id}/repeat` |
| Job list pagination | `?count=N` (limit only) | `?page=N&limit=N` + pagination object |
| Plan endpoints | `GET/POST /scans/{id}/plan` | Removed |
| Long-poll subscribe | `GET /scans/{id}/subscribe` | Removed — use WebSocket streams |
| New: summary | N/A | `GET /scans/{job_id}/summary` |
| New: manage callbacks | N/A | `POST/PUT /scans/{job_id}/callback[/restart]` |
| New: live results | N/A | WebSocket `wss://api.efflux.io/v3/stream/scans/{job_id}` |
| New: tags/description | N/A | `tags` (array, max 10) and `description` on all jobs |

---

## Breaking Changes in Detail

### 1. Base URL

```
# v2
https://api.effluxio.com/api/v2

# v3
https://api.efflux.io/v3
```

Note the domain also changed: `api.effluxio.com` → `api.efflux.io`.

---

### 2. Response Envelopes

Every single-resource response in v3 is wrapped in a document envelope. Every list response is wrapped in a paginated envelope. This is the most pervasive change.

**Single resource — v2:**
```json
{
  "job_id": "abc123",
  "status": "complete",
  ...
}
```

**Single resource — v3:**
```json
{
  "data": {
    "job_id": "abc123",
    "status": "complete",
    ...
  },
  "links": {
    "self": "https://api.efflux.io/v3/scans/abc123"
  }
}
```

**List — v2:**
```json
[
  { "job_id": "abc123", ... },
  { "job_id": "def456", ... }
]
```

**List — v3:**
```json
{
  "data": [
    { "job_id": "abc123", ... },
    { "job_id": "def456", ... }
  ],
  "pagination": {
    "limit": 20,
    "page": 1,
    "total": 150,
    "total_pages": 8,
    "has_next": true,
    "has_prev": false,
    "next_cursor": "...",
    "prev_cursor": "..."
  }
}
```

**Impact:** Every place you read a response, you now need `.data` to get the resource. Every place you read a list, you now need `.data` for the items and `.pagination` for page info.

---

### 3. Error Format

**v2 error:**
```json
{
  "error": "no valid ports provided"
}
```

**v3 error (RFC 7807):**
```json
{
  "type": "https://api.efflux.io/v3/errors/validation",
  "title": "Validation Error",
  "status": 400,
  "detail": "no valid ports provided",
  "instance": "/v3/scans",
  "errors": [
    { "field": "ports", "message": "no valid ports provided" }
  ]
}
```

On rate limit (429), an additional `rate_limit` object is present:
```json
{
  "type": "...",
  "title": "Rate Limit Exceeded",
  "status": 429,
  "detail": "...",
  "rate_limit": {
    "limit": 100,
    "remaining": 0,
    "reset_at": "2026-08-20T10:00:00Z",
    "retry_after_seconds": 47
  }
}
```

---

### 4. `fingerprint` — Integer to Boolean

This is a type change with semantic shift.

**v2:** `fingerprint` was an integer controlling fingerprint depth:
- `0` (or omit) — open check only, fastest
- `1` — evaluate banners on connection
- `2` — send probes to identify service, slowest (values 1 or 2 doubled request count)

**v3:** `fingerprint` is a boolean. `true` enables fingerprinting. The depth is no longer configurable per-request.

```json
// v2
{ "hosts": ["10.0.0.1"], "ports": ["80", "443"], "fingerprint": 2 }

// v3
{ "hosts": ["10.0.0.1"], "ports": ["80", "443"], "fingerprint": true }
```

**Migration:** Any non-zero `fingerprint` value maps to `true`. `fingerprint: 0` or omitted maps to `false` or omitted.

---

### 5. `checks_opts` Renamed and Simplified

**v2 field name:** `checks_opts`
**v3 field name:** `checks_options`

Beyond the rename, v2 had seven filtering options; v3 has three:

| Option | v2 | v3 |
|---|---|---|
| `cves_only` | yes | yes |
| `min_severity` | yes | yes |
| `max_severity` | yes | yes |
| `include_ids` | yes | **removed** |
| `exclude_ids` | yes | **removed** |
| `limit_to_ids` | yes | **removed** |
| `exclude_targets` | yes | **removed** |
| `limit_to_targets` | yes | **removed** |

```json
// v2
{
  "checks": true,
  "checks_opts": {
    "min_severity": "medium",
    "max_severity": "critical",
    "cves_only": false,
    "include_ids": ["nuclei-template-abc"],
    "exclude_ids": ["nuclei-template-xyz"]
  }
}

// v3
{
  "checks": true,
  "checks_options": {
    "min_severity": "medium",
    "max_severity": "critical",
    "cves_only": false
  }
}
```

If you used `include_ids`, `exclude_ids`, `limit_to_ids`, `exclude_targets`, or `limit_to_targets`, those options are no longer available at the per-request level.

---

### 6. Callback Format

**v2** used flat fields on a `Callback` object:

```json
{
  "callback": {
    "start_url": "https://myapp.com/hooks/start?job=$job_id",
    "start_method": "POST",
    "success_url": "https://myapp.com/hooks/done?job=$job_id",
    "success_method": "POST",
    "fail_url": "https://myapp.com/hooks/fail",
    "fail_method": "GET",
    "email": false,
    "summary_only": false
  }
}
```

**v3** uses nested event objects:

```json
{
  "callback": {
    "start": {
      "url": "https://myapp.com/hooks/start?job=$job_id",
      "method": "POST"
    },
    "success": {
      "url": "https://myapp.com/hooks/done?job=$job_id",
      "method": "POST"
    },
    "fail": {
      "url": "https://myapp.com/hooks/fail",
      "method": "GET"
    }
  }
}
```

**Removed:** `email` and `summary_only` options are no longer in the callback object.

**Callback responses** in v3 also include delivery attempt history on the `Callback` object returned in job responses:
```json
{
  "start": {
    "url": "https://myapp.com/hooks/start",
    "method": "POST",
    "attempts": [
      { "time": "2026-08-20T10:00:05Z", "code": 200, "raw": "OK", "error": "" }
    ],
    "complete": true
  },
  ...
}
```

---

### 7. Getting Scan Results — Split Endpoints

**v2:** `GET /scans/{job_id}` returned everything: job metadata, status, AND full result data.

**v3:** The job endpoint only returns metadata and status. Results are on a separate endpoint.

| What you need | v2 endpoint | v3 endpoint |
|---|---|---|
| Job status, metadata | `GET /scans/{job_id}` | `GET /scans/{job_id}` |
| Full scan results | `GET /scans/{job_id}` | `GET /scans/{job_id}/results` |
| Quick statistics | `GET /scans/{job_id}` | `GET /scans/{job_id}/summary` |

The v3 results endpoint (`/results`) is **not** wrapped in a `{ data }` envelope — it returns the `JobReport` object directly.

**Polling pattern:**
```
# v2: poll one endpoint until status = "complete", then read results from same response
GET /scans/{job_id}  →  { ..., status: "complete", results: { ... } }

# v3: poll status endpoint, then fetch results separately
GET /scans/{job_id}         →  { data: { ..., status: "complete" }, links: {} }
GET /scans/{job_id}/results →  { job_id, scan_results: { ... }, ... }
```

---

### 8. JobReport Field Renames

The structure returned by `GET /scans/{job_id}/results` has renamed top-level result maps:

| v2 field | v3 field | Type change |
|---|---|---|
| `results` | `scan_results` | Same structure (map: host → HostStatus) |
| `domain_info` | `domain_results` | Same structure (map: domain → DomainInfo) |
| `url_info` | `url_results` | **Type changed:** was `array<HTTPResult>`, now `map<url_string, UrlResult>` |
| *(new)* | `check_results` | Top-level `array<CheckResult>` across all hosts |

The `url_results` type change is significant: you can no longer iterate an array. You now iterate the map's entries, where keys are the URL strings.

---

### 9. CheckResult — Extended Fields

v3 `CheckResult` objects in `check_results` have additional context fields not present in v2:

| New field | Description |
|---|---|
| `type` | Result type identifier |
| `host` | Target host IP |
| `port` | Target port |
| `scheme` | Protocol scheme (http, https) |
| `url` | Full URL if applicable |
| `path` | URL path |
| `ip` | Resolved IP |
| `check_id` | Check template ID |
| `event_id` | Unique result event ID |

---

### 10. Repeat Job — Path Change

```
# v2
POST /scans/repeat/{job_id}

# v3
POST /scans/{job_id}/repeat
```

Response changes from raw `RequestResults` to `{ data: RequestResults, links: {} }` and returns HTTP 201 (not 200).

---

### 11. Job List Pagination

```
# v2 — single count param, returns raw array
GET /scans?count=50
→ [ {...}, {...}, ... ]

# v3 — page + limit, returns paginated response
GET /scans?page=1&limit=50
→ { data: [{...}, {...}], pagination: { page: 1, limit: 50, total: 200, ... } }
```

Default limit in v3 is 20 (not 10). Maximum is 1000.

---

### 12. Removed Endpoints

| Removed | Replacement |
|---|---|
| `GET /scans/{job_id}/plan` | No direct equivalent. Checks are configured via `checks_options` on scan creation. |
| `POST /scans/{job_id}/plan` | No direct equivalent. |
| `POST /scans/{job_id}/plan/eval` | No direct equivalent. |
| `GET /scans/{job_id}/subscribe` (long-poll) | WebSocket: `wss://api.efflux.io/v3/stream/scans/{job_id}` |

---

## New in v3

### Scan Summary Endpoint

A lightweight endpoint returning aggregated statistics without the full result payload:

```
GET /v3/scans/{job_id}/summary
```

Returns:
```json
{
  "job_id": "abc123",
  "user_id": "user1",
  "created_at": "...",
  "started_at": "...",
  "completed_at": "...",
  "accessible_host_count": 12,
  "accessible_port_count": 34,
  "accessible_domain_count": 5,
  "accessible_url_count": 8,
  "checks_matched": 3,
  "ports": ["80", "443", "22"],
  "services": ["http", "https", "ssh"],
  "software": ["nginx/1.25.0", "OpenSSH_8.9"],
  "certs": ["sha256:..."],
  "keys": ["rsa:2048:sha256:..."],
  "asns": ["AS13335 Cloudflare"],
  "hosts_per_country": { "US": 8, "DE": 4 }
}
```

### Callback Management Endpoints

Update or restart callback delivery after a job is created:

```
POST /v3/scans/{job_id}/callback
Body: { start: {...}, success: {...}, fail: {...} }
→ Returns updated Callback object

PUT /v3/scans/{job_id}/callback/restart
→ Retriggers pending callbacks, returns updated Callback object
```

### WebSocket Live Streams

Real-time results as they arrive, replacing the `/subscribe` long-poll:

```
wss://api.efflux.io/v3/stream/scans/{job_id}
```

Authentication: Pass your API key in the `Sec-WebSocket-Protocol` header:
```
Sec-WebSocket-Protocol: efflux.v1, YOUR_API_KEY
```

Event types received:
- `scan` — a port result arrived
- `dns` — a DNS result arrived
- `url` — a URL/HTTP result arrived
- `check` — a vulnerability check matched

Connected message format:
```json
{ "type": "connected", "job_id": "abc123", "scope": "job", "protocol": "efflux.v1" }
```

Event message format:
```json
{ "type": "scan", "job_id": "abc123", "data": { ...ScanResult... } }
```

You can also stream all jobs at once:
```
wss://api.efflux.io/v3/stream/scans
```

And monitor status changes:
```
wss://api.efflux.io/v3/stream/status?type=job
```

### Tags and Description on Jobs

Every scan request now accepts metadata:
```json
{
  "hosts": ["10.0.0.0/24"],
  "ports": ["top_100"],
  "tags": ["production", "q3-audit"],
  "description": "Quarterly infrastructure audit — prod network"
}
```

Tags: max 10, each max 40 characters. Description: max 300 characters.

---

## Complete v3 API Reference

### Authentication

All endpoints require your API key in the `Authorization` header:
```
Authorization: YOUR_API_KEY
```

### Base URL

```
https://api.efflux.io/v3
```

### Scans

| Method | Path | Description |
|---|---|---|
| `GET` | `/scans` | List scan jobs (paginated) |
| `POST` | `/scans` | Create a new scan job |
| `POST` | `/scans/eval` | Evaluate a scan request without executing |
| `GET` | `/scans/{job_id}` | Get job status and metadata |
| `GET` | `/scans/{job_id}/results` | Get full scan results |
| `GET` | `/scans/{job_id}/summary` | Get aggregated scan statistics |
| `POST` | `/scans/{job_id}/repeat` | Repeat a previous scan job |
| `POST` | `/scans/{job_id}/callback` | Update callback configuration |
| `PUT` | `/scans/{job_id}/callback/restart` | Restart callback delivery |

### Asset Maps / Domain Surveys

| Method | Path | Description |
|---|---|---|
| `GET` | `/assetmaps/surveys` | List domain surveys |
| `POST` | `/assetmaps/surveys` | Create a domain survey |
| `GET` | `/assetmaps/surveys/{survey_id}` | Get a survey |
| `GET` | `/assetmaps/surveys/{survey_id}/map` | Get the asset map for a survey |

### Captures (Headless Browser)

| Method | Path | Description |
|---|---|---|
| `GET` | `/captures` | List captures |
| `POST` | `/captures` | Create a capture |
| `GET` | `/captures/regions` | Available regions |
| `GET` | `/captures/{capture_id}` | Get capture status |
| `GET` | `/captures/{capture_id}/results` | Full capture report |
| `GET` | `/captures/{capture_id}/cookies` | Paginated cookies |
| `GET` | `/captures/{capture_id}/cookies/report` | Cookie privacy report |
| `GET` | `/captures/{capture_id}/html` | Captured HTML |
| `GET` | `/captures/{capture_id}/image` | Screenshot (binary) |
| `DELETE` | `/captures/{capture_id}/image` | Delete screenshot |
| `GET` | `/captures/{capture_id}/network-logs` | Network activity log |

### Certificate Monitoring

| Method | Path | Description |
|---|---|---|
| `GET` | `/cert-monitoring` | List monitored domains |
| `POST` | `/cert-monitoring` | Add a domain to monitor |
| `GET` | `/cert-monitoring/certs` | All matched certificates |
| `GET` | `/cert-monitoring/{domain}` | Get monitored domain |
| `DELETE` | `/cert-monitoring/{domain}` | Remove from monitoring |
| `GET` | `/cert-monitoring/{domain}/certs` | Certs for a domain |
| `GET` | `/cert-monitoring/{domain}/certs/{hash}` | Single certificate |
| `GET` | `/cert-monitoring/{domain}/count` | Certificate count (supports since/until filters) |

### Vulnerability Checks

| Method | Path | Description |
|---|---|---|
| `GET` | `/checks` | Query check results across all jobs (filters: job_id, severity, cve, date range) |

### Host & Port Lists

| Method | Path | Description |
|---|---|---|
| `GET/POST` | `/lists/hosts` | List / create host lists |
| `GET/PUT/DELETE` | `/lists/hosts/{list_id}` | Get / update / delete host list |
| `GET/POST` | `/lists/ports` | List / create port lists |
| `GET/PUT/DELETE` | `/lists/ports/{list_id}` | Get / update / delete port list |

### Info

| Method | Path | Description |
|---|---|---|
| `GET` | `/info/cves/{cve_id}` | Full CVE document (NVD data) |
| `GET` | `/info/ports/tcp/{count}` | Top N TCP ports |
| `GET` | `/info/ports/udp/{count}` | Top N UDP ports |
| `GET` | `/info/recent/domains` | Recently seen domains |
| `GET` | `/info/recent/hosts` | Recently seen hosts |
| `GET` | `/info/usage` | Usage statistics by date |

### JWT Tokens

| Method | Path | Description |
|---|---|---|
| `GET/POST` | `/auth/jwts` | List / create JWT tokens |
| `GET/DELETE` | `/auth/jwts/{jwt_id}` | Get / revoke a token |
| `PUT` | `/auth/jwts/{jwt_id}/permissions` | Update token permissions |

### Limits

| Method | Path | Description |
|---|---|---|
| `GET` | `/limits` | Your current plan limits |
| `GET` | `/limits/jwt` | JWT-specific limits |

### Monitoring Organizations

| Method | Path | Description |
|---|---|---|
| `GET/POST` | `/monitoring/organizations` | List / create organizations |
| `GET/PUT/DELETE` | `/monitoring/organizations/{org_id}` | Get / update / delete org |
| `GET/POST` | `/monitoring/organizations/{org_id}/domains` | Domain links in org |
| `GET/PUT/DELETE` | `/monitoring/organizations/{org_id}/domains/{link_id}` | Manage domain link |
| `GET/POST` | `/monitoring/organizations/{org_id}/ips` | IP links in org |
| `GET/PUT/DELETE` | `/monitoring/organizations/{org_id}/ips/{link_id}` | Manage IP link |
| `GET` | `/monitoring/domains` | All monitored domains (cross-org view) |
| `GET` | `/monitoring/ips` | All monitored IPs (cross-org view) |
| (+ capture, cert, permutation, survey sub-resources per link) | | |

### Permutations

| Method | Path | Description |
|---|---|---|
| `GET/POST` | `/permutations` | List / create permutation checks |
| `GET` | `/permutations/{check_id}` | Get check status |
| `GET` | `/permutations/{check_id}/lists` | Permutation wordlists |
| `GET` | `/permutations/{check_id}/report` | Full permutation report |

### Rules

| Method | Path | Description |
|---|---|---|
| `GET/POST` | `/rules` | List / create rules |
| `POST` | `/rules/evaluate` | Test a rule against data |
| `GET/PUT/DELETE` | `/rules/{rule_id}` | Get / update / delete rule |
| `GET` | `/rules/{rule_id}/matches` | Rule match results |

### Schedules

| Method | Path | Description |
|---|---|---|
| `GET/POST` | `/schedules` | List / create schedules |
| `GET/PUT/DELETE` | `/schedules/{schedule_id}` | Get / update / delete schedule |
| `GET` | `/schedules/{schedule_id}/history` | Schedule run history |

### Search

| Method | Path | Description |
|---|---|---|
| `GET` | `/search/advanced/dns` | BM25 full-text DNS search |
| `GET` | `/search/advanced/hosts` | BM25 full-text host/scan search |
| `GET` | `/search/advanced/urls` | BM25 full-text URL search |
| `GET` | `/search/domains/{domain}` | Aggregate view of a domain |
| `GET` | `/search/hosts/{host}` | Port statuses for a host |
| `GET` | `/search/hosts/{host}/summary` | Host summary |
| `GET` | `/search/my/hosts/{host}` | Your scan results for a host |

### Tasks

| Method | Path | Description |
|---|---|---|
| `GET/POST` | `/tasks` | List / create tasks |
| `GET` | `/tasks/available` | Available task types |
| `GET` | `/tasks/{task_id}` | Get task status |
| `GET` | `/tasks/{task_id}/results` | Task results (binary) |

### Billing

| Method | Path | Description |
|---|---|---|
| `GET` | `/billing/catalog` | Public plan catalog |
| `POST` | `/billing/checkout` | Start Stripe checkout |
| `POST` | `/billing/portal` | Open billing portal |
| `GET` | `/billing/status` | Current billing status |

### WebSocket Streams

| URL | Description |
|---|---|
| `wss://api.efflux.io/v3/stream/scans/{job_id}` | Live results for a specific job |
| `wss://api.efflux.io/v3/stream/scans` | Live results for all your jobs |
| `wss://api.efflux.io/v3/stream/status?type=job` | Job status change events |

---

## Data Type Reference

### ScanRequest (POST /scans body)

```json
{
  "hosts": ["1.2.3.4", "10.0.0.0/24", "my_host_list"],
  "ports": ["80", "443", "8080-8090", "top_100", "my_port_list"],
  "domains": ["example.com", "sub.example.com"],
  "paths": ["/admin", "/api/v1"],
  "paths_https": true,
  "urls": ["https://example.com/login"],
  "cves": ["CVE-2024-1234"],
  "proto": "tcp",
  "fingerprint": true,
  "checks": true,
  "checks_options": {
    "cves_only": false,
    "min_severity": "medium",
    "max_severity": "critical"
  },
  "collect": {
    "ssh": ["22", "2222"],
    "rdp": ["3389"]
  },
  "callback": {
    "start": { "url": "https://myapp.com/hook/start?job=$job_id", "method": "POST" },
    "success": { "url": "https://myapp.com/hook/done?job=$job_id", "method": "POST" },
    "fail": { "url": "https://myapp.com/hook/fail?job=$job_id", "method": "POST" }
  },
  "tags": ["production", "q3-audit"],
  "description": "Quarterly audit of production network"
}
```

**Mutual exclusion rules:**
- `cves` cannot be combined with `urls` or `paths`

### Job (GET /scans/{job_id} → data)

All request fields are reflected back, plus:

```
job_id, user_id, token_id: string
region: string
attributable: boolean
schedule_id: string
status: string            — "pending" | "running" | "complete" | "failed" | "canceled"
created_at, started_at, canceled_at, completed_at: string (ISO 8601)
host_count, port_count, domain_count, url_count, cve_count: integer
request_count: integer
accessible_host_count, accessible_port_count, accessible_domain_count, accessible_url_count: integer
total_connections: integer
checks_run, checks_matched: integer
rejected_hosts, rejected_ports, rejected_domains, rejected_urls, rejected_paths, rejected_cves: string[]
errors: string[]
```

### JobReport (GET /scans/{job_id}/results — not wrapped)

```
job_id, user_id, schedule_id, proto: string
hosts, host_lists, ports, port_lists, domains, urls, cves: string[]
*_count fields (same as Job)
fingerprint, checks: boolean
tags: string[]
description: string
created_at, started_at, completed_at: string
status: string

scan_results: map<host_ip, HostStatus>
domain_results: map<domain, DomainInfo>
url_results: map<url_string, UrlResult>
check_results: CheckResult[]
```

### HostStatus

```
metadata: HostMetadata {
  asn: string
  as_org: string
  country: string
  provider: string
  tor: boolean
  info: string
}
ports: map<port_string, ScanResult>
```

### ScanResult (per port, keyed by port number)

```
host, port, proto, checked_at: string
open: boolean
service, software, version, info, host_name, os, device_type, cpe: string
tls, http: boolean
http_info: UrlResult
certificates: Certificates
detections: Detection[]
collection: Collection   (protocol-specific data: ssh, smb, rdp, mongodb, etc.)
bytes_rcvd: integer
raw: string[]            (only if ?details=true)
```

### UrlResult

```
requested_url, remote_host, remote_port: string
supports_http2, supports_http3: boolean
secure_redirect: boolean
redirect_chain: Redirect[]       [{status_code, location}]
security_headers: Header[]       [{name, values}]
script_urls: string[]
other_headers: Header[]
tls: TLSResult                   (if HTTPS)
cookies: Cookie[]
detections: Detection[]
status_code: integer
```

### DomainInfo (v3 — more DNS types than v2)

```
a, aaaa, cname, mx, ns, txt, soa, caa, dmarc, spf: string[]
resolver: string
```

### CheckResult (in check_results array)

```
type, host, port, scheme, url, path, ip: string    (context — NEW in v3)
check_id: string                                    (NEW in v3)
event_id: string                                    (NEW in v3)
matched: string
check_name, description: string
references: string[]
check_type, severity: string
extract_name: string
extractions: string[]
cve_id, cwe_id: string[]
cvss_metrics: string
cvss_score, epss_score: number
cpe: string
interaction_request, interaction_addr, interaction_proto, interaction_timestamp: string
```

### JobSummary (GET /scans/{job_id}/summary)

```
job_id, user_id: string
created_at, started_at, completed_at: string
accessible_host_count, accessible_port_count, accessible_domain_count, accessible_url_count: integer
checks_matched: integer
ports: string[]           (distinct open ports across all hosts)
services: string[]        (distinct service names)
software: string[]        (distinct software/version strings)
certs: string[]           (certificate SHA256 fingerprints)
keys: string[]            (public key fingerprints)
asns: string[]            (ASN strings)
hosts_per_country: map<country_code, count>
```

---

## Migration Checklist

- [ ] Update base URL from `api.effluxio.com/api/v2` to `api.efflux.io/v3`
- [ ] Unwrap all single-resource responses: `response.data`
- [ ] Unwrap all list responses: `response.data` (items) + `response.pagination`
- [ ] Update error handling to read `detail` instead of `error`
- [ ] Handle new `rate_limit` object on 429 responses
- [ ] Change `fingerprint` from integer to boolean in scan requests
- [ ] Rename `checks_opts` to `checks_options` in scan requests
- [ ] Remove `include_ids`, `exclude_ids`, `limit_to_ids`, `exclude_targets`, `limit_to_targets` from checks options
- [ ] Restructure callback from flat fields to nested `{start, success, fail}` objects
- [ ] Remove `email` and `summary_only` from callback config
- [ ] Stop reading results from `GET /scans/{job_id}` — fetch from `GET /scans/{job_id}/results`
- [ ] Rename `results` → `scan_results` in JobReport processing code
- [ ] Rename `domain_info` → `domain_results` in JobReport processing code
- [ ] Rename `url_info` → `url_results` in JobReport processing code
- [ ] Update `url_results` access — it is now a map (not an array)
- [ ] Update `/scans/repeat/{id}` calls to `/scans/{id}/repeat`
- [ ] Update job list calls to use `page`/`limit` instead of `count`
- [ ] Iterate `check_results` at the JobReport level for cross-host check findings
- [ ] Remove any code using `/plan` endpoints
- [ ] Replace `/subscribe` long-polling with WebSocket stream or polling `GET /scans/{job_id}`
