# Efflux Scan API: v2 → v3 Migration Guide

This guide covers moving a scan integration from Efflux API **v2** to **v3**. It covers four topics:

1. [How the scan **request** changed](#2-request-structure-post-scans) (`POST /scans`)
2. [How you **fetch results** now](#3-fetching-results) (status, results, summary, streams, callbacks)
3. [The **per-port scan result**](#5-per-port-scan-result-portstatus--scanresult) (`PortStatus` → `ScanResult`)
4. [The **HTTP result**](#6-http-result-httpresult--urlresult) (`HTTPResult` → `UrlResult`)

**Sources.** Field lists come from [`v2.json`](../v2.json) and [`v3.json`](../v3.json). Behavior was checked against the v3 server source (`efflux-rest-api` `v3.20261109.1`, `empire-models` `v1.20261022.1`). Where the v3 spec and the server disagree, this guide follows the server. Those places are listed in [Spec vs. server differences](#11-spec-vs-server-differences).

---

## 1. At a glance

| Area | v2 | v3 |
|---|---|---|
| Base URL | `https://api.effluxio.com/api/v2` | `https://api.efflux.io/v3` |
| Auth | `Authorization: <api key>` | unchanged |
| Single-resource responses | bare object | `{ "data": {...}, "links": {...} }`, **including `/results` and `/summary`** |
| List responses | bare array | `{ "data": [...], "pagination": {...} }` |
| Errors | `{ "error": "..." }` | RFC 7807 Problem (`type`, `title`, `status`, `detail`, `errors[]`, `rate_limit`) |
| `fingerprint` | integer `0`/`1`/`2` | boolean |
| Check filters | `checks_opts` (8 options) | `checks_options` (3 options) |
| Callback | flat `start_url`, `success_url`, … | nested `{ start, success, fail }`, each `{ url, method }` or `{ callback_id }` |
| Status + results | one call: `GET /scans/{id}` returns everything | `GET /scans/{id}` = status only; `GET /scans/{id}/results` = report |
| Results before completion | returned with current status | `/results` returns **404** until `status == "complete"` |
| Live updates | `GET /scans/{id}/subscribe` (long-poll) | WebSocket `wss://api.efflux.io/v3/stream/...` |
| Report maps | `results`, `domain_info`, `url_info[]` | `scan_results`, `domain_results`, `url_results{}`, `check_results[]` |
| Per-port object | `PortStatus` | `ScanResult` (now carries `host`, `port`, `proto`, `checked_at`) |
| Per-port checks | `ports[p].checks[]` | moved off the port: `scan_results[h].checks[]` and top-level `check_results[]` |
| Per-port certificate | `certificate` (flat `TLSCertificate`) | `certificates` (`{ certificate, chain[], chain_valid, ocsp_staple, tls_version }`) |
| Per-port protocol data | 13 fields like `ssh_collection` | one `collection` object, e.g. `collection.ssh` (39 protocols) |
| HTTP result | `HTTPResult` | `UrlResult` (`requested_url` → `url`; header lists merged; cookies, certs, favicon hashes added) |
| Job list paging | `?count=N` | `?page=N&limit=N` (default 20, max 1000) |
| Repeat | `POST /scans/repeat/{id}` | `POST /scans/{id}/repeat` |
| Removed | `/plan`, `/plan/eval`, `/subscribe` | none |

---

## 2. Request structure (`POST /scans`)

The same body is used by `POST /scans/eval` (dry run).

### 2.1 Field-by-field

| v2 field | v3 field | Change |
|---|---|---|
| `hosts` | `hosts` | unchanged (IPs, CIDRs, ranges, host-list names) |
| `ports` | `ports` | unchanged (`"443"`, `"20-22"`, `"top_N"`, port-list names) |
| `domains` | `domains` | unchanged |
| `paths` | `paths` | unchanged |
| `paths_https` | `paths_https` | unchanged |
| `urls` | `urls` | unchanged |
| `cves` | `cves` | unchanged |
| `proto` | `proto` | unchanged (`"tcp"` default, `"udp"`) |
| `fingerprint` (int) | `fingerprint` (bool) | **type change**, see [2.3](#23-fingerprint-integer--boolean) |
| `checks` | `checks` | unchanged |
| `checks_opts` | `checks_options` | **renamed and reduced**, see [2.4](#24-checks_opts--checks_options) |
| `collect` | `collect` | unchanged shape (`{ "ssh": ["22", "my_ssh_ports"] }`). More collector names are accepted. |
| `callback` (flat) | `callback` (nested) | **restructured**, see [2.5](#25-callback-flat--nested) |
| none | `tags` | **new**: up to 10 strings, 40 characters each |
| none | `description` | **new**: up to 300 characters |

The exclusivity rules are the same as in v2. `cves` cannot be combined with `urls` or `paths`. When `cves`, `urls`, or `paths` are present, hosts and domains are used only as targets and are not scanned normally.

### 2.2 ⚠️ Leftover v2 fields are silently ignored

The v3 server decodes the body with a plain JSON unmarshal and does **not** reject unknown fields. If you only change the base URL, a v2 body behaves like this:

| v2 field sent to v3 | Result |
|---|---|
| `"fingerprint": 0`, `1`, or `2` | **400** `invalid message body` (an integer can't decode into a boolean) |
| `"checks_opts": {...}` | **silently ignored**: checks run with no severity filter |
| `"callback": { "success_url": ... }` | **silently ignored**: no callback fires and no error is returned |

Migrate these three fields explicitly. Don't count on errors to catch them.

### 2.3 `fingerprint`: integer → boolean

| v2 | Meaning | v3 |
|---|---|---|
| `0` or omitted | open check only | `false` or omitted |
| `1` | read banners on connect | `true` |
| `2` | send probes to identify the service | `true` |

v3 doesn't let you choose the depth. `fingerprint: true` still doubles the request count (`hosts × ports × 2`).

### 2.4 `checks_opts` → `checks_options`

| Option | v2 `checks_opts` | v3 `checks_options` |
|---|---|---|
| `cves_only` | ✓ | ✓ |
| `min_severity` | ✓ (free string) | ✓ enum: `info`, `low`, `medium`, `high`, `critical` |
| `max_severity` | ✓ (free string) | ✓ same enum |
| `include_ids` | ✓ | **removed** |
| `exclude_ids` | ✓ | **removed** |
| `limit_to_ids` | ✓ | **removed** |
| `exclude_targets` | ✓ | **removed** |
| `limit_to_targets` | ✓ | **removed** |

v3 validation: `min_severity` must be at or below `max_severity`, and both must be in the enum. v3 has no per-request way to pick or exclude individual check IDs or targets.

### 2.5 `callback`: flat → nested

**v2:**
```json
"callback": {
  "start_url": "https://hooks.example.com/start/$job_id",  "start_method": "POST",
  "success_url": "https://hooks.example.com/done/$job_id", "success_method": "POST",
  "fail_url": "https://hooks.example.com/fail/$job_id",    "fail_method": "POST",
  "email": false,
  "summary_only": true
}
```

**v3:**
```json
"callback": {
  "start":   { "url": "https://hooks.example.com/start/$job_id", "method": "POST" },
  "success": { "callback_id": "wh_123" },
  "fail":    { "url": "https://hooks.example.com/fail/$job_id" },
  "use_defaults": true
}
```

| v2 | v3 |
|---|---|
| `start_url` / `start_method` | `start.url` / `start.method` |
| `success_url` / `success_method` | `success.url` / `success.method` |
| `fail_url` / `fail_method` | `fail.url` / `fail.method` |
| `email` | **removed** |
| `summary_only` | **removed** |
| none | `<phase>.callback_id`: send to a saved webhook (`POST /webhooks`) instead of a URL. Don't set `url` on the same phase. |
| none | `use_defaults`: `false` skips your saved callback preferences (`GET/PUT /preferences`) |

Notes:
- `$job_id` in a URL is still replaced, and the `efflux-job-id` header is still sent on every callback.
- `method` is `POST` (default) or `GET`.
- Your account needs the callbacks permission. If a request sets a callback without it, the job is rejected.
- **Saved defaults:** if your preferences set callback defaults to `when_absent`, phases you leave empty are filled from them. In the job's echoed `callback`, `source` is `"request"` or `"preference"` for each phase, so you can tell which applied.
- You can change callbacks after creation with `POST /scans/{id}/callback` (same body as above) and re-trigger them with `PUT /scans/{id}/callback/restart`. Delivery history is at `GET /callback-deliveries`.

### 2.6 Full request, side by side

**v2:**
```json
{
  "hosts": ["203.0.113.0/28"],
  "ports": ["top_100"],
  "fingerprint": 2,
  "checks": true,
  "checks_opts": { "min_severity": "medium", "exclude_ids": ["some-check-id"] },
  "callback": { "success_url": "https://hooks.example.com/efflux/$job_id", "success_method": "POST" }
}
```

**v3:**
```json
{
  "hosts": ["203.0.113.0/28"],
  "ports": ["top_100"],
  "fingerprint": true,
  "checks": true,
  "checks_options": { "min_severity": "medium" },
  "callback": { "success": { "url": "https://hooks.example.com/efflux/$job_id", "method": "POST" } },
  "tags": ["prod", "perimeter"],
  "description": "Weekly perimeter scan"
}
```

### 2.7 The create response

| | v2 | v3 |
|---|---|---|
| Success | `200` bare `RequestResults` | `200` `{ "data": RequestResults, "links": { "self", "results", "summary" } }` |
| Job ID | `.job_id` | `.data.job_id` |
| Job rejected (for example, every host invalid) | varies | **`400` with a bare `RequestResults` body**: not a Problem and not wrapped. Check `status == "rejected"`, `errors[]`, and `rejected_*`. |
| Bad JSON / validation | `400 { "error" }` | `400` Problem |
| Limits | `401 { "error" }` | `401`/`429` Problem (`rate_limit` on 429) |
| Same job already running | none | `409` Problem |

Changes to `RequestResults`:
- **Removed:** `paths_https`, `path_count`, and the flat `callback_success_url`, `callback_success_method`, `callback_fail_url`, `callback_fail_method`, `callback_email`.
- **Added:** `checks_options`, `callback` (nested, with `delivery_id`, `attempts[]`, `complete`, `source` per phase), `tags`, `description`, `errors[]`.
- `fingerprint` is now a boolean.

---

## 3. Fetching results

### 3.1 The model changed

**v2: one endpoint.** You polled `GET /scans/{job_id}` (or long-polled `GET /scans/{job_id}/subscribe?timeout=60..120`). Each response was the full `JobReport`, with `status` and all results in one object.

**v3: status and results are separate.**

| Need | v3 call | Response |
|---|---|---|
| Is it done? | `GET /scans/{job_id}` | `{ data: Job, links }`: status, counts, echoed request. **No results.** |
| Full results | `GET /scans/{job_id}/results[?details=true]` | `{ data: JobReport, links }` |
| Rollup statistics | `GET /scans/{job_id}/summary` | `{ data: JobSummary, links }` |
| Push: live results | `wss://api.efflux.io/v3/stream/scans/{job_id}` | WebSocket envelopes (see [3.5](#35-websocket-streams-replace-subscribe)) |
| Push: status changes | `wss://api.efflux.io/v3/stream/status?type=job` | WebSocket status messages |
| Push: webhook | `callback.success` on the request | HTTP callback when the job finishes |

`job_id` can be the literal `last` to mean your most recent job, for example `GET /scans/last/results`.

### 3.2 Job status values

Values from the server (`models.Job.status`):

| Status | Meaning |
|---|---|
| `pending` | accepted and queued |
| `in progress` | running (note the space) |
| `complete` | finished; `/results` and `/summary` are available |
| `canceled` | canceled |
| `rejected` | not accepted (see `errors`, `rejected_*`) |

`acceptable` is only returned by `POST /scans/eval`.

### 3.3 `/results` and `/summary` return 404 until the job is complete

In v2 you could read a running job's report. In v3, `/results` and `/summary` return a **404 Problem** for any status other than `complete`, for example `detail: "job is not complete. Status: in progress"`. A 404 here doesn't mean the job is gone. **Poll `GET /scans/{id}`, not `/results`.**

### 3.4 Polling, side by side

**v2:**
```python
while True:
    report = requests.get(f"{V2}/scans/{job_id}", headers=H).json()
    if report["status"] == "complete":
        break
    time.sleep(10)

for host, hs in report["results"].items():
    for port, ps in hs["ports"].items():
        ...
```

**v3:**
```python
r = requests.post(f"{V3}/scans", json=body, headers=H)
if r.status_code == 400 and r.json().get("status") == "rejected":
    raise RuntimeError(r.json().get("errors"))      # bare RequestResults, not a Problem
r.raise_for_status()
job_id = r.json()["data"]["job_id"]

while True:
    job = requests.get(f"{V3}/scans/{job_id}", headers=H).json()["data"]
    if job["status"] == "complete":
        break
    if job["status"] in ("canceled", "rejected"):
        raise RuntimeError(job["status"])
    time.sleep(10)

report = requests.get(f"{V3}/scans/{job_id}/results", headers=H).json()["data"]   # note .data

for host, hs in report.get("scan_results", {}).items():
    for port, sr in hs.get("ports", {}).items():
        ...
```

### 3.5 WebSocket streams (replace `/subscribe`)

| Stream | URL |
|---|---|
| One job's live results | `wss://api.efflux.io/v3/stream/scans/{job_id}` |
| All your jobs' live results | `wss://api.efflux.io/v3/stream/scans` |
| Status changes | `wss://api.efflux.io/v3/stream/status?type=job` (types: `job`, `capture`, `task`, `survey`, `permutation`) |

- **Auth:** `Sec-WebSocket-Protocol: efflux.v1, <api key or token>`
- **First message:** `{ "type": "connected", "scope": "job", "job_id": "...", "protocol": "efflux.v1" }`
- **Result envelope:** `{ "type", "job_id", "tenant_id", "user_id", "pipeline", "region", "data" }`

| `type` | `data` is |
|---|---|
| `scan` | `ScanResultExtended`: `{ host, port, proto, first_seen, last_seen, host_metadata, tags, status }`. **The port result is in `data.status`** (a `ScanResult`, [section 5](#5-per-port-scan-result-portstatus--scanresult)). |
| `url` | `UrlResult` ([section 6](#6-http-result-httpresult--urlresult)) |
| `dns` | `DNSResult` |
| `check` | `CheckResult` |

- **Status message:** `{ "type": "job", "id": "<job_id>", "status": "complete", "user_id", "tenant_id", "time" }`
- `raw` fields are left out of stream events unless you pass `?raw_limit=N`.
- Streams are live only. Anything sent before you connected must come from `/results`.

### 3.6 Other fetch-related changes

| | v2 | v3 |
|---|---|---|
| List jobs | `GET /scans?count=10` → bare array | `GET /scans?page=1&limit=20` → `{ data, pagination: { page, limit, total, total_pages, has_next, has_prev, next_cursor, prev_cursor } }` |
| Repeat | `POST /scans/repeat/{id}` | `POST /scans/{id}/repeat` → `{ data: RequestResults }` |
| `details` param | on `GET /scans/{id}` | on `GET /scans/{id}/results` |
| Plans | `GET/POST /scans/{id}/plan`, `/plan/eval` | removed; use `checks_options` at creation |

**What `details=false` (the default) removes from `/results`:** the request echo arrays (`hosts`, `host_lists`, `ports`, `port_lists`, `domains`, `paths`, `urls`, `cves`) and HTTP `raw` bodies. Pass `details=true` if you need them.

---

## 4. `JobReport`: top level

**v2** (`GET /scans/{id}`):
```
JobReport
├── job_id, status, created_at, …counts…
├── results:     { "<ip>": HostStatus { metadata, ports: { "<port>": PortStatus } } }
├── domain_info: { "<domain>": DomainStatus { whois, dns, http, tls } }
└── url_info:    [ HTTPResult, … ]
```

**v3** (`GET /scans/{id}/results` → `.data`):
```
JobReport
├── job_id, user_id, status, created_at, …counts…, tags, description
├── scan_results:   { "<ip>": HostStatus { metadata, tags, ports: { "<port>": ScanResult }, checks: [CheckResult] } }
├── domain_results: { "<domain>": DomainInfo { dns_info, whois, rdap, http_info, https_info } }
├── url_results:    { "<url>": UrlResult }
└── check_results:  [ CheckResult, … ]
```

| v2 | v3 | Notes |
|---|---|---|
| `results` | `scan_results` | Same map shape (host → `HostStatus`). The values inside changed; see [section 5](#5-per-port-scan-result-portstatus--scanresult). |
| `domain_info` | `domain_results` | Value type changed; see [section 7](#7-domain-results-domainstatus--domaininfo). |
| `url_info` (array) | `url_results` (map) | Now keyed by URL; iterate `.items()` / `Object.entries()`. Values are `UrlResult`. |
| none | `check_results` | All check matches for the job |
| `paths`, `path_count` | removed | |
| none | `user_id`, `tags`, `description`, `accessible_domain_count` | added |
| `fingerprint` (int) | `fingerprint` (bool) | |

`HostStatus` gained `tags` (rule tags gathered from that host's ports) and `checks` (check results for that host). `metadata` (`asn`, `as_org`, `country`, `provider`, `tor`, `info`) is unchanged.

---

## 5. Per-port scan result: `PortStatus` → `ScanResult`

Path to one port:

```
v2:  report.results["203.0.113.5"].ports["443"]                → PortStatus
v3:  body.data.scan_results["203.0.113.5"].ports["443"]        → ScanResult
v3 stream:  envelope.data.status   (type == "scan")            → ScanResult
```

### 5.1 Field map

| v2 `PortStatus` | v3 `ScanResult` | Change |
|---|---|---|
| none | `host` | **new**: the IP. The object now identifies itself. |
| none | `port` | **new** |
| none | `proto` | **new**: `tcp` / `udp` |
| none | `checked_at` | **new**: timestamp of the observation |
| none | `tags` | **new**: tags applied by your rules |
| `open` | `open` | unchanged |
| `service` | `service` | unchanged |
| `software` | `software` | unchanged |
| `version` | `version` | unchanged |
| `info` | `info` | unchanged |
| `host_name` | `host_name` | unchanged |
| `os` | `os` | unchanged |
| `device_type` | `device_type` | unchanged |
| `cpe` | `cpe` | unchanged |
| `tls` | `tls` | unchanged (bool) |
| `http` | `http` | unchanged (bool) |
| `http_info` (`HTTPResult`) | `http_info` (`UrlResult`) | **type changed**; see [section 6](#6-http-result-httpresult--urlresult) |
| `certificate` (`TLSCertificate`) | `certificates` (`Certificates`) | **renamed and restructured**; see [5.2](#52-certificate--certificates) |
| `ssh_collection`, `rdp_collection`, … (13 fields) | `collection` (`Collection`) | **merged into one object**; see [5.3](#53-_collection-fields--collection) |
| `app_detections` (`AppDetectURLSet[]`) | `detections` (`Detection[]`) | **flattened**; see [5.4](#54-app_detections--detections) |
| `checks` (`CheckResult[]`) | removed | **moved off the port**; see [5.5](#55-checks-are-no-longer-on-the-port) |
| `bytes_rcvd` | `bytes_rcvd` | unchanged |
| `raw` | `raw` | unchanged (`string[]`) |

Fields with zero values (`false`, `""`, `0`, empty arrays) are left out of the JSON. Read with defaults, for example `sr.get("open", False)`.

### 5.2 `certificate` → `certificates`

v2 had one flat certificate with the issuer and subject split into parts. v3 wraps the leaf certificate with its chain and TLS metadata.

```
v2  certificate: TLSCertificate { fingerprint_*, version, serial_number, not_before, not_after,
                                  issuer_country … issuer_common_name, subject_country … subject_common_name }

v3  certificates: Certificates {
      certificate:  Certificate      ← the leaf
      chain:        [Certificate]    ← new
      chain_valid:  bool             ← new
      ocsp_staple:  bool             ← new
      tls_version:  string           ← new (negotiated TLS version)
    }
```

| v2 `TLSCertificate` | v3 `certificates.certificate` | Change |
|---|---|---|
| `fingerprint_md5` / `_sha1` / `_sha256` | same names | unchanged |
| `serial_number` | `serial_number` | unchanged |
| `not_before`, `not_after` (string) | `not_before`, `not_after` (**integer**) | **type change**. The spec doesn't give a unit, so check a real result before converting. |
| `issuer_country`, `issuer_organization`, `issuer_organizational_unit`, `issuer_locality`, `issuer_province`, `issuer_street_address`, `issuer_postal_code`, `issuer_serial_number`, `issuer_common_name` | `issuer` (string) | **9 fields collapsed into one string**. Parse it if you need parts such as CN or O. |
| `subject_*` (9 fields) | `subject` (string) | same as `issuer` |
| `version` | removed | |
| none | `key_usage[]`, `ext_key_usage[]`, `signature_algorithm`, `signature_valid`, `self_signed`, `is_ca`, `is_ev`, `is_precert`, `public_key`, `public_key_algorithm`, `ocsp_servers[]`, `ocsp_response`, `fingerprint_spki`, `fingerprint_spki_subject`, `fingerprint_tbs_certificate` | new |

The same `Certificates` object appears in `UrlResult.certificates` and on each `redirect_chain` hop.

### 5.3 `*_collection` fields → `collection`

Each v2 protocol field becomes a key under `collection`:

| v2 | v3 |
|---|---|
| `bacnet_collection` | `collection.bacnet` |
| `fox_collection` | `collection.fox` |
| `mongodb_collection` | `collection.mongodb` |
| `mssql_collection` | `collection.mssql` |
| `oracle_collection` | `collection.oracle` |
| `postgresql_collection` | `collection.postgresql` |
| `rdp_collection` | `collection.rdp` |
| `redis_collection` | `collection.redis` |
| `s7_collection` | `collection.s7` |
| `sip_collection` | `collection.sip` |
| `smb_collection` | `collection.smb` |
| `ssh_collection` | `collection.ssh` |
| `telnet_collection` | `collection.telnet` |
| `vnc_collection` | `collection.vnc` |

**New in v3:** `coap`, `dnp3`, `ethernet_ip`, `fins`, `ftp`, `hart_ip`, `ldap`, `mdns`, `melsec`, `memobus`, `modbus`, `mqtt`, `ntp`, `opc_ua`, `pclink`, `pcom`, `pcworx`, `profinet`, `ptp`, `rtsp`, `snmp`, `ssdp`, `syslog`, `telecontrol`, `winrm`.

**Collector fields that changed:**

| Collector | Change |
|---|---|
| `ssh` | Renamed and split by direction: `pub_key` → `host_key`, `pub_key_type` → `host_key_type`, `kex_algs` → `kex_algorithms[]`, `ciphers` → `ciphers_client_to_server[]` + `ciphers_server_to_client[]`, `macs` → `macs_*_to_*[]`, `compression` → `compression_*_to_*[]`. Removed: `misc`, `methods`, `raw`. Added: `pre_banner`, `comment`, `cookie`, `host_key_algorithms[]`, `host_key_fingerprint`, `languages_*`, `first_kex_packet_follows`, `kexinit_received`, `pqc_*`. Algorithm lists are now **arrays**, not strings. |
| `smb` | `neg_authentication_types` string → **array**. Added NetBIOS/DNS names, `ntlm_system_time`, `dialect_string`. |
| `telnet` | `do`, `will`, `wont`, `dont` string → **array**. Added `terminal_type`, `environment`, `is_rfc854`. |
| `sip` | `sdp_attributes` string → **array**. Removed `raw`. Added `server`, `www_authenticate`, `require`. |
| `s7` | Mostly rewritten: identity fields (`system`, `module`, `hardware`, `firmware`, `serial_number`, …) replaced by `module_name`, `order_code`, `firmware_version`, `rack`, `slot`, `blocks`, and others. |
| `oracle` | Typo fixed: `refuse_sys_rason` → `refuse_sys_reason`. Many fields added. |
| `mssql` | `certificate` → `certificates` |
| `rdp`, `vnc` | unchanged |
| `redis`, `mongodb`, `postgresql`, `bacnet`, `fox` | fields added only |

### 5.4 `app_detections` → `detections`

```
v2  app_detections: [ { url, detections: [ { name, matches, version, url } ] } ]   ← grouped by URL
v3  detections:     [ { name, info, cpe, website, categories[] } ]                 ← flat
```

v3 `Detection` has no `version` or `matches` field. It adds `cpe`, `website`, and `categories`. HTTP detections also appear on `http_info.detections`.

### 5.5 Checks are no longer on the port

v2 attached vulnerability matches to the port (`ports["443"].checks[]`). v3 has no `checks` on `ScanResult`. Check results live in:

- `scan_results["<ip>"].checks[]` (per host), and
- `check_results[]` (whole job).

Each v3 `CheckResult` carries its own context (`host`, `ip`, `port`, `scheme`, `url`, `path`, `type`, plus `check_id` and `event_id`), so you can rebuild the per-port view:

```python
from collections import defaultdict

checks_by_port = defaultdict(list)
seen = set()
for host, hs in report.get("scan_results", {}).items():
    for c in hs.get("checks", []):
        key = c.get("event_id") or id(c)
        if key not in seen:
            seen.add(key); checks_by_port[(c.get("host") or host, c.get("port"))].append(c)
for c in report.get("check_results", []):
    key = c.get("event_id") or id(c)
    if key not in seen:
        seen.add(key); checks_by_port[(c.get("host") or c.get("ip"), c.get("port"))].append(c)

port_443_checks = checks_by_port[("203.0.113.5", "443")]
```

The migration kit's clients include this as `JobReport.checks_by_port()` (Python) and `checksByPort(report)` with `portKey(host, port)` (TypeScript).

All v2 `CheckResult` fields are unchanged in v3.

### 5.6 One port, side by side (illustrative values)

**v2:** `results["203.0.113.5"].ports["443"]`
```json
{
  "open": true,
  "service": "https",
  "software": "nginx",
  "version": "1.25.3",
  "tls": true,
  "http": true,
  "http_info": {
    "requested_url": "https://203.0.113.5:443/",
    "remote_host": "203.0.113.5",
    "remote_port": "443",
    "supports_http2": true,
    "redirect_chain": [{ "status_code": 301, "location": "https://www.example.com/" }],
    "security_headers": [{ "name": "Strict-Transport-Security", "values": ["max-age=31536000"] }],
    "other_headers": [{ "name": "Server", "values": ["nginx"] }],
    "script_urls": ["https://www.example.com/app.js"]
  },
  "certificate": {
    "fingerprint_sha256": "9f2c…",
    "not_before": "2026-01-01T00:00:00Z",
    "not_after": "2026-12-31T23:59:59Z",
    "issuer_organization": "Example CA",
    "issuer_common_name": "Example CA R1",
    "subject_common_name": "www.example.com"
  },
  "app_detections": [
    { "url": "https://203.0.113.5/", "detections": [{ "name": "nginx", "version": "1.25.3", "matches": "server header" }] }
  ],
  "checks": [{ "check_name": "…", "severity": "medium" }]
}
```

**v3:** `data.scan_results["203.0.113.5"].ports["443"]`
```json
{
  "host": "203.0.113.5",
  "port": "443",
  "proto": "tcp",
  "checked_at": "2026-11-16T18:04:11Z",
  "open": true,
  "service": "https",
  "software": "nginx",
  "version": "1.25.3",
  "tls": true,
  "http": true,
  "http_info": {
    "url": "https://203.0.113.5:443/",
    "url_host": "203.0.113.5",
    "url_port": "443",
    "url_scheme": "https",
    "url_path": "/",
    "checked_at": "2026-11-16T18:04:12Z",
    "remote_host": "203.0.113.5",
    "remote_port": "443",
    "supports_http2": true,
    "redirect_chain": [{
      "status_code": 301,
      "location": "https://www.example.com/",
      "remote_host": "203.0.113.5",
      "remote_port": "443",
      "headers": [{ "name": "Location", "values": ["https://www.example.com/"] }]
    }],
    "headers": [
      { "name": "Strict-Transport-Security", "values": ["max-age=31536000"] },
      { "name": "Server", "values": ["nginx"] }
    ],
    "cookies": [{ "name": "sid", "path": "/", "domain": "", "max_age": 0, "secure": true, "http_only": true, "raw_cookie": "sid=…; Secure; HttpOnly" }],
    "script_urls": ["https://www.example.com/app.js"],
    "certificates": { "certificate": { "fingerprint_sha256": "9f2c…" }, "chain_valid": true, "tls_version": "TLS 1.3" },
    "detections": [{ "name": "nginx", "cpe": "cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*", "categories": ["Web servers"] }],
    "favicon_url": "https://203.0.113.5/favicon.ico",
    "favicon_mmh3": "-1234567890"
  },
  "certificates": {
    "certificate": {
      "subject": "CN=www.example.com",
      "issuer": "CN=Example CA R1,O=Example CA",
      "not_before": 1767225600,
      "not_after": 1798761599,
      "fingerprint_sha256": "9f2c…",
      "self_signed": false
    },
    "chain": [{ "subject": "CN=Example CA R1,O=Example CA", "is_ca": true }],
    "chain_valid": true,
    "tls_version": "TLS 1.3"
  },
  "detections": [{ "name": "nginx", "cpe": "cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*" }]
}
```
The checks for this port are now in `scan_results["203.0.113.5"].checks` / `check_results`, filtered by `port == "443"`.

---

## 6. HTTP result: `HTTPResult` → `UrlResult`

### 6.1 Where it appears

| Location | v2 | v3 |
|---|---|---|
| HTTP on a scanned port | `results[ip].ports[p].http_info` (`HTTPResult`) | `scan_results[ip].ports[p].http_info` (`UrlResult`) |
| Requested URLs / paths | `url_info[]` (array of `HTTPResult`) | `url_results{ "<url>": UrlResult }` |
| A domain's web response | `domain_info[d].http` (one `HTTPResult`) | `domain_results[d].http_info` **and** `domain_results[d].https_info` (one per scheme) |
| Live stream | none | `type: "url"` envelopes, `data` = `UrlResult` |

### 6.2 Field map

| v2 `HTTPResult` | v3 `UrlResult` | Change |
|---|---|---|
| `requested_url` | `url` | **renamed** (also the `url_results` map key) |
| none | `url_host`, `url_port`, `url_domain`, `url_scheme`, `url_path`, `url_query` | **new**: pre-parsed parts of `url` |
| none | `checked_at` | **new** |
| none | `tags` | **new**: rule tags |
| `remote_host` | `remote_host` | unchanged |
| `remote_port` | `remote_port` | unchanged |
| `supports_http2` | `supports_http2` | unchanged |
| `supports_http3` | `supports_http3` | unchanged |
| `secure_redirect` | `secure_redirect` | unchanged |
| `redirect_chain[]` | `redirect_chain[]` | **each hop enriched**; see [6.4](#64-redirect-chain-hops-are-richer) |
| `security_headers[]` + `other_headers[]` | `headers[]` | **merged into one list**; see [6.3](#63-security_headers--other_headers--headers) |
| `script_urls[]` | `script_urls[]` | unchanged |
| none | `cookies[]` | **new**: `{ name, value, path, domain, expires, max_age, secure, http_only, raw_cookie }` |
| none | `certificates` | **new**: same `Certificates` shape as [5.2](#52-certificate--certificates) |
| none | `detections[]` | **new**: technology detections for this URL |
| none | `favicon_url`, `favicon_mmh3`, `favicon_md5`, `favicon_sha1`, `favicon_sha256` | **new**: favicon hashes (mmh3 is the common pivot hash) |
| none | `raw` | **new**: raw response (string). Removed from `/results` unless `details=true`; left out of streams unless `raw_limit` is set. |

Neither version has a top-level HTTP status code on the result. Status codes appear only on `redirect_chain` entries.

### 6.3 `security_headers` + `other_headers` → `headers`

v3 returns every response header in one `headers` list (`{ name, values[] }`) and doesn't classify them. If your code relied on the v2 split, rebuild it:

```python
SECURITY_HEADERS = {
    "strict-transport-security", "content-security-policy", "content-security-policy-report-only",
    "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy",
    "cross-origin-opener-policy", "cross-origin-embedder-policy", "cross-origin-resource-policy",
    "x-xss-protection",
}

def split_headers(url_result):
    sec, other = [], []
    for h in url_result.get("headers", []):
        (sec if h["name"].lower() in SECURITY_HEADERS else other).append(h)
    return sec, other   # ≈ v2 security_headers, other_headers
```

v2's exact classification list wasn't published. Adjust `SECURITY_HEADERS` to match what you depended on. The kit's clients include this as `UrlResult.split_headers()` / `UrlResult.header(name)` (Python) and `splitHeaders()` / `getHeader()` (TypeScript).

### 6.4 Redirect chain hops are richer

| v2 `Redirect` | v3 `Redirect` |
|---|---|
| `status_code` | `status_code` |
| `location` | `location` |
| none | `remote_host`, `remote_port`: the server that answered this hop |
| none | `headers[]`: this hop's response headers |
| none | `script_urls[]` |
| none | `certificates`: the TLS certificate for this hop |

### 6.5 TLS details

v2 `domain_info[d].tls` held a `TLSResult` (`selected_protocol`, `selected_cipher`, `protocols[]`, `ciphers[]`, `jarm`, resumption and renegotiation flags, `certificate`). **v3 scan reports don't include protocol or cipher enumeration.** For each HTTPS response you get `certificates`: the leaf, the chain, `chain_valid`, `ocsp_staple`, and the negotiated `tls_version`.

---

## 7. Domain results: `DomainStatus` → `DomainInfo`

| v2 `DomainStatus` | v3 `DomainInfo` | Change |
|---|---|---|
| `dns` | `dns_info` | renamed |
| `whois` | `whois` | **internal shape changed** (below) |
| none | `rdap` | new: RDAP lookup result |
| `http` | `http_info` + `https_info` | split per scheme; type is `UrlResult` |
| `tls` | removed | see [6.5](#65-tls-details) |

**`DNSResult`:**
- Removed: `resolver`.
- Added: `domain`, `checked_at`, `tags`, `caa[]`, `ns[]`, `srv[]`, `soa[]`. `soa` holds objects: `{ name, ns, mailbox, serial, refresh, retry, expire, min_ttl }`.
- `a`, `aaaa`, `cname`, `dmarc`, `mx`, `spf`, `txt` are unchanged.

**`WhoisResult`:**
- `domain` changed from an **object** (`WhoisDomain`) to a **string** (the domain name).
- The old object moved to `domain_info`.
- Added `checked_at`.
- Contact fields (`registrar`, `registrant`, `administrative`, `technical`, `billing`) are unchanged.

---

## 8. `CheckResult`

All v2 fields are unchanged. v3 adds context so a result can stand on its own:

| New field | Meaning |
|---|---|
| `type` | result type |
| `host`, `ip`, `port`, `scheme`, `url`, `path` | the exact target that matched |
| `check_id` | template/check identifier |
| `event_id` | unique ID for this match (use it to de-duplicate) |

---

## 9. `GET /scans/{id}/summary` (new)

It returns `{ data: JobSummary, links }` once the job is `complete`. The server builds it from the report's `scan_results`:

| Field | Source |
|---|---|
| `job_id`, `user_id`, `created_at`, `started_at`, `completed_at` | job |
| `accessible_host_count`, `accessible_port_count`, `accessible_url_count`, `checks_matched` | job counters |
| `ports[]`, `services[]`, `software[]` | distinct values across all `ScanResult`s |
| `certs[]` | distinct `certificates.certificate.fingerprint_sha256` across ports |
| `asns[]`, `hosts_per_country{}` | host `metadata` |
| `keys[]`, `accessible_domain_count` | **not populated by the current server**, so they're always absent |

Use it when you only need rollups. It's much smaller than `/results`.

---

## 10. Migration checklist

**Connection and errors**
- [ ] Base URL `api.effluxio.com/api/v2` → `api.efflux.io/v3`
- [ ] Read single resources from `.data`, including `/results`, `/summary`, and the callback endpoints
- [ ] Read lists from `.data` and paginate with `.pagination`
- [ ] Error handling: read `detail` and `errors[]`, not `error`; handle `rate_limit` on 429
- [ ] On create, treat `400` + body `status == "rejected"` as a rejected job (bare `RequestResults`)

**Request**
- [ ] `fingerprint`: integer → boolean (any non-zero → `true`)
- [ ] `checks_opts` → `checks_options`; drop `include_ids`, `exclude_ids`, `limit_to_ids`, `exclude_targets`, `limit_to_targets`; use enum severities
- [ ] `callback`: flat `*_url` / `*_method` → `{ start, success, fail }: { url, method }`; drop `email` and `summary_only`
- [ ] Decide whether saved callback preferences should apply (`use_defaults`)
- [ ] Optionally add `tags` and `description`
- [ ] Confirm no v2-only fields remain, because v3 ignores them silently

**Fetching**
- [ ] Poll `GET /scans/{id}` → `.data.status` until `complete` (statuses: `pending`, `in progress`, `complete`, `canceled`, `rejected`)
- [ ] Then fetch `GET /scans/{id}/results` → `.data` (404 before completion is expected)
- [ ] Pass `details=true` if you read `hosts`, `ports`, or other echoed inputs, or HTTP `raw`, from the report
- [ ] Replace `/subscribe` with `/stream/scans/{id}` or `/stream/status`, or keep polling
- [ ] `/scans/repeat/{id}` → `/scans/{id}/repeat`
- [ ] `GET /scans?count=` → `?page=&limit=`
- [ ] Remove `/plan` usage

**Report shape**
- [ ] `results` → `scan_results`; `domain_info` → `domain_results`; `url_info[]` → `url_results{}`
- [ ] Per port: read `host`, `port`, and `proto` from the object if useful
- [ ] `certificate` → `certificates.certificate`; parse `issuer` and `subject` strings; `not_before` and `not_after` are integers
- [ ] `<proto>_collection` → `collection.<proto>`; update SSH, SMB, Telnet, SIP, S7, Oracle, and MSSQL field names and types
- [ ] `app_detections[].detections[]` → `detections[]`
- [ ] Per-port `checks` → `scan_results[ip].checks` / `check_results`, filtered by `port`
- [ ] HTTP: `requested_url` → `url`; `security_headers` + `other_headers` → `headers`; handle the new `cookies`, `certificates`, `detections`, and favicon fields
- [ ] Domains: `dns` → `dns_info`; `http` → `http_info` / `https_info`; `whois.domain` is now a string (object in `whois.domain_info`); no `tls`
- [ ] Read fields with defaults, because zero values are left out

**Using the kit clients** ([`python/`](python/), [`typescript/`](typescript/))
- [ ] `get_scan_results()` / `getScanResults()` and `get_scan_summary()` / `getScanSummary()` return a `DocumentResponse`; take `.data`
- [ ] `wait_for_job()` / `waitForJob()` returns on `complete`, `canceled` or `rejected`; check the status before fetching results
- [ ] Catch `EffluxJobRejectedError` (a subclass of `EffluxValidationError`) for rejected jobs

---

## 11. Spec vs. server differences

`v3.json` (generated from code annotations) disagrees with the running server in these places. The guide follows the server.

| Endpoint | `v3.json` says | Server actually does |
|---|---|---|
| `GET /scans/{id}/results` | 200 → bare `models.JobReport` | 200 → `{ data: JobReport, links }` |
| `GET /scans/{id}/summary` | 200 → bare `models.JobSummary` | 200 → `{ data: JobSummary, links }` |
| `POST /scans/{id}/callback` | body `models.Callback`; 200 → bare `models.Callback` | body `CallbackRequest` (`{start, success, fail}` with `url`/`method`/`callback_id`); 200 → `{ data: Callback }` |
| `PUT /scans/{id}/callback/restart` | 200 → bare `models.Callback` | 200 → `{ data: Callback }` |
| `POST /scans/{id}/repeat` | 201 | 200 |
| `POST /scans` (job rejected) | 400 → `api.Problem` | 400 → bare `RequestResults` with `status: "rejected"` |

---

## Appendix: other v3 endpoints

The full v3 surface beyond scans, for reference.

### Scans

| Method | Path | Description |
|---|---|---|
| `GET` | `/scans` | List scan jobs (paginated) |
| `POST` | `/scans` | Create a scan job |
| `POST` | `/scans/eval` | Evaluate a scan request without running it |
| `GET` | `/scans/{job_id}` | Job status and metadata |
| `GET` | `/scans/{job_id}/results` | Full scan report |
| `GET` | `/scans/{job_id}/summary` | Rollup statistics |
| `POST` | `/scans/{job_id}/repeat` | Repeat a job |
| `POST` | `/scans/{job_id}/callback` | Replace callback configuration |
| `PUT` | `/scans/{job_id}/callback/restart` | Re-trigger callbacks |

### Webhooks, callback deliveries, preferences

| Method | Path | Description |
|---|---|---|
| `GET/POST` | `/webhooks` | List / create saved webhooks (use with `callback.<phase>.callback_id`) |
| `GET/PUT/DELETE` | `/webhooks/{webhook_id}` | Get / update / delete a webhook |
| `GET` | `/webhooks/{webhook_id}/deliveries` | Deliveries for a webhook |
| `POST` | `/webhooks/{webhook_id}/rotate-secret` | Rotate the signing secret |
| `POST` | `/webhooks/{webhook_id}/test` | Queue a test delivery |
| `GET` | `/callback-deliveries` | List callback deliveries (state: `pending`, `delivered`, `failed`, `canceled`) |
| `GET` | `/callback-deliveries/{delivery_id}` | One delivery |
| `POST` | `/callback-deliveries/{delivery_id}/retry` | Retry a delivery |
| `GET/PUT` | `/preferences` | Includes default callbacks per job kind (`callbacks.apply`: `off` / `when_absent`) |

### WebSocket streams

| URL | Description |
|---|---|
| `wss://api.efflux.io/v3/stream/scans/{job_id}` | Live results for one job |
| `wss://api.efflux.io/v3/stream/scans` | Live results for all your jobs |
| `wss://api.efflux.io/v3/stream/status?type=job` | Status change events |

### Asset maps / domain surveys

| Method | Path | Description |
|---|---|---|
| `GET/POST` | `/assetmaps/surveys` | List / create domain surveys |
| `GET` | `/assetmaps/surveys/{survey_id}` | Get a survey |
| `GET` | `/assetmaps/surveys/{survey_id}/map` | Asset map for a survey |

### Captures (headless browser)

| Method | Path | Description |
|---|---|---|
| `GET/POST` | `/captures` | List / create captures |
| `GET` | `/captures/regions` | Available regions |
| `GET` | `/captures/{capture_id}` | Capture status |
| `GET` | `/captures/{capture_id}/results` | Full capture report |
| `GET` | `/captures/{capture_id}/cookies` | Paginated cookies |
| `GET` | `/captures/{capture_id}/cookies/report` | Cookie privacy report |
| `GET` | `/captures/{capture_id}/html` | Captured HTML |
| `GET/DELETE` | `/captures/{capture_id}/image` | Screenshot (binary) / delete it |
| `GET` | `/captures/{capture_id}/network-logs` | Network activity log |

### Certificate monitoring

| Method | Path | Description |
|---|---|---|
| `GET/POST` | `/cert-monitoring` | List / add monitored domains |
| `GET` | `/cert-monitoring/certs` | All matched certificates |
| `GET/DELETE` | `/cert-monitoring/{domain}` | Get / remove a monitored domain |
| `GET` | `/cert-monitoring/{domain}/certs` | Certs for a domain |
| `GET` | `/cert-monitoring/{domain}/certs/{hash}` | One certificate |
| `GET` | `/cert-monitoring/{domain}/count` | Certificate count (`since`/`until`) |

### Checks, lists, info, limits

| Method | Path | Description |
|---|---|---|
| `GET` | `/checks` | Check results across jobs (filters: job_id, severity, cve, dates) |
| `GET/POST` | `/lists/hosts` | List / create host lists |
| `GET/PUT/DELETE` | `/lists/hosts/{list_id}` | Manage a host list |
| `GET/POST` | `/lists/ports` | List / create port lists |
| `GET/PUT/DELETE` | `/lists/ports/{list_id}` | Manage a port list |
| `GET` | `/info/cves/{cve_id}` | CVE document |
| `GET` | `/info/ports/tcp/{count}`, `/info/ports/udp/{count}` | Top N ports |
| `GET` | `/info/recent/domains`, `/info/recent/hosts` | Recently seen |
| `GET` | `/info/usage` | Usage by date |
| `GET` | `/limits`, `/limits/jwt` | Plan limits |

### Other resources

| Area | Paths |
|---|---|
| JWT tokens | `/auth/jwts`, `/auth/jwts/{jwt_id}`, `/auth/jwts/{jwt_id}/permissions` |
| Monitoring orgs | `/monitoring/organizations[/{org_id}[/domains\|/ips[/{link_id}]]]`, `/monitoring/domains`, `/monitoring/ips` |
| Permutations | `/permutations`, `/permutations/{check_id}`, `/permutations/{check_id}/lists`, `/permutations/{check_id}/report` |
| Rules | `/rules`, `/rules/evaluate`, `/rules/{rule_id}`, `/rules/{rule_id}/matches` |
| Schedules | `/schedules`, `/schedules/{schedule_id}`, `/schedules/{schedule_id}/history` |
| Search | `/search/advanced/{dns,hosts,urls}`, `/search/domains/{domain}`, `/search/hosts/{host}[/summary]`, `/search/my/hosts/{host}` |
| Tasks | `/tasks`, `/tasks/available`, `/tasks/{task_id}`, `/tasks/{task_id}/results` |
| Billing | `/billing/catalog`, `/billing/checkout`, `/billing/portal`, `/billing/status` |
