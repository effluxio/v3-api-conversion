# Efflux API v2 → v3 Migration Kit

Everything you need to migrate your integration from Efflux API v2 to v3.

## Contents

```
migration-kit/
├── MIGRATION_GUIDE.md          Complete reference: all breaking changes, new features,
│                               data type changes, endpoint reference, migration checklist.
│
├── python/                     Python client for v3
│   ├── README.md
│   ├── requirements.txt
│   ├── efflux_v3/
│   │   ├── __init__.py
│   │   ├── client.py           EffluxV3Client — all API methods
│   │   ├── models.py           All v3 data types as Python dataclasses
│   │   └── exceptions.py       Typed exception hierarchy (RFC 7807)
│   └── examples/
│       └── migrate_scans.py    v2 vs v3 code side-by-side for every operation
│
└── typescript/                 TypeScript/JavaScript client for v3
    ├── README.md
    ├── package.json
    ├── tsconfig.json
    └── src/
        ├── index.ts            Re-exports everything
        ├── types.ts            All v3 TypeScript interfaces
        ├── client.ts           EffluxV3Client class + error classes
        ├── helpers.ts          checksByPort, splitHeaders, getHeader (v2-shape helpers)
        └── examples/
            └── migrate_scans.ts  v2 vs v3 code side-by-side for every operation
```

## Start Here

1. Read **[MIGRATION_GUIDE.md](MIGRATION_GUIDE.md)** — it covers every breaking change and includes a migration checklist.

2. Pick your language:
   - **Python** → see [python/README.md](python/README.md)
   - **TypeScript/JavaScript** → see [typescript/README.md](typescript/README.md)

3. Look at the example file for your language — every common operation is shown with commented-out v2 code alongside the v3 replacement.

## The Short Version

### Base URL changed

```
v2: https://api.effluxio.com/api/v2
v3: https://api.efflux.io/v3
```

### Every response is now wrapped

```json
// v2: raw object
{ "job_id": "abc", "status": "complete", ... }

// v3: wrapped in envelope
{ "data": { "job_id": "abc", "status": "complete", ... }, "links": {...} }

// v3 lists:
{ "data": [...], "pagination": { "page": 1, "total": 150, "has_next": true, ... } }
```

### Errors changed format

```json
// v2
{ "error": "no valid ports" }

// v3 (RFC 7807)
{ "status": 400, "detail": "no valid ports", "errors": [{"field": "ports", "message": "..."}] }
```

### Getting results is now two calls

```
// v2: one call for status + results
GET /scans/{job_id}  →  { status, results: {...}, domain_info: {...}, url_info: [...] }

// v3: status and results are separate
GET /scans/{job_id}          →  { data: { status, counts... } }
GET /scans/{job_id}/results  →  { data: { status, scan_results: {...}, domain_results: {...}, url_results: {...}, check_results: [...] } }
GET /scans/{job_id}/summary  →  { data: { ports: [...], services: [...], hosts_per_country: {...} } }
```

`/results` and `/summary` return **404 until `status` is `"complete"`**. Status values are
`pending`, `in progress`, `complete`, `canceled`, `rejected`. Poll `GET /scans/{job_id}`.

### Per-port results and HTTP results changed shape

```
PortStatus → ScanResult
  certificate          → certificates { certificate, chain, chain_valid, ocsp_staple, tls_version }
  ssh_collection, …    → collection.ssh, …
  app_detections       → detections (flat)
  checks               → moved off the port (HostStatus.checks / check_results)

HTTPResult → UrlResult
  requested_url                    → url
  security_headers + other_headers → headers
  new: cookies, certificates, detections, favicon hashes, parsed url_* parts
```

### Leftover v2 fields are silently ignored

The v3 server does not reject unknown fields. A leftover `checks_opts` or flat
`success_url` callback is dropped with no error. Migrate them explicitly.

### Three field renames in JobReport

```
results     → scan_results
domain_info → domain_results
url_info    → url_results  (also changed from array to map)
```

### fingerprint changed type

```
v2: fingerprint: 2    (integer: 0/1/2)
v3: fingerprint: true (boolean)
```

### Callback changed structure

```json
// v2 (flat)
{ "start_url": "...", "start_method": "POST", "success_url": "...", ... }

// v3 (nested)
{ "start": { "url": "...", "method": "POST" }, "success": { "url": "..." } }
```

### checks_opts renamed and simplified

```
v2: checks_opts    (8 options including include_ids, exclude_ids, etc.)
v3: checks_options (3 options: cves_only, min_severity, max_severity only)
```

## Migration Checklist

See the full checklist at the bottom of [MIGRATION_GUIDE.md](MIGRATION_GUIDE.md).
