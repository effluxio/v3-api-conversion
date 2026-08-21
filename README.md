# Efflux API Conversion

Resources for migrating from Efflux API **v2** to **v3**.

## Start here

Hand this to anyone still on v2:

**[migration-kit/](migration-kit/)** — everything needed to switch from the v2 scan API to v3, plus a full v3 reference.

| File | Purpose |
|---|---|
| [migration-kit/MIGRATION_GUIDE.md](migration-kit/MIGRATION_GUIDE.md) | Breaking changes, field renames, endpoint map, checklist |
| [migration-kit/python/](migration-kit/python/) | Python client, models, and side-by-side examples |
| [migration-kit/typescript/](migration-kit/typescript/) | TypeScript/JavaScript client, types, and examples |

## Live client tests

[client-tests/](client-tests/) — scripts that hit the live v3 API with the migration-kit Python and TypeScript clients.

```bash
export EFFLUX_API_KEY=your-api-key
./client-tests/run.sh
```

## Specs

| File | Description |
|---|---|
| [v2.json](v2.json) | Efflux Scan API v2 (Swagger 2.0) — `https://api.effluxio.com/api/v2` |
| [v3.json](v3.json) | Efflux Scan API v3 (Swagger 2.0) — `https://api.efflux.io/v3` |

## Quick delta (scans)

```
Base URL:   api.effluxio.com/api/v2  →  api.efflux.io/v3
Responses:  raw object / array       →  { data, links } / { data, pagination }
Errors:     { error: "..." }         →  RFC 7807 Problem Details
Results:    GET /scans/{id}          →  GET /scans/{id} (status) + /results + /summary
fingerprint: integer 0/1/2           →  boolean
checks_opts  →  checks_options (simplified)
callback:    flat fields             →  { start, success, fail }
```

See [migration-kit/MIGRATION_GUIDE.md](migration-kit/MIGRATION_GUIDE.md) for the full list.
