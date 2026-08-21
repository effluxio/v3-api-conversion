# Efflux v3 Client Integration Tests

Live tests against `https://api.efflux.io/v3` for the Python and TypeScript migration-kit clients.

Both scripts send:

```
User-Agent: Efflux-Online/1.0 (Web Client)
X-Proxy-Source: nextjs
```

Each script:

1. Lists each resource and fetches the latest (when present)
2. **Creates** test resources afterward:
   - scan: `1.1.1.1/32`, `top_10`, `fingerprint: true`
   - capture: `https://efflux.io`
   - permutation: `efflux.io`
   - survey: `efflux.io`
   - task: type `dnsrules`, target `efflux.io`
   - host list: `client_test_hosts` → `1.1.1.1` (create → fetch → delete)
   - port list: `client_test_ports` → `22`, `23` (create → fetch → delete)
3. Asserts response envelopes and item shapes
4. For complete jobs, fetches results/report/summary and asserts those structures

## Setup

```bash
export EFFLUX_API_KEY=your-api-key
```

## Run both

```bash
cd client-tests
chmod +x run.sh   # once
./run.sh
```

## Run one language

```bash
./run.sh --python-only
./run.sh --typescript-only
```

## Run one resource

```bash
./run.sh --resource scans
./run.sh --resource captures -v
```

Resources: `scans`, `captures`, `permutations`, `surveys`, `tasks`, `schedules`,
`host-lists`, `port-lists`, `rules`, `checks`, `cert-monitoring`, `limits`

## Run directly

```bash
# Python (no install needed)
python3 python/test_client.py
python3 python/test_client.py --resource scans --verbose

# TypeScript
cd typescript
npm install
npm test
npm test -- --resource scans --verbose
```

## What is validated

| Resource | Create | List | Detail | Results |
|---|---|---|---|---|
| scans | `POST /scans` (`1.1.1.1/32`, `top_10`, `fingerprint: true`) → `RequestResults` | `PagedResponse` + `Job` fields / dataclass | `GET /scans/{id}` | `JobReport` (`scan_results`, `domain_results`, `url_results`, `check_results`) + `JobSummary` |
| captures | envelope + `capture_id` | `GET /captures/{id}` | `GET .../results` |
| permutations | envelope + `check_id` | `GET /permutations/{id}` | `GET .../report` |
| surveys | envelope + `survey_id` | `GET /assetmaps/surveys/{id}` | `GET .../map` |
| tasks | envelope + `task_id` | `GET /tasks/{id}` | `GET .../results` |
| schedules | envelope + `schedule_id` | `GET /schedules/{id}` | — |
| host-lists | envelope + `list_id` | `GET /lists/hosts/{id}` | — |
| port-lists | envelope + `list_id` | `GET /lists/ports/{id}` | — |
| rules | envelope + `rule_id` | `GET /rules/{id}` | — |
| checks | envelope + `check_name` | — | — |
| cert-monitoring | envelope + `domain` | certs list | — |
| limits | object shape | — | — |

Empty lists skip detail/results checks (reported as skipped, not failed).
Incomplete latest jobs fall back to a complete item when available; otherwise results are skipped.
