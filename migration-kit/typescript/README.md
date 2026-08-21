# Efflux v3 TypeScript/JavaScript Client

TypeScript client for the Efflux v3 API. Uses the Fetch API — no dependencies required for Node 18+, Deno, Bun, or browsers.

## Requirements

- Node.js 18+ (for Fetch API and `globalThis.fetch`)
- TypeScript 5.0+ (optional — JS works too)
- For WebSocket streams: built-in browser WebSocket or `npm install ws`

## Quick Start (TypeScript)

```typescript
import { EffluxV3Client } from "./src/index.js";

const client = new EffluxV3Client({ apiKey: "your-api-key" });

// Create a scan
const response = await client.createScan({
  hosts: ["10.0.0.0/24"],
  ports: ["top_100"],
  fingerprint: true,
  tags: ["production"],
});
const jobId = response.data.job_id;

// Wait for completion
const job = await client.waitForJob(jobId);
console.log(`Done: ${job.status}`);

// Get results
const report = await client.getScanResults(jobId);
for (const [host, hostStatus] of Object.entries(report.scan_results)) {
  for (const [port, result] of Object.entries(hostStatus.ports)) {
    if (result.open) {
      console.log(`${host}:${port} — ${result.service}`);
    }
  }
}
```

## Quick Start (JavaScript / CommonJS)

```javascript
const { EffluxV3Client } = require("./dist/index.js");

const client = new EffluxV3Client({ apiKey: "your-api-key" });
```

## v2 → v3 Key Changes

| What you changed | Details |
|---|---|
| `fingerprint: 2` (number) | → `fingerprint: true` (boolean) |
| `checks_opts: {...}` | → `checks_options: {...}` (renamed, simplified) |
| `callback.start_url` | → `callback.start.url` (nested object) |
| `response.job_id` | → `response.data.job_id` (envelope) |
| `response.results` | → `report.scan_results` (separate endpoint) |
| `response.domain_info` | → `report.domain_results` |
| `for (const r of response.url_info)` | → `Object.entries(report.url_results)` |
| `GET /scans?count=50` | → `listScans(1, 50)` |
| `POST /scans/repeat/{id}` | → `repeatScan(id)` |
| `GET /scans/{id}/subscribe` | → `waitForJob(id)` or `streamJobEvents(id)` |

## Error Handling

```typescript
import { EffluxValidationError, EffluxRateLimitError, EffluxAPIError } from "./src/index.js";

try {
  const response = await client.createScan(request);
} catch (e) {
  if (e instanceof EffluxValidationError) {
    console.log(e.detail);     // human-readable
    console.log(e.fields);    // { field: message } object
  } else if (e instanceof EffluxRateLimitError) {
    console.log(e.retryAfterSeconds);
    console.log(e.resetAt);
  } else if (e instanceof EffluxAPIError) {
    console.log(`HTTP ${e.statusCode}: ${e.detail}`);
  }
}
```

## WebSocket Streams

```typescript
// Live results for a job (replaces v2 /subscribe)
const ws = client.streamJob(jobId);
ws.onmessage = (event) => {
  const msg = JSON.parse(event.data);
  if (msg.type === "scan" && msg.data.open) {
    console.log(`${msg.data.host}:${msg.data.port} — ${msg.data.service}`);
  }
};

// Async generator alternative
for await (const event of client.streamJobEvents(jobId)) {
  if (event.type === "scan") {
    console.log(event.data);
  }
}
```

## File Structure

```
src/
├── index.ts          — re-exports everything
├── types.ts          — all TypeScript interfaces
├── client.ts         — EffluxV3Client class + error classes
└── examples/
    └── migrate_scans.ts  — side-by-side v2/v3 migration examples
```

## Build

```bash
npm install
npm run build    # outputs to dist/
npm run typecheck
```

## Running Examples

```bash
export EFFLUX_API_KEY=your-key-here
npx ts-node --esm src/examples/migrate_scans.ts
```
