/**
 * Efflux API: v2 → v3 Scan Migration Examples (TypeScript)
 *
 * This file shows side-by-side v2 and v3 patterns for every common scan operation.
 * v2 comments show what the equivalent code looked like.
 * v3 code is the live implementation.
 */

import { EffluxV3Client, EffluxValidationError, EffluxRateLimitError, EffluxNotFoundError } from "../client.js";
import type { ScanRequest, Job, JobReport, ScanResult, CheckResult } from "../types.js";

const API_KEY = process.env.EFFLUX_API_KEY ?? "your-api-key-here";
const client = new EffluxV3Client({ apiKey: API_KEY });

// =============================================================================
// 1. CREATING A SCAN JOB
// =============================================================================

async function exampleCreateScan(): Promise<string> {
  /**
   * v2 (fetch):
   *
   * const res = await fetch("https://api.effluxio.com/api/v2/scans", {
   *   method: "POST",
   *   headers: { Authorization: API_KEY, "Content-Type": "application/json" },
   *   body: JSON.stringify({
   *     hosts: ["10.0.0.0/24"],
   *     ports: ["80", "443", "8080"],
   *     fingerprint: 2,              // integer: 0/1/2
   *     checks: true,
   *     checks_opts: {               // field was checks_opts
   *       min_severity: "medium",
   *       cves_only: false,
   *     },
   *   }),
   * });
   * const result = await res.json();  // raw object (no envelope)
   * const jobId = result.job_id;
   */

  // v3
  const response = await client.createScan({
    hosts: ["10.0.0.0/24"],
    ports: ["80", "443", "8080"],
    fingerprint: true,             // boolean (not integer)
    checks: true,
    checks_options: {              // renamed from checks_opts; simplified
      min_severity: "medium",
      cves_only: false,
    },
    tags: ["example"],             // new: optional metadata
    description: "Migration example scan",
  });

  // v3: unwrap .data from the response envelope
  const jobId = response.data.job_id;
  const status = response.data.status;
  const requestCount = response.data.request_count;

  console.log(`Created job: ${jobId} (status=${status}, requests=${requestCount})`);

  if (response.data.rejected_hosts.length > 0) {
    console.log("Rejected hosts:", response.data.rejected_hosts);
  }

  return jobId;
}

// =============================================================================
// 2. SCANNING WITH A CALLBACK
// =============================================================================

async function exampleCreateScanWithCallback(): Promise<string> {
  /**
   * v2 callback format (flat fields):
   *
   * callback: {
   *   start_url: "https://myapp.com/hook/start?job=$job_id",
   *   start_method: "POST",
   *   success_url: "https://myapp.com/hook/done?job=$job_id",
   *   success_method: "POST",
   *   fail_url: "https://myapp.com/hook/fail",
   *   fail_method: "GET",
   *   email: false,        // removed in v3
   *   summary_only: false, // removed in v3
   * }
   */

  // v3: nested event objects
  const response = await client.createScan({
    hosts: ["10.0.0.1"],
    ports: ["443"],
    callback: {
      start: {
        url: "https://myapp.com/hook/start?job=$job_id",
        method: "POST",
      },
      success: {
        url: "https://myapp.com/hook/done?job=$job_id",
        method: "POST",
      },
      fail: {
        url: "https://myapp.com/hook/fail",
        method: "GET",
      },
    },
  });

  console.log(`Created job with callbacks: ${response.data.job_id}`);
  return response.data.job_id;
}

// =============================================================================
// 3. EVALUATING A SCAN (DRY RUN)
// =============================================================================

async function exampleEvalScan(): Promise<void> {
  /**
   * v2:
   * const res = await fetch("https://api.effluxio.com/api/v2/scans/eval", { ... });
   * const result = await res.json();  // raw object
   */

  // v3
  const response = await client.evalScan({
    hosts: ["10.0.0.0/8"],
    ports: ["top_100"],
    checks: true,
  });

  const result = response.data; // unwrap .data

  console.log(`Would scan ${result.host_count} hosts × ${result.port_count} ports`);
  console.log(`Estimated requests: ${result.request_count}`);
  if (result.rejected_hosts.length > 0) {
    console.log("Rejected:", result.rejected_hosts);
  }
}

// =============================================================================
// 4. GETTING JOB STATUS
// =============================================================================

async function exampleGetJobStatus(jobId: string): Promise<void> {
  /**
   * v2: GET /scans/{job_id} returned BOTH status AND full results inline.
   *
   * const res = await fetch(`https://api.effluxio.com/api/v2/scans/${jobId}`, ...);
   * const result = await res.json();
   * const status = result.status;
   * const results = result.results;    // scan results were inline in v2
   */

  // v3: status only — results are on a separate endpoint
  const response = await client.getScan(jobId);
  const job = response.data;

  console.log(`Job ${job.job_id}: status=${job.status}`);
  console.log(`  Accessible hosts: ${job.accessible_host_count}`);
  console.log(`  Accessible ports: ${job.accessible_port_count}`);
  console.log(`  Checks matched: ${job.checks_matched}`);

  const running = ["pending", "running"].includes(job.status);
  const terminal = ["complete", "failed", "canceled"].includes(job.status);

  if (running) console.log("  Still running...");
  if (terminal) console.log("  Done!");
}

// =============================================================================
// 5. GETTING SCAN RESULTS (split from status in v3)
// =============================================================================

async function exampleGetResults(jobId: string): Promise<void> {
  /**
   * v2: Results were embedded in the job response.
   *
   * const result = await fetch(`/api/v2/scans/${jobId}`).then(r => r.json());
   *
   * for (const [host, hostData] of Object.entries(result.results)) {
   *   // field was "results"
   *   for (const [port, portData] of Object.entries(hostData.ports)) {
   *     if (portData.open) console.log(`${host}:${port} - ${portData.service}`);
   *   }
   * }
   *
   * for (const [domain, domainData] of Object.entries(result.domain_info)) {
   *   // field was "domain_info"
   *   console.log(domain, domainData.dns.a);
   * }
   *
   * for (const urlResult of result.url_info) {
   *   // url_info was an ARRAY in v2
   *   console.log(urlResult.requested_url);
   * }
   *
   * // checks were nested per-port in v2:
   * const portChecks = result.results[host].ports[port].checks;
   */

  // v3: separate results endpoint
  const report: JobReport = await client.getScanResults(jobId);

  // scan_results replaces "results"
  for (const [host, hostStatus] of Object.entries(report.scan_results)) {
    if (hostStatus.metadata) {
      console.log(`\nHost ${host} (${hostStatus.metadata.country}, ASN: ${hostStatus.metadata.asn})`);
    }

    for (const [portStr, scanResult] of Object.entries(hostStatus.ports)) {
      if (scanResult.open) {
        console.log(`  ${portStr}/tcp: ${scanResult.service} ${scanResult.software} ${scanResult.version}`);
        if (scanResult.tls) console.log(`    TLS: yes`);
        if (scanResult.http_info) {
          console.log(`    HTTP status: ${scanResult.http_info.status_code}`);
        }
      }
    }
  }

  // domain_results replaces "domain_info"
  for (const [domain, domainInfo] of Object.entries(report.domain_results)) {
    console.log(`\nDomain ${domain}:`);
    if (domainInfo.a.length > 0) console.log(`  A: ${domainInfo.a}`);
    if (domainInfo.mx.length > 0) console.log(`  MX: ${domainInfo.mx}`);
  }

  // url_results replaces "url_info" — now a dict (not an array!)
  for (const [url, urlResult] of Object.entries(report.url_results)) {
    // iterate Object.entries, not an array
    console.log(`\nURL ${url}: status ${urlResult.status_code}`);
  }

  // check_results — new in v3: top-level array with context
  for (const check of report.check_results) {
    console.log(`\nCheck: [${check.severity}] ${check.check_name}`);
    console.log(`  Host: ${check.host}:${check.port}`);   // context fields — new in v3
    console.log(`  CVEs: ${check.cve_id.join(", ")}`);
    console.log(`  CVSS: ${check.cvss_score}`);
  }
}

// =============================================================================
// 6. GETTING A SUMMARY (new in v3)
// =============================================================================

async function exampleGetSummary(jobId: string): Promise<void> {
  /**
   * New in v3 — no equivalent in v2.
   * Use instead of getScanResults() when you only need statistics.
   */
  const summary = await client.getScanSummary(jobId);

  console.log(`Summary for ${summary.job_id}:`);
  console.log(`  Accessible hosts: ${summary.accessible_host_count}`);
  console.log(`  Accessible ports: ${summary.accessible_port_count}`);
  console.log(`  Checks matched: ${summary.checks_matched}`);
  console.log(`  Open ports: ${summary.ports.join(", ")}`);
  console.log(`  Services: ${summary.services.join(", ")}`);
  console.log(`  ASNs: ${summary.asns.join(", ")}`);
  console.log(`  Countries:`, summary.hosts_per_country);
}

// =============================================================================
// 7. LISTING SCAN JOBS
// =============================================================================

async function exampleListJobs(): Promise<void> {
  /**
   * v2: ?count=50, returned plain array
   *
   * GET /scans?count=50
   * const jobs: Job[] = await res.json();  // plain array, no pagination info
   */

  // v3: page/limit params, paginated response
  const response = await client.listScans(1, 50);

  console.log(`Page 1 of ${response.pagination.total_pages} (${response.pagination.total} total)`);
  for (const job of response.data) {
    console.log(`  ${job.job_id}: ${job.status} — ${job.created_at}`);
  }

  if (response.pagination.has_next) {
    const nextPage = await client.listScans(2, 50);
    console.log(`Page 2 has ${nextPage.data.length} more jobs`);
  }

  // Async generator to iterate all pages
  console.log("\nAll jobs:");
  for await (const job of client.listAllScans(100)) {
    console.log(`  ${job.job_id}: ${job.status}`);
  }
}

// =============================================================================
// 8. REPEATING A JOB
// =============================================================================

async function exampleRepeatJob(jobId: string): Promise<string> {
  /**
   * v2: POST /scans/repeat/{job_id}   HTTP 200
   * v3: POST /scans/{job_id}/repeat   HTTP 201 (path changed)
   */

  const response = await client.repeatScan(jobId);
  const newJobId = response.data.job_id;
  console.log(`Repeated as new job: ${newJobId}`);
  return newJobId;
}

// =============================================================================
// 9. POLLING (replacing /subscribe)
// =============================================================================

async function examplePolling(jobId: string): Promise<void> {
  /**
   * v2 had a /subscribe long-poll (up to 120s):
   * GET /scans/{job_id}/subscribe?timeout=120
   *
   * v3 removed /subscribe. Use polling or WebSocket streams.
   */

  // Option A: Simple polling
  const job = await client.waitForJob(jobId, 5_000, 3_600_000);
  console.log(`Job complete: ${job.status}`);

  // Option B: Submit and wait in one call
  const { job: completedJob, report } = await client.runScanAndWait({
    hosts: ["192.168.1.0/24"],
    ports: ["22", "80", "443"],
  });
  console.log(`Found ${report.accessible_host_count} hosts with ${report.accessible_port_count} open ports`);

  // Option C: WebSocket stream for live results
  // Requires browser WebSocket or `ws` npm package
  async function watchJobLive(liveJobId: string): Promise<void> {
    for await (const event of client.streamJobEvents(liveJobId)) {
      if (event.type === "connected") {
        console.log("Stream connected for job:", event.job_id);
      } else if (event.type === "scan") {
        const result = event.data as ScanResult;
        if (result.open) {
          console.log(`Live: ${result.host}:${result.port} open — ${result.service}`);
        }
      } else if (event.type === "check") {
        const check = event.data as CheckResult;
        console.log(`Live check: [${check.severity}] ${check.check_name} on ${check.host}`);
      }
    }
    console.log("Stream ended");
  }
}

// =============================================================================
// 10. ERROR HANDLING
// =============================================================================

async function exampleErrorHandling(): Promise<void> {
  /**
   * v2 error format: { error: "message string" }
   * Check: if (!res.ok) { const err = await res.json(); console.log(err.error); }
   *
   * v3 error format (RFC 7807):
   * {
   *   "type": "...",
   *   "title": "Validation Error",
   *   "status": 400,
   *   "detail": "no valid ports provided",
   *   "errors": [{ "field": "ports", "message": "..." }]
   * }
   */

  // Import specific error classes for precise handling
  const { EffluxAPIError, EffluxAuthError } = await import("../client.js");

  try {
    await client.createScan({ hosts: ["not-valid!!!"], ports: [] });
  } catch (e) {
    if (e instanceof EffluxValidationError) {
      // 400 — read .detail (not .error like v2)
      console.log(`Validation failed: ${e.detail}`);
      // Per-field errors
      for (const [field, msg] of Object.entries(e.fields)) {
        console.log(`  Field '${field}': ${msg}`);
      }
    }
  }

  try {
    await client.getScan("nonexistent-id");
  } catch (e) {
    if (e instanceof EffluxNotFoundError) {
      console.log(`Not found: ${e.detail}`);
    }
  }

  try {
    await client.listScans();
  } catch (e) {
    if (e instanceof EffluxRateLimitError) {
      console.log(`Rate limited. Retry in ${e.retryAfterSeconds}s (resets: ${e.resetAt})`);
    }
  }

  // Generic catch
  try {
    await client.createScan({ hosts: ["1.2.3.4"] });
  } catch (e) {
    if (e instanceof EffluxAPIError) {
      console.log(`HTTP ${e.statusCode}: ${e.detail}`);
      if (e.fieldErrors.length > 0) {
        console.log("Field errors:", e.fieldErrors);
      }
    }
  }
}

// =============================================================================
// 11. CHECKS QUERY (new in v3)
// =============================================================================

async function exampleChecksQuery(): Promise<void> {
  /**
   * New in v3. In v2 you had to iterate every job's results to find checks.
   * v3 lets you query checks across all your scans with filters.
   */

  const response = await client.listChecks({
    severity: "critical",
    minDate: "2026-08-13T00:00:00Z",
    limit: 100,
  });

  console.log(`Found ${response.pagination.total} critical checks`);
  for (const check of response.data) {
    console.log(`  [${check.severity}] ${check.check_name} — ${check.host}:${check.port}`);
    if (check.cve_id.length > 0) {
      console.log(`    CVEs: ${check.cve_id.join(", ")}`);
    }
  }
}

// =============================================================================
// 12. WEBSOCKET STREAMS (new in v3, replaces /subscribe)
// =============================================================================

async function exampleWebSocketStream(jobId: string): Promise<void> {
  /**
   * v2: Long-poll via GET /scans/{job_id}/subscribe?timeout=120
   *     Held connection for up to 120s, returned when complete or timed out.
   *
   * v3: Real-time WebSocket stream.
   *     wss://api.efflux.io/v3/stream/scans/{job_id}
   *     Auth: Sec-WebSocket-Protocol: efflux.v1, YOUR_API_KEY
   */

  // For Node.js: npm install ws
  // For browsers: use built-in WebSocket

  // Low-level WebSocket
  const ws = client.streamJob(jobId);

  ws.onopen = () => console.log("WebSocket connected");
  ws.onmessage = (event) => {
    const msg = JSON.parse(event.data);
    switch (msg.type) {
      case "connected":
        console.log(`Streaming job ${msg.job_id}`);
        break;
      case "scan":
        if (msg.data.open) {
          console.log(`${msg.data.host}:${msg.data.port} open — ${msg.data.service}`);
        }
        break;
      case "dns":
        console.log(`DNS: ${JSON.stringify(msg.data)}`);
        break;
      case "url":
        console.log(`URL: ${msg.data.requested_url} ${msg.data.status_code}`);
        break;
      case "check":
        console.log(`Check: [${msg.data.severity}] ${msg.data.check_name}`);
        break;
    }
  };
  ws.onclose = () => console.log("Stream closed");
  ws.onerror = (err) => console.error("Stream error:", err);

  // Async generator alternative (cleaner)
  for await (const event of client.streamJobEvents(jobId)) {
    if (event.type === "scan" && (event.data as ScanResult).open) {
      const r = event.data as ScanResult;
      console.log(`${r.host}:${r.port} — ${r.service} ${r.version}`);
    }
  }
}

// =============================================================================
// Run Examples
// =============================================================================

async function main(): Promise<void> {
  console.log("=== Eval (dry-run) ===");
  await exampleEvalScan();

  console.log("\n=== Create scan ===");
  const jobId = await exampleCreateScan();

  console.log("\n=== List jobs ===");
  await exampleListJobs();

  console.log("\n=== Get status ===");
  await exampleGetJobStatus(jobId);

  console.log("\n=== Wait for completion ===");
  try {
    const job = await client.waitForJob(jobId, 10_000, 300_000);
    console.log(`Job finished: ${job.status}`);

    console.log("\n=== Full results ===");
    await exampleGetResults(jobId);

    console.log("\n=== Summary ===");
    await exampleGetSummary(jobId);

    console.log("\n=== Repeat job ===");
    await exampleRepeatJob(jobId);
  } catch (e) {
    if (e instanceof Error) {
      console.log(`Timed out or failed: ${e.message}`);
    }
  }

  console.log("\n=== Error handling ===");
  await exampleErrorHandling();

  console.log("\n=== Checks query ===");
  await exampleChecksQuery();
}

main().catch(console.error);
