/**
 * Live integration tests for the Efflux v3 TypeScript client.
 *
 * Requires:
 *   export EFFLUX_API_KEY=your-key
 *
 * Usage (from this directory):
 *   npm install
 *   npm test
 *   npm test -- --resource scans
 *   npm test -- --verbose
 */

import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CLIENT_SRC = path.resolve(__dirname, "../../migration-kit/typescript/src/index.ts");

// Load the client via dynamic import (works with tsx).
const clientMod = await import(pathToFileURL(CLIENT_SRC).href);
const {
  EffluxV3Client,
  EffluxAPIError,
  EffluxNotFoundError,
} = clientMod;

type AnyObj = Record<string, unknown>;

let PASS = 0;
let FAIL = 0;
let SKIP = 0;
let VERBOSE = false;
const FAILURES: Array<{ label: string; message: string; details: string[] }> = [];

function log(msg: string): void {
  console.log(msg);
}

function vlog(msg: string): void {
  if (VERBOSE) console.log(`    ${msg}`);
}

function jsonish(value: unknown): string {
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function formatErrorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}

function failureDetailLines(err: unknown, context?: unknown): string[] {
  const lines: string[] = [];
  if (context !== undefined) lines.push(`request: ${jsonish(context)}`);
  if (err instanceof EffluxAPIError) {
    lines.push(`status: ${err.statusCode}`);
    if (err.title) lines.push(`title: ${err.title}`);
    if (err.errorType) lines.push(`type: ${err.errorType}`);
    if (err.fieldErrors?.length) lines.push(`field_errors: ${jsonish(err.fieldErrors)}`);
    if (err.rateLimit) lines.push(`rate_limit: ${jsonish(err.rateLimit)}`);
    if (err.rawBody !== undefined) lines.push(`body: ${jsonish(err.rawBody)}`);
    else if (err.detail) lines.push(`detail: ${err.detail}`);
  } else if (err instanceof Error) {
    lines.push(`exception: ${err.name}`);
    if (err.message) lines.push(`message: ${err.message}`);
  }
  return lines;
}

function ok(label: string, detail = ""): void {
  PASS++;
  log(`  ✓ ${label}${detail ? ` — ${detail}` : ""}`);
}

function fail(label: string, err: unknown, context?: unknown): void {
  FAIL++;
  const message = formatErrorMessage(err);
  const details = failureDetailLines(err, context);
  FAILURES.push({ label, message, details });
  log(`  ✗ ${label}: ${message}`);
  for (const line of details) log(`      ${line}`);
  if (VERBOSE && err instanceof Error && err.stack) {
    console.error(err.stack);
  }
}

function skip(label: string, reason: string): void {
  SKIP++;
  log(`  ○ ${label}: skipped (${reason})`);
}

function printFailureSummary(): void {
  if (!FAILURES.length) return;
  log("\nFailures:");
  for (const item of FAILURES) {
    log(`  ✗ ${item.label}: ${item.message}`);
    for (const line of item.details) log(`      ${line}`);
  }
}

function requireApiKey(): string {
  const key = (process.env.EFFLUX_API_KEY ?? "").trim();
  if (!key) {
    console.error("ERROR: EFFLUX_API_KEY is not set.");
    console.error("  export EFFLUX_API_KEY=your-api-key");
    process.exit(2);
  }
  return key;
}

function assert(cond: unknown, msg: string): asserts cond {
  if (!cond) throw new Error(msg);
}

function assertType(value: unknown, expected: string, name: string): void {
  const actual = Array.isArray(value) ? "array" : typeof value;
  if (actual !== expected) {
    throw new Error(`${name}: expected ${expected}, got ${actual}`);
  }
}

function assertPaged(response: any, itemName = "item"): any[] {
  assert(response && typeof response === "object", "list response missing");
  assertType(response.data, "array", "response.data");
  assert(response.pagination && typeof response.pagination === "object", "response missing pagination");
  // Some list endpoints omit total/page on empty responses; only require a pagination object.
  const pag = response.pagination;
  vlog(
    `${response.data.length} ${itemName}(s), total=${pag.total ?? "n/a"}, page=${pag.page ?? "n/a"}`,
  );
  return response.data as any[];
}

function assertDocument(response: any): any {
  assert(response && typeof response === "object", "document response missing");
  assert(response.data !== undefined && response.data !== null, "DocumentResponse.data is null/undefined");
  return response.data;
}

function assertKeys(obj: any, required: string[], label: string): AnyObj {
  assertType(obj, "object", label);
  const missing = required.filter((k) => !(k in obj));
  if (missing.length) throw new Error(`${label} missing keys: ${missing.join(", ")}`);
  return obj as AnyObj;
}

function createdAtKey(item: any): string {
  return String(item?.created_at ?? item?.updated_at ?? "");
}

function pickLatest(items: any[], idGetter: (item: any) => string | undefined): any | null {
  if (!items.length) return null;
  const dated = items
    .filter((i) => idGetter(i))
    .map((i) => [createdAtKey(i), i] as const);
  if (!dated.length) return items[0];
  dated.sort((a, b) => (a[0] < b[0] ? 1 : a[0] > b[0] ? -1 : 0));
  return dated[0][1];
}

function isCompleteStatus(status: unknown): boolean {
  // All resources use status "complete" when finished.
  return String(status ?? "").toLowerCase() === "complete";
}

function findComplete(items: any[]): any | undefined {
  return items.find((i) => isCompleteStatus(i?.status));
}

function jobIdFrom409(detail: string): string | null {
  const marker = ": ";
  const idx = detail.lastIndexOf(marker);
  if (idx < 0) return null;
  const candidate = detail.slice(idx + marker.length).trim();
  return candidate || null;
}

function parseArgs(argv: string[]): { resource: string; verbose: boolean } {
  let resource = "all";
  let verbose = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--verbose" || a === "-v") verbose = true;
    else if (a === "--resource") resource = argv[++i] ?? "all";
    else if (a.startsWith("--resource=")) resource = a.slice("--resource=".length);
  }
  return { resource, verbose };
}

// ---------------------------------------------------------------------------
// Resource tests
// ---------------------------------------------------------------------------

async function testScans(client: InstanceType<typeof EffluxV3Client>): Promise<void> {
  log("\n[scans]");
  let items: any[] = [];

  // List / get / results first — before create, so we exercise an existing job.
  try {
    const listed = await client.listScans(1, 5);
    items = assertPaged(listed, "scan");
    for (const job of items) {
      assertKeys(job, ["job_id", "status"], "scan list item");
      // fingerprint may be omitted (undefined) on list items
      if (job.fingerprint !== undefined) {
        assertType(job.fingerprint, "boolean", "job.fingerprint");
      }
    }
    ok("listScans → PagedResponse<Job>", `${items.length} items`);
  } catch (e) {
    fail("listScans", e);
  }

  const latest = items.length ? pickLatest(items, (j) => j.job_id) : null;
  if (!latest) {
    skip("getScan / results / summary", "no scans in account yet");
  } else {
    let jobId = latest.job_id as string;
    vlog(`latest job_id=${jobId} status=${latest.status}`);

    try {
      const doc = await client.getScan(jobId);
      const job = assertDocument(doc);
      assertKeys(job, ["job_id", "status"], "getScan data");
      assert(job.job_id === jobId, `job_id mismatch: ${job.job_id} != ${jobId}`);
      ok("getScan → DocumentResponse<Job>", String(job.status));
    } catch (e) {
      fail("getScan", e);
    }

    let resultsJobId: string | null = jobId;
    if (!isCompleteStatus(latest.status)) {
      const complete = findComplete(items);
      if (!complete) {
        skip("getScanResults / summary", `latest status is ${JSON.stringify(latest.status)}, not complete`);
        resultsJobId = null;
      } else {
        resultsJobId = complete.job_id;
        vlog(`using complete job_id=${resultsJobId}`);
      }
    }

    if (resultsJobId) {
      try {
        const report = await client.getScanResults(resultsJobId);
        assertKeys(report, ["job_id", "status", "scan_results", "domain_results", "url_results", "check_results"], "JobReport");
        assertType(report.scan_results, "object", "scan_results");
        assertType(report.domain_results, "object", "domain_results");
        assertType(report.url_results, "object", "url_results");
        assertType(report.check_results, "array", "check_results");
        ok(
          "getScanResults → JobReport",
          `hosts=${Object.keys(report.scan_results).length} domains=${Object.keys(report.domain_results).length} ` +
            `urls=${Object.keys(report.url_results).length} checks=${report.check_results.length}`,
        );
      } catch (e) {
        if (e instanceof EffluxNotFoundError) skip("getScanResults", "results not found");
        else fail("getScanResults", e);
      }

      try {
        const summary = await client.getScanSummary(resultsJobId);
        assertKeys(summary, ["job_id", "ports", "services", "hosts_per_country"], "JobSummary");
        assertType(summary.ports, "array", "summary.ports");
        assertType(summary.services, "array", "summary.services");
        assertType(summary.hosts_per_country, "object", "summary.hosts_per_country");
        ok(
          "getScanSummary → JobSummary",
          `accessible_hosts=${summary.accessible_host_count} ports=${summary.ports.length}`,
        );
      } catch (e) {
        if (e instanceof EffluxNotFoundError) skip("getScanSummary", "summary not found");
        else fail("getScanSummary", e);
      }
    }
  }

  // Create last — so a new pending job does not block get/results above.
  try {
    const createResp = await client.createScan({
      hosts: ["1.1.1.1/32"],
      ports: ["top_10"],
      fingerprint: true,
      tags: ["client-test"],
      description: "client-tests createScan smoke",
    });
    const created = assertDocument(createResp);
    assertKeys(created, ["job_id", "status", "hosts", "ports", "request_count"], "createScan data");
    assertType(created.fingerprint, "boolean", "createScan fingerprint");
    assert(created.fingerprint === true, `fingerprint expected true, got ${created.fingerprint}`);
    assert(typeof created.job_id === "string" && created.job_id.length > 0, "job_id is empty");
    assert(typeof created.request_count === "number" && created.request_count >= 1, `request_count expected >= 1, got ${created.request_count}`);
    ok(
      "createScan → DocumentResponse<RequestResults>",
      `job_id=${created.job_id} status=${created.status} ` +
        `hosts=${created.host_count} ports=${created.port_count} requests=${created.request_count}`,
    );
    vlog(`rejected_hosts=${JSON.stringify(created.rejected_hosts)} rejected_ports=${JSON.stringify(created.rejected_ports)}`);
  } catch (e) {
    // 409 duplicate pending job means the create path / validation worked.
    if (e instanceof EffluxAPIError && e.statusCode === 409) {
      ok("createScan → 409 duplicate (create accepted)", e.detail);
    } else {
      fail("createScan", e);
    }
  }
}

async function testCaptures(client: InstanceType<typeof EffluxV3Client>): Promise<void> {
  log("\n[captures]");
  let items: any[] = [];
  try {
    const listed = await client.listCaptures(1, 5);
    items = assertPaged(listed, "capture");
    for (const item of items) assertKeys(item, ["capture_id", "status"], "capture list item");
    ok("listCaptures → PagedResponse", `${items.length} items`);
  } catch (e) {
    fail("listCaptures", e);
  }

  const latest = items.length ? pickLatest(items, (c) => c.capture_id) : null;
  if (!latest) {
    skip("getCapture / results", "no captures in account yet");
  } else {
    let captureId = latest.capture_id as string;
    vlog(`latest capture_id=${captureId} status=${latest.status}`);

    try {
      const doc = await client.getCapture(captureId);
      const data = assertDocument(doc);
      assertKeys(data, ["capture_id", "status"], "getCapture data");
      ok("getCapture → DocumentResponse", String(data.status));
    } catch (e) {
      fail("getCapture", e);
    }

    let resultsId: string | null = captureId;
    if (!isCompleteStatus(latest.status)) {
      const complete = findComplete(items);
      if (!complete) {
        skip("getCaptureResults", `latest status is ${JSON.stringify(latest.status)}`);
        resultsId = null;
      } else {
        resultsId = complete.capture_id;
      }
    }

    if (resultsId) {
      try {
        const results = await client.getCaptureResults(resultsId);
        assertType(results, "object", "capture results");
        ok("getCaptureResults → object", `keys=${Object.keys(results as object).slice(0, 8).join(",")}`);
      } catch (e) {
        if (e instanceof EffluxNotFoundError) skip("getCaptureResults", "results not found");
        else fail("getCaptureResults", e);
      }
    }
  }

  try {
    const doc = await client.createCapture("https://efflux.io");
    const data = assertDocument(doc);
    assertKeys(data, ["capture_id"], "createCapture data");
    ok("createCapture → DocumentResponse", `capture_id=${data.capture_id} status=${data.status ?? ""}`);
  } catch (e) {
    if (e instanceof EffluxAPIError && e.statusCode === 409) {
      ok("createCapture → 409 duplicate (create accepted)", e.detail);
    } else {
      fail("createCapture", e);
    }
  }
}

async function testPermutations(client: InstanceType<typeof EffluxV3Client>): Promise<void> {
  log("\n[permutations]");
  let items: any[] = [];
  try {
    const listed = await client.listPermutations(1, 5);
    items = assertPaged(listed, "permutation");
    for (const item of items) assertKeys(item, ["check_id"], "permutation list item");
    ok("listPermutations → PagedResponse", `${items.length} items`);
  } catch (e) {
    fail("listPermutations", e);
  }

  const latest = items.length ? pickLatest(items, (p) => p.check_id) : null;
  if (!latest) {
    skip("getPermutationCheck / report", "no permutations in account yet");
  } else {
    let checkId = latest.check_id as string;
    vlog(`latest check_id=${checkId} status=${latest.status}`);

    try {
      const doc = await client.getPermutationCheck(checkId);
      const data = assertDocument(doc);
      assertKeys(data, ["check_id"], "getPermutationCheck data");
      ok("getPermutationCheck → DocumentResponse", String(data.status ?? ""));
    } catch (e) {
      fail("getPermutationCheck", e);
    }

    let reportId: string | null = checkId;
    if (!isCompleteStatus(latest.status)) {
      const complete = findComplete(items);
      if (!complete) {
        skip("getPermutationReport", `latest status is ${JSON.stringify(latest.status)}`);
        reportId = null;
      } else {
        reportId = complete.check_id;
      }
    }

    if (reportId) {
      try {
        const report = await client.getPermutationReport(reportId);
        assertType(report, "object", "permutation report");
        ok("getPermutationReport → object", `keys=${Object.keys(report as object).slice(0, 8).join(",")}`);
      } catch (e) {
        if (e instanceof EffluxNotFoundError) skip("getPermutationReport", "report not found");
        else fail("getPermutationReport", e);
      }
    }
  }

  try {
    const doc = await client.createPermutationCheck("efflux.io");
    const data = assertDocument(doc);
    assertKeys(data, ["check_id"], "createPermutationCheck data");
    ok("createPermutationCheck → DocumentResponse", `check_id=${data.check_id} status=${data.status ?? ""}`);
  } catch (e) {
    if (e instanceof EffluxAPIError && e.statusCode === 409) {
      ok("createPermutationCheck → 409 duplicate (create accepted)", e.detail);
    } else {
      fail("createPermutationCheck", e);
    }
  }
}

async function testSurveys(client: InstanceType<typeof EffluxV3Client>): Promise<void> {
  log("\n[surveys / assetmaps]");
  let items: any[] = [];
  try {
    const listed = await client.listSurveys(1, 5);
    items = assertPaged(listed, "survey");
    for (const item of items) assertKeys(item, ["survey_id"], "survey list item");
    ok("listSurveys → PagedResponse", `${items.length} items`);
  } catch (e) {
    fail("listSurveys", e);
  }

  const latest = items.length ? pickLatest(items, (s) => s.survey_id) : null;
  if (!latest) {
    skip("getSurvey / assetMap", "no surveys in account yet");
  } else {
    let surveyId = latest.survey_id as string;
    vlog(`latest survey_id=${surveyId} status=${latest.status}`);

    try {
      const doc = await client.getSurvey(surveyId);
      const data = assertDocument(doc);
      assertKeys(data, ["survey_id"], "getSurvey data");
      ok("getSurvey → DocumentResponse", String(data.status ?? ""));
    } catch (e) {
      fail("getSurvey", e);
    }

    let mapId: string | null = surveyId;
    if (!isCompleteStatus(latest.status)) {
      const complete = findComplete(items);
      if (!complete) {
        skip("getAssetMap", `latest status is ${JSON.stringify(latest.status)}`);
        mapId = null;
      } else {
        mapId = complete.survey_id;
      }
    }

    if (mapId) {
      try {
        const doc = await client.getAssetMap(mapId);
        const data = assertDocument(doc);
        assertType(data, "object", "asset map data");
        ok("getAssetMap → DocumentResponse", `keys=${Object.keys(data as object).slice(0, 8).join(",")}`);
      } catch (e) {
        if (e instanceof EffluxNotFoundError) skip("getAssetMap", "map not found");
        else fail("getAssetMap", e);
      }
    }
  }

  try {
    const doc = await client.createSurvey("efflux.io");
    const data = assertDocument(doc);
    assertKeys(data, ["survey_id"], "createSurvey data");
    ok("createSurvey → DocumentResponse", `survey_id=${data.survey_id} status=${data.status ?? ""}`);
  } catch (e) {
    if (e instanceof EffluxAPIError && e.statusCode === 409) {
      ok("createSurvey → 409 duplicate (create accepted)", e.detail);
    } else {
      fail("createSurvey", e);
    }
  }
}

async function testTasks(client: InstanceType<typeof EffluxV3Client>): Promise<void> {
  log("\n[tasks]");
  let items: any[] = [];
  try {
    const listed = await client.listTasks(1, 5);
    items = assertPaged(listed, "task");
    for (const item of items) assertKeys(item, ["task_id"], "task list item");
    ok("listTasks → PagedResponse", `${items.length} items`);
  } catch (e) {
    fail("listTasks", e);
  }

  const latest = items.length ? pickLatest(items, (t) => t.task_id) : null;
  if (!latest) {
    skip("getTask / results", "no tasks in account yet");
  } else {
    let taskId = latest.task_id as string;
    vlog(`latest task_id=${taskId} status=${latest.status}`);

    try {
      const doc = await client.getTask(taskId);
      const data = assertDocument(doc);
      assertKeys(data, ["task_id"], "getTask data");
      ok("getTask → DocumentResponse", String(data.status ?? ""));
    } catch (e) {
      fail("getTask", e);
    }

    let resultsId: string | null = taskId;
    if (!isCompleteStatus(latest.status)) {
      const complete = findComplete(items);
      if (!complete) {
        skip("getTaskResults", `latest status is ${JSON.stringify(latest.status)}`);
        resultsId = null;
      } else {
        resultsId = complete.task_id;
      }
    }

    if (resultsId) {
      try {
        const results = await client.getTaskResults(resultsId);
        assertType(results, "object", "task results");
        ok("getTaskResults → object", `keys=${Object.keys(results as object).slice(0, 8).join(",")}`);
      } catch (e) {
        if (e instanceof EffluxNotFoundError) skip("getTaskResults", "results not found");
        else fail("getTaskResults", e);
      }
    }
  }

  const createBody = { target: "efflux.io", task: "dnsrules" };
  try {
    const doc = await client.createTask(createBody.target, createBody.task);
    const data = assertDocument(doc);
    assertKeys(data, ["task_id"], "createTask data");
    ok("createTask → DocumentResponse", `task_id=${data.task_id} status=${data.status ?? ""}`);
  } catch (e) {
    if (e instanceof EffluxAPIError && e.statusCode === 409) {
      ok("createTask → 409 duplicate (create accepted)", e.detail);
    } else {
      fail("createTask", e, createBody);
    }
  }
}

async function testSchedules(client: InstanceType<typeof EffluxV3Client>): Promise<void> {
  log("\n[schedules]");
  let items: any[] = [];
  try {
    const listed = await client.listSchedules(1, 5);
    items = assertPaged(listed, "schedule");
    for (const item of items) assertKeys(item, ["schedule_id"], "schedule list item");
    ok("listSchedules → PagedResponse", `${items.length} items`);
  } catch (e) {
    fail("listSchedules", e);
    return;
  }

  const latest = pickLatest(items, (s) => s.schedule_id);
  if (!latest) {
    skip("getSchedule", "no schedules in account");
    return;
  }

  try {
    const doc = await client.getSchedule(latest.schedule_id);
    const data = assertDocument(doc);
    assertKeys(data, ["schedule_id"], "getSchedule data");
    ok("getSchedule → DocumentResponse", String(data.name ?? ""));
  } catch (e) {
    fail("getSchedule", e);
  }
}

async function testHostLists(client: InstanceType<typeof EffluxV3Client>): Promise<void> {
  log("\n[host lists]");
  let items: any[] = [];
  try {
    const listed = await client.listHostLists(1, 5);
    items = assertPaged(listed, "host_list");
    for (const item of items) assertKeys(item, ["list_id"], "host list item");
    ok("listHostLists → PagedResponse", `${items.length} items`);
  } catch (e) {
    fail("listHostLists", e);
  }

  const latest = items.length ? pickLatest(items, (h) => h.list_id) : null;
  if (!latest) {
    skip("getHostList", "no host lists in account yet");
  } else {
    try {
      const doc = await client.getHostList(latest.list_id);
      const data = assertDocument(doc);
      assertKeys(data, ["list_id"], "getHostList data");
      ok("getHostList → DocumentResponse", String(data.name ?? ""));
    } catch (e) {
      fail("getHostList", e);
    }
  }

  let createdListId: string | null = null;
  const createBody = { name: "client_test_hosts", hosts: ["1.1.1.1"] };
  try {
    const doc = await client.createHostList(createBody.name, createBody.hosts);
    const data = assertDocument(doc);
    assertKeys(data, ["list_id"], "createHostList data");
    createdListId = String(data.list_id);
    ok("createHostList → DocumentResponse", `list_id=${createdListId} name=${data.name ?? ""}`);
  } catch (e) {
    if (e instanceof EffluxAPIError && e.statusCode === 409) {
      ok("createHostList → 409 duplicate (create accepted)", e.detail);
    } else {
      fail("createHostList", e, createBody);
    }
  }

  if (createdListId) {
    try {
      const doc = await client.getHostList(createdListId);
      const data = assertDocument(doc);
      assertKeys(data, ["list_id"], "get created hostList data");
      ok("getHostList (created) → DocumentResponse", String(data.name ?? ""));
    } catch (e) {
      fail("getHostList (created)", e);
    }

    try {
      await client.deleteHostList(createdListId);
      ok("deleteHostList → 204/ok", `list_id=${createdListId}`);
    } catch (e) {
      fail("deleteHostList", e);
    }
  }
}

async function testPortLists(client: InstanceType<typeof EffluxV3Client>): Promise<void> {
  log("\n[port lists]");
  let items: any[] = [];
  try {
    const listed = await client.listPortLists(1, 5);
    items = assertPaged(listed, "port_list");
    for (const item of items) assertKeys(item, ["list_id"], "port list item");
    ok("listPortLists → PagedResponse", `${items.length} items`);
  } catch (e) {
    fail("listPortLists", e);
  }

  const latest = items.length ? pickLatest(items, (p) => p.list_id) : null;
  if (!latest) {
    skip("getPortList", "no port lists in account yet");
  } else {
    try {
      const doc = await client.getPortList(latest.list_id);
      const data = assertDocument(doc);
      assertKeys(data, ["list_id"], "getPortList data");
      ok("getPortList → DocumentResponse", String(data.name ?? ""));
    } catch (e) {
      fail("getPortList", e);
    }
  }

  let createdListId: string | null = null;
  const createBody = { name: "client_test_ports", ports: ["22", "23"] };
  try {
    const doc = await client.createPortList(createBody.name, createBody.ports);
    const data = assertDocument(doc);
    assertKeys(data, ["list_id"], "createPortList data");
    createdListId = String(data.list_id);
    ok("createPortList → DocumentResponse", `list_id=${createdListId} name=${data.name ?? ""}`);
  } catch (e) {
    if (e instanceof EffluxAPIError && e.statusCode === 409) {
      ok("createPortList → 409 duplicate (create accepted)", e.detail);
    } else {
      fail("createPortList", e, createBody);
    }
  }

  if (createdListId) {
    try {
      const doc = await client.getPortList(createdListId);
      const data = assertDocument(doc);
      assertKeys(data, ["list_id"], "get created portList data");
      ok("getPortList (created) → DocumentResponse", String(data.name ?? ""));
    } catch (e) {
      fail("getPortList (created)", e);
    }

    try {
      await client.deletePortList(createdListId);
      ok("deletePortList → 204/ok", `list_id=${createdListId}`);
    } catch (e) {
      fail("deletePortList", e);
    }
  }
}

async function testRules(client: InstanceType<typeof EffluxV3Client>): Promise<void> {
  log("\n[rules]");
  let items: any[] = [];
  try {
    const listed = await client.listRules(1, 5);
    items = assertPaged(listed, "rule");
    for (const item of items) assertKeys(item, ["rule_id"], "rule list item");
    ok("listRules → PagedResponse", `${items.length} items`);
  } catch (e) {
    fail("listRules", e);
    return;
  }

  const latest = pickLatest(items, (r) => r.rule_id);
  if (!latest) {
    skip("getRule", "no rules in account");
    return;
  }

  try {
    const doc = await client.getRule(latest.rule_id);
    const data = assertDocument(doc);
    assertKeys(data, ["rule_id"], "getRule data");
    ok("getRule → DocumentResponse", String(data.name ?? data.rule_id ?? ""));
  } catch (e) {
    fail("getRule", e);
  }
}

async function testChecks(client: InstanceType<typeof EffluxV3Client>): Promise<void> {
  log("\n[checks]");
  try {
    const listed = await client.listChecks({ page: 1, limit: 5 });
    const items = assertPaged(listed, "check");
    for (const item of items) {
      assertKeys(item, ["check_name"], "check list item");
    }
    ok("listChecks → PagedResponse", `${items.length} items`);
  } catch (e) {
    fail("listChecks", e);
  }
}

async function testCertMonitoring(client: InstanceType<typeof EffluxV3Client>): Promise<void> {
  log("\n[cert-monitoring]");
  let items: any[] = [];
  try {
    const listed = await client.listMonitoredDomains(1, 5);
    items = assertPaged(listed, "monitored_domain");
    for (const item of items) assertKeys(item, ["domain"], "cert-monitoring list item");
    ok("listMonitoredDomains → PagedResponse", `${items.length} items`);
  } catch (e) {
    fail("listMonitoredDomains", e);
    return;
  }

  const latest = pickLatest(items, (d) => d.domain);
  if (!latest) {
    skip("getMonitoredDomainCerts", "no monitored domains");
    return;
  }

  try {
    const certs = await client.getMonitoredDomainCerts(latest.domain, 1, 5);
    assertPaged(certs, "cert");
    ok("getMonitoredDomainCerts → PagedResponse", `${certs.data.length} certs`);
  } catch (e) {
    fail("getMonitoredDomainCerts", e);
  }
}

async function testLimits(client: InstanceType<typeof EffluxV3Client>): Promise<void> {
  log("\n[limits]");
  try {
    const limits = await client.getLimits();
    assertType(limits, "object", "limits");
    const data = (limits as AnyObj).data ?? limits;
    assertType(data, "object", "limits data");
    ok("getLimits → object", `keys=${Object.keys(data as object).slice(0, 8).join(",")}`);
  } catch (e) {
    fail("getLimits", e);
  }
}

const RESOURCES: Record<string, (c: InstanceType<typeof EffluxV3Client>) => Promise<void>> = {
  scans: testScans,
  captures: testCaptures,
  permutations: testPermutations,
  surveys: testSurveys,
  tasks: testTasks,
  schedules: testSchedules,
  "host-lists": testHostLists,
  "port-lists": testPortLists,
  rules: testRules,
  checks: testChecks,
  "cert-monitoring": testCertMonitoring,
  limits: testLimits,
};

async function main(): Promise<number> {
  const args = parseArgs(process.argv.slice(2));
  VERBOSE = args.verbose;

  if (args.resource !== "all" && !(args.resource in RESOURCES)) {
    console.error(`Unknown resource: ${args.resource}`);
    console.error(`Choices: all, ${Object.keys(RESOURCES).join(", ")}`);
    return 2;
  }

  const apiKey = requireApiKey();
  const client = new EffluxV3Client({
    apiKey,
    defaultHeaders: {
      "User-Agent": "Efflux-Online/1.0 (Web Client)",
      "X-Proxy-Source": "nextjs",
    },
  });

  log(`Efflux v3 TypeScript client test — ${new Date().toISOString()}`);
  log(`Base URL: ${(client as any).baseUrl ?? "https://api.efflux.io/v3"}`);
  log(`Resource: ${args.resource}`);

  try {
    await client.getLimits();
    ok("auth / connectivity (GET /limits)");
  } catch (e) {
    fail("auth / connectivity", e);
    log("\nAborting: could not authenticate.");
    return 1;
  }

  const names = args.resource === "all" ? Object.keys(RESOURCES) : [args.resource];
  for (const name of names) {
    await RESOURCES[name](client);
  }

  log("\n" + "=".repeat(60));
  log(`Results: ${PASS} passed, ${FAIL} failed, ${SKIP} skipped`);
  printFailureSummary();
  return FAIL ? 1 : 0;
}

const code = await main();
process.exit(code);
