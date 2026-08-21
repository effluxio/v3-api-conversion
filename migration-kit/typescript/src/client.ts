/**
 * Efflux v3 API Client (TypeScript)
 *
 * Uses the Fetch API (built into Node 18+, Deno, Bun, and all modern browsers).
 * No third-party dependencies required for basic usage.
 *
 * For WebSocket streams, the browser WebSocket API or `ws` npm package is used.
 *
 * Usage:
 *   const client = new EffluxV3Client({ apiKey: "your-api-key" });
 *
 *   const response = await client.createScan({
 *     hosts: ["10.0.0.0/24"],
 *     ports: ["top_100"],
 *     fingerprint: true,
 *     tags: ["production"],
 *   });
 *   const jobId = response.data.job_id;
 *
 *   const job = await client.waitForJob(jobId);
 *   const results = await client.getScanResults(jobId);
 *
 *   for (const [host, hostStatus] of Object.entries(results.scan_results)) {
 *     for (const [port, scanResult] of Object.entries(hostStatus.ports)) {
 *       if (scanResult.open) {
 *         console.log(`${host}:${port} — ${scanResult.service}`);
 *       }
 *     }
 *   }
 */

import type {
  Callback,
  CallbackRequest,
  CheckResult,
  DocumentResponse,
  Job,
  JobReport,
  JobSummary,
  PagedResponse,
  Pagination,
  RequestResults,
  ScanRequest,
  Schedule,
  ScheduleRun,
  HostList,
  PortList,
  WSMessage,
} from "./types.js";

export const BASE_URL = "https://api.efflux.io/v3";

// ---------------------------------------------------------------------------
// Error Types
// ---------------------------------------------------------------------------

export class EffluxAPIError extends Error {
  public readonly statusCode: number;
  public readonly detail: string;
  public readonly title?: string;
  public readonly errorType?: string;
  public readonly fieldErrors: Array<{ field: string; message: string }>;
  public readonly rateLimit?: {
    limit: number;
    remaining: number;
    reset_at: string;
    retry_after_seconds: number;
  };
  public readonly rawBody: unknown;

  constructor(statusCode: number, body: Record<string, unknown>) {
    const detail = (body.detail as string) || (body.error as string) || "Unknown error";
    super(`HTTP ${statusCode}: ${detail}`);
    this.name = "EffluxAPIError";
    this.statusCode = statusCode;
    this.detail = detail;
    this.title = body.title as string | undefined;
    this.errorType = body.type as string | undefined;
    this.fieldErrors = (body.errors as Array<{ field: string; message: string }>) ?? [];
    this.rateLimit = body.rate_limit as EffluxAPIError["rateLimit"];
    this.rawBody = body;
  }

  get fields(): Record<string, string> {
    return Object.fromEntries(this.fieldErrors.map((e) => [e.field, e.message]));
  }
}

export class EffluxValidationError extends EffluxAPIError {
  constructor(body: Record<string, unknown>) {
    super(400, body);
    this.name = "EffluxValidationError";
  }
}

export class EffluxAuthError extends EffluxAPIError {
  constructor(statusCode: number, body: Record<string, unknown>) {
    super(statusCode, body);
    this.name = "EffluxAuthError";
  }
}

export class EffluxNotFoundError extends EffluxAPIError {
  constructor(body: Record<string, unknown>) {
    super(404, body);
    this.name = "EffluxNotFoundError";
  }
}

export class EffluxRateLimitError extends EffluxAPIError {
  constructor(body: Record<string, unknown>) {
    super(429, body);
    this.name = "EffluxRateLimitError";
  }

  get retryAfterSeconds(): number | undefined {
    return this.rateLimit?.retry_after_seconds;
  }

  get resetAt(): string | undefined {
    return this.rateLimit?.reset_at;
  }
}

export class EffluxTimeoutError extends Error {
  constructor(jobId: string, timeoutMs: number) {
    super(`Job ${jobId} did not complete within ${timeoutMs / 1000}s`);
    this.name = "EffluxTimeoutError";
  }
}

// ---------------------------------------------------------------------------
// Client Options
// ---------------------------------------------------------------------------

export interface EffluxV3ClientOptions {
  apiKey: string;
  baseUrl?: string;
  /** Fetch timeout in milliseconds. Default: 30000. */
  timeoutMs?: number;
  /** Custom fetch implementation. Defaults to global fetch. */
  fetch?: typeof fetch;
  /** Extra headers merged into every request (e.g. User-Agent, X-Proxy-Source). */
  defaultHeaders?: Record<string, string>;
}

// ---------------------------------------------------------------------------
// Main Client
// ---------------------------------------------------------------------------

export class EffluxV3Client {
  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;
  private readonly defaultHeaders: Record<string, string>;

  constructor(options: EffluxV3ClientOptions) {
    this.apiKey = options.apiKey;
    this.baseUrl = (options.baseUrl ?? BASE_URL).replace(/\/$/, "");
    this.timeoutMs = options.timeoutMs ?? 30_000;
    this.fetchImpl = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.defaultHeaders = { ...(options.defaultHeaders ?? {}) };
  }

  // -------------------------------------------------------------------------
  // Internal HTTP helpers
  // -------------------------------------------------------------------------

  private headers(): HeadersInit {
    return {
      Authorization: this.apiKey,
      "Content-Type": "application/json",
      Accept: "application/json",
      ...this.defaultHeaders,
    };
  }

  private buildUrl(path: string, params?: Record<string, string | number | boolean | undefined | null>): string {
    const url = new URL(`${this.baseUrl}${path}`);
    if (params) {
      for (const [key, value] of Object.entries(params)) {
        if (value !== undefined && value !== null) {
          url.searchParams.set(key, String(value));
        }
      }
    }
    return url.toString();
  }

  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
    params?: Record<string, string | number | boolean | undefined | null>,
  ): Promise<T> {
    const url = this.buildUrl(path, params);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    let response: Response;
    try {
      response = await this.fetchImpl(url, {
        method,
        headers: this.headers(),
        body: body !== undefined ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timer);
    }

    let responseBody: Record<string, unknown> = {};
    const text = await response.text();
    if (text) {
      try {
        responseBody = JSON.parse(text);
      } catch {
        responseBody = { detail: text };
      }
    }

    if (!response.ok) {
      switch (response.status) {
        case 400:
          throw new EffluxValidationError(responseBody);
        case 401:
        case 403:
          throw new EffluxAuthError(response.status, responseBody);
        case 404:
          throw new EffluxNotFoundError(responseBody);
        case 429:
          throw new EffluxRateLimitError(responseBody);
        default:
          throw new EffluxAPIError(response.status, responseBody);
      }
    }

    return responseBody as T;
  }

  private get<T>(path: string, params?: Record<string, string | number | boolean | undefined | null>): Promise<T> {
    return this.request<T>("GET", path, undefined, params);
  }

  private post<T>(path: string, body?: unknown): Promise<T> {
    return this.request<T>("POST", path, body);
  }

  private put<T>(path: string, body?: unknown): Promise<T> {
    return this.request<T>("PUT", path, body);
  }

  private delete<T>(path: string): Promise<T> {
    return this.request<T>("DELETE", path);
  }

  // -------------------------------------------------------------------------
  // Scans
  // -------------------------------------------------------------------------

  /**
   * POST /v3/scans — Create and start a new scan job.
   *
   * Returns a DocumentResponse; access the job via response.data.
   *
   * Breaking changes from v2:
   * - fingerprint is now boolean (was integer 0/1/2)
   * - checks_options replaces checks_opts
   * - callback uses nested {start, success, fail} format
   * - response is wrapped in DocumentResponse (access .data)
   */
  async createScan(request: ScanRequest): Promise<DocumentResponse<RequestResults>> {
    return this.post<DocumentResponse<RequestResults>>("/scans", request);
  }

  /**
   * POST /v3/scans/eval — Evaluate a scan request without executing.
   *
   * Preview host/port resolution and request count before consuming credits.
   * Same request body as createScan. Returns same response shape.
   */
  async evalScan(request: ScanRequest): Promise<DocumentResponse<RequestResults>> {
    return this.post<DocumentResponse<RequestResults>>("/scans/eval", request);
  }

  /**
   * GET /v3/scans/{job_id} — Get job status and metadata only.
   *
   * IMPORTANT: This no longer returns scan results.
   * - For full results: getScanResults(job_id)
   * - For statistics:   getScanSummary(job_id)
   */
  async getScan(jobId: string): Promise<DocumentResponse<Job>> {
    return this.get<DocumentResponse<Job>>(`/scans/${jobId}`);
  }

  /**
   * GET /v3/scans/{job_id}/results — Get the full scan results.
   *
   * Returns JobReport directly (NOT wrapped in DocumentResponse).
   *
   * v2 → v3 field renames in JobReport:
   *   results     → scan_results   (same map structure)
   *   domain_info → domain_results (same map structure)
   *   url_info    → url_results    (was array!, now Record<url, UrlResult>)
   *
   * New: check_results — top-level array of all check matches
   */
  async getScanResults(jobId: string, details = false): Promise<JobReport> {
    return this.get<JobReport>(`/scans/${jobId}/results`, details ? { details: "true" } : undefined);
  }

  /**
   * GET /v3/scans/{job_id}/summary — Get aggregated scan statistics.
   *
   * New in v3. Returns lightweight stats without full result payload.
   * Use instead of getScanResults() when you only need counts and lists.
   */
  async getScanSummary(jobId: string): Promise<JobSummary> {
    return this.get<JobSummary>(`/scans/${jobId}/summary`);
  }

  /**
   * GET /v3/scans — List scan jobs (paginated).
   *
   * v2 used ?count=N and returned a plain array.
   * v3 uses ?page=N&limit=N and returns { data: [...], pagination: {...} }.
   */
  async listScans(page = 1, limit = 20): Promise<PagedResponse<Job>> {
    return this.get<PagedResponse<Job>>("/scans", { page, limit });
  }

  /**
   * Async generator — iterate all scan jobs across all pages.
   *
   * Usage:
   *   for await (const job of client.listAllScans()) {
   *     console.log(job.job_id, job.status);
   *   }
   */
  async *listAllScans(limit = 100): AsyncGenerator<Job> {
    let page = 1;
    while (true) {
      const response = await this.listScans(page, limit);
      yield* response.data;
      if (!response.pagination.has_next) break;
      page++;
    }
  }

  /**
   * POST /v3/scans/{job_id}/repeat — Repeat a previous scan job.
   *
   * v2 path: POST /scans/repeat/{job_id}
   * v3 path: POST /scans/{job_id}/repeat  ← path changed
   *
   * Returns HTTP 201 + DocumentResponse<RequestResults>.
   */
  async repeatScan(jobId: string): Promise<DocumentResponse<RequestResults>> {
    return this.post<DocumentResponse<RequestResults>>(`/scans/${jobId}/repeat`);
  }

  /**
   * POST /v3/scans/{job_id}/callback — Update callback config after job creation.
   * New in v3.
   */
  async updateScanCallback(jobId: string, callback: CallbackRequest): Promise<Callback> {
    return this.post<Callback>(`/scans/${jobId}/callback`, callback);
  }

  /**
   * PUT /v3/scans/{job_id}/callback/restart — Retry callback deliveries.
   * New in v3.
   */
  async restartScanCallback(jobId: string): Promise<Callback> {
    return this.put<Callback>(`/scans/${jobId}/callback/restart`);
  }

  // -------------------------------------------------------------------------
  // Polling helpers
  // -------------------------------------------------------------------------

  /**
   * Poll GET /v3/scans/{job_id} until the job reaches a terminal state.
   *
   * Replaces the v2 /subscribe long-poll endpoint.
   *
   * @param pollIntervalMs - Milliseconds between status checks (default 5000).
   * @param timeoutMs - Maximum milliseconds to wait (default 3_600_000 = 1 hour).
   */
  async waitForJob(
    jobId: string,
    pollIntervalMs = 5_000,
    timeoutMs = 3_600_000,
  ): Promise<Job> {
    const deadline = Date.now() + timeoutMs;

    while (Date.now() < deadline) {
      const response = await this.getScan(jobId);
      const job = response.data;

      const terminal = ["complete", "failed", "canceled"];
      if (terminal.includes(job.status)) {
        return job;
      }

      const remaining = deadline - Date.now();
      if (remaining <= 0) break;
      await sleep(Math.min(pollIntervalMs, remaining));
    }

    throw new EffluxTimeoutError(jobId, timeoutMs);
  }

  /**
   * Create a scan job and wait for completion, then return both job and results.
   *
   * Usage:
   *   const { job, report } = await client.runScanAndWait({
   *     hosts: ["10.0.0.0/24"],
   *     ports: ["top_100"],
   *   });
   *   console.log(`Found ${report.accessible_host_count} hosts`);
   */
  async runScanAndWait(
    request: ScanRequest,
    options?: { pollIntervalMs?: number; timeoutMs?: number },
  ): Promise<{ job: Job; report: JobReport }> {
    const createResponse = await this.createScan(request);
    const jobId = createResponse.data.job_id;
    const job = await this.waitForJob(
      jobId,
      options?.pollIntervalMs,
      options?.timeoutMs,
    );
    const report = await this.getScanResults(jobId);
    return { job, report };
  }

  // -------------------------------------------------------------------------
  // WebSocket Streams
  // -------------------------------------------------------------------------

  /**
   * Open a WebSocket stream for live results from a specific job.
   * New in v3. Replaces the /subscribe long-poll endpoint.
   *
   * wss://api.efflux.io/v3/stream/scans/{job_id}
   *
   * Authentication via Sec-WebSocket-Protocol header.
   *
   * Usage (browser / Node.js with ws package):
   *   const ws = client.streamJob(jobId);
   *   ws.onmessage = (event) => {
   *     const msg: WSMessage = JSON.parse(event.data);
   *     if (msg.type === "scan") {
   *       console.log("Port result:", msg.data);
   *     }
   *   };
   *   ws.onclose = () => console.log("Stream closed");
   */
  streamJob(jobId: string): WebSocket {
    const wsBaseUrl = this.baseUrl.replace(/^https?/, "wss");
    const ws = new WebSocket(
      `${wsBaseUrl}/stream/scans/${jobId}`,
      [`efflux.v1`, this.apiKey],
    );
    return ws;
  }

  /**
   * Open a WebSocket stream for live results from all your jobs.
   * wss://api.efflux.io/v3/stream/scans
   */
  streamAllJobs(): WebSocket {
    const wsBaseUrl = this.baseUrl.replace(/^https?/, "wss");
    return new WebSocket(
      `${wsBaseUrl}/stream/scans`,
      [`efflux.v1`, this.apiKey],
    );
  }

  /**
   * Open a WebSocket stream for job status changes.
   * wss://api.efflux.io/v3/stream/status?type=job
   */
  streamJobStatus(): WebSocket {
    const wsBaseUrl = this.baseUrl.replace(/^https?/, "wss");
    return new WebSocket(
      `${wsBaseUrl}/stream/status?type=job`,
      [`efflux.v1`, this.apiKey],
    );
  }

  /**
   * Async generator for a live job stream — yields parsed WSMessage objects.
   *
   * Usage (Node.js with ws package installed):
   *   for await (const event of client.streamJobEvents(jobId)) {
   *     if (event.type === "scan") {
   *       const result = event.data as ScanResult;
   *       console.log(`${result.host}:${result.port} open=${result.open}`);
   *     }
   *   }
   */
  async *streamJobEvents(jobId: string): AsyncGenerator<WSMessage> {
    const ws = this.streamJob(jobId);
    const queue: WSMessage[] = [];
    let resolve: (() => void) | null = null;
    let done = false;
    let error: Error | null = null;

    ws.onmessage = (event: MessageEvent) => {
      try {
        queue.push(JSON.parse(event.data) as WSMessage);
        resolve?.();
        resolve = null;
      } catch {
        // skip unparseable messages
      }
    };

    ws.onclose = () => {
      done = true;
      resolve?.();
      resolve = null;
    };

    ws.onerror = (event: Event) => {
      error = new Error(`WebSocket error: ${event}`);
      done = true;
      resolve?.();
      resolve = null;
    };

    while (!done || queue.length > 0) {
      if (queue.length === 0 && !done) {
        await new Promise<void>((r) => {
          resolve = r;
        });
      }
      while (queue.length > 0) {
        yield queue.shift()!;
      }
    }

    if (error) throw error;
  }

  // -------------------------------------------------------------------------
  // Checks (cross-job query)
  // -------------------------------------------------------------------------

  /**
   * GET /v3/checks — Query vulnerability check results across all jobs.
   * New in v3. In v2 you had to iterate each job's results to find checks.
   */
  async listChecks(options?: {
    jobId?: string;
    severity?: string;
    cve?: string;
    minDate?: string;
    maxDate?: string;
    page?: number;
    limit?: number;
  }): Promise<PagedResponse<CheckResult>> {
    return this.get<PagedResponse<CheckResult>>("/checks", {
      job_id: options?.jobId,
      severity: options?.severity,
      cve: options?.cve,
      min_date: options?.minDate,
      max_date: options?.maxDate,
      page: options?.page ?? 1,
      limit: options?.limit ?? 20,
    });
  }

  // -------------------------------------------------------------------------
  // Host & Port Lists
  // -------------------------------------------------------------------------

  async listHostLists(page = 1, limit = 20): Promise<PagedResponse<HostList>> {
    return this.get<PagedResponse<HostList>>("/lists/hosts", { page, limit });
  }

  async createHostList(name: string, hosts: string[]): Promise<DocumentResponse<HostList>> {
    return this.post<DocumentResponse<HostList>>("/lists/hosts", { name, hosts });
  }

  async getHostList(listId: string): Promise<DocumentResponse<HostList>> {
    return this.get<DocumentResponse<HostList>>(`/lists/hosts/${listId}`);
  }

  async updateHostList(listId: string, name: string, hosts: string[]): Promise<DocumentResponse<HostList>> {
    return this.put<DocumentResponse<HostList>>(`/lists/hosts/${listId}`, { name, hosts });
  }

  async deleteHostList(listId: string): Promise<void> {
    await this.delete<unknown>(`/lists/hosts/${listId}`);
  }

  async listPortLists(page = 1, limit = 20): Promise<PagedResponse<PortList>> {
    return this.get<PagedResponse<PortList>>("/lists/ports", { page, limit });
  }

  async createPortList(name: string, ports: string[]): Promise<DocumentResponse<PortList>> {
    return this.post<DocumentResponse<PortList>>("/lists/ports", { name, ports });
  }

  async getPortList(listId: string): Promise<DocumentResponse<PortList>> {
    return this.get<DocumentResponse<PortList>>(`/lists/ports/${listId}`);
  }

  async deletePortList(listId: string): Promise<void> {
    await this.delete<unknown>(`/lists/ports/${listId}`);
  }

  // -------------------------------------------------------------------------
  // Schedules
  // -------------------------------------------------------------------------

  async listSchedules(page = 1, limit = 20): Promise<PagedResponse<Schedule>> {
    return this.get<PagedResponse<Schedule>>("/schedules", { page, limit });
  }

  async createSchedule(schedule: Record<string, unknown>): Promise<DocumentResponse<Schedule>> {
    return this.post<DocumentResponse<Schedule>>("/schedules", schedule);
  }

  async getSchedule(scheduleId: string): Promise<DocumentResponse<Schedule>> {
    return this.get<DocumentResponse<Schedule>>(`/schedules/${scheduleId}`);
  }

  async updateSchedule(scheduleId: string, schedule: Record<string, unknown>): Promise<DocumentResponse<Schedule>> {
    return this.put<DocumentResponse<Schedule>>(`/schedules/${scheduleId}`, schedule);
  }

  async deleteSchedule(scheduleId: string): Promise<void> {
    await this.delete<unknown>(`/schedules/${scheduleId}`);
  }

  async getScheduleHistory(scheduleId: string, page = 1, limit = 20): Promise<PagedResponse<ScheduleRun>> {
    return this.get<PagedResponse<ScheduleRun>>(`/schedules/${scheduleId}/history`, { page, limit });
  }

  // -------------------------------------------------------------------------
  // Search
  // -------------------------------------------------------------------------

  async searchDns(
    query: string,
    options?: { limit?: number; searchAfter?: string; fields?: string } & Record<string, unknown>,
  ): Promise<unknown> {
    const { limit, searchAfter, fields, ...filters } = options ?? {};
    return this.get<unknown>("/search/advanced/dns", {
      q: query,
      limit: limit ?? 20,
      search_after: searchAfter,
      fields,
      ...filters,
    });
  }

  async searchHosts(
    query: string,
    options?: { limit?: number; searchAfter?: string } & Record<string, unknown>,
  ): Promise<unknown> {
    const { limit, searchAfter, ...filters } = options ?? {};
    return this.get<unknown>("/search/advanced/hosts", {
      q: query,
      limit: limit ?? 20,
      search_after: searchAfter,
      ...filters,
    });
  }

  async searchUrls(
    query: string,
    options?: { limit?: number; searchAfter?: string } & Record<string, unknown>,
  ): Promise<unknown> {
    const { limit, searchAfter, ...filters } = options ?? {};
    return this.get<unknown>("/search/advanced/urls", {
      q: query,
      limit: limit ?? 20,
      search_after: searchAfter,
      ...filters,
    });
  }

  async lookupDomain(domain: string): Promise<unknown> {
    return this.get<unknown>(`/search/domains/${domain}`);
  }

  async lookupHost(host: string, page = 1, limit = 20): Promise<unknown> {
    return this.get<unknown>(`/search/hosts/${host}`, { page, limit });
  }

  async lookupHostSummary(host: string): Promise<unknown> {
    return this.get<unknown>(`/search/hosts/${host}/summary`);
  }

  async myHostResults(host: string): Promise<unknown> {
    return this.get<unknown>(`/search/my/hosts/${host}`);
  }

  // -------------------------------------------------------------------------
  // Captures
  // -------------------------------------------------------------------------

  async listCaptures(page = 1, limit = 100): Promise<PagedResponse<unknown>> {
    return this.get<PagedResponse<unknown>>("/captures", { page, limit });
  }

  async createCapture(url: string, options?: { region?: string; callback?: CallbackRequest }): Promise<DocumentResponse<unknown>> {
    return this.post<DocumentResponse<unknown>>("/captures", {
      url,
      region: options?.region,
      callback: options?.callback,
    });
  }

  async getCapture(captureId: string): Promise<DocumentResponse<unknown>> {
    return this.get<DocumentResponse<unknown>>(`/captures/${captureId}`);
  }

  async getCaptureResults(captureId: string): Promise<unknown> {
    return this.get<unknown>(`/captures/${captureId}/results`);
  }

  async getCaptureCookies(captureId: string, page = 1, limit = 100): Promise<PagedResponse<unknown>> {
    return this.get<PagedResponse<unknown>>(`/captures/${captureId}/cookies`, { page, limit });
  }

  async getCaptureCookieReport(captureId: string): Promise<unknown> {
    return this.get<unknown>(`/captures/${captureId}/cookies/report`);
  }

  async getCaptureHtml(captureId: string): Promise<unknown> {
    return this.get<unknown>(`/captures/${captureId}/html`);
  }

  async getCaptureNetworkLogs(captureId: string, page = 1, limit = 100): Promise<PagedResponse<unknown>> {
    return this.get<PagedResponse<unknown>>(`/captures/${captureId}/network-logs`, { page, limit });
  }

  // -------------------------------------------------------------------------
  // Asset Maps / Surveys
  // -------------------------------------------------------------------------

  async listSurveys(page = 1, limit = 20): Promise<PagedResponse<unknown>> {
    return this.get<PagedResponse<unknown>>("/assetmaps/surveys", { page, limit });
  }

  async createSurvey(domain: string, options?: { trackedSubdomains?: string[]; callback?: CallbackRequest }): Promise<DocumentResponse<unknown>> {
    return this.post<DocumentResponse<unknown>>("/assetmaps/surveys", {
      domain,
      tracked_subdomains: options?.trackedSubdomains,
      callback: options?.callback,
    });
  }

  async getSurvey(surveyId: string): Promise<DocumentResponse<unknown>> {
    return this.get<DocumentResponse<unknown>>(`/assetmaps/surveys/${surveyId}`);
  }

  async getAssetMap(surveyId: string): Promise<DocumentResponse<unknown>> {
    return this.get<DocumentResponse<unknown>>(`/assetmaps/surveys/${surveyId}/map`);
  }

  // -------------------------------------------------------------------------
  // Cert Monitoring
  // -------------------------------------------------------------------------

  async listMonitoredDomains(page = 1, limit = 20): Promise<PagedResponse<unknown>> {
    return this.get<PagedResponse<unknown>>("/cert-monitoring", { page, limit });
  }

  async addMonitoredDomain(domain: string): Promise<DocumentResponse<unknown>> {
    return this.post<DocumentResponse<unknown>>("/cert-monitoring", { domain });
  }

  async removeMonitoredDomain(domain: string): Promise<void> {
    await this.delete<unknown>(`/cert-monitoring/${domain}`);
  }

  async getMonitoredDomainCerts(domain: string, page = 1, limit = 20): Promise<PagedResponse<unknown>> {
    return this.get<PagedResponse<unknown>>(`/cert-monitoring/${domain}/certs`, { page, limit });
  }

  // -------------------------------------------------------------------------
  // Permutations
  // -------------------------------------------------------------------------

  async listPermutations(page = 1, limit = 20): Promise<PagedResponse<unknown>> {
    return this.get<PagedResponse<unknown>>("/permutations", { page, limit });
  }

  async createPermutationCheck(domain: string, callback?: CallbackRequest): Promise<DocumentResponse<unknown>> {
    return this.post<DocumentResponse<unknown>>("/permutations", { domain, callback });
  }

  async getPermutationCheck(checkId: string): Promise<DocumentResponse<unknown>> {
    return this.get<DocumentResponse<unknown>>(`/permutations/${checkId}`);
  }

  async getPermutationReport(checkId: string): Promise<unknown> {
    return this.get<unknown>(`/permutations/${checkId}/report`);
  }

  // -------------------------------------------------------------------------
  // Info
  // -------------------------------------------------------------------------

  async getCve(cveId: string): Promise<unknown> {
    return this.get<unknown>(`/info/cves/${cveId}`);
  }

  async getTopTcpPorts(count: number): Promise<unknown> {
    return this.get<unknown>(`/info/ports/tcp/${count}`);
  }

  async getTopUdpPorts(count: number): Promise<unknown> {
    return this.get<unknown>(`/info/ports/udp/${count}`);
  }

  async getUsage(page = 1, limit = 20): Promise<PagedResponse<unknown>> {
    return this.get<PagedResponse<unknown>>("/info/usage", { page, limit });
  }

  // -------------------------------------------------------------------------
  // Limits & Billing
  // -------------------------------------------------------------------------

  async getLimits(): Promise<unknown> {
    return this.get<unknown>("/limits");
  }

  async getBillingCatalog(): Promise<unknown> {
    return this.get<unknown>("/billing/catalog");
  }

  async getBillingStatus(): Promise<unknown> {
    return this.get<unknown>("/billing/status");
  }

  // -------------------------------------------------------------------------
  // Tasks
  // -------------------------------------------------------------------------

  async listTasks(page = 1, limit = 20): Promise<PagedResponse<unknown>> {
    return this.get<PagedResponse<unknown>>("/tasks", { page, limit });
  }

  async createTask(target: string, task: string, callback?: CallbackRequest): Promise<DocumentResponse<unknown>> {
    return this.post<DocumentResponse<unknown>>("/tasks", { target, task, callback });
  }

  async getAvailableTasks(): Promise<unknown> {
    return this.get<unknown>("/tasks/available");
  }

  async getTask(taskId: string): Promise<DocumentResponse<unknown>> {
    return this.get<DocumentResponse<unknown>>(`/tasks/${taskId}`);
  }

  async getTaskResults(taskId: string): Promise<unknown> {
    return this.get<unknown>(`/tasks/${taskId}/results`);
  }

  // -------------------------------------------------------------------------
  // Rules
  // -------------------------------------------------------------------------

  async listRules(page = 1, limit = 20): Promise<PagedResponse<unknown>> {
    return this.get<PagedResponse<unknown>>("/rules", { page, limit });
  }

  async createRule(rule: Record<string, unknown>): Promise<DocumentResponse<unknown>> {
    return this.post<DocumentResponse<unknown>>("/rules", rule);
  }

  async evaluateRule(rule: Record<string, unknown>, data: Record<string, unknown>): Promise<unknown> {
    return this.post<unknown>("/rules/evaluate", { rule, data });
  }

  async getRule(ruleId: string): Promise<DocumentResponse<unknown>> {
    return this.get<DocumentResponse<unknown>>(`/rules/${ruleId}`);
  }

  async deleteRule(ruleId: string): Promise<void> {
    await this.delete<unknown>(`/rules/${ruleId}`);
  }

  async getRuleMatches(ruleId: string, page = 1, limit = 20): Promise<PagedResponse<unknown>> {
    return this.get<PagedResponse<unknown>>(`/rules/${ruleId}/matches`, { page, limit });
  }
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export { sleep };
