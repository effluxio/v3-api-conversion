/**
 * Efflux v3 API TypeScript type definitions.
 *
 * Key changes from v2:
 * - All single-resource responses are wrapped in DocumentResponse<T>
 * - All list responses are wrapped in PagedResponse<T>
 * - Errors are RFC 7807 Problem Details (not { error: string })
 * - `fingerprint` is boolean (was integer 0/1/2)
 * - `checks_opts` renamed to `checks_options` and simplified to 3 fields
 * - Callback is nested {start, success, fail} (was flat fields)
 * - JobReport uses scan_results/domain_results/url_results (renamed from v2 fields)
 * - url_results is a Record<url, UrlResult> (was HTTPResult[] in v2)
 * - check_results is a new top-level array in JobReport
 */

// ---------------------------------------------------------------------------
// API Envelope Types
// ---------------------------------------------------------------------------

export interface DocumentResponse<T> {
  data: T;
  links: Record<string, string>;
}

export interface PagedResponse<T> {
  data: T[];
  pagination: Pagination;
}

export interface Pagination {
  limit: number;
  page: number;
  total: number;
  total_pages: number;
  has_next: boolean;
  has_prev: boolean;
  next_cursor?: string;
  prev_cursor?: string;
}

/** RFC 7807 Problem Details error response (replaces v2's { error: string }). */
export interface ApiProblem {
  type?: string;
  title?: string;
  status: number;
  detail: string;
  instance?: string;
  errors?: Array<{ field: string; message: string }>;
  rate_limit?: RateLimit;
}

export interface RateLimit {
  limit: number;
  remaining: number;
  reset_at: string;
  retry_after_seconds: number;
}

// ---------------------------------------------------------------------------
// Callback Types
// ---------------------------------------------------------------------------

/** Request body callback — used when creating scans/schedules/surveys/captures. */
export interface CallbackRequest {
  start?: { url: string; method?: string };
  success?: { url: string; method?: string };
  fail?: { url: string; method?: string };
}

/** Single webhook delivery attempt record. */
export interface CallbackAttempt {
  time: string;
  code: number;
  raw: string;
  error: string;
}

/** Status of a single callback event, including delivery history. */
export interface CallbackEventStatus {
  url: string;
  method: string;
  attempts: CallbackAttempt[];
  complete: boolean;
}

/**
 * Callback state as returned in Job/RequestResults responses.
 * Includes delivery attempt history for each event.
 *
 * v2 had flat fields (start_url, success_url, etc.).
 * v3 uses nested event objects.
 */
export interface Callback {
  start?: CallbackEventStatus;
  success?: CallbackEventStatus;
  fail?: CallbackEventStatus;
}

// ---------------------------------------------------------------------------
// Checks Options
// ---------------------------------------------------------------------------

/**
 * Options controlling which vulnerability checks run.
 *
 * v2 field name: checks_opts
 * v3 field name: checks_options
 *
 * Removed fields (no longer available in v3):
 *   include_ids, exclude_ids, limit_to_ids, exclude_targets, limit_to_targets
 */
export interface ChecksOptions {
  cves_only?: boolean;
  min_severity?: "info" | "low" | "medium" | "high" | "critical" | string;
  max_severity?: "info" | "low" | "medium" | "high" | "critical" | string;
}

// ---------------------------------------------------------------------------
// Scan Request
// ---------------------------------------------------------------------------

/**
 * Request body for POST /v3/scans and POST /v3/scans/eval.
 *
 * Breaking changes from v2:
 * - fingerprint: boolean (was integer 0/1/2)
 * - checks_options replaces checks_opts (renamed + simplified)
 * - callback: nested {start, success, fail} (was flat fields)
 * - tags and description are new
 *
 * Mutual exclusion: cves cannot be combined with urls or paths.
 */
export interface ScanRequest {
  /** IPs, CIDRs, or host list names. e.g. ["1.2.3.4", "10.0.0.0/24", "my_servers"] */
  hosts?: string[];
  /** Ports, ranges, top_N, or port list names. e.g. ["80", "443", "8080-8090", "top_100"] */
  ports?: string[];
  /** Domain names. Max 20 per job. */
  domains?: string[];
  /** URL paths to probe. Max 5. Mutually exclusive with cves. */
  paths?: string[];
  /** Use HTTPS for path probing. */
  paths_https?: boolean;
  /** Full or partial URLs. Max 20. Mutually exclusive with cves. */
  urls?: string[];
  /** CVE IDs to check. Max 5. Mutually exclusive with urls and paths. */
  cves?: string[];
  /** Protocol: "tcp" (default) or "udp". */
  proto?: "tcp" | "udp";
  /**
   * Enable service fingerprinting.
   * v2: integer (0=none, 1=banners, 2=probes)
   * v3: boolean (true=enabled)
   */
  fingerprint?: boolean;
  /** Enable vulnerability checks system. */
  checks?: boolean;
  /**
   * Checks filtering options.
   * v2 field name: checks_opts
   * v3 field name: checks_options (simplified — no include/exclude IDs)
   */
  checks_options?: ChecksOptions;
  /** Protocol-specific data collectors. Map of collector name to port list. */
  collect?: Record<string, string[]>;
  /**
   * Webhook callbacks on job lifecycle events.
   * v2: flat { start_url, start_method, success_url, ... }
   * v3: nested { start: {url, method}, success: {url, method}, fail: {url, method} }
   */
  callback?: CallbackRequest;
  /** Optional labels. Max 10 tags, 40 chars each. New in v3. */
  tags?: string[];
  /** Optional description. Max 300 chars. New in v3. */
  description?: string;
}

// ---------------------------------------------------------------------------
// Request Results (response from create/eval/repeat)
// ---------------------------------------------------------------------------

/**
 * Response from POST /v3/scans, POST /v3/scans/eval, POST /v3/scans/{id}/repeat.
 * Wrapped in DocumentResponse — access via response.data.
 *
 * Changes from v2:
 * - fingerprint is now boolean
 * - checks_options replaces checks_opts
 * - callback is nested format with delivery history
 * - tags, description, errors are new fields
 */
export interface RequestResults {
  job_id: string;
  proto: string;
  hosts: string[];
  host_lists: string[];
  ports: string[];
  port_lists: string[];
  domains: string[];
  paths: string[];
  urls: string[];
  cves: string[];
  plan_id?: string;
  fingerprint: boolean;
  checks: boolean;
  checks_options?: ChecksOptions;
  rejected_hosts: string[];
  rejected_ports: string[];
  rejected_domains: string[];
  rejected_urls: string[];
  rejected_paths: string[];
  rejected_cves: string[];
  host_count: number;
  port_count: number;
  domain_count: number;
  url_count: number;
  cve_count: number;
  request_count: number;
  callback?: Callback;
  tags: string[];
  description: string;
  created_at: string;
  status: string;
  /** Non-fatal issues encountered during job creation. New in v3. */
  errors: string[];
}

// ---------------------------------------------------------------------------
// Job (list / get)
// ---------------------------------------------------------------------------

/**
 * Scan job as returned by GET /v3/scans and GET /v3/scans/{job_id}.
 *
 * IMPORTANT: In v3, GET /v3/scans/{job_id} returns ONLY this metadata.
 * To get scan results: GET /v3/scans/{job_id}/results → JobReport
 * To get a summary:   GET /v3/scans/{job_id}/summary → JobSummary
 *
 * New fields in v3: user_id, token_id, region, attributable, tags, description,
 *                   accessible_domain_count, checks_options
 */
export interface Job {
  job_id: string;
  user_id: string;
  token_id: string;
  proto: string;
  hosts: string[];
  host_lists: string[];
  ports: string[];
  port_lists: string[];
  domains: string[];
  urls: string[];
  cves: string[];
  fingerprint: boolean;
  checks: boolean;
  checks_options?: ChecksOptions;
  collect: Record<string, string[]>;
  host_count: number;
  port_count: number;
  domain_count: number;
  url_count: number;
  cve_count: number;
  request_count: number;
  region: string;
  attributable: boolean;
  schedule_id: string;
  created_at: string;
  started_at: string;
  canceled_at: string;
  completed_at: string;
  accessible_host_count: number;
  accessible_port_count: number;
  /** New in v3 (v2 had accessible_host_count and accessible_port_count only). */
  accessible_domain_count: number;
  accessible_url_count: number;
  total_connections: number;
  checks_run: number;
  checks_matched: number;
  callback?: Callback;
  tags: string[];
  description: string;
  /** "pending" | "running" | "complete" | "failed" | "canceled" */
  status: string;
}

// ---------------------------------------------------------------------------
// Result Types
// ---------------------------------------------------------------------------

export interface Redirect {
  status_code: number;
  location: string;
}

export interface Header {
  name: string;
  values: string[];
}

export interface Cookie {
  name: string;
  value: string;
  domain: string;
  path: string;
  secure: boolean;
  http_only: boolean;
  same_site: string;
  expires: string;
}

/** Wappalyzer-style application detection. */
export interface Detection {
  name: string;
  matches: string;
  version: string;
  url: string;
}

export interface TLSResult {
  selected_protocol: string;
  selected_cipher: string;
  protocols: string[];
  mutual_tls: boolean;
  jarm: string;
  compression: boolean;
  session_id_resumption: boolean;
  session_ticket_resumption: boolean;
  secure_renegotiation: boolean;
  session_renegotiation: boolean;
  tls_fallback: boolean;
  tls_early_data: boolean;
  certificate?: Record<string, unknown>;
}

export interface Certificate {
  fingerprint_md5: string;
  fingerprint_sha1: string;
  fingerprint_sha256: string;
  version: string;
  serial_number: string;
  not_before: string;
  not_after: string;
  issuer_common_name: string;
  issuer_organization: string;
  issuer_country: string;
  subject_common_name: string;
  subject_organization: string;
  subject_country: string;
}

/**
 * HTTP/HTTPS result for a URL or port.
 * Replaces HTTPResult from v2.
 * In JobReport, url_results is Record<url, UrlResult> (v2 url_info was HTTPResult[]).
 */
export interface UrlResult {
  requested_url: string;
  remote_host: string;
  remote_port: string;
  supports_http2: boolean;
  supports_http3: boolean;
  secure_redirect: boolean;
  status_code: number;
  redirect_chain: Redirect[];
  security_headers: Header[];
  other_headers: Header[];
  script_urls: string[];
  cookies: Cookie[];
  detections: Detection[];
  tls?: TLSResult;
}

/**
 * Per-port scan result. Replaces v2's PortStatus.
 * Accessed via: jobReport.scan_results[host].ports[portStr]
 */
export interface ScanResult {
  host: string;
  port: string;
  proto: string;
  checked_at: string;
  open: boolean;
  service: string;
  software: string;
  version: string;
  info: string;
  host_name: string;
  os: string;
  device_type: string;
  cpe: string;
  tls: boolean;
  http: boolean;
  http_info?: UrlResult;
  certificates?: Record<string, unknown>;
  detections: Detection[];
  /** Protocol-specific collected data (SSH, SMB, RDP, MongoDB, Redis, etc.) */
  collection: Record<string, unknown>;
  bytes_rcvd: number;
  /** Raw response data — only populated when ?details=true */
  raw: string[];
}

export interface HostMetadata {
  asn: string;
  as_org: string;
  country: string;
  provider: string;
  tor: boolean;
  info: string;
}

/**
 * Per-host result container.
 * v2: JobReport.results[host] — same structure
 * v3: JobReport.scan_results[host] — field renamed
 */
export interface HostStatus {
  metadata?: HostMetadata;
  /** Map of port number string to scan result. */
  ports: Record<string, ScanResult>;
}

/**
 * DNS information for a domain.
 * v2 had DomainStatus with {whois, dns, http, tls}.
 * v3 DomainInfo has DNS records directly, with more record types.
 */
export interface DomainInfo {
  a: string[];
  aaaa: string[];
  cname: string[];
  mx: string[];
  ns: string[];
  txt: string[];
  soa: string[];
  caa: string[];
  dmarc: string[];
  spf: string[];
  resolver: string;
}

/**
 * Vulnerability check match result.
 *
 * New fields in v3 (context for where the check matched):
 *   type, host, port, scheme, url, path, ip, check_id, event_id
 */
export interface CheckResult {
  // Context fields — new in v3
  type: string;
  host: string;
  port: string;
  scheme: string;
  url: string;
  path: string;
  ip: string;
  check_id: string;
  event_id: string;
  // Core fields — same as v2
  matched: string;
  check_name: string;
  description: string;
  references: string[];
  check_type: string;
  severity: string;
  extract_name: string;
  extractions: string[];
  cve_id: string[];
  cwe_id: string[];
  cvss_metrics: string;
  cvss_score: number;
  epss_score: number;
  cpe: string;
  interaction_request: string;
  interaction_addr: string;
  interaction_proto: string;
  interaction_timestamp: string;
}

// ---------------------------------------------------------------------------
// JobReport
// ---------------------------------------------------------------------------

/**
 * Full scan results from GET /v3/scans/{job_id}/results.
 *
 * NOTE: This endpoint returns JobReport directly (NOT wrapped in DocumentResponse).
 *
 * v2 → v3 field renames:
 *   results      → scan_results   (Record<host_ip, HostStatus>)
 *   domain_info  → domain_results (Record<domain, DomainInfo>)
 *   url_info     → url_results    (was HTTPResult[], now Record<url, UrlResult>)
 *
 * New in v3:
 *   check_results — top-level array of all check matches, with full context
 */
export interface JobReport {
  job_id: string;
  user_id: string;
  schedule_id: string;
  proto: string;
  hosts: string[];
  host_lists: string[];
  ports: string[];
  port_lists: string[];
  domains: string[];
  urls: string[];
  cves: string[];
  host_count: number;
  port_count: number;
  domain_count: number;
  url_count: number;
  cve_count: number;
  request_count: number;
  fingerprint: boolean;
  checks: boolean;
  tags: string[];
  description: string;
  created_at: string;
  started_at: string;
  completed_at: string;
  accessible_host_count: number;
  accessible_port_count: number;
  accessible_domain_count: number;
  accessible_url_count: number;
  total_connections: number;
  checks_run: number;
  checks_matched: number;
  status: string;
  /**
   * Map of host IP → HostStatus (with per-port results).
   * v2 field name: results
   */
  scan_results: Record<string, HostStatus>;
  /**
   * Map of domain → DomainInfo (DNS records).
   * v2 field name: domain_info
   */
  domain_results: Record<string, DomainInfo>;
  /**
   * Map of URL string → UrlResult (HTTP details).
   * v2 field name: url_info — was an array! Now a map.
   */
  url_results: Record<string, UrlResult>;
  /**
   * Top-level array of all vulnerability check matches across all hosts.
   * New in v3. Includes context fields (host, port, scheme, check_id, event_id).
   * In v2, checks were nested inside each PortStatus.
   */
  check_results: CheckResult[];
}

// ---------------------------------------------------------------------------
// JobSummary (new in v3)
// ---------------------------------------------------------------------------

/**
 * Aggregated statistics from GET /v3/scans/{job_id}/summary.
 * New in v3. Use instead of JobReport when you only need statistics.
 */
export interface JobSummary {
  job_id: string;
  user_id: string;
  created_at: string;
  started_at: string;
  completed_at: string;
  accessible_host_count: number;
  accessible_port_count: number;
  accessible_domain_count: number;
  accessible_url_count: number;
  checks_matched: number;
  /** Distinct open port numbers across all hosts. */
  ports: string[];
  /** Distinct detected service names. */
  services: string[];
  /** Distinct software/version strings. */
  software: string[];
  /** Certificate SHA256 fingerprints. */
  certs: string[];
  /** Public key fingerprints. */
  keys: string[];
  /** ASN strings. */
  asns: string[];
  /** Host count per country code. */
  hosts_per_country: Record<string, number>;
}

// ---------------------------------------------------------------------------
// WebSocket Event Types (streams)
// ---------------------------------------------------------------------------

/** Received when a WebSocket connection is established. */
export interface WSConnectedMessage {
  type: "connected";
  job_id: string;
  scope: "job" | "all";
  protocol: string;
}

/** Received for each scan/dns/url/check event during a live job stream. */
export interface WSScanEventMessage {
  type: "scan" | "dns" | "url" | "check";
  job_id: string;
  data: ScanResult | DomainInfo | UrlResult | CheckResult;
  pipeline?: string;
  region?: string;
}

/** Received on the status stream when a job's status changes. */
export interface WSStatusChangeMessage {
  type: "job" | "capture" | "task" | "survey" | "permutation";
  id: string;
  status: string;
  time: string;
  user_id: string;
}

export type WSMessage = WSConnectedMessage | WSScanEventMessage | WSStatusChangeMessage;

// ---------------------------------------------------------------------------
// Other Resource Types
// ---------------------------------------------------------------------------

export interface Schedule {
  schedule_id: string;
  user_id: string;
  name: string;
  description: string;
  disabled: boolean;
  task_types: string[];
  frequency: string;
  minute: number;
  hour: number;
  day_of_week: number;
  day_of_month: number;
  last_run_at: string;
  next_run_at: string;
  run_until: string;
  scan?: ScanRequest;
  created_at: string;
  updated_at: string;
}

export interface NewSchedule {
  name: string;
  description?: string;
  disabled?: boolean;
  frequency: string;
  minute?: number;
  hour?: number;
  day_of_week?: number;
  day_of_month?: number;
  run_until?: string;
  scan?: ScanRequest;
}

export interface ScheduleRun {
  event_id: string;
  run_at: string;
  schedule_id: string;
  user_id: string;
  tenant_id: string;
  job_id: string;
  job_error: string;
  survey_id: string;
  survey_error: string;
  capture_id: string;
  capture_error: string;
  permutation_check_id: string;
  permutation_check_error: string;
}

export interface HostList {
  list_id: string;
  name: string;
  hosts: string[];
  host_count: number;
  user_id: string;
  created_at: string;
  updated_at: string;
}

export interface PortList {
  list_id: string;
  name: string;
  ports: string[];
  port_count: number;
  user_id: string;
  created_at: string;
  updated_at: string;
}

export interface JobSummaryLimits {
  scan_limits: {
    max_pending_jobs: number;
    max_concurrent_jobs: number;
    max_concurrent_requests: number;
    max_jobs_per_minute: number;
    max_requests_per_job: number;
    max_requests_per_month: number;
    max_requests_per_month_soft_cap: boolean;
  };
  regions: string[];
  plan: string;
  permissions: string[];
}
