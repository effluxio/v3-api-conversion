/**
 * Helpers for v2 → v3 result-shape changes.
 */

import type { CheckResult, Header, JobReport, UrlResult } from "./types.js";

/**
 * Header names treated as "security headers" by splitHeaders().
 * v2 split headers into security_headers / other_headers server-side; v3
 * returns one `headers` list. v2's exact list was never published, so pass
 * your own set if you depended on a specific classification.
 */
export const SECURITY_HEADERS: ReadonlySet<string> = new Set([
  "strict-transport-security",
  "content-security-policy",
  "content-security-policy-report-only",
  "x-frame-options",
  "x-content-type-options",
  "referrer-policy",
  "permissions-policy",
  "cross-origin-opener-policy",
  "cross-origin-embedder-policy",
  "cross-origin-resource-policy",
  "x-xss-protection",
]);

/** Rebuild v2's split: returns [securityHeaders, otherHeaders]. */
export function splitHeaders(
  result: UrlResult,
  securityNames: ReadonlySet<string> = SECURITY_HEADERS,
): [Header[], Header[]] {
  const security: Header[] = [];
  const other: Header[] = [];
  for (const h of result.headers ?? []) {
    (securityNames.has(h.name.toLowerCase()) ? security : other).push(h);
  }
  return [security, other];
}

/** Values of a response header (case-insensitive); [] if absent. */
export function getHeader(result: UrlResult, name: string): string[] {
  const wanted = name.toLowerCase();
  return result.headers?.find((h) => h.name.toLowerCase() === wanted)?.values ?? [];
}

/** Key used by checksByPort(): `${host}:${port}` (port is "" when the check has none). */
export function portKey(host: string, port: string | undefined): string {
  return `${host}:${port ?? ""}`;
}

/**
 * Group check results by host and port, like v2's PortStatus.checks.
 *
 * v3 no longer attaches checks to ports. This collects from every
 * HostStatus.checks and from JobReport.check_results, de-duplicating by
 * event_id. Look up with portKey(host, port).
 */
export function checksByPort(report: JobReport): Map<string, CheckResult[]> {
  const grouped = new Map<string, CheckResult[]>();
  const seen = new Set<unknown>();

  const add = (c: CheckResult, fallbackHost: string) => {
    const id = c.event_id || c;
    if (seen.has(id)) return;
    seen.add(id);
    const key = portKey(c.host || c.ip || fallbackHost, c.port);
    const list = grouped.get(key);
    if (list) list.push(c);
    else grouped.set(key, [c]);
  };

  for (const [host, hs] of Object.entries(report.scan_results ?? {})) {
    for (const c of hs.checks ?? []) add(c, host);
  }
  for (const c of report.check_results ?? []) add(c, "");
  return grouped;
}
