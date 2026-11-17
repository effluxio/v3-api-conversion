"""
Efflux v3 API data models.

All models are plain dataclasses with Optional fields for anything that may be absent.
Use from_dict() class methods to deserialize API responses.

Key differences from v2 model structure:
- Single resources arrive wrapped in DocumentResponse; access .data
- Lists arrive wrapped in PagedResponse; access .data and .pagination
- JobReport.scan_results replaces JobReport.results
- JobReport.domain_results replaces JobReport.domain_info
- JobReport.url_results replaces JobReport.url_info (was array, now dict)
- JobReport.check_results is a new top-level list of findings across all hosts
- ScanResult replaces PortStatus (checks moved off the port; certificate -> certificates;
  *_collection fields -> one collection dict; app_detections -> detections)
- UrlResult replaces HTTPResult (requested_url -> url; security_headers + other_headers -> headers)
- fingerprint is bool (not int)
- Callback is nested {start, success, fail} (not flat)
- Job status values: pending, in progress, complete, canceled, rejected

Field lists match the v3 server models (empire-models v1.20261022.1).
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Pagination & Envelope Types
# ---------------------------------------------------------------------------

@dataclass
class Pagination:
    limit: int = 20
    page: int = 1
    total: int = 0
    total_pages: int = 0
    has_next: bool = False
    has_prev: bool = False
    next_cursor: Optional[str] = None
    prev_cursor: Optional[str] = None

    @classmethod
    def from_dict(cls, d: dict) -> "Pagination":
        return cls(
            limit=d.get("limit", 20),
            page=d.get("page", 1),
            total=d.get("total", 0),
            total_pages=d.get("total_pages", 0),
            has_next=d.get("has_next", False),
            has_prev=d.get("has_prev", False),
            next_cursor=d.get("next_cursor"),
            prev_cursor=d.get("prev_cursor"),
        )


@dataclass
class PagedResponse:
    """
    Wraps paginated list responses from the v3 API.

    Usage:
        response = client.list_jobs(page=2, limit=50)
        for job in response.data:
            print(job.job_id)
        if response.pagination.has_next:
            next_page = client.list_jobs(page=3, limit=50)
    """
    data: List[Any] = field(default_factory=list)
    pagination: Pagination = field(default_factory=Pagination)


@dataclass
class DocumentResponse:
    """
    Wraps single-resource responses from the v3 API.

    Usage:
        response = client.create_scan(request)
        job_id = response.data.job_id
    """
    data: Any = None
    links: Dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Callback Types
# ---------------------------------------------------------------------------

@dataclass
class CallbackEvent:
    """
    A single callback event target (start, success, or fail).

    Set either url (+ optional method) or callback_id (a saved webhook from
    POST /v3/webhooks), not both. "$job_id" in url is replaced with the job ID.
    """
    url: str = ""
    method: str = "POST"
    callback_id: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "CallbackEvent":
        return cls(
            url=d.get("url", ""),
            method=d.get("method", "POST"),
            callback_id=d.get("callback_id", ""),
        )

    def to_dict(self) -> dict:
        if self.callback_id:
            return {"callback_id": self.callback_id}
        result = {"url": self.url}
        if self.method:
            result["method"] = self.method
        return result


@dataclass
class CallbackRequest:
    """
    Callback configuration for scan requests.

    v2 used flat fields (start_url, start_method, success_url, ...).
    v3 uses nested event objects.

    v2 → v3 mapping:
        start_url / start_method   → start.url / start.method
        success_url / success_method → success.url / success.method
        fail_url / fail_method     → fail.url / fail.method
        email / summary_only       → REMOVED (no equivalent in v3)

    WARNING: the v3 server ignores unknown fields, so a v2-style flat callback
    sent to v3 is silently dropped and no callback fires.

    use_defaults: None follows your saved preferences (GET/PUT /v3/preferences);
    False skips them for this job.
    """
    start: Optional[CallbackEvent] = None
    success: Optional[CallbackEvent] = None
    fail: Optional[CallbackEvent] = None
    use_defaults: Optional[bool] = None

    @classmethod
    def from_dict(cls, d: dict) -> "CallbackRequest":
        return cls(
            start=CallbackEvent.from_dict(d["start"]) if d.get("start") else None,
            success=CallbackEvent.from_dict(d["success"]) if d.get("success") else None,
            fail=CallbackEvent.from_dict(d["fail"]) if d.get("fail") else None,
            use_defaults=d.get("use_defaults"),
        )

    def to_dict(self) -> dict:
        result: dict = {}
        if self.start:
            result["start"] = self.start.to_dict()
        if self.success:
            result["success"] = self.success.to_dict()
        if self.fail:
            result["fail"] = self.fail.to_dict()
        if self.use_defaults is not None:
            result["use_defaults"] = self.use_defaults
        return result


@dataclass
class CallbackAttempt:
    """Records a single webhook delivery attempt."""
    time: str = ""
    code: int = 0
    raw: str = ""
    error: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "CallbackAttempt":
        return cls(
            time=d.get("time", ""),
            code=d.get("code", 0),
            raw=d.get("raw", ""),
            error=d.get("error", ""),
        )


@dataclass
class CallbackStatus:
    """
    Status of a single callback event including delivery history.

    source is "request" when the phase came from the scan request and
    "preference" when it was filled from your saved callback preferences.
    """
    url: str = ""
    method: str = "POST"
    callback_id: str = ""
    delivery_id: str = ""
    attempts: List[CallbackAttempt] = field(default_factory=list)
    complete: bool = False
    source: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "CallbackStatus":
        return cls(
            url=d.get("url", ""),
            method=d.get("method", "POST"),
            callback_id=d.get("callback_id", ""),
            delivery_id=d.get("delivery_id", ""),
            attempts=[CallbackAttempt.from_dict(a) for a in d.get("attempts", [])],
            complete=d.get("complete", False),
            source=d.get("source", ""),
        )


@dataclass
class Callback:
    """
    Callback state as returned in Job and RequestResults responses.
    Includes delivery attempt history for each event.
    """
    start: Optional[CallbackStatus] = None
    success: Optional[CallbackStatus] = None
    fail: Optional[CallbackStatus] = None

    @classmethod
    def from_dict(cls, d: dict) -> "Callback":
        if not d:
            return cls()
        return cls(
            start=CallbackStatus.from_dict(d["start"]) if d.get("start") else None,
            success=CallbackStatus.from_dict(d["success"]) if d.get("success") else None,
            fail=CallbackStatus.from_dict(d["fail"]) if d.get("fail") else None,
        )


# ---------------------------------------------------------------------------
# Checks Options
# ---------------------------------------------------------------------------

@dataclass
class ChecksOptions:
    """
    Options controlling which vulnerability checks run on a scan.

    v2 field name: checks_opts (with 8 options)
    v3 field name: checks_options (with 3 options)

    Removed from v3: include_ids, exclude_ids, limit_to_ids,
                     exclude_targets, limit_to_targets

    min_severity / max_severity must be one of: info, low, medium, high, critical,
    and min_severity must not be above max_severity.

    WARNING: the v3 server ignores unknown fields, so a leftover "checks_opts"
    key is silently dropped and checks run unfiltered.
    """
    cves_only: bool = False
    min_severity: Optional[str] = None
    max_severity: Optional[str] = None

    @classmethod
    def from_dict(cls, d: dict) -> "ChecksOptions":
        return cls(
            cves_only=d.get("cves_only", False),
            min_severity=d.get("min_severity"),
            max_severity=d.get("max_severity"),
        )

    def to_dict(self) -> dict:
        result: dict = {}
        if self.cves_only:
            result["cves_only"] = True
        if self.min_severity:
            result["min_severity"] = self.min_severity
        if self.max_severity:
            result["max_severity"] = self.max_severity
        return result


# ---------------------------------------------------------------------------
# Scan Request
# ---------------------------------------------------------------------------

@dataclass
class ScanRequest:
    """
    Request body for POST /v3/scans and POST /v3/scans/eval.

    Key differences from v2 Request:
    - fingerprint is bool (v2: int 0/1/2)
    - checks_options replaces checks_opts; simplified to 3 fields
    - callback uses nested {start, success, fail} objects (v2: flat fields)
    - tags and description are new
    """
    hosts: List[str] = field(default_factory=list)
    ports: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    paths: List[str] = field(default_factory=list)
    paths_https: bool = False
    urls: List[str] = field(default_factory=list)
    cves: List[str] = field(default_factory=list)
    proto: str = "tcp"
    fingerprint: bool = False
    checks: bool = False
    checks_options: Optional[ChecksOptions] = None
    collect: Dict[str, List[str]] = field(default_factory=dict)
    callback: Optional[CallbackRequest] = None
    tags: List[str] = field(default_factory=list)
    description: str = ""

    def to_dict(self) -> dict:
        d: dict = {}
        if self.hosts:
            d["hosts"] = self.hosts
        if self.ports:
            d["ports"] = self.ports
        if self.domains:
            d["domains"] = self.domains
        if self.paths:
            d["paths"] = self.paths
        if self.paths_https:
            d["paths_https"] = True
        if self.urls:
            d["urls"] = self.urls
        if self.cves:
            d["cves"] = self.cves
        if self.proto != "tcp":
            d["proto"] = self.proto
        if self.fingerprint:
            d["fingerprint"] = True
        if self.checks:
            d["checks"] = True
        if self.checks_options:
            d["checks_options"] = self.checks_options.to_dict()
        if self.collect:
            d["collect"] = self.collect
        if self.callback:
            d["callback"] = self.callback.to_dict()
        if self.tags:
            d["tags"] = self.tags
        if self.description:
            d["description"] = self.description
        return d


# ---------------------------------------------------------------------------
# Request Results (response from create/eval/repeat)
# ---------------------------------------------------------------------------

@dataclass
class RequestResults:
    """
    Response from POST /v3/scans, POST /v3/scans/eval, POST /v3/scans/{id}/repeat.
    Returned inside a DocumentResponse wrapper: response.data

    fingerprint is now bool (was int in v2).
    checks_options replaces checks_opts.
    callback reflects the nested v3 format with delivery attempt history.
    tags and description are new.
    errors is new — lists any non-fatal issues during job creation.
    """
    job_id: str = ""
    proto: str = "tcp"
    hosts: List[str] = field(default_factory=list)
    host_lists: List[str] = field(default_factory=list)
    ports: List[str] = field(default_factory=list)
    port_lists: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    paths: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    cves: List[str] = field(default_factory=list)
    plan_id: Optional[str] = None
    fingerprint: bool = False
    checks: bool = False
    checks_options: Optional[ChecksOptions] = None
    rejected_hosts: List[str] = field(default_factory=list)
    rejected_ports: List[str] = field(default_factory=list)
    rejected_domains: List[str] = field(default_factory=list)
    rejected_urls: List[str] = field(default_factory=list)
    rejected_paths: List[str] = field(default_factory=list)
    rejected_cves: List[str] = field(default_factory=list)
    host_count: int = 0
    port_count: int = 0
    domain_count: int = 0
    url_count: int = 0
    cve_count: int = 0
    request_count: int = 0
    callback: Optional[Callback] = None
    tags: List[str] = field(default_factory=list)
    description: str = ""
    created_at: str = ""
    status: str = ""
    errors: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict) -> "RequestResults":
        return cls(
            job_id=d.get("job_id", ""),
            proto=d.get("proto", "tcp"),
            hosts=d.get("hosts", []),
            host_lists=d.get("host_lists", []),
            ports=d.get("ports", []),
            port_lists=d.get("port_lists", []),
            domains=d.get("domains", []),
            paths=d.get("paths", []),
            urls=d.get("urls", []),
            cves=d.get("cves", []),
            plan_id=d.get("plan_id"),
            fingerprint=d.get("fingerprint", False),
            checks=d.get("checks", False),
            checks_options=ChecksOptions.from_dict(d["checks_options"]) if d.get("checks_options") else None,
            rejected_hosts=d.get("rejected_hosts", []),
            rejected_ports=d.get("rejected_ports", []),
            rejected_domains=d.get("rejected_domains", []),
            rejected_urls=d.get("rejected_urls", []),
            rejected_paths=d.get("rejected_paths", []),
            rejected_cves=d.get("rejected_cves", []),
            host_count=d.get("host_count", 0),
            port_count=d.get("port_count", 0),
            domain_count=d.get("domain_count", 0),
            url_count=d.get("url_count", 0),
            cve_count=d.get("cve_count", 0),
            request_count=d.get("request_count", 0),
            callback=Callback.from_dict(d["callback"]) if d.get("callback") else None,
            tags=d.get("tags", []),
            description=d.get("description", ""),
            created_at=d.get("created_at", ""),
            status=d.get("status", ""),
            errors=d.get("errors", []),
        )


# ---------------------------------------------------------------------------
# Job (list / get)
# ---------------------------------------------------------------------------

# Job status values sent by the v3 server. Note the space in "in progress".
JOB_STATUS_PENDING = "pending"
JOB_STATUS_IN_PROGRESS = "in progress"
JOB_STATUS_COMPLETE = "complete"
JOB_STATUS_CANCELED = "canceled"
JOB_STATUS_REJECTED = "rejected"
JOB_STATUS_ACCEPTABLE = "acceptable"  # only from POST /v3/scans/eval

@dataclass
class Job:
    """
    A scan job as returned by GET /v3/scans and GET /v3/scans/{job_id}.

    v3 GET /scans/{job_id} returns ONLY metadata and status.
    To get scan results, call GET /v3/scans/{job_id}/results (returns JobReport).
    To get a summary, call GET /v3/scans/{job_id}/summary (returns JobSummary).

    New fields in v3: user_id, token_id, region, attributable, tags, description,
                      accessible_domain_count, errors, checks_options
    """
    job_id: str = ""
    user_id: str = ""
    token_id: str = ""
    proto: str = "tcp"
    hosts: List[str] = field(default_factory=list)
    host_lists: List[str] = field(default_factory=list)
    ports: List[str] = field(default_factory=list)
    port_lists: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    cves: List[str] = field(default_factory=list)
    fingerprint: bool = False
    checks: bool = False
    checks_options: Optional[ChecksOptions] = None
    collect: Dict[str, List[str]] = field(default_factory=dict)
    host_count: int = 0
    port_count: int = 0
    domain_count: int = 0
    url_count: int = 0
    cve_count: int = 0
    request_count: int = 0
    region: str = ""
    attributable: bool = False
    schedule_id: str = ""
    created_at: str = ""
    started_at: str = ""
    canceled_at: str = ""
    completed_at: str = ""
    accessible_host_count: int = 0
    accessible_port_count: int = 0
    accessible_domain_count: int = 0
    accessible_url_count: int = 0
    total_connections: int = 0
    checks_run: int = 0
    checks_matched: int = 0
    callback: Optional[Callback] = None
    tags: List[str] = field(default_factory=list)
    description: str = ""
    status: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "Job":
        return cls(
            job_id=d.get("job_id", ""),
            user_id=d.get("user_id", ""),
            token_id=d.get("token_id", ""),
            proto=d.get("proto", "tcp"),
            hosts=d.get("hosts", []),
            host_lists=d.get("host_lists", []),
            ports=d.get("ports", []),
            port_lists=d.get("port_lists", []),
            domains=d.get("domains", []),
            urls=d.get("urls", []),
            cves=d.get("cves", []),
            fingerprint=d.get("fingerprint", False),
            checks=d.get("checks", False),
            checks_options=ChecksOptions.from_dict(d["checks_options"]) if d.get("checks_options") else None,
            collect=d.get("collect", {}),
            host_count=d.get("host_count", 0),
            port_count=d.get("port_count", 0),
            domain_count=d.get("domain_count", 0),
            url_count=d.get("url_count", 0),
            cve_count=d.get("cve_count", 0),
            request_count=d.get("request_count", 0),
            region=d.get("region", ""),
            attributable=d.get("attributable", False),
            schedule_id=d.get("schedule_id", ""),
            created_at=d.get("created_at", ""),
            started_at=d.get("started_at", ""),
            canceled_at=d.get("canceled_at", ""),
            completed_at=d.get("completed_at", ""),
            accessible_host_count=d.get("accessible_host_count", 0),
            accessible_port_count=d.get("accessible_port_count", 0),
            accessible_domain_count=d.get("accessible_domain_count", 0),
            accessible_url_count=d.get("accessible_url_count", 0),
            total_connections=d.get("total_connections", 0),
            checks_run=d.get("checks_run", 0),
            checks_matched=d.get("checks_matched", 0),
            callback=Callback.from_dict(d["callback"]) if d.get("callback") else None,
            tags=d.get("tags", []),
            description=d.get("description", ""),
            status=d.get("status", ""),
        )

    @property
    def is_complete(self) -> bool:
        return self.status == JOB_STATUS_COMPLETE

    @property
    def is_running(self) -> bool:
        """True while the job is queued or running ("pending" / "in progress")."""
        return self.status in (JOB_STATUS_PENDING, JOB_STATUS_IN_PROGRESS)

    @property
    def is_failed(self) -> bool:
        """True if the job ended without results ("canceled" or "rejected")."""
        return self.status in (JOB_STATUS_CANCELED, JOB_STATUS_REJECTED)


# ---------------------------------------------------------------------------
# Scan Result Types
#
# Zero values (False, "", 0, empty lists) are omitted from v3 JSON, so every
# from_dict() below supplies a default.
# ---------------------------------------------------------------------------

@dataclass
class Header:
    name: str = ""
    values: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict) -> "Header":
        return cls(name=d.get("name", ""), values=d.get("values") or [])


@dataclass
class Certificate:
    """
    One X.509 certificate (v3 models.Certificate).

    v2 TLSCertificate → v3 Certificate:
        fingerprint_md5/sha1/sha256, serial_number → unchanged
        not_before / not_after                     → now integers (were strings)
        issuer_* (9 fields)                        → issuer (one string)
        subject_* (9 fields)                       → subject (one string)
        version                                    → removed
    """
    serial_number: str = ""
    issuer: str = ""
    subject: str = ""
    not_before: int = 0
    not_after: int = 0
    key_usage: List[str] = field(default_factory=list)
    ext_key_usage: List[str] = field(default_factory=list)
    signature_algorithm: str = ""
    signature_valid: bool = False
    self_signed: bool = False
    is_ca: bool = False
    is_ev: bool = False
    is_precert: bool = False
    public_key: str = ""
    public_key_algorithm: str = ""
    ocsp_servers: List[str] = field(default_factory=list)
    ocsp_response: str = ""
    fingerprint_md5: str = ""
    fingerprint_sha1: str = ""
    fingerprint_sha256: str = ""
    fingerprint_spki: str = ""
    fingerprint_spki_subject: str = ""
    fingerprint_tbs_certificate: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "Certificate":
        return cls(
            serial_number=d.get("serial_number", ""),
            issuer=d.get("issuer", ""),
            subject=d.get("subject", ""),
            not_before=d.get("not_before", 0),
            not_after=d.get("not_after", 0),
            key_usage=d.get("key_usage") or [],
            ext_key_usage=d.get("ext_key_usage") or [],
            signature_algorithm=d.get("signature_algorithm", ""),
            signature_valid=d.get("signature_valid", False),
            self_signed=d.get("self_signed", False),
            is_ca=d.get("is_ca", False),
            is_ev=d.get("is_ev", False),
            is_precert=d.get("is_precert", False),
            public_key=d.get("public_key", ""),
            public_key_algorithm=d.get("public_key_algorithm", ""),
            ocsp_servers=d.get("ocsp_servers") or [],
            ocsp_response=d.get("ocsp_response", ""),
            fingerprint_md5=d.get("fingerprint_md5", ""),
            fingerprint_sha1=d.get("fingerprint_sha1", ""),
            fingerprint_sha256=d.get("fingerprint_sha256", ""),
            fingerprint_spki=d.get("fingerprint_spki", ""),
            fingerprint_spki_subject=d.get("fingerprint_spki_subject", ""),
            fingerprint_tbs_certificate=d.get("fingerprint_tbs_certificate", ""),
        )


@dataclass
class Certificates:
    """
    TLS certificate info for a port, URL, or redirect hop (v3 models.Certificates).

    Replaces v2 PortStatus.certificate (a single flat TLSCertificate).
    """
    certificate: Optional[Certificate] = None   # the leaf certificate
    chain: List[Certificate] = field(default_factory=list)
    chain_valid: bool = False
    ocsp_staple: bool = False
    tls_version: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "Certificates":
        d = d or {}
        return cls(
            certificate=Certificate.from_dict(d["certificate"]) if d.get("certificate") else None,
            chain=[Certificate.from_dict(c) for c in d.get("chain") or []],
            chain_valid=d.get("chain_valid", False),
            ocsp_staple=d.get("ocsp_staple", False),
            tls_version=d.get("tls_version", ""),
        )


@dataclass
class Redirect:
    """
    One hop in UrlResult.redirect_chain.
    v3 adds remote_host, remote_port, headers, script_urls, certificates per hop.
    """
    status_code: int = 0
    location: str = ""
    remote_host: str = ""
    remote_port: str = ""
    headers: List[Header] = field(default_factory=list)
    script_urls: List[str] = field(default_factory=list)
    certificates: Optional[Certificates] = None

    @classmethod
    def from_dict(cls, d: dict) -> "Redirect":
        return cls(
            status_code=d.get("status_code", 0),
            location=d.get("location", ""),
            remote_host=d.get("remote_host", ""),
            remote_port=d.get("remote_port", ""),
            headers=[Header.from_dict(h) for h in d.get("headers") or []],
            script_urls=d.get("script_urls") or [],
            certificates=Certificates.from_dict(d["certificates"]) if d.get("certificates") else None,
        )


@dataclass
class Cookie:
    """A cookie set by an HTTP response (v3 models.Cookie)."""
    name: str = ""
    value: str = ""
    path: str = ""
    domain: str = ""
    expires: str = ""
    max_age: int = 0
    secure: bool = False
    http_only: bool = False
    raw_cookie: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "Cookie":
        return cls(
            name=d.get("name", ""),
            value=d.get("value", ""),
            path=d.get("path", ""),
            domain=d.get("domain", ""),
            expires=d.get("expires", ""),
            max_age=d.get("max_age", 0),
            secure=d.get("secure", False),
            http_only=d.get("http_only", False),
            raw_cookie=d.get("raw_cookie", ""),
        )


@dataclass
class Detection:
    """
    A technology detection (v3 models.Detection).

    v2 had app_detections: [{url, detections: [{name, matches, version, url}]}].
    v3 has a flat list of {name, info, cpe, website, categories}; there is no
    version or matches field.
    """
    name: str = ""
    info: str = ""
    cpe: str = ""
    website: str = ""
    categories: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict) -> "Detection":
        return cls(
            name=d.get("name", ""),
            info=d.get("info", ""),
            cpe=d.get("cpe", ""),
            website=d.get("website", ""),
            categories=d.get("categories") or [],
        )


# Header names treated as "security headers" by split_headers(). v2 split headers
# into security_headers / other_headers server-side; v3 returns one list.
SECURITY_HEADERS = frozenset({
    "strict-transport-security", "content-security-policy", "content-security-policy-report-only",
    "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy",
    "cross-origin-opener-policy", "cross-origin-embedder-policy", "cross-origin-resource-policy",
    "x-xss-protection",
})


@dataclass
class UrlResult:
    """
    HTTP(S) result for a URL, a port, or a domain (v3 models.UrlResult).
    Replaces v2 HTTPResult.

    v2 HTTPResult → v3 UrlResult:
        requested_url                      → url (also the key in JobReport.url_results)
        security_headers + other_headers   → headers (one list; see split_headers())
        redirect_chain                     → redirect_chain (hops now carry more data)
        new: url_* parts, checked_at, tags, cookies, certificates, detections,
             favicon_* hashes, raw (only with details=true)

    There is no top-level status code; status codes are on redirect_chain hops.
    """
    url: str = ""
    url_host: str = ""
    url_port: str = ""
    url_domain: str = ""
    url_scheme: str = ""
    url_path: str = ""
    url_query: str = ""
    checked_at: str = ""
    tags: List[str] = field(default_factory=list)
    remote_host: str = ""
    remote_port: str = ""
    supports_http2: bool = False
    supports_http3: bool = False
    secure_redirect: bool = False
    redirect_chain: List[Redirect] = field(default_factory=list)
    headers: List[Header] = field(default_factory=list)
    cookies: List[Cookie] = field(default_factory=list)
    script_urls: List[str] = field(default_factory=list)
    certificates: Optional[Certificates] = None
    detections: List[Detection] = field(default_factory=list)
    favicon_url: str = ""
    favicon_mmh3: str = ""
    favicon_md5: str = ""
    favicon_sha1: str = ""
    favicon_sha256: str = ""
    raw: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "UrlResult":
        return cls(
            url=d.get("url", ""),
            url_host=d.get("url_host", ""),
            url_port=d.get("url_port", ""),
            url_domain=d.get("url_domain", ""),
            url_scheme=d.get("url_scheme", ""),
            url_path=d.get("url_path", ""),
            url_query=d.get("url_query", ""),
            checked_at=d.get("checked_at", ""),
            tags=d.get("tags") or [],
            remote_host=d.get("remote_host", ""),
            remote_port=d.get("remote_port", ""),
            supports_http2=d.get("supports_http2", False),
            supports_http3=d.get("supports_http3", False),
            secure_redirect=d.get("secure_redirect", False),
            redirect_chain=[Redirect.from_dict(r) for r in d.get("redirect_chain") or []],
            headers=[Header.from_dict(h) for h in d.get("headers") or []],
            cookies=[Cookie.from_dict(c) for c in d.get("cookies") or []],
            script_urls=d.get("script_urls") or [],
            certificates=Certificates.from_dict(d["certificates"]) if d.get("certificates") else None,
            detections=[Detection.from_dict(x) for x in d.get("detections") or []],
            favicon_url=d.get("favicon_url", ""),
            favicon_mmh3=d.get("favicon_mmh3", ""),
            favicon_md5=d.get("favicon_md5", ""),
            favicon_sha1=d.get("favicon_sha1", ""),
            favicon_sha256=d.get("favicon_sha256", ""),
            raw=d.get("raw", ""),
        )

    def header(self, name: str) -> List[str]:
        """Values of a response header (case-insensitive); [] if absent."""
        wanted = name.lower()
        for h in self.headers:
            if h.name.lower() == wanted:
                return h.values
        return []

    def split_headers(self, security_names: frozenset = SECURITY_HEADERS) -> tuple:
        """
        Rebuild the v2 split: returns (security_headers, other_headers).
        v2's exact classification list was never published; pass your own set if needed.
        """
        sec: List[Header] = []
        other: List[Header] = []
        for h in self.headers:
            (sec if h.name.lower() in security_names else other).append(h)
        return sec, other


@dataclass
class ScanResult:
    """
    Per-port scan result. Replaces v2's PortStatus.
    Accessed via: job_report.scan_results[host].ports[port_str]

    v2 PortStatus → v3 ScanResult:
        new: host, port, proto, checked_at, tags
        http_info (HTTPResult)            → http_info (UrlResult)
        certificate (TLSCertificate)      → certificates (Certificates)
        ssh_collection, rdp_collection, … → collection["ssh"], collection["rdp"], …
        app_detections                    → detections (flat)
        checks                            → removed; see HostStatus.checks,
                                            JobReport.check_results, JobReport.checks_by_port()

    collection is kept as a dict keyed by protocol (39 collectors); each value is
    that collector's raw JSON object.
    """
    host: str = ""
    port: str = ""
    proto: str = ""
    checked_at: str = ""
    tags: List[str] = field(default_factory=list)
    open: bool = False
    service: str = ""
    software: str = ""
    version: str = ""
    info: str = ""
    host_name: str = ""
    os: str = ""
    device_type: str = ""
    cpe: str = ""
    tls: bool = False
    http: bool = False
    http_info: Optional[UrlResult] = None
    certificates: Optional[Certificates] = None
    detections: List[Detection] = field(default_factory=list)
    collection: Dict[str, Any] = field(default_factory=dict)
    bytes_rcvd: int = 0
    raw: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict) -> "ScanResult":
        return cls(
            host=d.get("host", ""),
            port=d.get("port", ""),
            proto=d.get("proto", ""),
            checked_at=d.get("checked_at", ""),
            tags=d.get("tags") or [],
            open=d.get("open", False),
            service=d.get("service", ""),
            software=d.get("software", ""),
            version=d.get("version", ""),
            info=d.get("info", ""),
            host_name=d.get("host_name", ""),
            os=d.get("os", ""),
            device_type=d.get("device_type", ""),
            cpe=d.get("cpe", ""),
            tls=d.get("tls", False),
            http=d.get("http", False),
            http_info=UrlResult.from_dict(d["http_info"]) if d.get("http_info") else None,
            certificates=Certificates.from_dict(d["certificates"]) if d.get("certificates") else None,
            detections=[Detection.from_dict(x) for x in d.get("detections") or []],
            collection=d.get("collection") or {},
            bytes_rcvd=d.get("bytes_rcvd", 0),
            raw=d.get("raw") or [],
        )


@dataclass
class HostMetadata:
    asn: str = ""
    as_org: str = ""
    country: str = ""
    provider: str = ""
    tor: bool = False
    info: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "HostMetadata":
        return cls(
            asn=d.get("asn", ""),
            as_org=d.get("as_org", ""),
            country=d.get("country", ""),
            provider=d.get("provider", ""),
            tor=d.get("tor", False),
            info=d.get("info", ""),
        )


@dataclass
class SOA:
    name: str = ""
    ns: str = ""
    mailbox: str = ""
    serial: int = 0
    refresh: int = 0
    retry: int = 0
    expire: int = 0
    min_ttl: int = 0

    @classmethod
    def from_dict(cls, d: dict) -> "SOA":
        return cls(
            name=d.get("name", ""),
            ns=d.get("ns", ""),
            mailbox=d.get("mailbox", ""),
            serial=d.get("serial", 0),
            refresh=d.get("refresh", 0),
            retry=d.get("retry", 0),
            expire=d.get("expire", 0),
            min_ttl=d.get("min_ttl", 0),
        )


@dataclass
class DNSResult:
    """
    DNS records for a domain (v3 models.DNSResult).
    v2 → v3: resolver removed; domain, checked_at, tags, caa, ns, srv, soa added.
    """
    domain: str = ""
    checked_at: str = ""
    tags: List[str] = field(default_factory=list)
    a: List[str] = field(default_factory=list)
    aaaa: List[str] = field(default_factory=list)
    caa: List[str] = field(default_factory=list)
    cname: List[str] = field(default_factory=list)
    dmarc: List[str] = field(default_factory=list)
    mx: List[str] = field(default_factory=list)
    ns: List[str] = field(default_factory=list)
    spf: List[str] = field(default_factory=list)
    srv: List[str] = field(default_factory=list)
    txt: List[str] = field(default_factory=list)
    soa: List[SOA] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict) -> "DNSResult":
        return cls(
            domain=d.get("domain", ""),
            checked_at=d.get("checked_at", ""),
            tags=d.get("tags") or [],
            a=d.get("a") or [],
            aaaa=d.get("aaaa") or [],
            caa=d.get("caa") or [],
            cname=d.get("cname") or [],
            dmarc=d.get("dmarc") or [],
            mx=d.get("mx") or [],
            ns=d.get("ns") or [],
            spf=d.get("spf") or [],
            srv=d.get("srv") or [],
            txt=d.get("txt") or [],
            soa=[SOA.from_dict(s) for s in d.get("soa") or []],
        )


@dataclass
class DomainInfo:
    """
    Everything collected for one domain (v3 models.DomainInfo).
    Accessed via: job_report.domain_results[domain]

    v2 DomainStatus {whois, dns, http, tls} → v3 DomainInfo:
        dns   → dns_info (DNSResult)
        whois → whois (raw dict; NOTE whois["domain"] is now a string and the
                       old WhoisDomain object moved to whois["domain_info"])
        http  → http_info + https_info (one UrlResult per scheme)
        tls   → removed (certificate data is on UrlResult.certificates)
        new: rdap (raw dict)
    """
    dns_info: Optional[DNSResult] = None
    whois: Dict[str, Any] = field(default_factory=dict)
    rdap: Dict[str, Any] = field(default_factory=dict)
    http_info: Optional[UrlResult] = None
    https_info: Optional[UrlResult] = None

    @classmethod
    def from_dict(cls, d: dict) -> "DomainInfo":
        return cls(
            dns_info=DNSResult.from_dict(d["dns_info"]) if d.get("dns_info") else None,
            whois=d.get("whois") or {},
            rdap=d.get("rdap") or {},
            http_info=UrlResult.from_dict(d["http_info"]) if d.get("http_info") else None,
            https_info=UrlResult.from_dict(d["https_info"]) if d.get("https_info") else None,
        )


@dataclass
class CheckResult:
    """
    Vulnerability check match result.
    v3 adds: type, host, port, scheme, url, path, ip, check_id, event_id
    These provide context about where the check matched.
    """
    # Context fields (new in v3)
    type: str = ""
    host: str = ""
    port: str = ""
    scheme: str = ""
    url: str = ""
    path: str = ""
    ip: str = ""
    check_id: str = ""
    event_id: str = ""
    # Core fields (same as v2)
    matched: str = ""
    check_name: str = ""
    description: str = ""
    references: List[str] = field(default_factory=list)
    check_type: str = ""
    severity: str = ""
    extract_name: str = ""
    extractions: List[str] = field(default_factory=list)
    cve_id: List[str] = field(default_factory=list)
    cwe_id: List[str] = field(default_factory=list)
    cvss_metrics: str = ""
    cvss_score: float = 0.0
    epss_score: float = 0.0
    cpe: str = ""
    interaction_request: str = ""
    interaction_addr: str = ""
    interaction_proto: str = ""
    interaction_timestamp: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "CheckResult":
        return cls(
            type=d.get("type", ""),
            host=d.get("host", ""),
            port=d.get("port", ""),
            scheme=d.get("scheme", ""),
            url=d.get("url", ""),
            path=d.get("path", ""),
            ip=d.get("ip", ""),
            check_id=d.get("check_id", ""),
            event_id=d.get("event_id", ""),
            matched=d.get("matched", ""),
            check_name=d.get("check_name", ""),
            description=d.get("description", ""),
            references=d.get("references", []),
            check_type=d.get("check_type", ""),
            severity=d.get("severity", ""),
            extract_name=d.get("extract_name", ""),
            extractions=d.get("extractions", []),
            cve_id=d.get("cve_id", []),
            cwe_id=d.get("cwe_id", []),
            cvss_metrics=d.get("cvss_metrics", ""),
            cvss_score=float(d.get("cvss_score") or 0),
            epss_score=float(d.get("epss_score") or 0),
            cpe=d.get("cpe", ""),
            interaction_request=d.get("interaction_request", ""),
            interaction_addr=d.get("interaction_addr", ""),
            interaction_proto=d.get("interaction_proto", ""),
            interaction_timestamp=d.get("interaction_timestamp", ""),
        )


@dataclass
class HostStatus:
    """
    Per-host result container in a JobReport.
    Accessed via: job_report.scan_results[host_ip]

    v2: JobReport.results[host] = HostStatus with .ports map of PortStatus
    v3: JobReport.scan_results[host] = HostStatus with .ports map of ScanResult
    New in v3: tags (rule tags from this host's ports) and checks (check matches
    for this host — checks are no longer attached to individual ports).
    """
    metadata: Optional[HostMetadata] = None
    tags: List[str] = field(default_factory=list)
    ports: Dict[str, ScanResult] = field(default_factory=dict)
    checks: List[CheckResult] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict) -> "HostStatus":
        return cls(
            metadata=HostMetadata.from_dict(d["metadata"]) if d.get("metadata") else None,
            tags=d.get("tags") or [],
            ports={p: ScanResult.from_dict(v) for p, v in (d.get("ports") or {}).items()},
            checks=[CheckResult.from_dict(c) for c in d.get("checks") or []],
        )


# ---------------------------------------------------------------------------
# JobReport
# ---------------------------------------------------------------------------

@dataclass
class JobReport:
    """
    Full scan results from GET /v3/scans/{job_id}/results.

    The endpoint wraps the report like every other single resource:
    { "data": JobReport, "links": {...} }. EffluxV3Client.get_scan_results()
    returns a DocumentResponse whose .data is this object.

    The endpoint returns 404 until the job's status is "complete".

    v2 → v3 field renames:
        results       → scan_results   (map: host_ip → HostStatus)
        domain_info   → domain_results (map: domain → DomainInfo)
        url_info      → url_results    (was array<HTTPResult>, now map<url → UrlResult>)

    New in v3:
        check_results  — top-level array of check matches. Each carries context
                         (host, ip, port, scheme, url, path, check_id, event_id).
                         Use checks_by_port() to rebuild the v2 per-port view.

    Without details=true, the server strips the request echo arrays (hosts,
    host_lists, ports, port_lists, domains, urls, cves) and UrlResult.raw.
    """
    job_id: str = ""
    user_id: str = ""
    schedule_id: str = ""
    proto: str = ""
    hosts: List[str] = field(default_factory=list)
    host_lists: List[str] = field(default_factory=list)
    ports: List[str] = field(default_factory=list)
    port_lists: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    cves: List[str] = field(default_factory=list)
    host_count: int = 0
    port_count: int = 0
    domain_count: int = 0
    url_count: int = 0
    cve_count: int = 0
    request_count: int = 0
    fingerprint: bool = False
    checks: bool = False
    tags: List[str] = field(default_factory=list)
    description: str = ""
    created_at: str = ""
    started_at: str = ""
    completed_at: str = ""
    accessible_host_count: int = 0
    accessible_port_count: int = 0
    accessible_domain_count: int = 0
    accessible_url_count: int = 0
    total_connections: int = 0
    checks_run: int = 0
    checks_matched: int = 0
    status: str = ""
    scan_results: Dict[str, HostStatus] = field(default_factory=dict)
    domain_results: Dict[str, DomainInfo] = field(default_factory=dict)
    url_results: Dict[str, UrlResult] = field(default_factory=dict)
    check_results: List[CheckResult] = field(default_factory=list)

    def checks_by_port(self) -> Dict[tuple, List[CheckResult]]:
        """
        Group check results by (host, port), like v2's PortStatus.checks.

        Collects from every HostStatus.checks and from check_results,
        de-duplicating by event_id. Checks without a port are keyed (host, "").
        """
        grouped: Dict[tuple, List[CheckResult]] = {}
        seen: set = set()

        def add(c: CheckResult, fallback_host: str) -> None:
            key = c.event_id or id(c)
            if key in seen:
                return
            seen.add(key)
            grouped.setdefault((c.host or c.ip or fallback_host, c.port), []).append(c)

        for host, hs in self.scan_results.items():
            for c in hs.checks:
                add(c, host)
        for c in self.check_results:
            add(c, "")
        return grouped

    @classmethod
    def from_dict(cls, d: dict) -> "JobReport":
        scan_results = {}
        for host, host_data in (d.get("scan_results") or {}).items():
            scan_results[host] = HostStatus.from_dict(host_data)

        domain_results = {}
        for domain, domain_data in (d.get("domain_results") or {}).items():
            domain_results[domain] = DomainInfo.from_dict(domain_data)

        url_results = {}
        for url, url_data in (d.get("url_results") or {}).items():
            url_results[url] = UrlResult.from_dict(url_data)

        return cls(
            job_id=d.get("job_id", ""),
            user_id=d.get("user_id", ""),
            schedule_id=d.get("schedule_id", ""),
            proto=d.get("proto", ""),
            hosts=d.get("hosts", []),
            host_lists=d.get("host_lists", []),
            ports=d.get("ports", []),
            port_lists=d.get("port_lists", []),
            domains=d.get("domains", []),
            urls=d.get("urls", []),
            cves=d.get("cves", []),
            host_count=d.get("host_count", 0),
            port_count=d.get("port_count", 0),
            domain_count=d.get("domain_count", 0),
            url_count=d.get("url_count", 0),
            cve_count=d.get("cve_count", 0),
            request_count=d.get("request_count", 0),
            fingerprint=d.get("fingerprint", False),
            checks=d.get("checks", False),
            tags=d.get("tags", []),
            description=d.get("description", ""),
            created_at=d.get("created_at", ""),
            started_at=d.get("started_at", ""),
            completed_at=d.get("completed_at", ""),
            accessible_host_count=d.get("accessible_host_count", 0),
            accessible_port_count=d.get("accessible_port_count", 0),
            accessible_domain_count=d.get("accessible_domain_count", 0),
            accessible_url_count=d.get("accessible_url_count", 0),
            total_connections=d.get("total_connections", 0),
            checks_run=d.get("checks_run", 0),
            checks_matched=d.get("checks_matched", 0),
            status=d.get("status", ""),
            scan_results=scan_results,
            domain_results=domain_results,
            url_results=url_results,
            check_results=[CheckResult.from_dict(c) for c in d.get("check_results") or []],
        )


# ---------------------------------------------------------------------------
# JobSummary (new in v3)
# ---------------------------------------------------------------------------

@dataclass
class JobSummary:
    """
    Lightweight aggregated statistics from GET /v3/scans/{job_id}/summary.
    New in v3. Use this instead of fetching the full JobReport when you only
    need counts, port lists, service names, or country breakdown.
    """
    job_id: str = ""
    user_id: str = ""
    created_at: str = ""
    started_at: str = ""
    completed_at: str = ""
    accessible_host_count: int = 0
    accessible_port_count: int = 0
    accessible_domain_count: int = 0
    accessible_url_count: int = 0
    checks_matched: int = 0
    ports: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    software: List[str] = field(default_factory=list)
    certs: List[str] = field(default_factory=list)
    keys: List[str] = field(default_factory=list)
    asns: List[str] = field(default_factory=list)
    hosts_per_country: Dict[str, int] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict) -> "JobSummary":
        return cls(
            job_id=d.get("job_id", ""),
            user_id=d.get("user_id", ""),
            created_at=d.get("created_at", ""),
            started_at=d.get("started_at", ""),
            completed_at=d.get("completed_at", ""),
            accessible_host_count=d.get("accessible_host_count", 0),
            accessible_port_count=d.get("accessible_port_count", 0),
            accessible_domain_count=d.get("accessible_domain_count", 0),
            accessible_url_count=d.get("accessible_url_count", 0),
            checks_matched=d.get("checks_matched", 0),
            ports=d.get("ports", []),
            services=d.get("services", []),
            software=d.get("software", []),
            certs=d.get("certs", []),
            keys=d.get("keys", []),
            asns=d.get("asns", []),
            hosts_per_country=d.get("hosts_per_country", {}),
        )
