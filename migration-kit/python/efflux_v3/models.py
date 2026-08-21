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
- ScanResult replaces PortStatus
- fingerprint is bool (not int)
- Callback is nested {start, success, fail} (not flat)
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
    """A single callback event target (start, success, or fail)."""
    url: str = ""
    method: str = "POST"

    @classmethod
    def from_dict(cls, d: dict) -> "CallbackEvent":
        return cls(url=d.get("url", ""), method=d.get("method", "POST"))

    def to_dict(self) -> dict:
        return {"url": self.url, "method": self.method}


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
    """
    start: Optional[CallbackEvent] = None
    success: Optional[CallbackEvent] = None
    fail: Optional[CallbackEvent] = None

    @classmethod
    def from_dict(cls, d: dict) -> "CallbackRequest":
        return cls(
            start=CallbackEvent.from_dict(d["start"]) if d.get("start") else None,
            success=CallbackEvent.from_dict(d["success"]) if d.get("success") else None,
            fail=CallbackEvent.from_dict(d["fail"]) if d.get("fail") else None,
        )

    def to_dict(self) -> dict:
        result = {}
        if self.start:
            result["start"] = self.start.to_dict()
        if self.success:
            result["success"] = self.success.to_dict()
        if self.fail:
            result["fail"] = self.fail.to_dict()
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
    """Status of a single callback event including delivery history."""
    url: str = ""
    method: str = "POST"
    attempts: List[CallbackAttempt] = field(default_factory=list)
    complete: bool = False

    @classmethod
    def from_dict(cls, d: dict) -> "CallbackStatus":
        return cls(
            url=d.get("url", ""),
            method=d.get("method", "POST"),
            attempts=[CallbackAttempt.from_dict(a) for a in d.get("attempts", [])],
            complete=d.get("complete", False),
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

    v2 field name: checks_opts (with 7 options)
    v3 field name: checks_options (with 3 options)

    Removed from v3: include_ids, exclude_ids, limit_to_ids,
                     exclude_targets, limit_to_targets
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
        return self.status == "complete"

    @property
    def is_running(self) -> bool:
        return self.status in ("pending", "running")

    @property
    def is_failed(self) -> bool:
        return self.status == "failed"


# ---------------------------------------------------------------------------
# Scan Result Types
# ---------------------------------------------------------------------------

@dataclass
class Redirect:
    status_code: int = 0
    location: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "Redirect":
        return cls(status_code=d.get("status_code", 0), location=d.get("location", ""))


@dataclass
class Header:
    name: str = ""
    values: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict) -> "Header":
        return cls(name=d.get("name", ""), values=d.get("values", []))


@dataclass
class Cookie:
    name: str = ""
    value: str = ""
    domain: str = ""
    path: str = ""
    secure: bool = False
    http_only: bool = False
    same_site: str = ""
    expires: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "Cookie":
        return cls(
            name=d.get("name", ""),
            value=d.get("value", ""),
            domain=d.get("domain", ""),
            path=d.get("path", ""),
            secure=d.get("secure", False),
            http_only=d.get("http_only", False),
            same_site=d.get("same_site", ""),
            expires=d.get("expires", ""),
        )


@dataclass
class Detection:
    """Wappalyzer-style application detection."""
    name: str = ""
    matches: str = ""
    version: str = ""
    url: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "Detection":
        return cls(
            name=d.get("name", ""),
            matches=d.get("matches", ""),
            version=d.get("version", ""),
            url=d.get("url", ""),
        )


@dataclass
class TLSResult:
    selected_protocol: str = ""
    selected_cipher: str = ""
    protocols: List[str] = field(default_factory=list)
    mutual_tls: bool = False
    jarm: str = ""
    compression: bool = False
    session_id_resumption: bool = False
    session_ticket_resumption: bool = False
    secure_renegotiation: bool = False
    session_renegotiation: bool = False
    tls_fallback: bool = False
    tls_early_data: bool = False
    certificate: Optional[dict] = None

    @classmethod
    def from_dict(cls, d: dict) -> "TLSResult":
        return cls(
            selected_protocol=d.get("selected_protocol", ""),
            selected_cipher=d.get("selected_cipher", ""),
            protocols=d.get("protocols", []),
            mutual_tls=d.get("mutual_tls", False),
            jarm=d.get("jarm", ""),
            compression=d.get("compression", False),
            session_id_resumption=d.get("session_id_resumption", False),
            session_ticket_resumption=d.get("session_ticket_resumption", False),
            secure_renegotiation=d.get("secure_renegotiation", False),
            session_renegotiation=d.get("session_renegotiation", False),
            tls_fallback=d.get("tls_fallback", False),
            tls_early_data=d.get("tls_early_data", False),
            certificate=d.get("certificate"),
        )


@dataclass
class Certificate:
    """Certificate data from TLS scan."""
    fingerprint_md5: str = ""
    fingerprint_sha1: str = ""
    fingerprint_sha256: str = ""
    version: str = ""
    serial_number: str = ""
    not_before: str = ""
    not_after: str = ""
    issuer_common_name: str = ""
    issuer_organization: str = ""
    issuer_country: str = ""
    subject_common_name: str = ""
    subject_organization: str = ""
    subject_country: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "Certificate":
        return cls(
            fingerprint_md5=d.get("fingerprint_md5", ""),
            fingerprint_sha1=d.get("fingerprint_sha1", ""),
            fingerprint_sha256=d.get("fingerprint_sha256", ""),
            version=d.get("version", ""),
            serial_number=d.get("serial_number", ""),
            not_before=d.get("not_before", ""),
            not_after=d.get("not_after", ""),
            issuer_common_name=d.get("issuer_common_name", ""),
            issuer_organization=d.get("issuer_organization", ""),
            issuer_country=d.get("issuer_country", ""),
            subject_common_name=d.get("subject_common_name", ""),
            subject_organization=d.get("subject_organization", ""),
            subject_country=d.get("subject_country", ""),
        )


@dataclass
class Certificates:
    """Container for certificates found on a port."""
    # The collection field; raw dict kept flexible for protocol-specific certs
    raw: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict) -> "Certificates":
        return cls(raw=d or {})


@dataclass
class UrlResult:
    """
    HTTP/HTTPS result for a URL or port.
    Replaces HTTPResult from v2 — includes more data (cookies, TLS, detections).
    In JobReport, url_results is a map<url_string, UrlResult> (v2 url_info was an array).
    """
    requested_url: str = ""
    remote_host: str = ""
    remote_port: str = ""
    supports_http2: bool = False
    supports_http3: bool = False
    secure_redirect: bool = False
    status_code: int = 0
    redirect_chain: List[Redirect] = field(default_factory=list)
    security_headers: List[Header] = field(default_factory=list)
    other_headers: List[Header] = field(default_factory=list)
    script_urls: List[str] = field(default_factory=list)
    cookies: List[Cookie] = field(default_factory=list)
    detections: List[Detection] = field(default_factory=list)
    tls: Optional[TLSResult] = None

    @classmethod
    def from_dict(cls, d: dict) -> "UrlResult":
        return cls(
            requested_url=d.get("requested_url", ""),
            remote_host=d.get("remote_host", ""),
            remote_port=d.get("remote_port", ""),
            supports_http2=d.get("supports_http2", False),
            supports_http3=d.get("supports_http3", False),
            secure_redirect=d.get("secure_redirect", False),
            status_code=d.get("status_code", 0),
            redirect_chain=[Redirect.from_dict(r) for r in d.get("redirect_chain", [])],
            security_headers=[Header.from_dict(h) for h in d.get("security_headers", [])],
            other_headers=[Header.from_dict(h) for h in d.get("other_headers", [])],
            script_urls=d.get("script_urls", []),
            cookies=[Cookie.from_dict(c) for c in d.get("cookies", [])],
            detections=[Detection.from_dict(det) for det in d.get("detections", [])],
            tls=TLSResult.from_dict(d["tls"]) if d.get("tls") else None,
        )


@dataclass
class ScanResult:
    """
    Per-port scan result. Replaces v2's PortStatus.
    Accessed via: job_report.scan_results[host].ports[port_str]
    """
    host: str = ""
    port: str = ""
    proto: str = ""
    checked_at: str = ""
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
            detections=[Detection.from_dict(det) for det in d.get("detections", [])],
            collection=d.get("collection", {}),
            bytes_rcvd=d.get("bytes_rcvd", 0),
            raw=d.get("raw", []),
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
class HostStatus:
    """
    Per-host result container in a JobReport.
    Accessed via: job_report.scan_results[host_ip]

    v2: JobReport.results[host] = HostStatus with .ports map of PortStatus
    v3: JobReport.scan_results[host] = HostStatus with .ports map of ScanResult
    """
    metadata: Optional[HostMetadata] = None
    ports: Dict[str, ScanResult] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict) -> "HostStatus":
        ports = {}
        for port_str, port_data in d.get("ports", {}).items():
            ports[port_str] = ScanResult.from_dict(port_data)
        return cls(
            metadata=HostMetadata.from_dict(d["metadata"]) if d.get("metadata") else None,
            ports=ports,
        )


@dataclass
class DomainInfo:
    """
    DNS information for a domain.
    v2 had DomainStatus with {whois, dns, http, tls}.
    v3 DomainInfo has DNS records directly, with more record types.
    """
    a: List[str] = field(default_factory=list)
    aaaa: List[str] = field(default_factory=list)
    cname: List[str] = field(default_factory=list)
    mx: List[str] = field(default_factory=list)
    ns: List[str] = field(default_factory=list)
    txt: List[str] = field(default_factory=list)
    soa: List[str] = field(default_factory=list)
    caa: List[str] = field(default_factory=list)
    dmarc: List[str] = field(default_factory=list)
    spf: List[str] = field(default_factory=list)
    resolver: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "DomainInfo":
        return cls(
            a=d.get("a", []),
            aaaa=d.get("aaaa", []),
            cname=d.get("cname", []),
            mx=d.get("mx", []),
            ns=d.get("ns", []),
            txt=d.get("txt", []),
            soa=d.get("soa", []),
            caa=d.get("caa", []),
            dmarc=d.get("dmarc", []),
            spf=d.get("spf", []),
            resolver=d.get("resolver", ""),
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


# ---------------------------------------------------------------------------
# JobReport
# ---------------------------------------------------------------------------

@dataclass
class JobReport:
    """
    Full scan results from GET /v3/scans/{job_id}/results.

    NOTE: This endpoint returns the report directly (NOT wrapped in DocumentResponse).

    v2 → v3 field renames:
        results       → scan_results   (map: host_ip → HostStatus)
        domain_info   → domain_results (map: domain → DomainInfo)
        url_info      → url_results    (was array<HTTPResult>, now map<url → UrlResult>)

    New in v3:
        check_results  — top-level array of all check matches across all hosts
                         Includes context fields (host, port, scheme, url, check_id, event_id)
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

    @classmethod
    def from_dict(cls, d: dict) -> "JobReport":
        scan_results = {}
        for host, host_data in d.get("scan_results", {}).items():
            scan_results[host] = HostStatus.from_dict(host_data)

        domain_results = {}
        for domain, domain_data in d.get("domain_results", {}).items():
            domain_results[domain] = DomainInfo.from_dict(domain_data)

        url_results = {}
        for url, url_data in d.get("url_results", {}).items():
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
            check_results=[CheckResult.from_dict(c) for c in d.get("check_results", [])],
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
