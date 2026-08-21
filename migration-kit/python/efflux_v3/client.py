"""
Efflux v3 API client.

Usage:
    from efflux_v3 import EffluxV3Client, ScanRequest, CallbackRequest, CallbackEvent

    client = EffluxV3Client(api_key="your-api-key")

    request = ScanRequest(
        hosts=["10.0.0.0/24"],
        ports=["top_100"],
        fingerprint=True,
        tags=["production"],
    )
    response = client.create_scan(request)
    job_id = response.data.job_id

    job = client.wait_for_job(job_id)
    results = client.get_scan_results(job_id)
    for host, host_status in results.scan_results.items():
        for port, scan_result in host_status.ports.items():
            if scan_result.open:
                print(f"{host}:{port} — {scan_result.service}")
"""
import json
import time
from typing import Dict, Generator, List, Optional
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from urllib.parse import urlencode

from .exceptions import EffluxAPIError
from .models import (
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
)

BASE_URL = "https://api.efflux.io/v3"


class EffluxV3Client:
    """
    HTTP client for the Efflux v3 API.

    All responses are deserialized into typed model objects.
    Errors raise typed exceptions from efflux_v3.exceptions.
    """

    def __init__(
        self,
        api_key: str,
        base_url: str = BASE_URL,
        timeout: int = 30,
        default_headers: Optional[Dict[str, str]] = None,
    ):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.default_headers = dict(default_headers or {})

    # -----------------------------------------------------------------------
    # Internal HTTP helpers
    # -----------------------------------------------------------------------

    def _headers(self) -> dict:
        headers = {
            "Authorization": self.api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        headers.update(self.default_headers)
        return headers

    def _request(self, method: str, path: str, body: Optional[dict] = None, params: Optional[dict] = None) -> dict:
        url = f"{self.base_url}{path}"
        if params:
            filtered = {k: v for k, v in params.items() if v is not None}
            if filtered:
                url = f"{url}?{urlencode(filtered)}"

        data = json.dumps(body).encode() if body is not None else None
        req = Request(url, data=data, headers=self._headers(), method=method)

        try:
            with urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
                if not raw:
                    return {}
                return json.loads(raw)
        except HTTPError as e:
            raw = e.read()
            try:
                error_body = json.loads(raw)
            except Exception:
                error_body = {"detail": raw.decode(errors="replace"), "status": e.code}
            raise EffluxAPIError.from_response(e.code, error_body) from e

    def _get(self, path: str, params: Optional[dict] = None) -> dict:
        return self._request("GET", path, params=params)

    def _post(self, path: str, body: Optional[dict] = None) -> dict:
        return self._request("POST", path, body=body)

    def _put(self, path: str, body: Optional[dict] = None) -> dict:
        return self._request("PUT", path, body=body)

    def _delete(self, path: str) -> dict:
        return self._request("DELETE", path)

    # -----------------------------------------------------------------------
    # Scans
    # -----------------------------------------------------------------------

    def create_scan(self, request: ScanRequest) -> DocumentResponse:
        """
        POST /v3/scans — Create and start a new scan job.

        Returns a DocumentResponse; access the job via response.data.
        response.data is a RequestResults object with job_id and status.

        Raises:
            EffluxValidationError: 400 — invalid request (bad hosts, ports, etc.)
            EffluxAuthError: 401 — invalid or expired API key
            EffluxRateLimitError: 429 — rate limit exceeded
        """
        raw = self._post("/scans", body=request.to_dict())
        return DocumentResponse(
            data=RequestResults.from_dict(raw.get("data", {})),
            links=raw.get("links", {}),
        )

    def eval_scan(self, request: ScanRequest) -> DocumentResponse:
        """
        POST /v3/scans/eval — Evaluate a scan request without executing it.

        Use this to preview what hosts/ports will be resolved and how many
        requests the scan will consume before actually running it.

        Returns the same DocumentResponse<RequestResults> as create_scan,
        but no job is started and no credits are consumed.
        """
        raw = self._post("/scans/eval", body=request.to_dict())
        return DocumentResponse(
            data=RequestResults.from_dict(raw.get("data", {})),
            links=raw.get("links", {}),
        )

    def get_scan(self, job_id: str) -> DocumentResponse:
        """
        GET /v3/scans/{job_id} — Get job status and metadata.

        IMPORTANT: This no longer returns scan results.
        For results, call get_scan_results(job_id).
        For a summary, call get_scan_summary(job_id).

        Returns DocumentResponse; access the job via response.data (a Job object).
        """
        raw = self._get(f"/scans/{job_id}")
        return DocumentResponse(
            data=Job.from_dict(raw.get("data", {})),
            links=raw.get("links", {}),
        )

    def get_scan_results(self, job_id: str, details: bool = False) -> JobReport:
        """
        GET /v3/scans/{job_id}/results — Get the full scan results.

        This endpoint returns a JobReport directly (not wrapped in DocumentResponse).

        The JobReport contains:
          - scan_results: dict[host_ip, HostStatus]  (was 'results' in v2)
          - domain_results: dict[domain, DomainInfo] (was 'domain_info' in v2)
          - url_results: dict[url, UrlResult]         (was 'url_info' array in v2)
          - check_results: list[CheckResult]           (new in v3)

        Args:
            job_id: The job ID to fetch results for.
            details: If True, include raw bytes data in ScanResult.raw.
        """
        params = {"details": "true"} if details else None
        raw = self._get(f"/scans/{job_id}/results", params=params)
        return JobReport.from_dict(raw)

    def get_scan_summary(self, job_id: str) -> JobSummary:
        """
        GET /v3/scans/{job_id}/summary — Get aggregated scan statistics.

        New in v3. Returns a lightweight summary without full result payloads:
        open port numbers, service names, software versions, ASNs, country breakdown.

        Use this instead of get_scan_results() when you only need statistics.
        """
        raw = self._get(f"/scans/{job_id}/summary")
        return JobSummary.from_dict(raw)

    def list_scans(self, page: int = 1, limit: int = 20) -> PagedResponse:
        """
        GET /v3/scans — List scan jobs (paginated).

        v2 used ?count=N and returned a plain array.
        v3 uses ?page=N&limit=N and returns { data: [...], pagination: {...} }.

        Args:
            page: 1-based page number.
            limit: Items per page (max 1000, default 20).

        Returns:
            PagedResponse with .data (list[Job]) and .pagination.
        """
        raw = self._get("/scans", params={"page": page, "limit": limit})
        jobs = [Job.from_dict(j) for j in raw.get("data", [])]
        pagination = Pagination.from_dict(raw.get("pagination", {}))
        return PagedResponse(data=jobs, pagination=pagination)

    def list_all_scans(self, limit: int = 100) -> Generator[Job, None, None]:
        """
        Iterate through all scan jobs across all pages.

        Usage:
            for job in client.list_all_scans():
                print(job.job_id, job.status)
        """
        page = 1
        while True:
            response = self.list_scans(page=page, limit=limit)
            yield from response.data
            if not response.pagination.has_next:
                break
            page += 1

    def repeat_scan(self, job_id: str) -> DocumentResponse:
        """
        POST /v3/scans/{job_id}/repeat — Repeat a previous scan job.

        v2 path was POST /scans/repeat/{job_id}.
        v3 path is POST /scans/{job_id}/repeat.

        Returns HTTP 201 + DocumentResponse<RequestResults>.
        """
        raw = self._post(f"/scans/{job_id}/repeat")
        return DocumentResponse(
            data=RequestResults.from_dict(raw.get("data", {})),
            links=raw.get("links", {}),
        )

    def update_scan_callback(self, job_id: str, callback: CallbackRequest) -> Callback:
        """
        POST /v3/scans/{job_id}/callback — Update callback configuration after job creation.

        New in v3. Allows changing webhook URLs/methods for an in-progress or completed job.

        Returns the updated Callback object (with delivery history).
        """
        raw = self._post(f"/scans/{job_id}/callback", body=callback.to_dict())
        return Callback.from_dict(raw)

    def restart_scan_callback(self, job_id: str) -> Callback:
        """
        PUT /v3/scans/{job_id}/callback/restart — Retry pending callback deliveries.

        New in v3. Re-triggers any callbacks that haven't completed delivery.

        Returns the updated Callback object.
        """
        raw = self._put(f"/scans/{job_id}/callback/restart")
        return Callback.from_dict(raw)

    # -----------------------------------------------------------------------
    # Polling helpers
    # -----------------------------------------------------------------------

    def wait_for_job(
        self,
        job_id: str,
        poll_interval: float = 5.0,
        timeout: float = 3600.0,
    ) -> Job:
        """
        Poll GET /v3/scans/{job_id} until the job completes or fails.

        Replaces the v2 /subscribe long-poll endpoint.
        For real-time results, use WebSocket streams instead (see docs).

        Args:
            job_id: The job to wait for.
            poll_interval: Seconds between status checks (default 5).
            timeout: Maximum seconds to wait (default 3600 = 1 hour).

        Returns:
            The completed (or failed) Job.

        Raises:
            TimeoutError: If the job doesn't complete within timeout seconds.
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            response = self.get_scan(job_id)
            job = response.data
            if not job.is_running:
                return job
            time.sleep(poll_interval)
        raise TimeoutError(f"Job {job_id} did not complete within {timeout}s")

    def run_scan_and_wait(
        self,
        request: ScanRequest,
        poll_interval: float = 5.0,
        timeout: float = 3600.0,
    ) -> tuple:
        """
        Create a scan job and wait for it to complete.

        Returns:
            (Job, JobReport) — the completed job and its full results.

        Usage:
            job, report = client.run_scan_and_wait(ScanRequest(
                hosts=["10.0.0.0/24"],
                ports=["top_100"],
            ))
            print(f"Found {report.accessible_host_count} hosts")
        """
        create_response = self.create_scan(request)
        job_id = create_response.data.job_id
        job = self.wait_for_job(job_id, poll_interval=poll_interval, timeout=timeout)
        report = self.get_scan_results(job_id)
        return job, report

    # -----------------------------------------------------------------------
    # Checks (cross-job query)
    # -----------------------------------------------------------------------

    def list_checks(
        self,
        job_id: Optional[str] = None,
        severity: Optional[str] = None,
        cve: Optional[str] = None,
        min_date: Optional[str] = None,
        max_date: Optional[str] = None,
        page: int = 1,
        limit: int = 20,
    ) -> PagedResponse:
        """
        GET /v3/checks — Query vulnerability check results across all jobs.

        New in v3. Allows querying checks across all your scans with filters.

        Args:
            job_id: Filter to a specific job.
            severity: Filter by severity (info, low, medium, high, critical).
            cve: Filter by CVE ID.
            min_date: Earliest result date (ISO 8601).
            max_date: Latest result date (ISO 8601).
            page: Page number.
            limit: Results per page.
        """
        raw = self._get("/checks", params={
            "job_id": job_id,
            "severity": severity,
            "cve": cve,
            "min_date": min_date,
            "max_date": max_date,
            "page": page,
            "limit": limit,
        })
        checks = [CheckResult.from_dict(c) for c in raw.get("data", [])]
        pagination = Pagination.from_dict(raw.get("pagination", {}))
        return PagedResponse(data=checks, pagination=pagination)

    # -----------------------------------------------------------------------
    # Host & Port Lists
    # -----------------------------------------------------------------------

    def list_host_lists(self, page: int = 1, limit: int = 20) -> PagedResponse:
        """GET /v3/lists/hosts"""
        raw = self._get("/lists/hosts", params={"page": page, "limit": limit})
        return PagedResponse(data=raw.get("data", []), pagination=Pagination.from_dict(raw.get("pagination", {})))

    def create_host_list(self, name: str, hosts: List[str]) -> DocumentResponse:
        """POST /v3/lists/hosts"""
        raw = self._post("/lists/hosts", body={"name": name, "hosts": hosts})
        return DocumentResponse(data=raw.get("data"), links=raw.get("links", {}))

    def get_host_list(self, list_id: str) -> DocumentResponse:
        """GET /v3/lists/hosts/{list_id}"""
        raw = self._get(f"/lists/hosts/{list_id}")
        return DocumentResponse(data=raw.get("data"), links=raw.get("links", {}))

    def update_host_list(self, list_id: str, name: str, hosts: List[str]) -> DocumentResponse:
        """PUT /v3/lists/hosts/{list_id}"""
        raw = self._put(f"/lists/hosts/{list_id}", body={"name": name, "hosts": hosts})
        return DocumentResponse(data=raw.get("data"), links=raw.get("links", {}))

    def delete_host_list(self, list_id: str) -> None:
        """DELETE /v3/lists/hosts/{list_id}"""
        self._delete(f"/lists/hosts/{list_id}")

    def list_port_lists(self, page: int = 1, limit: int = 20) -> PagedResponse:
        """GET /v3/lists/ports"""
        raw = self._get("/lists/ports", params={"page": page, "limit": limit})
        return PagedResponse(data=raw.get("data", []), pagination=Pagination.from_dict(raw.get("pagination", {})))

    def create_port_list(self, name: str, ports: List[str]) -> DocumentResponse:
        """POST /v3/lists/ports"""
        raw = self._post("/lists/ports", body={"name": name, "ports": ports})
        return DocumentResponse(data=raw.get("data"), links=raw.get("links", {}))

    def get_port_list(self, list_id: str) -> DocumentResponse:
        """GET /v3/lists/ports/{list_id}"""
        raw = self._get(f"/lists/ports/{list_id}")
        return DocumentResponse(data=raw.get("data"), links=raw.get("links", {}))

    def delete_port_list(self, list_id: str) -> None:
        """DELETE /v3/lists/ports/{list_id}"""
        self._delete(f"/lists/ports/{list_id}")

    # -----------------------------------------------------------------------
    # Schedules
    # -----------------------------------------------------------------------

    def list_schedules(self, page: int = 1, limit: int = 20) -> PagedResponse:
        """GET /v3/schedules"""
        raw = self._get("/schedules", params={"page": page, "limit": limit})
        return PagedResponse(data=raw.get("data", []), pagination=Pagination.from_dict(raw.get("pagination", {})))

    def create_schedule(self, schedule: dict) -> DocumentResponse:
        """POST /v3/schedules"""
        raw = self._post("/schedules", body=schedule)
        return DocumentResponse(data=raw.get("data"), links=raw.get("links", {}))

    def get_schedule(self, schedule_id: str) -> DocumentResponse:
        """GET /v3/schedules/{schedule_id}"""
        raw = self._get(f"/schedules/{schedule_id}")
        return DocumentResponse(data=raw.get("data"), links=raw.get("links", {}))

    def update_schedule(self, schedule_id: str, schedule: dict) -> DocumentResponse:
        """PUT /v3/schedules/{schedule_id}"""
        raw = self._put(f"/schedules/{schedule_id}", body=schedule)
        return DocumentResponse(data=raw.get("data"), links=raw.get("links", {}))

    def delete_schedule(self, schedule_id: str) -> None:
        """DELETE /v3/schedules/{schedule_id}"""
        self._delete(f"/schedules/{schedule_id}")

    def get_schedule_history(self, schedule_id: str, page: int = 1, limit: int = 20) -> PagedResponse:
        """GET /v3/schedules/{schedule_id}/history"""
        raw = self._get(f"/schedules/{schedule_id}/history", params={"page": page, "limit": limit})
        return PagedResponse(data=raw.get("data", []), pagination=Pagination.from_dict(raw.get("pagination", {})))

    # -----------------------------------------------------------------------
    # Search
    # -----------------------------------------------------------------------

    def search_dns(self, query: str, limit: int = 20, search_after: Optional[str] = None, **filters) -> dict:
        """
        GET /v3/search/advanced/dns — BM25 full-text DNS search.

        Args:
            query: Search query string.
            limit: Results per page (max 100).
            search_after: Pagination token from previous response's next_token.
            **filters: Additional filters: domain, a, aaaa, mx, ns, cname, etc.
        """
        params = {"q": query, "limit": limit, **filters}
        if search_after:
            params["search_after"] = search_after
        return self._get("/search/advanced/dns", params=params)

    def search_hosts(self, query: str, limit: int = 20, search_after: Optional[str] = None, **filters) -> dict:
        """GET /v3/search/advanced/hosts — BM25 full-text scan result search."""
        params = {"q": query, "limit": limit, **filters}
        if search_after:
            params["search_after"] = search_after
        return self._get("/search/advanced/hosts", params=params)

    def search_urls(self, query: str, limit: int = 20, search_after: Optional[str] = None, **filters) -> dict:
        """GET /v3/search/advanced/urls — BM25 full-text URL search."""
        params = {"q": query, "limit": limit, **filters}
        if search_after:
            params["search_after"] = search_after
        return self._get("/search/advanced/urls", params=params)

    def lookup_domain(self, domain: str) -> dict:
        """GET /v3/search/domains/{domain} — Aggregate view of a domain."""
        return self._get(f"/search/domains/{domain}")

    def lookup_host(self, host: str, page: int = 1, limit: int = 20) -> dict:
        """GET /v3/search/hosts/{host} — Port statuses for a host."""
        return self._get(f"/search/hosts/{host}", params={"page": page, "limit": limit})

    def lookup_host_summary(self, host: str) -> dict:
        """GET /v3/search/hosts/{host}/summary — Host summary."""
        return self._get(f"/search/hosts/{host}/summary")

    def my_host_results(self, host: str) -> dict:
        """GET /v3/search/my/hosts/{host} — Your scan results for a specific host."""
        return self._get(f"/search/my/hosts/{host}")

    # -----------------------------------------------------------------------
    # Captures
    # -----------------------------------------------------------------------

    def list_captures(self, page: int = 1, limit: int = 100) -> PagedResponse:
        """GET /v3/captures"""
        raw = self._get("/captures", params={"page": page, "limit": limit})
        return PagedResponse(data=raw.get("data", []), pagination=Pagination.from_dict(raw.get("pagination", {})))

    def create_capture(self, url: str, region: Optional[str] = None, callback: Optional[dict] = None) -> DocumentResponse:
        """POST /v3/captures"""
        body: dict = {"url": url}
        if region:
            body["region"] = region
        if callback:
            body["callback"] = callback
        raw = self._post("/captures", body=body)
        return DocumentResponse(data=raw.get("data"), links=raw.get("links", {}))

    def get_capture(self, capture_id: str) -> DocumentResponse:
        """GET /v3/captures/{capture_id}"""
        raw = self._get(f"/captures/{capture_id}")
        return DocumentResponse(data=raw.get("data"), links=raw.get("links", {}))

    def get_capture_results(self, capture_id: str) -> dict:
        """GET /v3/captures/{capture_id}/results"""
        return self._get(f"/captures/{capture_id}/results")

    def get_capture_cookies(self, capture_id: str, page: int = 1, limit: int = 100) -> PagedResponse:
        """GET /v3/captures/{capture_id}/cookies"""
        raw = self._get(f"/captures/{capture_id}/cookies", params={"page": page, "limit": limit})
        return PagedResponse(data=raw.get("data", []), pagination=Pagination.from_dict(raw.get("pagination", {})))

    def get_capture_cookie_report(self, capture_id: str) -> dict:
        """GET /v3/captures/{capture_id}/cookies/report"""
        return self._get(f"/captures/{capture_id}/cookies/report")

    def get_capture_html(self, capture_id: str) -> dict:
        """GET /v3/captures/{capture_id}/html"""
        return self._get(f"/captures/{capture_id}/html")

    def get_capture_network_logs(self, capture_id: str, page: int = 1, limit: int = 100) -> PagedResponse:
        """GET /v3/captures/{capture_id}/network-logs"""
        raw = self._get(f"/captures/{capture_id}/network-logs", params={"page": page, "limit": limit})
        return PagedResponse(data=raw.get("data", []), pagination=Pagination.from_dict(raw.get("pagination", {})))

    # -----------------------------------------------------------------------
    # Asset Maps / Domain Surveys
    # -----------------------------------------------------------------------

    def list_surveys(self, page: int = 1, limit: int = 20) -> PagedResponse:
        """GET /v3/assetmaps/surveys"""
        raw = self._get("/assetmaps/surveys", params={"page": page, "limit": limit})
        return PagedResponse(data=raw.get("data", []), pagination=Pagination.from_dict(raw.get("pagination", {})))

    def create_survey(self, domain: str, tracked_subdomains: Optional[List[str]] = None, callback: Optional[dict] = None) -> DocumentResponse:
        """POST /v3/assetmaps/surveys"""
        body: dict = {"domain": domain}
        if tracked_subdomains:
            body["tracked_subdomains"] = tracked_subdomains
        if callback:
            body["callback"] = callback
        raw = self._post("/assetmaps/surveys", body=body)
        return DocumentResponse(data=raw.get("data"), links=raw.get("links", {}))

    def get_survey(self, survey_id: str) -> DocumentResponse:
        """GET /v3/assetmaps/surveys/{survey_id}"""
        raw = self._get(f"/assetmaps/surveys/{survey_id}")
        return DocumentResponse(data=raw.get("data"), links=raw.get("links", {}))

    def get_asset_map(self, survey_id: str) -> DocumentResponse:
        """GET /v3/assetmaps/surveys/{survey_id}/map"""
        raw = self._get(f"/assetmaps/surveys/{survey_id}/map")
        return DocumentResponse(data=raw.get("data"), links=raw.get("links", {}))

    # -----------------------------------------------------------------------
    # Cert Monitoring
    # -----------------------------------------------------------------------

    def list_monitored_domains(self, page: int = 1, limit: int = 20) -> PagedResponse:
        """GET /v3/cert-monitoring"""
        raw = self._get("/cert-monitoring", params={"page": page, "limit": limit})
        return PagedResponse(data=raw.get("data", []), pagination=Pagination.from_dict(raw.get("pagination", {})))

    def add_monitored_domain(self, domain: str) -> DocumentResponse:
        """POST /v3/cert-monitoring"""
        raw = self._post("/cert-monitoring", body={"domain": domain})
        return DocumentResponse(data=raw.get("data"), links=raw.get("links", {}))

    def get_monitored_domain(self, domain: str) -> DocumentResponse:
        """GET /v3/cert-monitoring/{domain}"""
        raw = self._get(f"/cert-monitoring/{domain}")
        return DocumentResponse(data=raw.get("data"), links=raw.get("links", {}))

    def remove_monitored_domain(self, domain: str) -> None:
        """DELETE /v3/cert-monitoring/{domain}"""
        self._delete(f"/cert-monitoring/{domain}")

    def list_certs_for_domain(self, domain: str, page: int = 1, limit: int = 20) -> PagedResponse:
        """GET /v3/cert-monitoring/{domain}/certs"""
        raw = self._get(f"/cert-monitoring/{domain}/certs", params={"page": page, "limit": limit})
        return PagedResponse(data=raw.get("data", []), pagination=Pagination.from_dict(raw.get("pagination", {})))

    # -----------------------------------------------------------------------
    # Permutations
    # -----------------------------------------------------------------------

    def list_permutations(self, page: int = 1, limit: int = 20) -> PagedResponse:
        """GET /v3/permutations"""
        raw = self._get("/permutations", params={"page": page, "limit": limit})
        return PagedResponse(data=raw.get("data", []), pagination=Pagination.from_dict(raw.get("pagination", {})))

    def create_permutation_check(self, domain: str, callback: Optional[dict] = None) -> DocumentResponse:
        """POST /v3/permutations"""
        body: dict = {"domain": domain}
        if callback:
            body["callback"] = callback
        raw = self._post("/permutations", body=body)
        return DocumentResponse(data=raw.get("data"), links=raw.get("links", {}))

    def get_permutation_check(self, check_id: str) -> DocumentResponse:
        """GET /v3/permutations/{check_id}"""
        raw = self._get(f"/permutations/{check_id}")
        return DocumentResponse(data=raw.get("data"), links=raw.get("links", {}))

    def get_permutation_report(self, check_id: str) -> dict:
        """GET /v3/permutations/{check_id}/report"""
        return self._get(f"/permutations/{check_id}/report")

    # -----------------------------------------------------------------------
    # Info
    # -----------------------------------------------------------------------

    def get_cve(self, cve_id: str) -> dict:
        """GET /v3/info/cves/{cve_id} — Full CVE document."""
        return self._get(f"/info/cves/{cve_id}")

    def get_top_tcp_ports(self, count: int) -> dict:
        """GET /v3/info/ports/tcp/{count} — Top N TCP ports."""
        return self._get(f"/info/ports/tcp/{count}")

    def get_top_udp_ports(self, count: int) -> dict:
        """GET /v3/info/ports/udp/{count} — Top N UDP ports."""
        return self._get(f"/info/ports/udp/{count}")

    def get_usage(self, page: int = 1, limit: int = 20) -> PagedResponse:
        """GET /v3/info/usage — Usage statistics by date."""
        raw = self._get("/info/usage", params={"page": page, "limit": limit})
        return PagedResponse(data=raw.get("data", []), pagination=Pagination.from_dict(raw.get("pagination", {})))

    # -----------------------------------------------------------------------
    # Limits
    # -----------------------------------------------------------------------

    def get_limits(self) -> dict:
        """GET /v3/limits — Your current plan limits."""
        return self._get("/limits")

    # -----------------------------------------------------------------------
    # Billing
    # -----------------------------------------------------------------------

    def get_billing_catalog(self) -> dict:
        """GET /v3/billing/catalog — Public plan catalog."""
        return self._get("/billing/catalog")

    def get_billing_status(self) -> dict:
        """GET /v3/billing/status — Your current billing status."""
        return self._get("/billing/status")

    # -----------------------------------------------------------------------
    # Tasks
    # -----------------------------------------------------------------------

    def list_tasks(self, page: int = 1, limit: int = 20) -> PagedResponse:
        """GET /v3/tasks"""
        raw = self._get("/tasks", params={"page": page, "limit": limit})
        return PagedResponse(data=raw.get("data", []), pagination=Pagination.from_dict(raw.get("pagination", {})))

    def create_task(self, target: str, task: str, callback: Optional[dict] = None) -> DocumentResponse:
        """POST /v3/tasks"""
        body: dict = {"target": target, "task": task}
        if callback:
            body["callback"] = callback
        raw = self._post("/tasks", body=body)
        return DocumentResponse(data=raw.get("data"), links=raw.get("links", {}))

    def get_available_tasks(self) -> dict:
        """GET /v3/tasks/available — Available task types."""
        return self._get("/tasks/available")

    def get_task(self, task_id: str) -> DocumentResponse:
        """GET /v3/tasks/{task_id}"""
        raw = self._get(f"/tasks/{task_id}")
        return DocumentResponse(data=raw.get("data"), links=raw.get("links", {}))

    def get_task_results(self, task_id: str) -> dict:
        """GET /v3/tasks/{task_id}/results — Task results (may be binary)."""
        return self._get(f"/tasks/{task_id}/results")

    # -----------------------------------------------------------------------
    # Rules
    # -----------------------------------------------------------------------

    def list_rules(self, page: int = 1, limit: int = 20) -> PagedResponse:
        """GET /v3/rules"""
        raw = self._get("/rules", params={"page": page, "limit": limit})
        return PagedResponse(data=raw.get("data", []), pagination=Pagination.from_dict(raw.get("pagination", {})))

    def create_rule(self, rule: dict) -> DocumentResponse:
        """POST /v3/rules"""
        raw = self._post("/rules", body=rule)
        return DocumentResponse(data=raw.get("data"), links=raw.get("links", {}))

    def evaluate_rule(self, rule: dict, data: dict) -> dict:
        """POST /v3/rules/evaluate — Test a rule against data without saving."""
        return self._post("/rules/evaluate", body={"rule": rule, "data": data})

    def get_rule(self, rule_id: str) -> DocumentResponse:
        """GET /v3/rules/{rule_id}"""
        raw = self._get(f"/rules/{rule_id}")
        return DocumentResponse(data=raw.get("data"), links=raw.get("links", {}))

    def delete_rule(self, rule_id: str) -> None:
        """DELETE /v3/rules/{rule_id}"""
        self._delete(f"/rules/{rule_id}")

    def get_rule_matches(self, rule_id: str, page: int = 1, limit: int = 20) -> PagedResponse:
        """GET /v3/rules/{rule_id}/matches"""
        raw = self._get(f"/rules/{rule_id}/matches", params={"page": page, "limit": limit})
        return PagedResponse(data=raw.get("data", []), pagination=Pagination.from_dict(raw.get("pagination", {})))
