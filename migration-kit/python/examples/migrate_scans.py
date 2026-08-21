"""
Efflux API: v2 → v3 Scan Migration Examples

This file shows side-by-side v2 and v3 patterns for every common scan operation.
Run these examples against the v3 API by setting your API key.

    python examples/migrate_scans.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from efflux_v3 import (
    EffluxV3Client,
    ScanRequest,
    CallbackRequest,
    CallbackEvent,
    ChecksOptions,
)
from efflux_v3.exceptions import EffluxAPIError, EffluxRateLimitError, EffluxNotFoundError

API_KEY = os.environ.get("EFFLUX_API_KEY", "your-api-key-here")
client = EffluxV3Client(api_key=API_KEY)


# =============================================================================
# 1. CREATING A SCAN JOB
# =============================================================================

def example_create_scan():
    """Creating a basic scan job."""

    # --- v2 (requests library) ---
    # import requests
    # response = requests.post(
    #     "https://api.effluxio.com/api/v2/scans",
    #     headers={"Authorization": API_KEY},
    #     json={
    #         "hosts": ["10.0.0.0/24"],
    #         "ports": ["80", "443", "8080"],
    #         "fingerprint": 2,             # integer: 0/1/2
    #         "checks": True,
    #         "checks_opts": {              # field was checks_opts
    #             "min_severity": "medium",
    #             "cves_only": False,
    #         },
    #     }
    # )
    # result = response.json()              # raw object (no envelope)
    # job_id = result["job_id"]
    # status = result["status"]

    # --- v3 ---
    response = client.create_scan(ScanRequest(
        hosts=["10.0.0.0/24"],
        ports=["80", "443", "8080"],
        fingerprint=True,                 # boolean (not integer)
        checks=True,
        checks_options=ChecksOptions(     # renamed from checks_opts; simplified
            min_severity="medium",
            cves_only=False,
        ),
        tags=["example"],                 # new: optional metadata
        description="Migration example scan",
    ))

    # v3: access .data on the response envelope
    job_id = response.data.job_id
    status = response.data.status
    request_count = response.data.request_count

    print(f"Created job: {job_id} (status={status}, requests={request_count})")

    # Check for rejected inputs (same field names as v2)
    if response.data.rejected_hosts:
        print(f"Rejected hosts: {response.data.rejected_hosts}")

    return job_id


# =============================================================================
# 2. SCANNING WITH A CALLBACK
# =============================================================================

def example_create_scan_with_callback():
    """Creating a scan with webhook callbacks."""

    # --- v2 ---
    # json={
    #     "hosts": ["10.0.0.1"],
    #     "ports": ["443"],
    #     "callback": {
    #         "start_url": "https://myapp.com/hook/start?job=$job_id",
    #         "start_method": "POST",
    #         "success_url": "https://myapp.com/hook/done?job=$job_id",
    #         "success_method": "POST",
    #         "fail_url": "https://myapp.com/hook/fail",
    #         "fail_method": "GET",
    #         "email": False,              # removed in v3
    #         "summary_only": False,       # removed in v3
    #     }
    # }

    # --- v3: nested callback objects ---
    response = client.create_scan(ScanRequest(
        hosts=["10.0.0.1"],
        ports=["443"],
        callback=CallbackRequest(
            start=CallbackEvent(
                url="https://myapp.com/hook/start?job=$job_id",
                method="POST",
            ),
            success=CallbackEvent(
                url="https://myapp.com/hook/done?job=$job_id",
                method="POST",
            ),
            fail=CallbackEvent(
                url="https://myapp.com/hook/fail",
                method="GET",
            ),
        ),
    ))
    print(f"Created job with callbacks: {response.data.job_id}")
    return response.data.job_id


# =============================================================================
# 3. EVALUATING A SCAN (DRY RUN)
# =============================================================================

def example_eval_scan():
    """Preview scan scope without executing."""

    # --- v2 ---
    # response = requests.post("https://api.effluxio.com/api/v2/scans/eval", ...)
    # result = response.json()   # raw object

    # --- v3 ---
    response = client.eval_scan(ScanRequest(
        hosts=["10.0.0.0/8"],
        ports=["top_100"],
        checks=True,
    ))
    result = response.data  # access .data

    print(f"Would scan {result.host_count} hosts × {result.port_count} ports")
    print(f"Estimated requests: {result.request_count}")
    if result.rejected_hosts:
        print(f"Rejected hosts: {result.rejected_hosts}")


# =============================================================================
# 4. GETTING JOB STATUS
# =============================================================================

def example_get_job_status(job_id: str):
    """Getting job status — v3 returns status only, NOT results."""

    # --- v2 ---
    # response = requests.get(f"https://api.effluxio.com/api/v2/scans/{job_id}", ...)
    # result = response.json()  # contained BOTH status AND full results
    # status = result["status"]
    # results = result["results"]  # scan results were inline in v2

    # --- v3: status only ---
    response = client.get_scan(job_id)
    job = response.data

    print(f"Job {job.job_id}: status={job.status}")
    print(f"  Accessible hosts: {job.accessible_host_count}")
    print(f"  Accessible ports: {job.accessible_port_count}")
    print(f"  Checks matched: {job.checks_matched}")

    # Convenience properties
    if job.is_running:
        print("  Still running...")
    elif job.is_complete:
        print("  Done!")
    elif job.is_failed:
        print("  Failed.")


# =============================================================================
# 5. GETTING SCAN RESULTS (split from status in v3)
# =============================================================================

def example_get_results(job_id: str):
    """Getting full scan results — now a separate endpoint in v3."""

    # --- v2 ---
    # GET /scans/{job_id} returned everything including results inline:
    # result = response.json()
    # for host, host_data in result["results"].items():        # field was "results"
    #     for port, port_data in host_data["ports"].items():
    #         if port_data["open"]:
    #             print(f"{host}:{port} - {port_data['service']}")
    #
    # for domain, domain_data in result["domain_info"].items():  # field was "domain_info"
    #     print(f"{domain}: {domain_data['dns']['a']}")
    #
    # for url_result in result["url_info"]:                     # was an ARRAY
    #     print(url_result["requested_url"])
    #
    # for check in host_data["ports"][port]["checks"]:  # checks were per-port in v2
    #     print(check["check_name"])

    # --- v3 ---
    # Step 1: Confirm job is complete (optional but recommended)
    job_response = client.get_scan(job_id)
    job = job_response.data
    if not job.is_complete:
        print(f"Job not complete yet: {job.status}")
        return

    # Step 2: Fetch results from dedicated endpoint
    report = client.get_scan_results(job_id)

    # scan_results replaces "results" — same structure otherwise
    for host, host_status in report.scan_results.items():
        if host_status.metadata:
            print(f"\nHost {host} ({host_status.metadata.country}, ASN: {host_status.metadata.asn})")

        for port_str, scan_result in host_status.ports.items():
            if scan_result.open:
                print(f"  {port_str}/tcp: {scan_result.service} {scan_result.software} {scan_result.version}")
                if scan_result.tls:
                    print(f"    TLS: yes")
                if scan_result.http_info:
                    print(f"    HTTP status: {scan_result.http_info.status_code}")

    # domain_results replaces "domain_info"
    for domain, domain_info in report.domain_results.items():
        print(f"\nDomain {domain}:")
        if domain_info.a:
            print(f"  A: {domain_info.a}")
        if domain_info.mx:
            print(f"  MX: {domain_info.mx}")

    # url_results replaces "url_info" — now a dict (not an array!)
    for url, url_result in report.url_results.items():   # iterate dict items, not an array
        print(f"\nURL {url}: status {url_result.status_code}")

    # check_results is new in v3 — top-level array across all hosts
    for check in report.check_results:
        print(f"\nCheck match: [{check.severity}] {check.check_name}")
        print(f"  Host: {check.host}:{check.port}")    # context fields new in v3
        print(f"  CVEs: {check.cve_id}")
        print(f"  CVSS: {check.cvss_score}")


# =============================================================================
# 6. GETTING A SCAN SUMMARY (new in v3)
# =============================================================================

def example_get_summary(job_id: str):
    """
    Get aggregated statistics without the full result payload.
    New in v3 — no equivalent existed in v2.
    Use this when you need counts/lists, not per-host detail.
    """
    summary = client.get_scan_summary(job_id)

    print(f"Job {summary.job_id} summary:")
    print(f"  Accessible hosts: {summary.accessible_host_count}")
    print(f"  Accessible ports: {summary.accessible_port_count}")
    print(f"  Checks matched: {summary.checks_matched}")
    print(f"  Open ports: {summary.ports}")
    print(f"  Services: {summary.services}")
    print(f"  Software: {summary.software}")
    print(f"  ASNs: {summary.asns}")
    print(f"  Countries: {summary.hosts_per_country}")


# =============================================================================
# 7. LISTING SCAN JOBS
# =============================================================================

def example_list_jobs():
    """Listing jobs — v3 uses page/limit pagination."""

    # --- v2 ---
    # GET /scans?count=50
    # response = requests.get(..., params={"count": 50})
    # jobs = response.json()   # raw array, no pagination info

    # --- v3 ---
    response = client.list_scans(page=1, limit=50)
    print(f"Page 1 of {response.pagination.total_pages} ({response.pagination.total} total jobs)")

    for job in response.data:
        print(f"  {job.job_id}: {job.status} — {job.created_at}")

    # Fetch next page
    if response.pagination.has_next:
        next_page = client.list_scans(page=2, limit=50)
        print(f"Page 2 has {len(next_page.data)} more jobs")

    # Or iterate all jobs automatically
    print("\nAll jobs:")
    for job in client.list_all_scans(limit=100):
        print(f"  {job.job_id}: {job.status}")


# =============================================================================
# 8. REPEATING A JOB
# =============================================================================

def example_repeat_job(job_id: str):
    """Repeat a previous job — path changed in v3."""

    # --- v2 ---
    # POST /scans/repeat/{job_id}
    # response = requests.post(f".../scans/repeat/{job_id}", ...)
    # result = response.json()  # raw object, HTTP 200

    # --- v3 ---
    # POST /scans/{job_id}/repeat   <-- path changed
    response = client.repeat_scan(job_id)
    # Returns HTTP 201 + DocumentResponse (access .data)
    new_job_id = response.data.job_id
    print(f"Repeated as new job: {new_job_id}")


# =============================================================================
# 9. POLLING (replacing /subscribe)
# =============================================================================

def example_polling(job_id: str):
    """
    Wait for a job to complete.
    v2 had a /subscribe long-poll (up to 120s). v3 removed it.
    Use wait_for_job() for simple polling, or WebSocket for live results.
    """

    # --- v2 ---
    # GET /scans/{job_id}/subscribe?timeout=120
    # response = requests.get(f".../scans/{job_id}/subscribe", params={"timeout": 120})
    # result = response.json()  # returned when complete or after timeout

    # --- v3: poll status endpoint ---
    job = client.wait_for_job(job_id, poll_interval=5.0, timeout=3600.0)
    print(f"Job complete: {job.status}")

    # Or submit and wait in one call:
    job, report = client.run_scan_and_wait(ScanRequest(
        hosts=["192.168.1.0/24"],
        ports=["22", "80", "443"],
    ))
    print(f"Found {report.accessible_host_count} hosts with {report.accessible_port_count} open ports")


# =============================================================================
# 10. ERROR HANDLING
# =============================================================================

def example_error_handling():
    """Error handling — v3 uses RFC 7807 Problem Details instead of {error: string}."""

    # --- v2 error format ---
    # { "error": "no valid ports provided" }

    # --- v3 error format ---
    # {
    #   "type": "...",
    #   "title": "Validation Error",
    #   "status": 400,
    #   "detail": "no valid ports provided",
    #   "errors": [{"field": "ports", "message": "no valid ports provided"}]
    # }

    from efflux_v3.exceptions import (
        EffluxValidationError,
        EffluxRateLimitError,
        EffluxNotFoundError,
        EffluxAuthError,
    )

    try:
        # Intentionally invalid request
        client.create_scan(ScanRequest(hosts=["not-a-valid-cidr!!!"], ports=[]))
    except EffluxValidationError as e:
        # 400 — read detail (not "error" key like in v2)
        print(f"Validation failed: {e.detail}")
        for field, msg in e.fields.items():
            print(f"  Field '{field}': {msg}")

    try:
        client.get_scan("nonexistent-job-id")
    except EffluxNotFoundError as e:
        print(f"Not found: {e.detail}")

    try:
        client.list_scans()
    except EffluxRateLimitError as e:
        print(f"Rate limited. Retry in {e.retry_after_seconds}s (resets at {e.reset_at})")

    # Generic API error handling
    try:
        client.create_scan(ScanRequest(hosts=["1.2.3.4"]))
    except EffluxAPIError as e:
        print(f"HTTP {e.status_code}: {e.detail}")
        if e.field_errors:
            print(f"Field errors: {e.field_errors}")


# =============================================================================
# 11. CHECKS QUERY (new in v3)
# =============================================================================

def example_checks_query():
    """
    Query vulnerability check results across all jobs.
    New in v3 — in v2 you had to iterate job results to find checks.
    """
    # Get all critical/high findings from the last week
    response = client.list_checks(
        severity="critical",
        min_date="2026-08-13T00:00:00Z",
        limit=100,
    )
    print(f"Found {response.pagination.total} critical checks")
    for check in response.data:
        print(f"  [{check.severity}] {check.check_name} — {check.host}:{check.port}")
        if check.cve_id:
            print(f"    CVEs: {', '.join(check.cve_id)}")


# =============================================================================
# Run examples
# =============================================================================

if __name__ == "__main__":
    print("=== Eval (dry-run) ===")
    example_eval_scan()

    print("\n=== Create scan ===")
    job_id = example_create_scan()

    print("\n=== List jobs ===")
    example_list_jobs()

    print("\n=== Get status ===")
    example_get_job_status(job_id)

    print("\n=== Wait for completion ===")
    try:
        import time
        job = client.wait_for_job(job_id, poll_interval=10.0, timeout=300.0)
        print(f"Job finished: {job.status}")

        print("\n=== Full results ===")
        example_get_results(job_id)

        print("\n=== Summary ===")
        example_get_summary(job_id)

        print("\n=== Repeat job ===")
        example_repeat_job(job_id)
    except TimeoutError:
        print("Job timed out — check status manually")

    print("\n=== Error handling ===")
    example_error_handling()

    print("\n=== Checks query ===")
    example_checks_query()
