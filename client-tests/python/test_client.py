#!/usr/bin/env python3
"""
Live integration tests for the Efflux v3 Python client.

Requires:
    export EFFLUX_API_KEY=your-key

Usage:
    python test_client.py
    python test_client.py --resource scans
    python test_client.py --verbose
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import traceback
from datetime import datetime, timezone
from typing import Any, Callable, Optional
from dataclasses import fields, is_dataclass

# Resolve migration-kit/python so `import efflux_v3` works without install.
_HERE = os.path.dirname(os.path.abspath(__file__))
_PYTHON_CLIENT = os.path.normpath(os.path.join(_HERE, "..", "..", "migration-kit", "python"))
sys.path.insert(0, _PYTHON_CLIENT)

from efflux_v3 import (  # noqa: E402
    EffluxV3Client,
    Job,
    JobReport,
    JobSummary,
    PagedResponse,
    DocumentResponse,
    RequestResults,
    ScanRequest,
)
from efflux_v3.exceptions import EffluxAPIError, EffluxNotFoundError  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

PASS = 0
FAIL = 0
SKIP = 0
VERBOSE = False
FAILURES: list[dict[str, Any]] = []


def log(msg: str) -> None:
    print(msg)


def vlog(msg: str) -> None:
    if VERBOSE:
        print(f"    {msg}")


def _jsonish(value: Any) -> str:
    try:
        return json.dumps(value, default=str, sort_keys=True)
    except TypeError:
        return repr(value)


def format_error_message(err: Exception | str) -> str:
    if isinstance(err, str):
        return err
    return str(err)


def failure_detail_lines(err: Exception | str, context: Any = None) -> list[str]:
    lines: list[str] = []
    if context is not None:
        lines.append(f"request: {_jsonish(context)}")
    if isinstance(err, EffluxAPIError):
        lines.append(f"status: {err.status_code}")
        if err.title:
            lines.append(f"title: {err.title}")
        if err.error_type:
            lines.append(f"type: {err.error_type}")
        if err.instance:
            lines.append(f"instance: {err.instance}")
        if err.field_errors:
            lines.append(f"field_errors: {_jsonish(err.field_errors)}")
        if err.rate_limit:
            lines.append(f"rate_limit: {_jsonish(err.rate_limit)}")
        if err.raw_body is not None:
            lines.append(f"body: {_jsonish(err.raw_body)}")
        elif err.detail:
            lines.append(f"detail: {err.detail}")
    elif isinstance(err, Exception):
        lines.append(f"exception: {type(err).__name__}")
        if str(err):
            lines.append(f"message: {err}")
    return lines


def ok(label: str, detail: str = "") -> None:
    global PASS
    PASS += 1
    suffix = f" — {detail}" if detail else ""
    log(f"  ✓ {label}{suffix}")


def fail(label: str, err: Exception | str, context: Any = None) -> None:
    global FAIL
    FAIL += 1
    msg = format_error_message(err)
    details = failure_detail_lines(err, context)
    FAILURES.append({"label": label, "message": msg, "details": details})
    log(f"  ✗ {label}: {msg}")
    for line in details:
        log(f"      {line}")
    if VERBOSE and isinstance(err, Exception):
        traceback.print_exc()


def skip(label: str, reason: str) -> None:
    global SKIP
    SKIP += 1
    log(f"  ○ {label}: skipped ({reason})")


def print_failure_summary() -> None:
    if not FAILURES:
        return
    log("\nFailures:")
    for item in FAILURES:
        log(f"  ✗ {item['label']}: {item['message']}")
        for line in item["details"]:
            log(f"      {line}")


def require_api_key() -> str:
    key = os.environ.get("EFFLUX_API_KEY", "").strip()
    if not key:
        print("ERROR: EFFLUX_API_KEY is not set.", file=sys.stderr)
        print("  export EFFLUX_API_KEY=your-api-key", file=sys.stderr)
        sys.exit(2)
    return key


def assert_type(value: Any, expected: type, name: str) -> None:
    if not isinstance(value, expected):
        raise AssertionError(f"{name}: expected {expected.__name__}, got {type(value).__name__}")


def assert_paged(response: Any, item_name: str = "item") -> list:
    assert_type(response, PagedResponse, "list response")
    assert_type(response.data, list, "response.data")
    assert hasattr(response, "pagination"), "response missing pagination"
    pag = response.pagination
    # Some list endpoints omit total/page on empty responses; require a pagination object only.
    vlog(
        f"{len(response.data)} {item_name}(s), "
        f"total={getattr(pag, 'total', None)}, page={getattr(pag, 'page', None)}"
    )
    return response.data


def assert_document(response: Any) -> Any:
    assert_type(response, DocumentResponse, "document response")
    if response.data is None:
        raise AssertionError("DocumentResponse.data is None")
    return response.data


def assert_dict_keys(obj: Any, required: list[str], label: str) -> dict:
    assert_type(obj, dict, label)
    missing = [k for k in required if k not in obj]
    if missing:
        raise AssertionError(f"{label} missing keys: {missing}")
    return obj


def assert_dataclass_instance(obj: Any, cls: type, label: str) -> None:
    assert_type(obj, cls, label)
    if not is_dataclass(obj):
        raise AssertionError(f"{label}: expected dataclass instance of {cls.__name__}")
    # Touch every field to ensure from_dict populated without raising
    for f in fields(obj):
        getattr(obj, f.name)


def created_at_key(item: Any) -> str:
    if isinstance(item, dict):
        return item.get("created_at") or item.get("updated_at") or ""
    return getattr(item, "created_at", "") or getattr(item, "updated_at", "") or ""


def pick_latest(items: list, id_getter: Callable[[Any], Optional[str]]) -> Optional[Any]:
    """Prefer newest by created_at; fall back to first item."""
    if not items:
        return None
    dated = [(created_at_key(i), i) for i in items if id_getter(i)]
    if not dated:
        return items[0]
    dated.sort(key=lambda t: t[0], reverse=True)
    return dated[0][1]


def status_of(item: Any) -> str:
    if isinstance(item, dict):
        return str(item.get("status") or "")
    return str(getattr(item, "status", "") or "")


def is_complete_status(status: str) -> bool:
    """All resources use status 'complete' when finished."""
    return status.lower() == "complete"


def find_complete(items: list) -> Optional[Any]:
    return next((i for i in items if is_complete_status(status_of(i))), None)


def job_id_from_409(detail: str) -> Optional[str]:
    """Extract job id from: '... already pending or in progress: scan_xxx'."""
    marker = ": "
    if marker not in detail:
        return None
    candidate = detail.rsplit(marker, 1)[-1].strip()
    return candidate or None


# ---------------------------------------------------------------------------
# Resource tests
# ---------------------------------------------------------------------------

def test_scans(client: EffluxV3Client) -> None:
    log("\n[scans]")

    # List / get / results first — before create, so we exercise an existing job.
    try:
        listed = client.list_scans(page=1, limit=5)
        items = assert_paged(listed, "scan")
        for job in items:
            assert_dataclass_instance(job, Job, "list item")
            if not job.job_id:
                raise AssertionError("Job.job_id is empty")
        ok("list_scans → PagedResponse[Job]", f"{len(items)} items")
    except Exception as e:
        fail("list_scans", e)
        items = []

    latest = pick_latest(items, lambda j: j.job_id) if items else None
    if not latest:
        skip("get_scan / results / summary", "no scans in account yet")
    else:
        job_id = latest.job_id
        vlog(f"latest job_id={job_id} status={latest.status}")

        try:
            doc = client.get_scan(job_id)
            job = assert_document(doc)
            assert_dataclass_instance(job, Job, "get_scan data")
            if job.job_id != job_id:
                raise AssertionError(f"job_id mismatch: {job.job_id} != {job_id}")
            ok("get_scan → DocumentResponse[Job]", job.status)
        except Exception as e:
            fail("get_scan", e)

        results_job_id = job_id
        if not is_complete_status(status_of(latest)):
            skip("get_scan_results / summary", f"latest status is {status_of(latest)!r}, not complete")
            complete = find_complete(items)
            if complete:
                results_job_id = complete.job_id
                vlog(f"using complete job_id={results_job_id}")
            else:
                results_job_id = None

        if results_job_id:
            try:
                report = client.get_scan_results(results_job_id)
                assert_dataclass_instance(report, JobReport, "get_scan_results")
                if report.job_id and report.job_id != results_job_id:
                    raise AssertionError(f"JobReport.job_id mismatch: {report.job_id}")
                assert_type(report.scan_results, dict, "scan_results")
                assert_type(report.domain_results, dict, "domain_results")
                assert_type(report.url_results, dict, "url_results")
                assert_type(report.check_results, list, "check_results")
                ok(
                    "get_scan_results → JobReport",
                    f"hosts={len(report.scan_results)} domains={len(report.domain_results)} "
                    f"urls={len(report.url_results)} checks={len(report.check_results)}",
                )
            except EffluxNotFoundError:
                skip("get_scan_results", "results not found (job may still be processing)")
            except Exception as e:
                fail("get_scan_results", e)

            try:
                summary = client.get_scan_summary(results_job_id)
                assert_dataclass_instance(summary, JobSummary, "get_scan_summary")
                assert_type(summary.ports, list, "summary.ports")
                assert_type(summary.services, list, "summary.services")
                assert_type(summary.hosts_per_country, dict, "summary.hosts_per_country")
                ok(
                    "get_scan_summary → JobSummary",
                    f"accessible_hosts={summary.accessible_host_count} ports={len(summary.ports)}",
                )
            except EffluxNotFoundError:
                skip("get_scan_summary", "summary not found")
            except Exception as e:
                fail("get_scan_summary", e)

    # Create last — so a new pending job does not block get/results above.
    try:
        create_resp = client.create_scan(ScanRequest(
            hosts=["1.1.1.1/32"],
            ports=["top_10"],
            fingerprint=True,
            tags=["client-test"],
            description="client-tests create_scan smoke",
        ))
        created = assert_document(create_resp)
        assert_dataclass_instance(created, RequestResults, "create_scan data")
        if not created.job_id:
            raise AssertionError("RequestResults.job_id is empty")
        if created.fingerprint is not True:
            raise AssertionError(f"fingerprint expected True, got {created.fingerprint!r}")
        if created.request_count < 1:
            raise AssertionError(f"request_count expected >= 1, got {created.request_count}")
        ok(
            "create_scan → DocumentResponse[RequestResults]",
            f"job_id={created.job_id} status={created.status} "
            f"hosts={created.host_count} ports={created.port_count} requests={created.request_count}",
        )
        vlog(f"rejected_hosts={created.rejected_hosts} rejected_ports={created.rejected_ports}")
    except EffluxAPIError as e:
        if e.status_code == 409:
            ok("create_scan → 409 duplicate (create accepted)", e.detail)
        else:
            fail("create_scan", e)
    except Exception as e:
        fail("create_scan", e)


def test_captures(client: EffluxV3Client) -> None:
    log("\n[captures]")
    items: list = []
    try:
        listed = client.list_captures(page=1, limit=5)
        items = assert_paged(listed, "capture")
        for item in items:
            assert_dict_keys(item, ["capture_id", "status"], "capture list item")
        ok("list_captures → PagedResponse", f"{len(items)} items")
    except Exception as e:
        fail("list_captures", e)

    latest = pick_latest(items, lambda c: c.get("capture_id")) if items else None
    if not latest:
        skip("get_capture / results", "no captures in account yet")
    else:
        capture_id = latest["capture_id"]
        vlog(f"latest capture_id={capture_id} status={latest.get('status')}")

        try:
            doc = client.get_capture(capture_id)
            data = assert_document(doc)
            assert_dict_keys(data, ["capture_id", "status"], "get_capture data")
            ok("get_capture → DocumentResponse", data.get("status", ""))
        except Exception as e:
            fail("get_capture", e)

        results_id = capture_id
        if not is_complete_status(str(latest.get("status") or "")):
            complete = find_complete(items)
            if not complete:
                skip("get_capture_results", f"latest status is {latest.get('status')!r}")
                results_id = None
            else:
                results_id = complete["capture_id"]

        if results_id:
            try:
                results = client.get_capture_results(results_id)
                assert_type(results, dict, "capture results")
                ok("get_capture_results → dict", f"keys={list(results.keys())[:8]}")
            except EffluxNotFoundError:
                skip("get_capture_results", "results not found")
            except Exception as e:
                fail("get_capture_results", e)

    try:
        doc = client.create_capture("https://efflux.io")
        data = assert_document(doc)
        assert_dict_keys(data, ["capture_id"], "create_capture data")
        ok("create_capture → DocumentResponse", f"capture_id={data.get('capture_id')} status={data.get('status', '')}")
    except EffluxAPIError as e:
        if e.status_code == 409:
            ok("create_capture → 409 duplicate (create accepted)", e.detail)
        else:
            fail("create_capture", e)
    except Exception as e:
        fail("create_capture", e)


def test_permutations(client: EffluxV3Client) -> None:
    log("\n[permutations]")
    items: list = []
    try:
        listed = client.list_permutations(page=1, limit=5)
        items = assert_paged(listed, "permutation")
        for item in items:
            assert_dict_keys(item, ["check_id"], "permutation list item")
        ok("list_permutations → PagedResponse", f"{len(items)} items")
    except Exception as e:
        fail("list_permutations", e)

    latest = pick_latest(items, lambda p: p.get("check_id")) if items else None
    if not latest:
        skip("get_permutation_check / report", "no permutations in account yet")
    else:
        check_id = latest["check_id"]
        vlog(f"latest check_id={check_id} status={latest.get('status')}")

        try:
            doc = client.get_permutation_check(check_id)
            data = assert_document(doc)
            assert_dict_keys(data, ["check_id"], "get_permutation_check data")
            ok("get_permutation_check → DocumentResponse", data.get("status", ""))
        except Exception as e:
            fail("get_permutation_check", e)

        report_id = check_id
        if not is_complete_status(str(latest.get("status") or "")):
            complete = find_complete(items)
            if not complete:
                skip("get_permutation_report", f"latest status is {latest.get('status')!r}")
                report_id = None
            else:
                report_id = complete["check_id"]

        if report_id:
            try:
                report = client.get_permutation_report(report_id)
                assert_type(report, dict, "permutation report")
                ok("get_permutation_report → dict", f"keys={list(report.keys())[:8]}")
            except EffluxNotFoundError:
                skip("get_permutation_report", "report not found")
            except Exception as e:
                fail("get_permutation_report", e)

    try:
        doc = client.create_permutation_check("efflux.io")
        data = assert_document(doc)
        assert_dict_keys(data, ["check_id"], "create_permutation_check data")
        ok(
            "create_permutation_check → DocumentResponse",
            f"check_id={data.get('check_id')} status={data.get('status', '')}",
        )
    except EffluxAPIError as e:
        if e.status_code == 409:
            ok("create_permutation_check → 409 duplicate (create accepted)", e.detail)
        else:
            fail("create_permutation_check", e)
    except Exception as e:
        fail("create_permutation_check", e)


def test_surveys(client: EffluxV3Client) -> None:
    log("\n[surveys / assetmaps]")
    items: list = []
    try:
        listed = client.list_surveys(page=1, limit=5)
        items = assert_paged(listed, "survey")
        for item in items:
            assert_dict_keys(item, ["survey_id"], "survey list item")
        ok("list_surveys → PagedResponse", f"{len(items)} items")
    except Exception as e:
        fail("list_surveys", e)

    latest = pick_latest(items, lambda s: s.get("survey_id")) if items else None
    if not latest:
        skip("get_survey / asset_map", "no surveys in account yet")
    else:
        survey_id = latest["survey_id"]
        vlog(f"latest survey_id={survey_id} status={latest.get('status')}")

        try:
            doc = client.get_survey(survey_id)
            data = assert_document(doc)
            assert_dict_keys(data, ["survey_id"], "get_survey data")
            ok("get_survey → DocumentResponse", data.get("status", ""))
        except Exception as e:
            fail("get_survey", e)

        map_id = survey_id
        if not is_complete_status(str(latest.get("status") or "")):
            complete = find_complete(items)
            if not complete:
                skip("get_asset_map", f"latest status is {latest.get('status')!r}")
                map_id = None
            else:
                map_id = complete["survey_id"]

        if map_id:
            try:
                doc = client.get_asset_map(map_id)
                data = assert_document(doc)
                assert_type(data, dict, "asset map data")
                ok("get_asset_map → DocumentResponse", f"keys={list(data.keys())[:8]}")
            except EffluxNotFoundError:
                skip("get_asset_map", "map not found")
            except Exception as e:
                fail("get_asset_map", e)

    try:
        doc = client.create_survey("efflux.io")
        data = assert_document(doc)
        assert_dict_keys(data, ["survey_id"], "create_survey data")
        ok("create_survey → DocumentResponse", f"survey_id={data.get('survey_id')} status={data.get('status', '')}")
    except EffluxAPIError as e:
        if e.status_code == 409:
            ok("create_survey → 409 duplicate (create accepted)", e.detail)
        else:
            fail("create_survey", e)
    except Exception as e:
        fail("create_survey", e)


def test_tasks(client: EffluxV3Client) -> None:
    log("\n[tasks]")
    items: list = []
    try:
        listed = client.list_tasks(page=1, limit=5)
        items = assert_paged(listed, "task")
        for item in items:
            assert_dict_keys(item, ["task_id"], "task list item")
        ok("list_tasks → PagedResponse", f"{len(items)} items")
    except Exception as e:
        fail("list_tasks", e)

    latest = pick_latest(items, lambda t: t.get("task_id")) if items else None
    if not latest:
        skip("get_task / results", "no tasks in account yet")
    else:
        task_id = latest["task_id"]
        vlog(f"latest task_id={task_id} status={latest.get('status')}")

        try:
            doc = client.get_task(task_id)
            data = assert_document(doc)
            assert_dict_keys(data, ["task_id"], "get_task data")
            ok("get_task → DocumentResponse", data.get("status", ""))
        except Exception as e:
            fail("get_task", e)

        results_id = task_id
        if not is_complete_status(str(latest.get("status") or "")):
            complete = find_complete(items)
            if not complete:
                skip("get_task_results", f"latest status is {latest.get('status')!r}")
                results_id = None
            else:
                results_id = complete["task_id"]

        if results_id:
            try:
                results = client.get_task_results(results_id)
                assert_type(results, dict, "task results")
                ok("get_task_results → dict", f"keys={list(results.keys())[:8]}")
            except EffluxNotFoundError:
                skip("get_task_results", "results not found")
            except Exception as e:
                fail("get_task_results", e)

    create_body = {"target": "efflux.io", "task": "dnsrules"}
    try:
        doc = client.create_task(target=create_body["target"], task=create_body["task"])
        data = assert_document(doc)
        assert_dict_keys(data, ["task_id"], "create_task data")
        ok("create_task → DocumentResponse", f"task_id={data.get('task_id')} status={data.get('status', '')}")
    except EffluxAPIError as e:
        if e.status_code == 409:
            ok("create_task → 409 duplicate (create accepted)", e.detail)
        else:
            fail("create_task", e, context=create_body)
    except Exception as e:
        fail("create_task", e, context=create_body)


def test_schedules(client: EffluxV3Client) -> None:
    log("\n[schedules]")
    try:
        listed = client.list_schedules(page=1, limit=5)
        items = assert_paged(listed, "schedule")
        for item in items:
            assert_dict_keys(item, ["schedule_id"], "schedule list item")
        ok("list_schedules → PagedResponse", f"{len(items)} items")
    except Exception as e:
        fail("list_schedules", e)
        return

    latest = pick_latest(items, lambda s: s.get("schedule_id"))
    if not latest:
        skip("get_schedule", "no schedules in account")
        return

    schedule_id = latest["schedule_id"]
    try:
        doc = client.get_schedule(schedule_id)
        data = assert_document(doc)
        assert_dict_keys(data, ["schedule_id"], "get_schedule data")
        ok("get_schedule → DocumentResponse", data.get("name", ""))
    except Exception as e:
        fail("get_schedule", e)


def test_host_lists(client: EffluxV3Client) -> None:
    log("\n[host lists]")
    items: list = []
    try:
        listed = client.list_host_lists(page=1, limit=5)
        items = assert_paged(listed, "host_list")
        for item in items:
            assert_dict_keys(item, ["list_id"], "host list item")
        ok("list_host_lists → PagedResponse", f"{len(items)} items")
    except Exception as e:
        fail("list_host_lists", e)

    latest = pick_latest(items, lambda h: h.get("list_id")) if items else None
    if not latest:
        skip("get_host_list", "no host lists in account yet")
    else:
        try:
            doc = client.get_host_list(latest["list_id"])
            data = assert_document(doc)
            assert_dict_keys(data, ["list_id"], "get_host_list data")
            ok("get_host_list → DocumentResponse", data.get("name", ""))
        except Exception as e:
            fail("get_host_list", e)

    created_list_id = None
    create_body = {"name": "client_test_hosts", "hosts": ["1.1.1.1"]}
    try:
        doc = client.create_host_list(create_body["name"], create_body["hosts"])
        data = assert_document(doc)
        assert_dict_keys(data, ["list_id"], "create_host_list data")
        created_list_id = data.get("list_id")
        ok(
            "create_host_list → DocumentResponse",
            f"list_id={created_list_id} name={data.get('name', '')}",
        )
    except EffluxAPIError as e:
        if e.status_code == 409:
            ok("create_host_list → 409 duplicate (create accepted)", e.detail)
        else:
            fail("create_host_list", e, context=create_body)
    except Exception as e:
        fail("create_host_list", e, context=create_body)

    if created_list_id:
        try:
            doc = client.get_host_list(created_list_id)
            data = assert_document(doc)
            assert_dict_keys(data, ["list_id"], "get created host_list data")
            ok("get_host_list (created) → DocumentResponse", data.get("name", ""))
        except Exception as e:
            fail("get_host_list (created)", e)

        try:
            client.delete_host_list(created_list_id)
            ok("delete_host_list → 204/ok", f"list_id={created_list_id}")
        except Exception as e:
            fail("delete_host_list", e)


def test_port_lists(client: EffluxV3Client) -> None:
    log("\n[port lists]")
    items: list = []
    try:
        listed = client.list_port_lists(page=1, limit=5)
        items = assert_paged(listed, "port_list")
        for item in items:
            assert_dict_keys(item, ["list_id"], "port list item")
        ok("list_port_lists → PagedResponse", f"{len(items)} items")
    except Exception as e:
        fail("list_port_lists", e)

    latest = pick_latest(items, lambda p: p.get("list_id")) if items else None
    if not latest:
        skip("get_port_list", "no port lists in account yet")
    else:
        try:
            doc = client.get_port_list(latest["list_id"])
            data = assert_document(doc)
            assert_dict_keys(data, ["list_id"], "get_port_list data")
            ok("get_port_list → DocumentResponse", data.get("name", ""))
        except Exception as e:
            fail("get_port_list", e)

    created_list_id = None
    create_body = {"name": "client_test_ports", "ports": ["22", "23"]}
    try:
        doc = client.create_port_list(create_body["name"], create_body["ports"])
        data = assert_document(doc)
        assert_dict_keys(data, ["list_id"], "create_port_list data")
        created_list_id = data.get("list_id")
        ok(
            "create_port_list → DocumentResponse",
            f"list_id={created_list_id} name={data.get('name', '')}",
        )
    except EffluxAPIError as e:
        if e.status_code == 409:
            ok("create_port_list → 409 duplicate (create accepted)", e.detail)
        else:
            fail("create_port_list", e, context=create_body)
    except Exception as e:
        fail("create_port_list", e, context=create_body)

    if created_list_id:
        try:
            doc = client.get_port_list(created_list_id)
            data = assert_document(doc)
            assert_dict_keys(data, ["list_id"], "get created port_list data")
            ok("get_port_list (created) → DocumentResponse", data.get("name", ""))
        except Exception as e:
            fail("get_port_list (created)", e)

        try:
            client.delete_port_list(created_list_id)
            ok("delete_port_list → 204/ok", f"list_id={created_list_id}")
        except Exception as e:
            fail("delete_port_list", e)


def test_rules(client: EffluxV3Client) -> None:
    log("\n[rules]")
    try:
        listed = client.list_rules(page=1, limit=5)
        items = assert_paged(listed, "rule")
        for item in items:
            assert_dict_keys(item, ["rule_id"], "rule list item")
        ok("list_rules → PagedResponse", f"{len(items)} items")
    except Exception as e:
        fail("list_rules", e)
        return

    latest = pick_latest(items, lambda r: r.get("rule_id"))
    if not latest:
        skip("get_rule", "no rules in account")
        return

    try:
        doc = client.get_rule(latest["rule_id"])
        data = assert_document(doc)
        assert_dict_keys(data, ["rule_id"], "get_rule data")
        ok("get_rule → DocumentResponse", data.get("name", data.get("rule_id", "")))
    except Exception as e:
        fail("get_rule", e)


def test_checks(client: EffluxV3Client) -> None:
    log("\n[checks]")
    try:
        listed = client.list_checks(page=1, limit=5)
        items = assert_paged(listed, "check")
        for item in items:
            # CheckResult dataclass when typed; may be dict depending on client path
            if hasattr(item, "check_name"):
                vlog(f"check={item.check_name} severity={item.severity}")
            elif isinstance(item, dict):
                assert_dict_keys(item, ["check_name"], "check list item")
            else:
                raise AssertionError(f"unexpected check item type: {type(item)}")
        ok("list_checks → PagedResponse", f"{len(items)} items")
    except Exception as e:
        fail("list_checks", e)


def test_cert_monitoring(client: EffluxV3Client) -> None:
    log("\n[cert-monitoring]")
    try:
        listed = client.list_monitored_domains(page=1, limit=5)
        items = assert_paged(listed, "monitored_domain")
        for item in items:
            assert_dict_keys(item, ["domain"], "cert-monitoring list item")
        ok("list_monitored_domains → PagedResponse", f"{len(items)} items")
    except Exception as e:
        fail("list_monitored_domains", e)
        return

    latest = pick_latest(items, lambda d: d.get("domain"))
    if not latest:
        skip("get_monitored_domain / certs", "no monitored domains")
        return

    domain = latest["domain"]
    try:
        doc = client.get_monitored_domain(domain)
        data = assert_document(doc)
        assert_dict_keys(data, ["domain"], "get_monitored_domain data")
        ok("get_monitored_domain → DocumentResponse", domain)
    except Exception as e:
        fail("get_monitored_domain", e)

    try:
        certs = client.list_certs_for_domain(domain, page=1, limit=5)
        assert_paged(certs, "cert")
        ok("list_certs_for_domain → PagedResponse", f"{len(certs.data)} certs")
    except Exception as e:
        fail("list_certs_for_domain", e)


def test_limits(client: EffluxV3Client) -> None:
    log("\n[limits]")
    try:
        limits = client.get_limits()
        assert_type(limits, dict, "limits")
        # DocumentResponse-style or raw; accept either
        data = limits.get("data", limits) if isinstance(limits, dict) else limits
        assert_type(data, dict, "limits data")
        ok("get_limits → dict", f"keys={list(data.keys())[:8]}")
    except Exception as e:
        fail("get_limits", e)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

RESOURCES: dict[str, Callable[[EffluxV3Client], None]] = {
    "scans": test_scans,
    "captures": test_captures,
    "permutations": test_permutations,
    "surveys": test_surveys,
    "tasks": test_tasks,
    "schedules": test_schedules,
    "host-lists": test_host_lists,
    "port-lists": test_port_lists,
    "rules": test_rules,
    "checks": test_checks,
    "cert-monitoring": test_cert_monitoring,
    "limits": test_limits,
}


def main() -> int:
    global VERBOSE

    parser = argparse.ArgumentParser(description="Test Efflux v3 Python client against live API")
    parser.add_argument(
        "--resource",
        choices=sorted(RESOURCES.keys()) + ["all"],
        default="all",
        help="Resource type to test (default: all)",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()
    VERBOSE = args.verbose

    api_key = require_api_key()
    client = EffluxV3Client(
        api_key=api_key,
        default_headers={
            "User-Agent": "Efflux-Online/1.0 (Web Client)",
            "X-Proxy-Source": "nextjs",
        },
    )

    log(f"Efflux v3 Python client test — {datetime.now(timezone.utc).isoformat()}")
    log(f"Base URL: {client.base_url}")
    log(f"Resource: {args.resource}")

    # Smoke: auth works
    try:
        client.get_limits()
        ok("auth / connectivity (GET /limits)")
    except EffluxAPIError as e:
        fail("auth / connectivity", e)
        log("\nAborting: could not authenticate.")
        return 1

    names = list(RESOURCES.keys()) if args.resource == "all" else [args.resource]
    for name in names:
        RESOURCES[name](client)

    log("\n" + "=" * 60)
    log(f"Results: {PASS} passed, {FAIL} failed, {SKIP} skipped")
    print_failure_summary()
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
