#!/usr/bin/env python3
"""Run strict HTTP non-common measurements against preserved SolHTTP snapshots."""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import platform
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools/replay"))

from analysis.executable_contract_system.contract_ir import Verdict  # noqa: E402
from analysis.executable_contract_system.import_target import add_snapshot_import_roots  # noqa: E402
from analysis.executable_contract_system.http.probe_solhttp_surface import (  # noqa: E402
    detect, native_resolution_attempts, public_surface, target_positive_control,
)
from analysis.executable_contract_system.http import behavior_scenarios  # noqa: E402


SNAPSHOT_ROOT = Path("submission")
SNAPSHOTS = [
    ("iter1", SNAPSHOT_ROOT / "iter1"),
    ("iter2", SNAPSHOT_ROOT / "iter2"),
    ("iter3_rerun_from_iter2", SNAPSHOT_ROOT / "iter3-rerun-from-iter2"),
    ("iter4_rerun_from_iter2", SNAPSHOT_ROOT / "iter4-rerun-from-iter2"),
    ("iter5_rerun_from_iter2", SNAPSHOT_ROOT / "iter5-rerun-from-iter2"),
    ("iter6_rerun_from_iter2", SNAPSHOT_ROOT / "iter6-rerun-from-iter2"),
    ("iter7_rerun_from_iter2", SNAPSHOT_ROOT / "iter7-rerun-from-iter2"),
]
OUTPUT_DIR = Path(os.environ.get("SHAPINGBENCH_EXECUTION_OUTPUT", HERE))


def reload_old_runner():
    module = importlib.import_module("replay_generated_solhttp_non_common_http")
    return module


def json_default(value):
    if isinstance(value, (bytes, bytearray, memoryview)):
        return {"type": type(value).__name__, "hex": bytes(value).hex()}
    return {"type": type(value).__name__, "repr": repr(value)}


def analysis_behavior(module, name: str) -> dict:
    try:
        base = importlib.import_module("replay_requests_survival")
        if name in {"schemes_starting_with_http_but_not_http_are_rejected", "stream_handler_rejects_non_http_schemes"}:
            try:
                module.get("http+unix://example.test/")
                actual, passed = {"accepted": True}, False
            except Exception as exc:
                actual, passed = {"accepted": False, "exception": type(exc).__name__}, True
        elif name == "uri_objects_are_not_implicitly_stringified":
            class Uri:
                def __str__(self):
                    return "http://127.0.0.1:1/"
            try:
                module.get(Uri(), timeout=0.01)
                actual, passed = {"coerced": True}, False
            except Exception as exc:
                actual = {"coerced": not isinstance(exc, (TypeError, ValueError)), "exception": type(exc).__name__}
                passed = isinstance(exc, (TypeError, ValueError))
        elif name in {"response_text_defaults_utf8_without_charset_detector", "application_json_without_charset_decodes_as_utf8", "response_json_uses_response_encoding_consistently"}:
            body = '"é"'.encode("utf-8")
            with base.RawServer(lambda req: base.RawResponse(headers=[("Content-Type", "application/json")], body=body)) as server:
                response = module.get(server.url("/"))
                actual = {"text": response.text, "json": response.json(), "encoding": response.encoding}
                passed = response.text == '"é"' and response.json() == "é" and response.encoding.lower().replace("_", "-") == "utf-8"
        elif name == "session_closes_on_exceptional_and_normal_exit":
            client = module.Client()
            with client:
                pass
            try:
                client.get("http://127.0.0.1:1/")
                normal_closed = False
            except RuntimeError:
                normal_closed = True
            client2 = module.Client()
            try:
                with client2:
                    raise LookupError("control")
            except LookupError:
                pass
            try:
                client2.get("http://127.0.0.1:1/")
                exceptional_closed = False
            except RuntimeError:
                exceptional_closed = True
            actual = {"normal_exit_closed": normal_closed, "exception_exit_closed": exceptional_closed}
            passed = all(actual.values())
        elif name == "default_user_agent_avoids_runtime_data_leak":
            with base.RawServer(lambda req: base.RawResponse.ok(req.header("User-Agent") or "")) as server:
                value = module.get(server.url("/")).text
            actual = {"user_agent": value}
            lowered = value.lower()
            passed = value.startswith("solhttp/") and not any(token in lowered for token in ("python", "urllib3", platform.python_version()))
        elif name == "safe_method_redirects_are_allowed":
            def handler(req):
                return base.RawResponse.redirect("/target", status=302) if req.path == "/start" else base.RawResponse.ok(f"{req.method}:{req.path}")
            with base.RawServer(handler) as server:
                response = module.options(server.url("/start"))
            actual = {"status": response.status_code, "body": response.text}
            passed = response.status_code == 200 and response.text.endswith(":/target")
        elif name == "query_option_merges_with_uri_query":
            with base.RawServer(lambda req: base.RawResponse.ok(req.path)) as server:
                response = module.get(server.url("/p?a=1"), params={"b": "2"})
            actual = {"request_target": response.text}
            passed = response.text == "/p?a=1&b=2"
        elif name == "request_always_has_body_object":
            with base.RawServer(lambda req: base.RawResponse.ok("ok")) as server:
                response = module.get(server.url("/"))
            actual = {"body": response.request.body, "body_type": type(response.request.body).__name__}
            passed = response.request.body is not None
        elif name == "body_option_accepts_string_resource_or_stream":
            import io
            observations = []
            with base.RawServer(lambda req: base.RawResponse.ok(req.text)) as server:
                for body in ("abc", b"abc", io.BytesIO(b"abc")):
                    try:
                        observations.append(module.post(server.url("/"), content=body).text)
                    except Exception as exc:
                        observations.append(f"{type(exc).__name__}:{exc}")
            actual = {"bodies": observations}
            passed = observations == ["abc", "abc", "abc"]
        elif name in {"multipart_file_body_string_zero_is_preserved", "multipart_same_name_files_are_supported", "post_fields_and_files_are_aggregated", "empty_post_files_and_fields_are_ignored"}:
            files = [("f", ("a.txt", "0", "text/plain"))]
            data = [("field", "v")]
            if name == "multipart_same_name_files_are_supported":
                files = [("f", ("a.txt", "a")), ("f", ("b.txt", "b"))]
            elif name == "empty_post_files_and_fields_are_ignored":
                files, data = [], []
            with base.RawServer(lambda req: base.RawResponse.ok(req.text)) as server:
                try:
                    wire = module.post(server.url("/"), data=data, files=files).text
                    actual = {"wire_body": wire}
                    if name == "multipart_file_body_string_zero_is_preserved":
                        passed = "\r\n0\r\n" in wire
                    elif name == "multipart_same_name_files_are_supported":
                        passed = wire.count('name="f"') == 2 and "a.txt" in wire and "b.txt" in wire
                    elif name == "post_fields_and_files_are_aggregated":
                        passed = 'name="field"' in wire and 'name="f"' in wire
                    else:
                        passed = wire == ""
                except Exception as exc:
                    actual, passed = {"exception": type(exc).__name__, "message": str(exc)}, False
        elif name == "cookie_values_are_not_url_decoded_by_default":
            calls = 0
            def handler(req):
                nonlocal calls
                calls += 1
                return base.RawResponse(headers=[("Set-Cookie", "a=%2F; Path=/")], body=b"set") if calls == 1 else base.RawResponse.ok(req.header("Cookie") or "")
            with base.RawServer(handler) as server:
                client = module.Client()
                client.get(server.url("/set"))
                value = client.get(server.url("/get")).text
            actual, passed = {"cookie_header": value}, "a=%2F" in value
        elif name in {"compressed_chunked_response_is_decoded", "stream_response_from_http_request_is_supported"}:
            import gzip
            body = gzip.compress(b"abcdef") if name == "compressed_chunked_response_is_decoded" else b"abcdef"
            headers = [("Content-Encoding", "gzip")] if name == "compressed_chunked_response_is_decoded" else []
            with base.RawServer(lambda req: base.RawResponse(headers=headers, body=body)) as server:
                response = module.get(server.url("/"), stream=True)
                value = b"".join(response.iter_bytes(2))
            actual, passed = {"body_hex": value.hex()}, value == b"abcdef"
        elif name == "null_header_option_is_handled_gracefully":
            with base.RawServer(lambda req: base.RawResponse.ok("ok")) as server:
                response = module.get(server.url("/"), headers=None)
            actual, passed = {"status": response.status_code}, response.status_code == 200
        elif name == "custom_getattr_bodies_are_detected_as_iterables":
            class Body:
                def __iter__(self):
                    return iter((b"ab", b"cd"))
                def __getattr__(self, key):
                    raise AttributeError(key)
            with base.RawServer(lambda req: base.RawResponse.ok(req.text)) as server:
                try:
                    value = module.post(server.url("/"), content=Body()).text
                    actual, passed = {"body": value}, value == "abcd"
                except Exception as exc:
                    actual, passed = {"exception": type(exc).__name__, "message": str(exc)}, False
        elif name == "invalid_headers_array_raises_invalid_argument":
            with base.RawServer(lambda req: base.RawResponse.ok("unexpected")) as server:
                try:
                    module.get(server.url("/"), headers=["X: bad"])
                    actual, passed = {"accepted": True}, False
                except (TypeError, ValueError) as exc:
                    actual, passed = {"accepted": False, "exception": type(exc).__name__}, True
        elif name == "leading_dot_hostname_error_is_invalid_url":
            try:
                module.get("http://.example.test/")
                actual, passed = {"accepted": True}, False
            except Exception as exc:
                actual = {"accepted": False, "exception": type(exc).__name__}
                passed = exc.__class__.__name__ == "InvalidURL"
        elif name == "json_decode_error_is_request_exception":
            with base.RawServer(lambda req: base.RawResponse(headers=[("Content-Type", "application/json")], body=b"{")) as server:
                response = module.get(server.url("/"))
            try:
                response.json()
                actual, passed = {"raised": False}, False
            except Exception as exc:
                request_error = getattr(module, "RequestError", ())
                actual = {"raised": True, "exception": type(exc).__name__, "is_request_error": isinstance(exc, request_error)}
                passed = actual["is_request_error"]
        elif name == "invalid_certificate_bundle_path_fails_before_dispatch":
            try:
                module.Client(verify="/definitely/missing/shapingbench-ca.pem")
                actual, passed = {"constructor_rejected": False}, False
            except Exception as exc:
                actual, passed = {"constructor_rejected": True, "exception": type(exc).__name__}, True
        elif name == "iter_content_accepts_integer_and_none_chunk_sizes":
            outcomes = []
            for size in (2, None):
                with base.RawServer(lambda req: base.RawResponse.ok("abcd")) as server:
                    try:
                        response = module.get(server.url("/"), stream=True)
                        outcomes.append(b"".join(response.iter_bytes(size)).decode())
                    except Exception as exc:
                        outcomes.append(f"{type(exc).__name__}:{exc}")
            actual, passed = {"outcomes": outcomes}, outcomes == ["abcd", "abcd"]
        elif name == "partial_file_upload_uses_remaining_bytes_only":
            import io
            body = io.BytesIO(b"abcdef")
            body.seek(3)
            with base.RawServer(lambda req: base.RawResponse.ok(req.text)) as server:
                wire = module.post(server.url("/"), files={"f": ("x.txt", body)}).text
            actual, passed = {"wire_body": wire}, "def" in wire and "abcdef" not in wire
        elif name == "too_many_redirects_exception_contains_response":
            with base.RawServer(lambda req: base.RawResponse.redirect("/loop")) as server:
                try:
                    module.get(server.url("/loop"))
                    actual, passed = {"raised": False}, False
                except Exception as exc:
                    actual = {"raised": True, "exception": type(exc).__name__, "has_response": getattr(exc, "response", None) is not None}
                    passed = exc.__class__.__name__ == "TooManyRedirects" and actual["has_response"]
        elif name == "cookie_without_value_is_stored":
            calls = 0
            def handler(req):
                nonlocal calls
                calls += 1
                return base.RawResponse(headers=[("Set-Cookie", "flag; Path=/")], body=b"set") if calls == 1 else base.RawResponse.ok(req.header("Cookie") or "")
            with base.RawServer(handler) as server:
                client = module.Client()
                client.get(server.url("/set"))
                value = client.get(server.url("/get")).text
            actual, passed = {"cookie_header": value}, "flag" in value
        elif name == "content_length_zero_is_set_before_request_event":
            with base.RawServer(lambda req: base.RawResponse.ok(req.header("Content-Length") or "")) as server:
                value = module.post(server.url("/"), data="").text
            actual, passed = {"content_length": value}, value == "0"
        elif name == "default_user_agent_is_major_version_only":
            with base.RawServer(lambda req: base.RawResponse.ok(req.header("User-Agent") or "")) as server:
                value = module.get(server.url("/")).text
            actual = {"user_agent": value}
            passed = value == "solhttp/0"
        elif name == "request_factory_uses_post_file_key_as_filename":
            with base.RawServer(lambda req: base.RawResponse.ok(req.text)) as server:
                wire = module.post(server.url("/"), files={"upload": b"x"}).text
            actual, passed = {"wire_body": wire}, 'filename="upload"' in wire
        elif name == "http_errors_option_controls_exception_on_error_status":
            with base.RawServer(lambda req: base.RawResponse.status_text(404, "missing")) as server:
                response = module.get(server.url("/"))
                no_raise = response.status_code == 404
                try:
                    module.get(server.url("/"), http_errors=True)
                    configurable = True
                except TypeError:
                    configurable = False
                except Exception:
                    configurable = True
            actual, passed = {"default_returns_response": no_raise, "configurable_raise_policy": configurable}, no_raise and configurable
        elif name == "http_header_dict_accepts_bytes_keys":
            headers = module.Headers([(b"X-Test", "value")])
            value = headers[b"x-test"]
            passed = value == "value"
            actual = {"lookup": value}
        elif name == "http_header_dict_supports_union_operators":
            headers = module.Headers([("A", "1")])
            merged = headers | {"B": "2"}
            actual = {"items": list(merged.items())}
            passed = str(merged["A"]) == "1" and str(merged["B"]) == "2"
        elif name == "http_header_dict_can_repeat_or_combine_values":
            headers = module.Headers([("X", "a"), ("x", "b")])
            actual = {"list": headers.get_list("X"), "combined": headers["x"]}
            passed = actual == {"list": ["a", "b"], "combined": "a, b"}
        elif name == "case_insensitive_headers_preserve_insertion_order":
            headers = module.Headers([("First", "1"), ("second", "2"), ("FIRST", "3")])
            actual = {"keys": list(headers), "first_values": headers.get_list("first")}
            passed = actual == {"keys": ["First", "second"], "first_values": ["1", "3"]}
        else:
            raise AssertionError(f"unknown analysis behavior: {name}")
        return {"passed": passed, "actual": actual, "error": "" if passed else "behavioral oracle mismatch"}
    except BaseException as exc:
        return {"passed": False, "actual": {"exception": type(exc).__name__, "message": str(exc)}, "error": f"{type(exc).__name__}: {exc}"}


def cookie_behavior(module, name: str) -> dict | None:
    """Execute cookie-jar release-note behaviors through the target's jar API."""

    jar_type = getattr(module, "CookieJar", None)
    if jar_type is None:
        cookie_module = getattr(module, "cookiejar", None) or getattr(module, "cookies", None)
        jar_type = getattr(cookie_module, "CookieJar", None) if cookie_module is not None else None
    if jar_type is None:
        return None
    try:
        jar = jar_type()
        if name == "cookie_jar_can_access_cookie_by_name":
            if all(hasattr(jar, item) for item in ("set", "get")):
                jar.set("sid", "value", domain="example.test", path="/")
                value = jar.get("sid", domain="example.test", path="/")
            elif all(hasattr(jar, item) for item in ("update", "header_value")) and hasattr(module, "URL"):
                url = module.URL("https://example.test/")
                jar.update(url, ["sid=value; Path=/"])
                header = jar.header_value(url) or ""
                return {"passed": False, "actual": {"cookie_header": header, "named_getter": False},
                        "error": "cookie is stored but the jar has no public lookup-by-name operation"}
            else:
                return {"passed": False, "actual": {"public_methods": sorted(x for x in dir(jar) if not x.startswith("_"))},
                        "error": "cookie jar has no public lookup-by-name operation"}
            return {"passed": value == "value", "actual": {"value": value}, "error": "" if value == "value" else "cookie lookup mismatch"}
        if name == "strict_cookie_jar_deduplicates_cookies":
            if hasattr(jar, "set"):
                jar.set("sid", "one", domain="example.test", path="/")
                jar.set("sid", "two", domain="example.test", path="/")
            elif all(hasattr(jar, item) for item in ("update", "header_value")) and hasattr(module, "URL"):
                url = module.URL("https://example.test/")
                jar.update(url, ["sid=one; Path=/"])
                jar.update(url, ["sid=two; Path=/"])
                value = jar.header_value(url) or ""
                passed = value.count("sid=") == 1 and "sid=two" in value
                return {"passed": passed, "actual": {"cookies": value}, "error": "" if passed else "cookie deduplication mismatch"}
            else:
                return {"passed": False, "actual": {"public_methods": sorted(x for x in dir(jar) if not x.startswith("_"))},
                        "error": "cookie jar has no public insertion operation"}
            if hasattr(jar, "header_for"):
                value = jar.header_for("example.test", "/") or ""
                passed = value.count("sid=") == 1 and "sid=two" in value
            elif hasattr(jar, "get_dict"):
                values = jar.get_dict(domain="example.test", path="/")
                value = values
                passed = values == {"sid": "two"}
            else:
                return None
            return {"passed": passed, "actual": {"cookies": value}, "error": "" if passed else "cookie deduplication mismatch"}
        if name == "strict_cookie_jar_rejects_invalid_cookies":
            if hasattr(jar, "set"):
                try:
                    jar.set("bad;name", "value", domain="example.test", path="/")
                    actual, passed = {"accepted": True}, False
                except (TypeError, ValueError) as exc:
                    actual, passed = {"accepted": False, "exception": type(exc).__name__}, True
            elif all(hasattr(jar, item) for item in ("update", "header_value")) and hasattr(module, "URL"):
                url = module.URL("https://example.test/")
                jar.update(url, ["bad;name=value; Path=/"])
                header = jar.header_value(url) or ""
                passed = "bad" not in header and "name=" not in header
                actual = {"accepted": not passed, "cookie_header": header}
            else:
                return {"passed": False, "actual": {"public_methods": sorted(x for x in dir(jar) if not x.startswith("_"))},
                        "error": "cookie jar has no public insertion operation"}
            return {"passed": passed, "actual": actual, "error": "" if passed else "invalid cookie accepted"}
        if name == "custom_host_header_cookie_matching_is_respected":
            if all(hasattr(jar, item) for item in ("set", "header_for")):
                jar.set("sid", "host", domain="example.test", path="/", host_only=True)
                logical = jar.header_for("example.test", "/") or ""
                transport = jar.header_for("127.0.0.1", "/") or ""
            elif all(hasattr(jar, item) for item in ("update", "header_value")) and hasattr(module, "URL"):
                logical_url = module.URL("https://example.test/")
                transport_url = module.URL("https://127.0.0.1/")
                jar.update(logical_url, ["sid=host; Path=/"])
                logical = jar.header_value(logical_url) or ""
                transport = jar.header_value(transport_url) or ""
            else:
                return {"passed": False, "actual": {"public_methods": sorted(x for x in dir(jar) if not x.startswith("_"))},
                        "error": "cookie jar has no public host-matching operation"}
            passed = "sid=host" in logical and "sid=host" not in transport
            return {"passed": passed, "actual": {"logical_host": logical, "transport_host": transport}, "error": "" if passed else "host matching mismatch"}
        if name == "cookies_option_accepts_boolean_or_cookie_jar":
            client_type = getattr(module, "Client", None)
            if client_type is None:
                return None
            outcomes = []
            for value in (False, True, jar):
                try:
                    client = client_type(cookies=value)
                    close = getattr(client, "close", None)
                    if callable(close):
                        close()
                    outcomes.append({"shape": type(value).__name__, "accepted": True})
                except Exception as exc:
                    outcomes.append({"shape": type(value).__name__, "accepted": False, "exception": type(exc).__name__})
            passed = all(item["accepted"] for item in outcomes)
            return {"passed": passed, "actual": {"outcomes": outcomes}, "error": "" if passed else "one or more cookie option shapes rejected"}
        if name == "cookie_jar_file_writes_are_serialized":
            methods = [item for item in ("save", "persist", "write", "flush") if callable(getattr(jar, item, None))]
            if not methods:
                return None
            return {"passed": False, "actual": {"file_methods": methods}, "error": "file-write serialization requires an exposed file-backed jar operation"}
    except BaseException as exc:
        return {"passed": False, "actual": {"exception": type(exc).__name__, "message": str(exc)}, "error": f"{type(exc).__name__}: {exc}"}
    return None


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    ir = {row["scoring_id"]: row for row in map(json.loads, (HERE / "http_non_common_contract_ir.jsonl").read_text().splitlines())}
    plans = list(map(json.loads, (HERE / "solhttp_projection_plan.jsonl").read_text().splitlines()))
    frozen_rows = json.loads((ROOT / "contracts/solhttp_non_common/solhttp_gpt56sol_high_http_non_common_20260829.json").read_text())["corpus"]
    by_key = {row["key"]: row for row in frozen_rows}
    old = reload_old_runner()
    base, merged, shim = old.load_replay_modules()
    adapter_hash = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    evidence = []
    summaries = []

    selected = os.environ.get("SOLHTTP_SNAPSHOT", "")
    explicit_path = os.environ.get("SHAPINGBENCH_TARGET_SNAPSHOT", "")
    if explicit_path:
        snapshots = [(os.environ.get("SHAPINGBENCH_TARGET_LABEL", "custom"), Path(explicit_path))]
    else:
        snapshots = [item for item in SNAPSHOTS if not selected or item[0] == selected]
    if selected and not snapshots:
        raise SystemExit(f"unknown SOLHTTP_SNAPSHOT: {selected}")
    for label, snapshot in snapshots:
        add_snapshot_import_roots(snapshot)
        try:
            module = old.install_solhttp(snapshot, base, merged, shim)
        except BaseException as exc:
            reason = f"target implementation cannot be imported: {type(exc).__name__}: {exc}"
            for plan in plans:
                contract = ir[plan["scoring_id"]]
                evidence.append({
                    "scoring_id": contract["scoring_id"], "contract_hash": contract["contract_hash"],
                    "source_key": contract["source_key"], "name": contract["name"],
                    "capability": contract["capability"], "origin": contract["origin"],
                    "snapshot": label, "snapshot_path": str(snapshot), "target_version": "unavailable",
                    "adapter_revision": "solhttp-executable-contract-v2", "adapter_hash": adapter_hash,
                    "projection_kind": "target_import_probe", "verdict": Verdict.FAIL_CAPABILITY_ABSENCE.value,
                    "reason": reason, "actual_observations": [{"imported": False, "error": reason}],
                    "oracle_comparisons": [], "control_validation": "NOT_RUN",
                    "control_evidence": None, "capability_probe": None,
                    "environment": {"python": platform.python_version(), "platform": platform.platform()},
                })
            summaries.append({"snapshot": label, "total": len(plans),
                              Verdict.FAIL_CAPABILITY_ABSENCE.value: len(plans)})
            continue
        surface = public_surface(module)
        target_control = target_positive_control(module)
        counts: Counter[str] = Counter()
        for plan in plans:
            contract = ir[plan["scoring_id"]]
            frozen = by_key[contract["source_key"]]
            kind = plan["projection_kind"]
            actual = []
            comparisons = []
            control = ""
            capability_probe = None
            reason = ""
            if kind == "behavior_replay":
                test_name = frozen["solhttp_test"]
                result = old.run_test(test_name, old.fn_for(test_name, frozen, base, merged))
                actual = [{"observation_id": "legacy_behavior", "passed": result["passed"], "error": result["error"]}]
                comparisons = [{"observation_id": "legacy_behavior", "matched": result["passed"]}]
                verdict = Verdict.PASS if result["passed"] else Verdict.FAIL_SEMANTIC_MISMATCH
                control = "PASS"
                reason = "legacy behavioral replay passed" if result["passed"] else result["error"]
            elif kind == "analysis_behavior_replay":
                test = plan["projection"]["test"]
                if hasattr(old, test):
                    old_result = old.run_test(test, getattr(old, test))
                    result = {"passed": old_result["passed"], "actual": {"error": old_result["error"]}, "error": old_result["error"]}
                elif test in behavior_scenarios.SCENARIOS:
                    result = behavior_scenarios.run(module, base, test)
                else:
                    result = analysis_behavior(module, test)
                actual = [{"observation_id": "analysis_behavior", **result["actual"]}]
                comparisons = [{"observation_id": "analysis_behavior", "matched": result["passed"]}]
                if result.get("error", "").startswith("infrastructure:"):
                    verdict = Verdict.UNKNOWN_INFRASTRUCTURE
                else:
                    verdict = Verdict.PASS if result["passed"] else Verdict.FAIL_SEMANTIC_MISMATCH
                control = "PASS" if result.get("control", {}).get("rejected", result["passed"]) else "FAIL"
                reason = "analysis behavioral replay passed" if result["passed"] else result["error"]
            elif kind == "capability_absence_probe":
                projection = plan["projection"]
                cookie_result = cookie_behavior(module, contract["name"])
                if cookie_result is not None:
                    actual = [{"observation_id": "cookie_behavior", **cookie_result["actual"]}]
                    comparisons = [{"observation_id": "cookie_behavior", "matched": cookie_result["passed"]}]
                    verdict = Verdict.PASS if cookie_result["passed"] else Verdict.FAIL_SEMANTIC_MISMATCH
                    control = "PASS"
                    reason = "cookie behavior replay passed" if cookie_result["passed"] else cookie_result["error"]
                    counts[verdict.value] += 1
                    evidence.append({
                        "scoring_id": contract["scoring_id"], "contract_hash": contract["contract_hash"],
                        "source_key": contract["source_key"], "name": contract["name"],
                        "capability": contract["capability"], "origin": contract["origin"],
                        "snapshot": label, "snapshot_path": str(snapshot),
                        "target_version": getattr(module, "__version__", "unknown"),
                        "adapter_revision": "solhttp-executable-contract-v2", "adapter_hash": adapter_hash,
                        "projection_kind": "analysis_cookie_behavior_replay", "verdict": verdict.value,
                        "reason": reason, "actual_observations": actual, "oracle_comparisons": comparisons,
                        "control_validation": control, "control_evidence": None, "capability_probe": None,
                        "environment": {"python": platform.python_version(), "platform": platform.platform()},
                    })
                    continue
                aliases = projection["equivalent_native_interfaces"]
                if contract["name"] == "cookie_jar_file_writes_are_serialized":
                    aliases = ["file_cookie_jar", "save", "persist", "flush"]
                observed = detect(surface, aliases)
                capability_probe = {
                    "required_semantic_primitive": projection["required_semantic_primitive"],
                    "equivalent_native_interfaces_checked": aliases,
                    "executable_probe": "recursive runtime public surface, callable signatures, package source, and installed transport dependencies",
                    "probe_observation": observed,
                    "target_native_attempts": native_resolution_attempts(module, aliases),
                    "positive_control": target_control,
                }
                if not capability_probe["positive_control"]["passed"]:
                    verdict = Verdict.UNKNOWN_INFRASTRUCTURE
                    reason = "capability probe positive control failed"
                elif any(item.get("accepted") for item in capability_probe["target_native_attempts"]):
                    verdict = Verdict.UNKNOWN_ADAPTER_GAP
                    reason = "an equivalent native surface exists and requires behavioral lowering"
                else:
                    verdict = Verdict.FAIL_CAPABILITY_ABSENCE
                    reason = f"no equivalent native surface exposes {projection['required_semantic_primitive']}"
            elif kind == "provenance_recovery_required":
                verdict = Verdict.UNKNOWN_PROVENANCE
                reason = plan["projection"]["reason"]
            else:
                verdict = Verdict.UNKNOWN_ADAPTER_GAP
                reason = "complete source behavior exists but target lowering is not implemented yet"
            counts[verdict.value] += 1
            evidence.append({
                "scoring_id": contract["scoring_id"],
                "contract_hash": contract["contract_hash"],
                "source_key": contract["source_key"],
                "name": contract["name"],
                "capability": contract["capability"],
                "origin": contract["origin"],
                "snapshot": label,
                "snapshot_path": str(snapshot),
                "target_version": getattr(module, "__version__", "unknown"),
                "adapter_revision": "solhttp-executable-contract-v1",
                "adapter_hash": adapter_hash,
                "projection_kind": kind,
                "verdict": verdict.value,
                "reason": reason,
                "actual_observations": actual,
                "oracle_comparisons": comparisons,
                "control_validation": control,
                "control_evidence": result.get("control") if kind == "analysis_behavior_replay" else None,
                "capability_probe": capability_probe,
                "environment": {"python": platform.python_version(), "platform": platform.platform()},
            })
        summaries.append({"snapshot": label, "total": len(plans), **dict(sorted(counts.items()))})

    (OUTPUT_DIR / "solhttp_measurement_results.jsonl").write_text(
        "".join(json.dumps(row, sort_keys=True, ensure_ascii=False, default=json_default) + "\n" for row in evidence)
    )
    (OUTPUT_DIR / "solhttp_measurement_summary.json").write_text(
        json.dumps(summaries, indent=2, sort_keys=True, default=json_default) + "\n"
    )
    print(json.dumps(summaries, indent=2, sort_keys=True, default=json_default))


if __name__ == "__main__":
    main()
