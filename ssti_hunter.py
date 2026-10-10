#!/usr/bin/env python3
"""Bounded, heuristic SSTI checks for authorized systems."""

import argparse
import json
import math
import re
import urllib.error
import urllib.parse
import urllib.request

MAX_PARAMETERS = 8
MAX_REQUESTS = 40
MAX_TIMEOUT = 30.0
MAX_RESPONSE_BYTES = 16 * 1024
MAX_URL_LENGTH = 2048
MAX_HEADERS = 20
MAX_HEADER_BYTES = 8192

# Each probe performs only a small arithmetic operation and expects 49.
DETECTION_PAYLOADS = [
    {"payload": "{{7*7}}", "expect": "49", "engine": "Jinja2/Twig"},
    {"payload": "${7*7}", "expect": "49", "engine": "Freemarker"},
    {"payload": "#{7*7}", "expect": "49", "engine": "Thymeleaf"},
    {"payload": "<%= 7*7 %>", "expect": "49", "engine": "ERB/JSP"},
    {"payload": "{7*7}", "expect": "49", "engine": "Smarty"},
]


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def validate_url(url: str) -> None:
    if len(url) > MAX_URL_LENGTH:
        raise ValueError(f"URL must be at most {MAX_URL_LENGTH} characters")
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("URL must be an absolute http:// or https:// URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Credentials in the URL are not allowed")
    try:
        parsed.port
    except ValueError as exc:
        raise ValueError("URL contains an invalid port") from exc


def validate_inputs(
    url: str,
    params: list[str],
    method: str,
    headers: dict[str, str],
    timeout: float,
) -> None:
    validate_url(url)
    if not params or len(params) > MAX_PARAMETERS:
        raise ValueError(f"Provide between 1 and {MAX_PARAMETERS} parameters")
    if len(params) * len(DETECTION_PAYLOADS) > MAX_REQUESTS:
        raise ValueError(f"Request count exceeds the limit of {MAX_REQUESTS}")
    if any(not param.strip() or len(param) > 128 for param in params):
        raise ValueError("Parameter names must be non-empty and at most 128 characters")
    if len(set(params)) != len(params):
        raise ValueError("Parameter names must be unique")
    if method.upper() not in ("GET", "POST"):
        raise ValueError("Method must be GET or POST")
    if not math.isfinite(timeout) or not 0 < timeout <= MAX_TIMEOUT:
        raise ValueError(f"Timeout must be greater than 0 and at most {MAX_TIMEOUT:g} seconds")
    if len(headers) > MAX_HEADERS:
        raise ValueError(f"At most {MAX_HEADERS} extra headers are allowed")
    header_bytes = 0
    for key, value in headers.items():
        if not re.fullmatch(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+", key):
            raise ValueError(f"Invalid HTTP header name: {key!r}")
        if any((ord(char) < 32 and char != "\t") or ord(char) == 127 for char in value):
            raise ValueError(f"Invalid control character in HTTP header: {key!r}")
        try:
            header_bytes += len(key) + len(value.encode("latin-1"))
        except UnicodeEncodeError as exc:
            raise ValueError(f"HTTP header value is not Latin-1 encodable: {key!r}") from exc
    if header_bytes > MAX_HEADER_BYTES:
        raise ValueError(f"Extra headers must total at most {MAX_HEADER_BYTES} characters")


def _read_response(response) -> tuple[str, bool]:
    raw = response.read(MAX_RESPONSE_BYTES + 1)
    truncated = len(raw) > MAX_RESPONSE_BYTES
    return raw[:MAX_RESPONSE_BYTES].decode(errors="replace"), truncated


def _request(url: str, method: str, data: bytes | None, extra_headers: dict[str, str], timeout: float) -> dict:
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("User-Agent", "SSTIHunter/2.0")
    if data is not None:
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    for key, value in extra_headers.items():
        req.add_header(key, value)

    opener = urllib.request.build_opener(NoRedirectHandler)
    try:
        with opener.open(req, timeout=timeout) as response:
            body, truncated = _read_response(response)
            status = response.status
            error = "redirect blocked" if 300 <= status < 400 else None
            return {"url": url, "status": status, "body": body, "truncated": truncated, "error": error}
    except urllib.error.HTTPError as exc:
        status = exc.code
        exc.close()
        error = "redirect blocked" if 300 <= status < 400 else None
        return {"url": url, "status": status, "body": "", "truncated": False, "error": error}
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        reason = exc.reason if isinstance(exc, urllib.error.URLError) else exc
        return {"url": url, "status": 0, "body": "", "truncated": False, "error": str(reason)}


def inject_get(url: str, param: str, payload: str, extra_headers: dict, timeout: float) -> dict:
    parsed = urllib.parse.urlsplit(url)
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    query = [(key, value) for key, value in query if key != param]
    query.append((param, payload))
    target = urllib.parse.urlunsplit(parsed._replace(query=urllib.parse.urlencode(query)))
    return _request(target, "GET", None, extra_headers, timeout)


def inject_post(url: str, param: str, payload: str, extra_headers: dict, timeout: float) -> dict:
    data = urllib.parse.urlencode({param: payload}).encode()
    return _request(url, "POST", data, extra_headers, timeout)


def test_ssti(url: str, param: str, method: str, extra_headers: dict, timeout: float) -> dict:
    validate_inputs(url, [param], method, extra_headers, timeout)
    findings = []
    failures = []
    for test in DETECTION_PAYLOADS:
        payload = test["payload"]
        if method.upper() == "POST":
            response = inject_post(url, param, payload, extra_headers, timeout)
        else:
            response = inject_get(url, param, payload, extra_headers, timeout)

        record = {
            "url": response["url"],
            "param": param,
            "payload": payload,
            "engine": test["engine"],
            "status": response["status"],
        }
        if response.get("error"):
            failures.append({**record, "error": response["error"]})
        elif not 200 <= response["status"] < 300:
            failures.append({**record, "error": f"HTTP status {response['status']}"})
        elif test["expect"] in response["body"]:
            findings.append({
                **record,
                "expected": test["expect"],
                "evidence": "heuristic: expected arithmetic result appeared in the response",
                "response_truncated": response["truncated"],
            })
        elif response["truncated"]:
            failures.append({**record, "error": "response truncated; absence of evidence is inconclusive"})
    return {"findings": findings, "failures": failures}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Bounded SSTI heuristic checks for authorized systems only."
    )
    parser.add_argument("url", help="HTTP(S) target URL")
    parser.add_argument("--params", nargs="+", required=True, help=f"Parameters to test (maximum {MAX_PARAMETERS})")
    parser.add_argument("--method", default="GET", choices=["GET", "POST"])
    parser.add_argument("--timeout", type=float, default=10, help=f"Per-operation timeout, maximum {MAX_TIMEOUT:g} seconds")
    parser.add_argument("--header", action="append", default=[], metavar="'Key: Value'", help="Extra request header (repeatable)")
    parser.add_argument("--out", help="Output JSON report file")
    args = parser.parse_args()

    headers = {}
    for header in args.header:
        if ":" not in header:
            parser.error(f"Invalid header {header!r}; expected 'Key: Value'")
        key, value = header.split(":", 1)
        key, value = key.strip(), value.lstrip()
        if key in headers:
            parser.error(f"Duplicate header name: {key}")
        headers[key] = value
    try:
        validate_inputs(args.url, args.params, args.method, headers, args.timeout)
    except ValueError as exc:
        parser.error(str(exc))

    report = {"parameters": [], "findings": [], "failures": []}
    for param in args.params:
        print(f"[*] Testing parameter {param!r} with {len(DETECTION_PAYLOADS)} bounded probes")
        result = test_ssti(args.url, param, args.method, headers, args.timeout)
        report["findings"].extend(result["findings"])
        report["failures"].extend(result["failures"])
        if result["findings"] and result["failures"]:
            outcome = "heuristic_evidence_with_inconclusive_probes"
        elif result["findings"]:
            outcome = "heuristic_evidence"
        elif result["failures"]:
            outcome = "inconclusive"
        else:
            outcome = "no_heuristic_evidence"
        report["parameters"].append({
            "param": param,
            "probes_sent": len(DETECTION_PAYLOADS),
            "outcome": outcome,
        })
        for finding in result["findings"]:
            print(f"  [!] Heuristic evidence: param={param} engine={finding['engine']}")
        if not result["findings"] and not result["failures"]:
            print(f"  [OK] No heuristic evidence found for {param!r}")
        for failure in result["failures"]:
            print(f"  [!] Inconclusive probe: param={param} engine={failure['engine']} ({failure['error']})")

    print(f"\n[*] {len(report['findings'])} heuristic findings; {len(report['failures'])} failed/inconclusive probes")
    if args.out:
        with open(args.out, "w", encoding="utf-8") as output:
            json.dump(report, output, indent=2)
        print(f"[*] Results → {args.out}")
    return 0 if not report["failures"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
