#!/usr/bin/env python3
"""
SSTI Hunter — Server-Side Template Injection Detection Tool
Detects SSTI in various template engines: Jinja2, Twig, Freemarker, Velocity, Pebble.
Author: Omar Khalid (amooryx) | github.com/amooryx/ssti-hunter
AUTHORIZED USE ONLY — for authorized security testing and bug bounty.
"""

import argparse
import json
import math
import re
import sys
import urllib.parse
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor

# Engine-specific payloads (safe detection only — no RCE payloads)
DETECTION_PAYLOADS = [
    # Math expression that evaluates to a unique number — engine-independent
    {"payload": "{{7*7}}",          "expect": "49",    "engine": "Jinja2/Twig"},
    {"payload": "${7*7}",           "expect": "49",    "engine": "Freemarker/Groovy"},
    {"payload": "#{7*7}",           "expect": "49",    "engine": "Thymeleaf"},
    {"payload": "<%= 7*7 %>",       "expect": "49",    "engine": "ERB/JSP"},
    {"payload": "{7*7}",            "expect": "49",    "engine": "Smarty"},
    {"payload": "{{7*'7'}}",        "expect": "7777777", "engine": "Jinja2"},
    {"payload": "${\"freq\"?upper_case}", "expect": "FREQ", "engine": "Freemarker"},
    {"payload": "@{7*7}",           "expect": "49",    "engine": "Thymeleaf (expr)"},
    # Error-based
    {"payload": "{{''.__class__}}", "expect": "<class 'str'>", "engine": "Jinja2 (Python)"},
]

def inject_get(url: str, param: str, payload: str, extra_headers: dict, timeout: float) -> dict:
    parsed = urllib.parse.urlparse(url)
    qs     = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    new_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)))
    req = urllib.request.Request(new_url)
    req.add_header("User-Agent", "SSTIHunter/1.0")
    for k, v in extra_headers.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(16384).decode(errors="ignore")
            return {"url": new_url, "status": resp.status, "body": body}
    except urllib.error.HTTPError as e:
        body = e.read(4096).decode(errors="ignore") if hasattr(e, 'read') else ""
        return {"url": new_url, "status": e.code, "body": body}
    except Exception as ex:
        return {"url": new_url, "status": 0, "error": str(ex), "body": ""}

def inject_post(url: str, param: str, payload: str, extra_headers: dict, timeout: float) -> dict:
    data = urllib.parse.urlencode({param: payload}).encode()
    req  = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("User-Agent", "SSTIHunter/1.0")
    for k, v in extra_headers.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(16384).decode(errors="ignore")
            return {"url": url, "status": resp.status, "body": body}
    except urllib.error.HTTPError as e:
        body = e.read(4096).decode(errors="ignore") if hasattr(e, 'read') else ""
        return {"url": url, "status": e.code, "body": body}
    except Exception as ex:
        return {"url": url, "status": 0, "error": str(ex), "body": ""}

def test_ssti(url: str, param: str, method: str, extra_headers: dict, timeout: float) -> list[dict]:
    findings = []
    for test in DETECTION_PAYLOADS:
        payload = test["payload"]
        expect  = test["expect"]
        if method.upper() == "POST":
            resp = inject_post(url, param, payload, extra_headers, timeout)
        else:
            resp = inject_get(url, param, payload, extra_headers, timeout)

        if expect in resp.get("body", ""):
            findings.append({
                "url":     resp["url"],
                "param":   param,
                "payload": payload,
                "expect":  expect,
                "engine":  test["engine"],
                "status":  resp["status"],
                "confirmed": True,
            })
    return findings

def main():
    parser = argparse.ArgumentParser(
        description="SSTI Hunter — Template Injection Detection (Authorized use only)",
    )
    parser.add_argument("url",        help="Target URL")
    parser.add_argument("--params",   nargs="+", required=True, help="Parameters to test")
    parser.add_argument("--method",   default="GET", choices=["GET", "POST"])
    parser.add_argument("--threads",  type=int, default=3)
    parser.add_argument("--timeout",  type=float, default=10)
    parser.add_argument("--header",   nargs="*", help="Extra headers: 'Key: Value'")
    parser.add_argument("--out",      help="Output JSON file")
    args = parser.parse_args()

    headers = {}
    if args.header:
        for h in args.header:
            if ": " in h:
                k, v = h.split(": ", 1)
                headers[k] = v

    print(f"[*] SSTI testing {args.url} — params: {args.params} — method: {args.method}")
    all_findings = []
    for param in args.params:
        findings = test_ssti(args.url, param, args.method, headers, args.timeout)
        if findings:
            for f in findings:
                print(f"  [!!!] SSTI CONFIRMED: param={param} engine={f['engine']}")
                print(f"        payload: {f['payload']}  → expected: {f['expect']}")
            all_findings.extend(findings)
        else:
            print(f"  [OK] No SSTI detected in '{param}'")

    print(f"\n[*] {len(all_findings)} SSTI findings")
    if args.out:
        with open(args.out, "w") as f:
            json.dump(all_findings, f, indent=2)
        print(f"[*] Results → {args.out}")

if __name__ == "__main__":
    main()
