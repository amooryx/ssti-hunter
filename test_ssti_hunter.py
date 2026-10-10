import contextlib
import io
import json
import os
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch

import ssti_hunter


class FixtureHandler(BaseHTTPRequestHandler):
    sink_hits = 0

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/sink")
            self.end_headers()
            return
        if path == "/sink":
            type(self).sink_hits += 1
            body = b"49"
        elif path == "/large":
            body = b"x" * (ssti_hunter.MAX_RESPONSE_BYTES * 2)
        elif path == "/plain":
            body = b"ordinary response"
        else:
            query = parse_qs(urlsplit(self.path).query)
            body = b"49" if query.get("name") else b"not rendered"
        self.send_body(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        form = parse_qs(self.rfile.read(length).decode())
        self.send_body(b"49" if form.get("name") else b"not rendered")

    def send_body(self, body):
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


class SSTIHunterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), FixtureHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def test_arithmetic_results_are_reported_as_heuristic(self):
        result = ssti_hunter.test_ssti(
            self.base_url + "/render", "name", "GET", {}, 2.0
        )
        self.assertEqual(len(result["findings"]), len(ssti_hunter.DETECTION_PAYLOADS))
        self.assertEqual(result["failures"], [])
        self.assertTrue(all("heuristic" in finding["evidence"] for finding in result["findings"]))
        self.assertTrue(all(finding.get("confirmed") is None for finding in result["findings"]))

    def test_post_parameters_are_checked(self):
        result = ssti_hunter.test_ssti(
            self.base_url + "/render", "name", "POST", {}, 2.0
        )
        self.assertEqual(len(result["findings"]), len(ssti_hunter.DETECTION_PAYLOADS))
        self.assertEqual(result["failures"], [])

    def test_redirect_is_not_followed_and_is_inconclusive(self):
        FixtureHandler.sink_hits = 0
        result = ssti_hunter.test_ssti(
            self.base_url + "/redirect", "name", "GET", {}, 2.0
        )
        self.assertEqual(len(result["failures"]), len(ssti_hunter.DETECTION_PAYLOADS))
        self.assertTrue(all(failure["error"] == "redirect blocked" for failure in result["failures"]))
        self.assertEqual(FixtureHandler.sink_hits, 0)

    def test_response_read_is_capped_and_marked_truncated(self):
        response = ssti_hunter.inject_get(
            self.base_url + "/large", "name", "{{7*7}}", {}, 2.0
        )
        self.assertTrue(response["truncated"])
        self.assertLessEqual(len(response["body"].encode()), ssti_hunter.MAX_RESPONSE_BYTES)

    def test_invalid_scope_and_timeout_are_rejected(self):
        with self.assertRaises(ValueError):
            ssti_hunter.validate_inputs("file:///tmp/a", ["name"], "GET", {}, 1.0)
        with self.assertRaises(ValueError):
            ssti_hunter.validate_inputs(self.base_url, ["name"] * 9, "GET", {}, 1.0)
        with self.assertRaises(ValueError):
            ssti_hunter.validate_inputs(self.base_url, ["name"], "GET", {}, 31.0)

    def test_json_report_labels_a_clean_check_as_no_heuristic_evidence(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = os.path.join(temp_dir, "report.json")
            with patch.object(sys, "argv", [
                "ssti_hunter.py",
                self.base_url + "/plain",
                "--params",
                "name",
                "--out",
                report_path,
            ]):
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(ssti_hunter.main(), 0)
            with open(report_path, encoding="utf-8") as report_file:
                report = json.load(report_file)
        self.assertEqual(report["parameters"][0]["outcome"], "no_heuristic_evidence")
        self.assertEqual(report["parameters"][0]["probes_sent"], 5)
        self.assertEqual(report["failures"], [])


if __name__ == "__main__":
    unittest.main()
