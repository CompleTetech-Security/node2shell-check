# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-CompleteTech-Commercial
# Copyright (c) 2026 CompleteTech LLC. See LICENSING.md.
"""Behavioral tests use synthetic metadata and loopback HTTP fixtures only."""

from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

import node2shell_check as checker


def invoke_cli(arguments):
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        try:
            status = checker.main(arguments)
        except SystemExit as exc:
            status = exc.code
    return status, stdout.getvalue(), stderr.getvalue()


class InspectionTests(unittest.TestCase):
    def inspect(self, headers=None, body="<title>Example</title>", status=200):
        result = checker.Result(input_url="https://example.test/", final_url="https://example.test/")
        checker.inspect_page(checker.Response(status, headers or {}, body, False), result)
        return result

    def test_explicit_node_header_is_version_evidence(self):
        result = self.inspect({"server": "Node.js/24.22.0", "content-type": "text/html"})
        self.assertEqual(result.node_version, "24.22.0")
        self.assertEqual(result.node2shell_status, "potentially_affected")
        self.assertEqual(result.node2shell_exploitability, "not_tested")

    def test_dedicated_version_header_is_supported(self):
        result = self.inspect({"x-node-version": "v22.23.4"})
        self.assertEqual(result.node_version.lstrip("v"), "22.23.4")
        self.assertEqual(result.node2shell_status, "fixed_version_reported")

    def test_framework_version_is_never_node_version(self):
        for headers, body in (
            ({"x-powered-by": "Express/5.1.0"}, "<title>API</title>"),
            ({"x-powered-by": "Next.js"}, '<script src="/_next/static/chunk.js"></script>'),
            ({}, '<script id="__NEXT_DATA__" type="application/json">{}</script>'),
        ):
            with self.subTest(headers=headers, body=body):
                result = self.inspect(headers, body)
                self.assertEqual(result.node_version, "")
                self.assertEqual(result.node2shell_status, "unknown")

    def test_conflicting_explicit_versions_remain_unknown(self):
        result = self.inspect({"server": "Node.js/24.22.0", "x-node-version": "24.22.1"})
        self.assertEqual(result.node2shell_status, "unknown")
        self.assertEqual(len(result.node_version_candidates), 2)

    def test_brotli_response_is_not_decoder_exposure(self):
        result = self.inspect({"content-encoding": "br"}, "not a Brotli payload")
        self.assertTrue(result.response_brotli)
        self.assertEqual(result.node2shell_status, "unknown")
        self.assertEqual(result.node2shell_exploitability, "not_tested")
        self.assertEqual(result.node_version, "")

    def test_hidden_node_version_is_unknown(self):
        result = self.inspect({"server": "nginx"})
        self.assertEqual(result.node2shell_status, "unknown")
        self.assertEqual(result.node_version, "")

    def test_arbitrary_page_text_is_not_runtime_version(self):
        result = self.inspect({}, "<h1>Node.js/24.22.1 documentation</h1>")
        self.assertEqual(result.node2shell_status, "unknown")
        self.assertEqual(result.node_version, "")

    def test_product_name_ending_in_node_is_not_node_runtime(self):
        result = self.inspect({"server": "my-node/24.22.1"})
        self.assertEqual(result.node2shell_status, "unknown")
        self.assertNotEqual(result.status, "node_detected")

    def test_conflicting_header_after_display_limit_remains_unknown(self):
        header = "Node/24.22.1 " + ("gateway " * 350) + "Node/24.22.0"
        result = self.inspect({"server": header})
        self.assertEqual(result.node2shell_status, "unknown")
        self.assertEqual(len(result.node_version_candidates), 2)

    def test_display_cutoff_cannot_remove_vendor_suffix(self):
        prefix = "gateway " + " " * (2048 - len("gateway ") - len("Node/24.22.1"))
        result = self.inspect({"server": prefix + "Node/24.22.1-vendor"})
        self.assertEqual(result.node2shell_status, "unknown")


class UrlAndRobotsTests(unittest.TestCase):
    def test_bare_domain_defaults_to_https(self):
        self.assertEqual(checker.normalize_url("example.test"), "https://example.test/")

    def test_invalid_or_credentialed_urls_are_rejected(self):
        for value in ("https://name:secret@example.test/", "file:///etc/passwd", "ftp://example.test/", "https://example.test:99999/", "https://example.test/\r\nInjected: yes"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                checker.normalize_url(value)

    def test_robots_longest_match_and_allow_tie(self):
        policy = checker.RobotsPolicy("User-agent: *\nDisallow: /private\nAllow: /private/public\nDisallow: /same\nAllow: /same\n", 0.001)
        self.assertFalse(policy.can_fetch("https://example.test/private/file"))
        self.assertTrue(policy.can_fetch("https://example.test/private/public/file"))
        self.assertTrue(policy.can_fetch("https://example.test/same"))

    def test_specific_robot_group_wins(self):
        policy = checker.RobotsPolicy(f"User-agent: *\nDisallow: /\n\nUser-agent: {checker.BOT}\nAllow: /\nDisallow: /secret\n", 0.001)
        self.assertTrue(policy.can_fetch("https://example.test/page"))
        self.assertFalse(policy.can_fetch("https://example.test/secret"))

    def test_robots_wildcards_and_terminal_anchor(self):
        policy = checker.RobotsPolicy("User-agent: *\nDisallow: /*.json$\n", 0.001)
        self.assertFalse(policy.can_fetch("https://example.test/a/data.json"))
        self.assertTrue(policy.can_fetch("https://example.test/a/data.json/view"))

    def test_adversarial_robots_wildcards_finish_promptly(self):
        # A child process bounds the regression test itself if a future change
        # reintroduces exponential regex backtracking on untrusted robots data.
        program = (
            "import node2shell_check as c\n"
            "pattern = '/' + '*a' * 30 + 'z'\n"
            "policy = c.RobotsPolicy('User-agent: *\\nDisallow: ' + pattern, 0.001)\n"
            "assert policy.can_fetch('https://example.test/' + 'a' * 40)\n"
        )
        completed = subprocess.run(
            [sys.executable, "-c", program],
            cwd=Path(__file__).resolve().parent,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)


class FixtureHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_GET(self):
        self.server.requests.append((self.command, self.path, dict(self.headers)))
        status, headers, body = self.server.routes.get(self.path, (404, {}, b"not found"))
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_POST(self):
        self.server.requests.append((self.command, self.path, dict(self.headers)))
        self.send_error(405)


class HttpBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
        cls.server.daemon_threads = True
        cls.server.requests = []
        cls.server.routes = {}
        cls.thread = threading.Thread(target=cls.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=3)

    def setUp(self):
        self.server.requests.clear()
        self.server.routes = {
            "/robots.txt": (200, {"Content-Type": "text/plain"}, "User-agent: *\nAllow: /\n"),
            "/page": (200, {"Content-Type": "text/html", "X-Node-Version": "24.22.0"}, '<title>Fixture</title><script src="/never-fetch.js"></script>'),
        }
        self.scanner = checker.Checker(timeout=2, delay=0.001)

    def paths(self):
        return [entry[1] for entry in self.server.requests]

    def test_only_robots_and_requested_page_are_fetched(self):
        result = self.scanner.check(self.base + "/page")
        self.assertEqual(result.node2shell_status, "potentially_affected")
        self.assertEqual(self.paths(), ["/robots.txt", "/page"])
        for method, _, headers in self.server.requests:
            self.assertEqual(method, "GET")
            self.assertEqual(headers.get("Accept-Encoding"), "identity")
            self.assertNotIn("Content-Encoding", headers)
            self.assertIn(checker.BOT, headers.get("User-Agent", ""))

    def test_robots_disallow_stops_before_page(self):
        self.server.routes["/robots.txt"] = (200, {}, "User-agent: *\nDisallow: /page\n")
        result = self.scanner.check(self.base + "/page")
        self.assertEqual(result.status, "blocked")
        self.assertEqual(result.node2shell_status, "unknown")
        self.assertEqual(self.paths(), ["/robots.txt"])

    def test_unavailable_robots_is_not_bypassed(self):
        for status in (401, 403, 429, 500, 503):
            with self.subTest(status=status):
                self.server.requests.clear()
                self.server.routes["/robots.txt"] = (status, {}, "restricted")
                result = checker.Checker(timeout=2, delay=0.001).check(self.base + "/page")
                self.assertEqual(result.status, "blocked")
                self.assertEqual(self.paths(), ["/robots.txt"])

    def test_absent_robots_allows_ordinary_page_request(self):
        for status in (404, 410):
            with self.subTest(status=status):
                self.server.requests.clear()
                self.server.routes["/robots.txt"] = (status, {}, "")
                result = checker.Checker(timeout=2, delay=0.001).check(self.base + "/page")
                self.assertEqual(result.node2shell_status, "potentially_affected")
                self.assertEqual(self.paths(), ["/robots.txt", "/page"])

    def test_html_or_compressed_robots_fails_closed(self):
        for headers, body in (({}, "<!doctype html><html>login</html>"), ({"Content-Encoding": "br"}, "User-agent: *\nAllow: /")):
            with self.subTest(headers=headers):
                self.server.requests.clear()
                self.server.routes["/robots.txt"] = (200, headers, body)
                result = checker.Checker(timeout=2, delay=0.001).check(self.base + "/page")
                self.assertEqual(result.status, "blocked")
                self.assertEqual(self.paths(), ["/robots.txt"])

    def test_excessive_crawl_delay_does_not_sleep_or_fetch_page(self):
        self.server.routes["/robots.txt"] = (200, {}, "User-agent: *\nCrawl-delay: 100\n")
        with mock.patch.object(checker.time, "sleep", side_effect=AssertionError("must stop before sleeping")):
            result = self.scanner.check(self.base + "/page")
        self.assertEqual(result.status, "blocked")
        self.assertEqual(self.paths(), ["/robots.txt"])

    def test_same_origin_redirect_reuses_robots(self):
        self.server.routes["/start"] = (302, {"Location": "/page"}, "")
        result = self.scanner.check(self.base + "/start")
        self.assertEqual(result.node2shell_status, "potentially_affected")
        self.assertEqual(self.paths(), ["/robots.txt", "/start", "/page"])

    def test_cross_host_redirect_does_not_expand_scan_scope(self):
        self.server.routes["/start"] = (302, {"Location": f"http://localhost:{self.server.server_port}/page"}, "")
        result = self.scanner.check(self.base + "/start")
        self.assertEqual(result.status, "blocked")
        self.assertEqual(self.paths(), ["/robots.txt", "/start"])

    def test_redirect_loop_stops_without_retry(self):
        self.server.routes["/start"] = (302, {"Location": "/start"}, "")
        result = self.scanner.check(self.base + "/start")
        self.assertEqual(result.status, "blocked")
        self.assertEqual(self.paths(), ["/robots.txt", "/start"])

    def test_access_restrictions_are_not_retried(self):
        self.server.routes["/page"] = (429, {"Retry-After": "1"}, "wait")
        result = self.scanner.check(self.base + "/page")
        self.assertEqual(result.status, "blocked")
        self.assertEqual(self.paths(), ["/robots.txt", "/page"])

    def test_environment_proxy_is_not_used(self):
        with mock.patch.dict(os.environ, {"http_proxy": "http://127.0.0.1:1", "HTTP_PROXY": "http://127.0.0.1:1", "ALL_PROXY": "http://127.0.0.1:1", "no_proxy": "", "NO_PROXY": ""}):
            result = checker.Checker(timeout=2, delay=0.001).check(self.base + "/page")
        self.assertEqual(result.node2shell_status, "potentially_affected")
        self.assertEqual(self.paths(), ["/robots.txt", "/page"])

    def test_large_body_is_truncated_to_configured_limit(self):
        self.server.routes["/page"] = (200, {"Content-Type": "text/html"}, "A" * 128)
        response = self.scanner.request(self.base + "/page", 32)
        self.assertTrue(response.truncated)
        self.assertLessEqual(len(response.body), 32)


class ReportAndCliTests(unittest.TestCase):
    def test_html_escapes_untrusted_labels_and_brand(self):
        result = checker.Result(input_url='<img src=x onerror="alert(1)">')
        result.node2shell_notes = ['<script>alert("notes")</script>']
        report = checker.render_html([asdict(result)], logo=None, brand='<script>alert("brand")</script>')
        self.assertNotIn("<script>", report.lower())
        self.assertNotIn('<img src=x', report)
        self.assertIn("&lt;", report)
        self.assertIn("Content-Security-Policy", report)

    def test_csv_formula_fields_are_neutralized(self):
        for value in ("=1+1", "+SUM(A1)", "-1+1", "@SUM(A1)", " \t=HYPERLINK(\"x\")"):
            with self.subTest(value=value):
                self.assertTrue(checker.csv_safe(value).startswith("'"))

    def test_offline_version_mode_never_calls_network(self):
        with mock.patch.object(checker.Checker, "request", side_effect=AssertionError("offline mode contacted network")):
            status, stdout, _ = invoke_cli(["--node-version", "24.22.0", "--node-version", "24.22.1", "--format", "json"])
        self.assertEqual(status, 0)
        report = json.loads(stdout)
        self.assertTrue(report["complete"])
        self.assertEqual([row["node2shell_status"] for row in report["results"]], ["potentially_affected", "fixed_version_reported"])
        self.assertTrue(all(row["node2shell_exploitability"] == "not_tested" for row in report["results"]))

    def test_fail_on_finding_has_explicit_exit_code(self):
        for version, expected in (("24.22.0", 1), ("24.22.1", 0), ("20.19.0", 1)):
            with self.subTest(version=version):
                status, stdout, _ = invoke_cli(["--node-version", version, "--format", "json", "--fail-on-finding"])
                self.assertEqual(status, expected)
                self.assertTrue(json.loads(stdout)["complete"])

    def test_existing_output_survives_without_force(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            output.write_text("preserve this", encoding="utf-8")
            status, _, _ = invoke_cli(["--node-version", "24.22.1", "--format", "json", "--output", str(output)])
            self.assertEqual(status, 2)
            self.assertEqual(output.read_text(encoding="utf-8"), "preserve this")

    def test_force_replaces_output_with_valid_report(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            output.write_text("replace this", encoding="utf-8")
            status, _, _ = invoke_cli(["--node-version", "24.22.1", "--format", "json", "--output", str(output), "--force"])
            self.assertEqual(status, 0)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(report["results"][0]["node2shell_status"], "fixed_version_reported")

    def test_inventory_assessment_preserves_vendor_uncertainty(self):
        with tempfile.TemporaryDirectory() as directory:
            inventory = Path(directory) / "runtime.json"
            inventory.write_text(json.dumps({"schema_version": 1, "label": "container-example", "node_version": "24.22.1", "build_source": "vendor"}), encoding="utf-8")
            with mock.patch.object(checker.Checker, "request", side_effect=AssertionError("inventory contacted network")):
                status, stdout, _ = invoke_cli(["--inventory", str(inventory), "--format", "json"])
            self.assertEqual(status, 0)
            result = json.loads(stdout)["results"][0]
            self.assertEqual(result["node2shell_status"], "unknown")
            self.assertEqual(result["source"], "inventory")

    def test_inventory_cannot_be_overwritten_even_with_force(self):
        with tempfile.TemporaryDirectory() as directory:
            inventory = Path(directory) / "runtime.json"
            original = json.dumps({"schema_version": 1, "node_version": "24.22.1"})
            inventory.write_text(original, encoding="utf-8")
            status, _, _ = invoke_cli(["--inventory", str(inventory), "--output", str(inventory), "--force"])
            self.assertEqual(status, 2)
            self.assertEqual(inventory.read_text(encoding="utf-8"), original)

    def test_default_logo_cannot_be_overwritten_even_with_force(self):
        with tempfile.TemporaryDirectory() as directory:
            logo = Path(directory) / "logo.png"
            original = b"\x89PNG\r\n\x1a\nsynthetic-logo"
            logo.write_bytes(original)
            with mock.patch.object(checker, "DEFAULT_LOGO", logo):
                status, _, _ = invoke_cli(["--node-version", "24.22.1", "--format", "html", "--output", str(logo), "--force"])
            self.assertEqual(status, 2)
            self.assertEqual(logo.read_bytes(), original)

    def test_invalid_inventory_is_an_operational_error(self):
        with tempfile.TemporaryDirectory() as directory:
            inventory = Path(directory) / "runtime.json"
            for record in ({"schema_version": 2, "node_version": "24.22.1"}, {"schema_version": 1, "node_version": ["24.22.1"]}, {"schema_version": 1, "node_version": "24.22.1", "brotli_decompress_available": "false"}):
                with self.subTest(record=record):
                    inventory.write_text(json.dumps(record), encoding="utf-8")
                    status, _, _ = invoke_cli(["--inventory", str(inventory), "--format", "json"])
                    self.assertEqual(status, 2)

    def test_nonfinite_timeouts_and_header_injection_are_rejected(self):
        for arguments in (["--timeout", "nan"], ["--delay", "inf"], ["--timeout", "0"], ["--contact", "mail@example.test\r\nX-Injected: yes"]):
            with self.subTest(arguments=arguments):
                status, _, _ = invoke_cli(["--node-version", "24.22.1"] + arguments)
                self.assertEqual(status, 2)

    def test_interruption_preserves_completed_json_results(self):
        result = checker.Result(input_url="https://example.test/", status="no_evidence", fetch_status="ok")
        with mock.patch.object(checker.Checker, "check", side_effect=[result, KeyboardInterrupt()]):
            status, stdout, _ = invoke_cli(["https://example.test/", "https://other.example/", "--format", "json"])
        self.assertEqual(status, 130)
        report = json.loads(stdout)
        self.assertFalse(report["complete"])
        self.assertEqual(len(report["results"]), 1)

    def test_operational_failure_produces_error_exit_and_json(self):
        result = checker.Result(input_url="https://example.test/", status="error", fetch_status="dns_error")
        with mock.patch.object(checker.Checker, "check", return_value=result):
            status, stdout, _ = invoke_cli(["https://example.test/", "--format", "json"])
        self.assertEqual(status, 2)
        self.assertEqual(json.loads(stdout)["results"][0]["fetch_status"], "dns_error")


if __name__ == "__main__":
    unittest.main()
