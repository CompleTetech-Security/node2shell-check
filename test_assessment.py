"""Risk-boundary tests for the offline Node2Shell assessment."""

import json
from pathlib import Path
import shutil
import subprocess
import unittest

from node2shell_check import assess_node2shell


class AssessmentTests(unittest.TestCase):
    def test_fixed_release_boundaries_across_all_supported_lines(self):
        cases = [
            ("22.23.3", "potentially_affected", "22.23.4"),
            ("22.23.4", "fixed_version_reported", "22.23.4"),
            ("22.24.0", "fixed_version_reported", "22.23.4"),
            ("24.22.0", "potentially_affected", "24.22.1"),
            ("24.22.1", "fixed_version_reported", "24.22.1"),
            ("24.23.0", "fixed_version_reported", "24.22.1"),
            ("26.12.0", "potentially_affected", "26.12.1"),
            ("26.12.1", "fixed_version_reported", "26.12.1"),
            ("26.13.0", "fixed_version_reported", "26.12.1"),
            ("22.9.99", "potentially_affected", "22.23.4"),
        ]
        for version, status, fixed in cases:
            with self.subTest(version=version):
                result = assess_node2shell(version)
                self.assertEqual(status, result["node2shell_status"])
                self.assertEqual(fixed, result["node2shell_fixed_version"])
                self.assertEqual("not_tested", result["node2shell_exploitability"])

    def test_missing_version_and_node_hint_never_imply_absence_or_fix(self):
        for hint in (False, True):
            result = assess_node2shell(node_hint=hint, brotli_version="1.2.1", brotli_block_switch_error=-17)
            self.assertEqual("unknown", result["node2shell_status"])
            self.assertEqual("version_not_disclosed", result["node2shell_version_status"])

    def test_conflicting_versions_are_retained_even_with_an_explicit_version(self):
        result = assess_node2shell("24.22.1", version_candidates=["24.22.0"])
        self.assertEqual("unknown", result["node2shell_status"])
        self.assertEqual("conflicting_versions", result["node2shell_version_status"])

    def test_common_leading_v_and_duplicate_candidates_normalize(self):
        result = assess_node2shell("v24.22.1", version_candidates=[" 24.22.1 ", "v24.22.1"])
        self.assertEqual("fixed_version_reported", result["node2shell_status"])

    def test_qualified_invalid_and_partial_versions_never_qualify_as_fixed(self):
        values = [
            "24.22", "24", "latest", "24.22.1-rc.1", "24.22.1+vendor.1",
            "24.22.1~deb1", "24.22.1-custom", "24.22.1.2", "24.22.1junk",
            "024.22.1", "24.022.1", "２４.２２.１", "-24.22.1", "v",
            "1" * 129 + ".0.0", 24, True,
        ]
        for version in values:
            with self.subTest(version=version):
                self.assertEqual("unknown", assess_node2shell(version)["node2shell_status"])

    def test_vendor_and_custom_builds_are_not_cleared_by_version_or_constant(self):
        for source in ("vendor", "custom", "distribution", "distro", "unrecognized", None):
            for version in ("24.22.0", "24.22.1"):
                with self.subTest(source=source, version=version):
                    result = assess_node2shell(version, build_source=source, brotli_block_switch_error=-17)
                    self.assertEqual("unknown", result["node2shell_status"])
                    self.assertEqual("vendor_build_unverified", result["node2shell_version_status"])

    def test_supported_old_version_with_patch_marker_requires_backport_review(self):
        result = assess_node2shell("24.22.0", brotli_block_switch_error=-17)
        self.assertEqual("unknown", result["node2shell_status"])
        self.assertEqual("backport_evidence_unverified", result["node2shell_version_status"])

    def test_brotli_version_alone_cannot_override_node_release_assessment(self):
        for brotli in ("1.0.9", "1.1.0", "1.2.0", "1.2.1", "999.999.999"):
            self.assertEqual("potentially_affected", assess_node2shell("24.22.0", brotli_version=brotli)["node2shell_status"])
            self.assertEqual("fixed_version_reported", assess_node2shell("24.22.1", brotli_version=brotli)["node2shell_status"])

    def test_fixed_version_with_missing_brotli_api_is_not_cleared(self):
        result = assess_node2shell("24.22.1", brotli_decompress_available=False)
        self.assertEqual("unknown", result["node2shell_status"])
        self.assertEqual("brotli_decoder_unavailable", result["node2shell_version_status"])

    def test_contradictory_typed_runtime_metadata_is_not_cleared(self):
        for constant in (-9, 17, "-17", False, -17.0):
            with self.subTest(constant=constant):
                result = assess_node2shell("24.22.1", brotli_block_switch_error=constant)
                self.assertEqual("unknown", result["node2shell_status"])
                self.assertEqual("runtime_metadata_inconsistent", result["node2shell_version_status"])
        self.assertEqual("unknown", assess_node2shell("24.22.1", brotli_decompress_available="true")["node2shell_status"])

    def test_complete_decoder_metadata_without_patch_constant_requires_review(self):
        result = assess_node2shell("24.22.1", brotli_version="1.2.0", brotli_decompress_available=True, brotli_block_switch_error=None)
        self.assertEqual("unknown", result["node2shell_status"])
        self.assertEqual("runtime_metadata_inconsistent", result["node2shell_version_status"])

    def test_null_constant_without_complete_metadata_is_not_a_false_contradiction(self):
        result = assess_node2shell("24.22.1", brotli_block_switch_error=None)
        self.assertEqual("fixed_version_reported", result["node2shell_status"])
        self.assertTrue(any("No Brotli block-switch" in note for note in result["node2shell_notes"]))

    def test_matching_decoder_metadata_reports_only_a_version_based_fix(self):
        result = assess_node2shell("24.22.1", brotli_version="1.2.0", brotli_decompress_available=True, brotli_block_switch_error=-17)
        self.assertEqual("fixed_version_reported", result["node2shell_status"])
        self.assertEqual("not_tested", result["node2shell_exploitability"])
        self.assertTrue(any("not proof" in note for note in result["node2shell_notes"]))

    def test_unsupported_and_future_lines_do_not_inherit_another_lines_fix(self):
        for version in ("0.12.0", "10.0.0", "18.99.0", "20.99.0", "21.0.0", "23.99.0", "25.99.0"):
            with self.subTest(version=version):
                result = assess_node2shell(version)
                self.assertEqual("unsupported_runtime", result["node2shell_status"])
                self.assertEqual("", result["node2shell_fixed_version"])
        for version in ("27.0.0", "28.0.0", "999.0.0"):
            self.assertEqual("unknown", assess_node2shell(version)["node2shell_status"])

    def test_empty_and_malformed_candidates_are_bounded_and_unknown(self):
        for candidates in ([], ["", None], [1], {"version": "24.22.1"}, ["24.22.1"] * 129):
            with self.subTest(candidates=candidates):
                self.assertEqual("unknown", assess_node2shell(version_candidates=candidates)["node2shell_status"])

    def test_result_has_dated_sources_and_no_exploit_claim(self):
        result = assess_node2shell("24.22.0")
        self.assertEqual(["CVE-2026-111497"], result["node2shell_cves"])
        self.assertEqual("2026-10-23", result["node2shell_rules_as_of"])
        self.assertTrue(result["node2shell_sources"])
        self.assertTrue(all(url.startswith("https://nodejs.org/") for url in result["node2shell_sources"]))
        self.assertEqual("not_tested", result["node2shell_exploitability"])


@unittest.skipUnless(shutil.which("node"), "Node.js is not installed")
class CollectorTests(unittest.TestCase):
    def test_collector_emits_only_expected_inventory_fields(self):
        path = Path(__file__).with_name("collect-runtime.cjs")
        process = subprocess.run([shutil.which("node"), str(path)], capture_output=True, text=True, timeout=10, check=True)
        self.assertEqual("", process.stderr)
        data = json.loads(process.stdout)
        self.assertEqual({
            "schema_version", "label", "runtime", "node_version", "build_source",
            "brotli_version", "brotli_decompress_available", "brotli_block_switch_error",
            "platform", "architecture",
        }, set(data))
        self.assertEqual(1, data["schema_version"])
        self.assertEqual("node", data["runtime"])
        self.assertEqual("unknown", data["build_source"])
        self.assertIsInstance(data["brotli_decompress_available"], bool)


if __name__ == "__main__":
    unittest.main()
