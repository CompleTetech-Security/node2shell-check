"""Synthetic release envelopes and mocked gh; no production requests or signing."""
from datetime import datetime, timedelta, timezone
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("keyless_rules", Path(__file__).parent / "tools/signed_rules/keyless_rules.py")
k = importlib.util.module_from_spec(spec)
spec.loader.exec_module(k)


class KeylessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.artifact, self.bundle, self.trust, self.state, self.output = [self.root / name for name in ("rules.json", "bundle.json", "roots.jsonl", "state.json", "review.json")]
        self.bundle.write_text("synthetic-bundle", encoding="utf-8")
        self.trust.write_text("independent-synthetic-root", encoding="utf-8")
        self.now = datetime(2026, 10, 26, tzinfo=timezone.utc)
        self.value = k.build(1001, "a" * 40, self.now)
        self.artifact.write_bytes(k.encoded(self.value))

    def verify(self, value=None, **kwargs):
        if value is not None:
            self.artifact.write_bytes(k.encoded(value))
        with patch("socket.socket", side_effect=AssertionError("offline only")):
            with patch.object(k, "verify_provenance") as proof:
                result = k.verify(self.artifact, self.bundle, self.trust, self.state, self.output, now=self.now, **kwargs)
                proof.assert_called_once()
                return result

    def test_build_matches_embedded_snapshot_and_never_changes_checker(self):
        import node2shell_check as checker
        before = Path(checker.__file__).read_bytes()
        self.assertEqual({str(a): list(b) for a, b in checker.NODE2SHELL_FIXES.items()}, self.value["rules"]["fixes"])
        self.assertEqual(hashlib.sha256(before).hexdigest(), self.value["rules"]["checker_sha256"])
        self.verify()
        self.assertEqual(self.value["rules"], json.loads(self.output.read_bytes()))
        self.assertEqual(before, Path(checker.__file__).read_bytes())
        self.assertEqual(1001, json.loads(self.state.read_bytes())["sequence"])

    def test_unsigned_tampered_and_untrusted_rejections_preserve_previous_output(self):
        self.verify()
        before = self.output.read_bytes()
        for error in (ValueError("wrong publisher"), subprocess.CalledProcessError(1, ["gh"]), subprocess.TimeoutExpired(["gh"], 1)):
            with patch.object(k, "verify_provenance", side_effect=error):
                with self.assertRaises((ValueError, subprocess.SubprocessError)):
                    k.verify(self.artifact, self.bundle, self.trust, self.state, self.output, True, self.now)
            self.assertEqual(before, self.output.read_bytes())

    def test_expiry_future_timestamps_and_schema_uncertainty_fail_closed(self):
        self.verify()
        before = self.output.read_bytes()
        cases = []
        for key, value in [("expires_at", k.timestamp(self.now)), ("issued_at", k.timestamp(self.now + timedelta(minutes=6))), ("sequence", True), ("source_commit", "../x")]:
            item = copy.deepcopy(self.value); item[key] = value; cases.append(item)
        for key, value in [("exploitability", "confirmed"), ("fixes", {"24": [22, 0, 1]}), ("as_of", "2099-01-01"), ("sources", ["https://private.invalid"] )]:
            item = copy.deepcopy(self.value); item["rules"][key] = value; cases.append(item)
        for value in cases:
            with self.assertRaises(ValueError): self.verify(value, force=True)
            self.assertEqual(before, self.output.read_bytes())

    def test_rollback_sequence_reuse_and_same_artifact_retry(self):
        self.verify()
        self.verify(force=True)
        for sequence in (1000, 1001):
            value = copy.deepcopy(self.value); value["sequence"] = sequence
            value["rules"]["checker_sha256"] = "b" * 64
            with self.assertRaisesRegex(ValueError, "rollback|reuse"): self.verify(value, force=True)
        newer = copy.deepcopy(self.value); newer["sequence"] = 2001
        self.verify(newer, force=True)
        self.assertEqual(2001, json.loads(self.state.read_bytes())["sequence"])

    def test_clock_rollback_invalid_state_and_existing_lock_are_not_bypassed(self):
        self.verify()
        prior = json.loads(self.state.read_bytes())
        prior["accepted_at"] = k.timestamp(self.now + timedelta(minutes=10))
        self.state.write_bytes(k.encoded(prior))
        with patch.object(k, "verify_provenance"):
            with self.assertRaisesRegex(ValueError, "Clock rollback"):
                k.verify(self.artifact, self.bundle, self.trust, self.state, self.output, True, self.now + timedelta(minutes=4))
        self.state.write_text('{"sequence":1}', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "durable state"): self.verify(force=True)
        lock = self.state.with_name(self.state.name + ".lock"); lock.write_text("other owner", encoding="utf-8")
        with self.assertRaises(FileExistsError): self.verify(force=True)
        self.assertEqual("other owner", lock.read_text())

    def test_protected_paths_hardlinks_and_no_clobber(self):
        self.verify()
        with self.assertRaises(ValueError): self.verify()
        for path in (self.artifact, self.bundle, self.trust, self.state, self.state.with_name(self.state.name + ".lock"), Path(__file__).parent / "node2shell_check.py"):
            with self.assertRaises(ValueError):
                k.verify(self.artifact, self.bundle, self.trust, self.state, path, True, self.now)
        alias = self.root / "alias"; os.link(self.artifact, alias)
        with self.assertRaises(ValueError):
            k.verify(self.artifact, self.bundle, self.trust, self.state, alias, True, self.now)

    def test_failed_output_fences_rollback_and_allows_verified_retry(self):
        real_atomic = k.atomic
        def failure(path, data, replace=False):
            if path == self.output: raise OSError("output unavailable")
            return real_atomic(path, data, replace)
        with patch.object(k, "atomic", side_effect=failure):
            with self.assertRaises(OSError): self.verify()
        self.assertEqual(1001, json.loads(self.state.read_bytes())["sequence"])
        self.assertFalse(self.output.exists())
        self.verify()
        self.assertEqual([], list(self.root.glob(".rules-*")))

    def test_gh_policy_checks_cert_numeric_ids_and_exact_source_identity(self):
        good = [{"verificationResult": {"signature": {"certificate": {"sourceRepositoryIdentifier": k.REPOSITORY_ID, "sourceRepositoryOwnerIdentifier": k.OWNER_ID}}}}]
        for wrong in (False, True):
            value = copy.deepcopy(good)
            if wrong: value[0]["verificationResult"]["signature"]["certificate"]["sourceRepositoryIdentifier"] = "123"
            def run(command, **kwargs):
                self.assertIn("--custom-trusted-root", command)
                self.assertIn("--bundle", command)
                for expected in (k.IDENTITY, k.ISSUER, "--deny-self-hosted-runners", "--source-digest", "--signer-digest", "refs/heads/main"):
                    self.assertIn(expected, command)
                self.assertNotIn("shell", kwargs)
                kwargs["stdout"].write(k.encoded(value))
            with patch.object(k.shutil, "which", return_value="trusted-gh"), patch.object(k.subprocess, "run", side_effect=run):
                if wrong:
                    with self.assertRaisesRegex(ValueError, "numeric identity"):
                        k.verify_provenance(self.artifact, self.bundle, self.trust, "a" * 40)
                else: k.verify_provenance(self.artifact, self.bundle, self.trust, "a" * 40)

    def test_oversize_duplicate_json_and_malformed_output_never_publish(self):
        self.artifact.write_bytes(b" " * (k.MAX_BYTES + 1))
        with self.assertRaises(ValueError): self.verify()
        self.artifact.write_bytes(b'{"schema":1,"schema":2}')
        with self.assertRaises(ValueError): self.verify()
        self.assertFalse(self.state.exists()); self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
