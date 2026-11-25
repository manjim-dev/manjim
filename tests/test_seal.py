import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from manjim.cli import EXIT_FINDINGS, EXIT_OK, EXIT_USAGE, main


class SealTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.d = Path(self._tmp.name)
        self.report = self.d / "report.json"
        self.report.write_bytes(b'{"score": 82}\n')
        self.seal = self.d / "report.json.seal"
        self.key = self.d / "audit.key"

    def tearDown(self):
        self._tmp.cleanup()

    def run_cli(self, *argv):
        return main([str(a) for a in argv])

    # --- integrity-only ---
    def test_unkeyed_roundtrip_matches_sha256sum(self):
        self.assertEqual(self.run_cli("seal", self.report), EXIT_OK)
        doc = json.loads(self.seal.read_text())
        self.assertEqual(doc["algorithm"], "sha256")
        self.assertEqual(doc["digest"], hashlib.sha256(self.report.read_bytes()).hexdigest())
        self.assertEqual(self.run_cli("verify", self.report), EXIT_OK)

    def test_unkeyed_detects_change(self):
        self.run_cli("seal", self.report)
        self.report.write_bytes(b'{"score": 99}\n')
        self.assertEqual(self.run_cli("verify", self.report), EXIT_FINDINGS)

    def test_deterministic(self):
        self.run_cli("seal", self.report)
        a = self.seal.read_bytes()
        self.run_cli("seal", self.report)
        self.assertEqual(a, self.seal.read_bytes())
        self.assertNotIn(b"\r", a)
        self.assertTrue(a.endswith(b"\n"))

    # --- keyed ---
    def test_keyed_roundtrip_and_tamper(self):
        self.assertEqual(self.run_cli("keygen", self.key), EXIT_OK)
        self.assertEqual(self.run_cli("seal", self.report, "--key", self.key), EXIT_OK)
        self.assertEqual(json.loads(self.seal.read_text())["algorithm"], "hmac-sha256")
        self.assertEqual(self.run_cli("verify", self.report, "--key", self.key), EXIT_OK)
        self.report.write_bytes(b'{"score": 99}\n')
        self.assertEqual(self.run_cli("verify", self.report, "--key", self.key), EXIT_FINDINGS)

    def test_wrong_key_fails(self):
        self.run_cli("keygen", self.key)
        other = self.d / "other.key"
        self.run_cli("keygen", other)
        self.run_cli("seal", self.report, "--key", self.key)
        self.assertEqual(self.run_cli("verify", self.report, "--key", other), EXIT_FINDINGS)

    def test_attacker_reseal_without_key_is_rejected(self):
        # keyed seal replaced by an unkeyed one of the tampered file
        self.run_cli("keygen", self.key)
        self.run_cli("seal", self.report, "--key", self.key)
        self.report.write_bytes(b'{"score": 99}\n')
        self.run_cli("seal", self.report)
        self.assertEqual(self.run_cli("verify", self.report, "--key", self.key), EXIT_FINDINGS)

    def test_keyed_seal_without_key_is_usage_error(self):
        self.run_cli("keygen", self.key)
        self.run_cli("seal", self.report, "--key", self.key)
        self.assertEqual(self.run_cli("verify", self.report), EXIT_USAGE)

    def test_key_trailing_newline_tolerated(self):
        self.key.write_bytes(b"a" * 32 + b"\r\n")
        self.run_cli("seal", self.report, "--key", self.key)
        self.key.write_bytes(b"a" * 32)
        self.assertEqual(self.run_cli("verify", self.report, "--key", self.key), EXIT_OK)

    # --- usage / malformed ---
    def test_short_key_rejected(self):
        self.key.write_bytes(b"short")
        self.assertEqual(self.run_cli("seal", self.report, "--key", self.key), EXIT_USAGE)

    def test_missing_inputs(self):
        self.assertEqual(self.run_cli("seal", self.d / "nope.json"), EXIT_USAGE)
        self.assertEqual(self.run_cli("verify", self.report), EXIT_USAGE)  # no seal yet
        self.assertEqual(self.run_cli("seal", self.report, "--key", self.d / "nokey"), EXIT_USAGE)

    def test_malformed_seal_fails(self):
        self.seal.write_text("not json")
        self.assertEqual(self.run_cli("verify", self.report), EXIT_FINDINGS)
        self.seal.write_text('{"manjim_seal": 1, "algorithm": "md5", "digest": "x"}')
        self.assertEqual(self.run_cli("verify", self.report), EXIT_FINDINGS)

    def test_custom_seal_path(self):
        out = self.d / "sub.seal"
        self.assertEqual(self.run_cli("seal", self.report, "--out", out), EXIT_OK)
        self.assertEqual(self.run_cli("verify", self.report, "--seal", out), EXIT_OK)

    def test_keygen_refuses_overwrite(self):
        self.run_cli("keygen", self.key)
        self.assertEqual(self.run_cli("keygen", self.key), EXIT_USAGE)
        self.assertEqual(self.run_cli("keygen", self.key, "--force"), EXIT_OK)
        self.assertEqual(len(self.key.read_bytes().strip()), 64)


if __name__ == "__main__":
    unittest.main()
