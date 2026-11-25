import json
import os
import tempfile
import unittest
from pathlib import Path

from manjim import audit
from manjim.cli import EXIT_FINDINGS, EXIT_OK, EXIT_USAGE, main

# built at runtime so this file never contains a scanner-matchable secret
FAKE_AWS = "AKIA" + "Z" * 16
FAKE_GH = "ghp" + "_" + "a" * 36
PK_HEADER = "-----BEGIN " + "RSA PRIVATE KEY-----"


def clean_repo(d: Path) -> None:
    (d / ".gitignore").write_text(".env\n*.key\n")
    (d / "LICENSE").write_text("Apache-2.0\n")
    (d / "SECURITY.md").write_text("report privately\n")
    (d / "app.py").write_text("print('hi')\n")


class AuditTest(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.d = Path(self._t.name)

    def tearDown(self):
        self._t.cleanup()

    def checks(self, **kw):
        return [f.check for f in audit.run(self.d, **kw).findings]

    def test_clean_repo_scores_100(self):
        clean_repo(self.d)
        rep = audit.run(self.d)
        self.assertEqual(rep.findings, [])
        self.assertEqual(rep.score, 100)

    def test_empty_dir_flags_missing_files(self):
        self.assertEqual(self.checks(), ["MJ003", "MJ007", "MJ008"])

    def test_secrets_detected_and_masked(self):
        clean_repo(self.d)
        (self.d / "cfg.py").write_text(f'aws = "{FAKE_AWS}"\ntok = "{FAKE_GH}"\n{PK_HEADER}\npassword = "hunter2hunter2"\n')
        rep = audit.run(self.d)
        s = [f for f in rep.findings if f.check == "MJ001"]
        self.assertEqual([f.line for f in s], [1, 2, 3, 4])
        blob = json.dumps(audit.to_dict(rep, None))
        self.assertNotIn(FAKE_AWS, blob)
        self.assertNotIn("hunter2hunter2", blob)

    def test_mask_off_shows_value(self):
        clean_repo(self.d)
        (self.d / "c.py").write_text(f'k = "{FAKE_AWS}"\n')
        self.assertIn(FAKE_AWS, audit.run(self.d, mask=False).findings[0].detail)

    def test_sensitive_files_and_allowlist(self):
        clean_repo(self.d)
        for n in (".env", "server.pem", "id_rsa", ".env.example"):
            (self.d / n).write_text("x\n")
        got = sorted(f.path for f in audit.run(self.d).findings if f.check == "MJ002")
        self.assertEqual(got, [".env", "id_rsa", "server.pem"])

    def test_gitignore_gaps(self):
        clean_repo(self.d)
        (self.d / ".gitignore").write_text("dist/\n")
        f = [f for f in audit.run(self.d).findings if f.check == "MJ004"]
        self.assertEqual(f[0].detail, "missing: .env, *.key")

    def test_moving_action_ref(self):
        clean_repo(self.d)
        wf = self.d / ".github" / "workflows"
        wf.mkdir(parents=True)
        (wf / "ci.yml").write_text("steps:\n  - uses: actions/checkout@v6\n  - uses: evil/act@main\n")
        f = [f for f in audit.run(self.d).findings if f.check == "MJ006"]
        self.assertEqual((f[0].line, f[0].detail), (3, "evil/act@main"))

    @unittest.skipUnless(os.name == "posix", "POSIX permissions")
    def test_world_writable(self):
        clean_repo(self.d)
        os.chmod(self.d / "app.py", 0o666)
        self.assertIn("MJ005", self.checks())

    def test_excludes_and_binary_skipped(self):
        clean_repo(self.d)
        (self.d / "node_modules").mkdir()
        (self.d / "node_modules" / "x.js").write_text(f'k="{FAKE_AWS}"\n')
        (self.d / "blob.bin").write_bytes(b"\x00\x01" + FAKE_AWS.encode())
        self.assertEqual(self.checks(), [])

    def test_score_caps_repeats(self):
        clean_repo(self.d)
        (self.d / "c.py").write_text("".join(f'k{i} = "{FAKE_AWS}"\n' for i in range(50)))
        self.assertEqual(audit.run(self.d).score, 60)  # capped at 2x high weight

    def test_deterministic_json(self):
        clean_repo(self.d)
        (self.d / "c.py").write_text(f'k = "{FAKE_AWS}"\n')
        a = audit.render(audit.run(self.d), "json", 70)
        b = audit.render(audit.run(self.d), "json", 70)
        self.assertEqual(a, b)

    # --- CLI ---
    def test_cli_fail_under_and_out(self):
        clean_repo(self.d)
        (self.d / "c.py").write_text(f'k = "{FAKE_AWS}"\n')
        out = self.d / "out" / "r.json"
        out.parent.mkdir()
        self.assertEqual(main(["audit", str(self.d), "--fail-under", "90", "--format", "json", "--out", str(out)]),
                         EXIT_FINDINGS)
        doc = json.loads(out.read_bytes())
        self.assertEqual((doc["score"], doc["passed"]), (80, False))
        self.assertNotIn(b"\r", out.read_bytes())
        self.assertEqual(main(["audit", str(self.d), "--fail-under", "80", "--out", str(out)]), EXIT_OK)

    def test_cli_config_fail_under_and_exclude(self):
        clean_repo(self.d)
        (self.d / "vendor").mkdir()
        (self.d / "vendor" / "c.py").write_text(f'k = "{FAKE_AWS}"\n')
        (self.d / "manjim.toml").write_text('version = 1\nfail_under = 100\nexclude = ["vendor"]\n')
        self.assertEqual(main(["audit", str(self.d), "--out", str(self.d / "r.txt")]), EXIT_OK)

    def test_cli_usage_errors(self):
        self.assertEqual(main(["audit", str(self.d / "missing")]), EXIT_USAGE)
        (self.d / "manjim.toml").write_text("not = = toml")
        self.assertEqual(main(["audit", str(self.d)]), EXIT_USAGE)

    def test_sarif(self):
        clean_repo(self.d)
        (self.d / "c.py").write_text(f'x = 1\nk = "{FAKE_AWS}"\n')
        (self.d / "LICENSE").unlink()
        doc = json.loads(audit.render(audit.run(self.d), "sarif", None))
        self.assertEqual(doc["version"], "2.1.0")
        run = doc["runs"][0]
        rules = [r["id"] for r in run["tool"]["driver"]["rules"]]
        self.assertEqual(rules, sorted(audit.CHECKS))
        by_rule = {r["ruleId"]: r for r in run["results"]}
        sec = by_rule["MJ001"]
        self.assertEqual(sec["level"], "error")
        self.assertEqual(rules[sec["ruleIndex"]], "MJ001")
        self.assertEqual(sec["locations"][0]["physicalLocation"]["region"], {"startLine": 2})
        self.assertNotIn("region", by_rule["MJ008"]["locations"][0]["physicalLocation"])
        self.assertNotIn(FAKE_AWS, json.dumps(doc))
        self.assertEqual(run["properties"]["score"], 75)

    def test_cli_sarif_out(self):
        out = self.d / "r.sarif"
        self.assertEqual(main(["audit", str(self.d), "--format", "sarif", "--out", str(out)]), EXIT_OK)
        self.assertEqual(json.loads(out.read_bytes())["version"], "2.1.0")

    def test_md_format(self):
        text = audit.render(audit.run(self.d), "md", None)
        self.assertIn("| MJ003 |", text)


if __name__ == "__main__":
    unittest.main()
