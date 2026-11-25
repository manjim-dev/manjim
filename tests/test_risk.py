import copy
import csv
import io
import json
import tempfile
import unittest
from pathlib import Path

from manjim import risk
from manjim.cli import EXIT_FINDINGS, EXIT_OK, EXIT_USAGE, main


def asset(**kw):
    a = {"id": "A1", "name": "DB", "risks": [{"id": "R1", "threat": "x", "likelihood": 2, "impact": 2}]}
    a.update(kw)
    return a


class RiskTest(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.d = Path(self._t.name)
        self.f = self.d / "assets.json"

    def tearDown(self):
        self._t.cleanup()

    def write(self, doc):
        self.f.write_text(json.dumps(doc))

    def test_rating_bands(self):
        self.assertEqual([risk.rating(s) for s in (1, 4, 5, 9, 10, 16, 20, 25)],
                         ["low", "low", "medium", "medium", "high", "high", "critical", "critical"])

    def test_example_builds_sorted(self):
        rows, flags = risk.build(copy.deepcopy(risk.EXAMPLE))
        self.assertEqual([r.score for r in rows], sorted((r.score for r in rows), reverse=True))
        self.assertEqual([(f.asset_id, f.section) for f in flags], [("A1", "s.8(6)")])

    def test_dpdp_flags(self):
        doc = {"assets": [asset(personal_data=True, data_categories=["Children"], cross_border=True)]}
        _, flags = risk.build(doc)
        self.assertEqual([f.section for f in flags], ["s.8(5)", "s.8(6)", "s.8(7)", "s.9", "s.16"])

    def test_no_flags_without_personal_data(self):
        _, flags = risk.build({"assets": [asset(data_categories=["children"])]})
        self.assertEqual(flags, [])

    def test_validation_errors_name_the_field(self):
        bad = [
            ({"assets": []}, "non-empty"),
            ({"assets": [asset(risks=[{"threat": "x", "likelihood": 6, "impact": 1}])]}, "risks[0].likelihood"),
            ({"assets": [asset(risks=[{"threat": "x", "likelihood": True, "impact": 1}])]}, "likelihood"),
            ({"assets": [asset(), asset()]}, "duplicated"),
            ({"assets": [asset(risks=[{"threat": "x", "likelihood": 1, "impact": 1, "treatment": "ignore"}])]}, "treatment"),
            ({"assets": [asset(confidentiality=4)]}, "confidentiality"),
            ({"assets": [asset(personal_data="yes")]}, "personal_data"),
        ]
        for doc, needle in bad:
            with self.subTest(needle=needle), self.assertRaises(risk.RiskError) as cm:
                risk.build(risk.load(self._dump(doc)))
            self.assertIn(needle, str(cm.exception))

    def _dump(self, doc):
        self.write(doc)
        return self.f

    def test_formats_deterministic(self):
        doc = copy.deepcopy(risk.EXAMPLE)
        rows, flags = risk.build(doc)
        for fmt in ("text", "json", "md", "csv"):
            self.assertEqual(risk.render(doc, rows, flags, fmt), risk.render(doc, *risk.build(doc), fmt))
        out = list(csv.reader(io.StringIO(risk.render(doc, rows, flags, "csv"))))
        self.assertEqual(out[0][0], "asset_id")
        self.assertEqual(len(out), 1 + len(rows))

    def test_md_escapes_pipes(self):
        doc = {"assets": [asset(name="a|b")]}
        self.assertIn("a\\|b", risk.render(doc, *risk.build(doc), "md"))

    # --- CLI ---
    def test_cli_example_then_run(self):
        self.assertEqual(main(["risk", str(self.f), "--example"]), EXIT_OK)
        self.assertEqual(main(["risk", str(self.f), "--example"]), EXIT_USAGE)
        out = self.d / "r.csv"
        self.assertEqual(main(["risk", str(self.f), "--format", "csv", "--out", str(out)]), EXIT_OK)
        self.assertNotIn(b"\r", out.read_bytes())

    def test_cli_fail_on(self):
        self.write({"assets": [asset(risks=[{"threat": "x", "likelihood": 3, "impact": 5}])]})  # 15 high
        self.assertEqual(main(["risk", str(self.f), "--fail-on", "high"]), EXIT_FINDINGS)
        self.assertEqual(main(["risk", str(self.f), "--fail-on", "critical"]), EXIT_OK)
        self.assertEqual(main(["risk", str(self.f)]), EXIT_OK)

    def test_cli_usage(self):
        self.assertEqual(main(["risk", str(self.d / "missing.json")]), EXIT_USAGE)
        self.f.write_text("{not json")
        self.assertEqual(main(["risk", str(self.f)]), EXIT_USAGE)


if __name__ == "__main__":
    unittest.main()
