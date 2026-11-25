import tomllib
import tempfile
import unittest
from pathlib import Path

from manjim import __version__
from manjim.cli import CONFIG_NAME, EXIT_OK, EXIT_USAGE, main


class TestInit(unittest.TestCase):
    def test_init_writes_config(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(main(["init", d]), EXIT_OK)
            cfg = tomllib.loads((Path(d) / CONFIG_NAME).read_text())
            self.assertEqual(cfg["version"], 1)

    def test_init_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            main(["init", d])
            self.assertEqual(main(["init", d]), EXIT_USAGE)
            self.assertEqual(main(["init", d, "--force"]), EXIT_OK)

    def test_version(self):
        self.assertRegex(__version__, r"^\d+\.\d+\.\d+")


if __name__ == "__main__":
    unittest.main()
