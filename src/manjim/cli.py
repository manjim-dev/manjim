"""Command-line entry point. Stdlib only."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from manjim import __version__

# Exit codes (stable contract, documented in README)
EXIT_OK = 0
EXIT_FINDINGS = 1      # score below --fail-under / verify mismatch
EXIT_USAGE = 2         # bad args, missing files
EXIT_NOT_IMPLEMENTED = 3

CONFIG_NAME = "manjim.toml"  # read back with stdlib tomllib (3.11+)
DEFAULT_CONFIG = """\
version = 1
frameworks = ["iso27001:2022", "soc2"]
fail_under = 0
mask_secrets = true
exclude = [".git", "node_modules", ".venv", "__pycache__"]
"""


def cmd_init(args: argparse.Namespace) -> int:
    target = Path(args.path) / CONFIG_NAME
    if target.exists() and not args.force:
        print(f"{target} already exists (use --force to overwrite)", file=sys.stderr)
        return EXIT_USAGE
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(DEFAULT_CONFIG, encoding="utf-8")
    print(f"wrote {target}")
    return EXIT_OK


def _todo(name: str):
    def run(_: argparse.Namespace) -> int:
        print(f"manjim {name}: not implemented yet", file=sys.stderr)
        return EXIT_NOT_IMPLEMENTED
    return run


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="manjim", description=__doc__)
    p.add_argument("--version", action="version", version=f"manjim {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("init", help="create manjim.toml in a directory")
    s.add_argument("path", nargs="?", default=".")
    s.add_argument("--force", action="store_true")
    s.set_defaults(func=cmd_init)

    s = sub.add_parser("audit", help="audit a path, map findings to ISO 27001:2022 / SOC 2")
    s.add_argument("path")
    s.add_argument("--fail-under", type=int, default=None, metavar="SCORE")
    s.add_argument("--format", choices=["text", "json", "md"], default="text")
    s.set_defaults(func=_todo("audit"))

    s = sub.add_parser("risk", help="build a DPDP-aware risk register from assets.json")
    s.add_argument("assets")
    s.add_argument("--format", choices=["text", "json", "md", "csv"], default="text")
    s.set_defaults(func=_todo("risk"))

    s = sub.add_parser("seal", help="seal a report (integrity; tamper-evident with --key)")
    s.add_argument("file")
    s.add_argument("--key", help="HMAC key file")
    s.set_defaults(func=_todo("seal"))

    s = sub.add_parser("verify", help="verify a sealed report")
    s.add_argument("file")
    s.add_argument("--key", help="HMAC key file")
    s.set_defaults(func=_todo("verify"))
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)
