"""Command-line entry point. Stdlib only."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from manjim import __version__
from manjim import audit as _audit
from manjim import risk as _risk
from manjim import seal as _seal

# Exit codes (stable contract, documented in README)
EXIT_OK = 0
EXIT_FINDINGS = 1      # score below --fail-under / verify mismatch
EXIT_USAGE = 2         # bad args, missing files
EXIT_NOT_IMPLEMENTED = 3  # reserved for future stubs

CONFIG_NAME = "manjim.toml"  # read back with stdlib tomllib (3.11+)
DEFAULT_CONFIG = """\
version = 1
frameworks = ["iso27001:2022", "soc2"]
fail_under = 0
mask_secrets = true
exclude = [".git", "node_modules", ".venv", "__pycache__"]
# ignore = ["MJ008", "MJ001:tests/*"]  # check, or check:path-glob
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


def cmd_audit(args: argparse.Namespace) -> int:
    root = Path(args.path)
    try:
        cfg = _audit.load_config(root) if root.is_dir() else {}
        rep = _audit.run(root, exclude=cfg.get("exclude"), mask=cfg.get("mask_secrets", True),
                         ignore=_audit.parse_ignore(cfg.get("ignore")))
    except _audit.AuditError as e:
        print(f"manjim audit: {e}", file=sys.stderr)
        return EXIT_USAGE
    fail_under = args.fail_under if args.fail_under is not None else (cfg.get("fail_under") or None)
    text = _audit.render(rep, args.format, fail_under)
    _emit(text, args.out, f"score {rep.score}")
    return EXIT_FINDINGS if fail_under is not None and rep.score < fail_under else EXIT_OK


def _emit(text: str, out: str | None, note: str) -> None:
    if out:
        Path(out).write_bytes(text.encode("utf-8"))  # UTF-8 + LF on every OS
        print(f"wrote {out} ({note})")
    else:
        sys.stdout.write(text)


def cmd_risk(args: argparse.Namespace) -> int:
    path = Path(args.assets)
    if args.example:
        if path.exists():
            print(f"manjim risk: {path} already exists", file=sys.stderr)
            return EXIT_USAGE
        path.write_bytes((json.dumps(_risk.EXAMPLE, indent=2) + "\n").encode("utf-8"))
        print(f"wrote example {path}")
        return EXIT_OK
    try:
        doc = _risk.load(path)
        rows, flags = _risk.build(doc)
    except _risk.RiskError as e:
        print(f"manjim risk: {e}", file=sys.stderr)
        return EXIT_USAGE
    _emit(_risk.render(doc, rows, flags, args.format), args.out, f"{len(rows)} risks")
    w = _risk.worst(rows)
    if args.fail_on and w and _risk.RATINGS.index(w) >= _risk.RATINGS.index(args.fail_on):
        return EXIT_FINDINGS
    return EXIT_OK


def _key(args: argparse.Namespace) -> bytes | None:
    return _seal.load_key(Path(args.key)) if args.key else None


def cmd_seal(args: argparse.Namespace) -> int:
    try:
        out = _seal.seal(Path(args.file), _key(args), Path(args.out) if args.out else None)
    except _seal.SealError as e:
        print(f"manjim seal: {e}", file=sys.stderr)
        return EXIT_USAGE
    mode = "tamper-evident" if args.key else "integrity-only"
    print(f"sealed {args.file} -> {out} ({mode})")
    return EXIT_OK


def cmd_verify(args: argparse.Namespace) -> int:
    try:
        alg = _seal.verify(Path(args.file), _key(args), Path(args.seal) if args.seal else None)
    except _seal.SealError as e:
        print(f"manjim verify: {e}", file=sys.stderr)
        return EXIT_USAGE
    except _seal.VerifyFailed as e:
        print(f"FAIL {e}", file=sys.stderr)
        return EXIT_FINDINGS
    print(f"OK {args.file} ({alg})")
    return EXIT_OK


def cmd_keygen(args: argparse.Namespace) -> int:
    try:
        _seal.generate_key(Path(args.path), force=args.force)
    except _seal.SealError as e:
        print(f"manjim keygen: {e}", file=sys.stderr)
        return EXIT_USAGE
    print(f"wrote {args.path} (keep it secret; do not commit)")
    return EXIT_OK


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
    s.add_argument("--format", choices=["text", "json", "md", "sarif"], default="text")
    s.add_argument("--out", help="write report to file (UTF-8, LF); use this instead of > on Windows")
    s.set_defaults(func=cmd_audit)

    s = sub.add_parser("risk", help="build a DPDP-aware risk register from assets.json")
    s.add_argument("assets")
    s.add_argument("--format", choices=["text", "json", "md", "csv"], default="text")
    s.add_argument("--out", help="write register to file (UTF-8, LF)")
    s.add_argument("--fail-on", choices=list(_risk.RATINGS), help="exit 1 if any risk is rated this or worse")
    s.add_argument("--example", action="store_true", help="write a sample assets.json to ASSETS and exit")
    s.set_defaults(func=cmd_risk)

    s = sub.add_parser("seal", help="seal a report (integrity; tamper-evident with --key)")
    s.add_argument("file")
    s.add_argument("--key", help="HMAC key file")
    s.add_argument("--out", help="seal path (default: <file>.seal)")
    s.set_defaults(func=cmd_seal)

    s = sub.add_parser("verify", help="verify a sealed report")
    s.add_argument("file")
    s.add_argument("--key", help="HMAC key file")
    s.add_argument("--seal", help="seal path (default: <file>.seal)")
    s.set_defaults(func=cmd_verify)

    s = sub.add_parser("keygen", help="write a random 256-bit HMAC key file")
    s.add_argument("path", nargs="?", default="audit.key")
    s.add_argument("--force", action="store_true")
    s.set_defaults(func=cmd_keygen)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)
