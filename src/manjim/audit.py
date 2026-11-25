"""Repository hygiene audit mapped to ISO/IEC 27001:2022 Annex A and SOC 2 TSC. Stdlib only.

Deterministic: findings sorted, no timestamps, POSIX relative paths.
Mappings are indicative evidence pointers, not a certification opinion.
"""
from __future__ import annotations

import json
import os
import re
import stat
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from manjim import __version__

MAX_SCAN_BYTES = 1 << 20  # skip content scan above 1 MiB
WEIGHT = {"high": 20, "medium": 10, "low": 5}
DEFAULT_EXCLUDE = [".git", "node_modules", ".venv", "venv", "__pycache__"]


@dataclass(frozen=True)
class Check:
    id: str
    title: str
    severity: str
    iso27001: tuple[str, ...]
    soc2: tuple[str, ...]


CHECKS = {c.id: c for c in [
    Check("MJ001", "Hard-coded secret in file", "high", ("A.5.17", "A.8.24"), ("CC6.1",)),
    Check("MJ002", "Sensitive file present (key, credential, .env)", "high", ("A.5.17", "A.8.12"), ("CC6.1",)),
    Check("MJ003", "No .gitignore at root", "medium", ("A.8.4",), ("CC8.1",)),
    Check("MJ004", ".gitignore does not exclude .env or key files", "medium", ("A.8.4", "A.8.12"), ("CC6.1",)),
    Check("MJ005", "World-writable file", "medium", ("A.8.3",), ("CC6.1",)),
    Check("MJ006", "CI action pinned to a moving branch", "medium", ("A.5.21", "A.8.30"), ("CC9.2",)),
    Check("MJ007", "No SECURITY.md (vulnerability disclosure)", "low", ("A.5.24", "A.8.8"), ("CC7.1",)),
    Check("MJ008", "No LICENSE file", "low", ("A.5.32",), ()),
]}

SECRET_PATTERNS = [
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}")),
    ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("private-key", re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----")),
    ("assignment", re.compile(
        r"""(?i)\b(?:api[_-]?key|secret|passw(?:or)?d|access[_-]?token|auth[_-]?token)\b\s*[:=]\s*["']([^"'\s]{8,})["']""")),
]
SENSITIVE_NAMES = {".env", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "credentials.json", ".htpasswd", ".netrc"}
SENSITIVE_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".jks", ".keystore"}
SENSITIVE_ALLOW = {".env.example", ".env.sample", ".env.template"}
MOVING_REF = re.compile(r"^\s*-?\s*uses:\s*([\w.-]+/[\w./-]+)@(main|master|HEAD|latest)\s*(?:#.*)?$", re.M)


@dataclass
class Finding:
    check: str
    path: str
    line: int = 0
    detail: str = ""

    def key(self):
        return (self.check, self.path, self.line, self.detail)


@dataclass
class Report:
    root: str
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0

    @property
    def score(self) -> int:
        penalty = 0
        for cid, check in CHECKS.items():
            n = sum(1 for f in self.findings if f.check == cid)
            if n:
                w = WEIGHT[check.severity]
                penalty += min(w + (n - 1) * (w // 4), 2 * w)  # repeats count, capped per check
        return max(0, 100 - penalty)


class AuditError(Exception):
    pass


def load_config(root: Path) -> dict:
    p = root / "manjim.toml"
    if not p.is_file():
        return {}
    try:
        return tomllib.loads(p.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as e:
        raise AuditError(f"bad {p}: {e}") from None


def _mask(s: str) -> str:
    return s[:4] + "*" * min(8, max(0, len(s) - 4))


def _is_sensitive(name: str) -> bool:
    low = name.lower()
    if low in SENSITIVE_ALLOW:
        return False
    return low in SENSITIVE_NAMES or low.startswith(".env.") or Path(low).suffix in SENSITIVE_SUFFIXES


def _scan_text(rel: str, text: str, mask: bool, out: list[Finding]) -> None:
    for lineno, line in enumerate(text.splitlines(), 1):
        for kind, rx in SECRET_PATTERNS:
            m = rx.search(line)
            if m:
                val = m.group(1) if m.groups() else m.group(0)
                if kind == "private-key":
                    val = m.group(0)  # header is not secret
                elif mask:
                    val = _mask(val)
                out.append(Finding("MJ001", rel, lineno, f"{kind}: {val}"))
                break  # one finding per line


def run(root: Path, exclude: list[str] | None = None, mask: bool = True) -> Report:
    if not root.is_dir():
        raise AuditError(f"not a directory: {root}")
    excl = set(exclude if exclude is not None else DEFAULT_EXCLUDE)
    rep = Report(root=root.resolve().name)
    posix = os.name == "posix"

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in excl)
        for name in sorted(filenames):
            if name in excl or name.endswith(".seal"):
                continue
            p = Path(dirpath) / name
            rel = p.relative_to(root).as_posix()
            try:
                st = p.lstat()
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            if _is_sensitive(name):
                rep.findings.append(Finding("MJ002", rel))
            if posix and st.st_mode & stat.S_IWOTH:
                rep.findings.append(Finding("MJ005", rel, detail=oct(st.st_mode & 0o777)))
            if st.st_size > MAX_SCAN_BYTES:
                continue
            try:
                data = p.read_bytes()
            except OSError:
                continue
            if b"\x00" in data[:8192]:
                continue  # binary
            rep.files_scanned += 1
            text = data.decode("utf-8", errors="replace")
            _scan_text(rel, text, mask, rep.findings)
            if rel.startswith(".github/workflows/") and name.endswith((".yml", ".yaml")):
                for m in MOVING_REF.finditer(text):
                    line = text.count("\n", 0, m.start()) + 1
                    rep.findings.append(Finding("MJ006", rel, line, f"{m.group(1)}@{m.group(2)}"))

    gi = root / ".gitignore"
    if not gi.is_file():
        rep.findings.append(Finding("MJ003", ".gitignore"))
    else:
        pats = {l.strip().lstrip("/") for l in gi.read_text(encoding="utf-8", errors="replace").splitlines()}
        missing = [x for x, ok in ((".env", {".env", ".env*", ".env.*", "*.env"} & pats),
                                   ("*.key", {"*.key", "*.pem"} & pats)) if not ok]
        if missing:
            rep.findings.append(Finding("MJ004", ".gitignore", detail="missing: " + ", ".join(missing)))
    if not any((root / n).is_file() for n in ("SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md")):
        rep.findings.append(Finding("MJ007", "SECURITY.md"))
    if not any((root / n).is_file() for n in ("LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING")):
        rep.findings.append(Finding("MJ008", "LICENSE"))

    rep.findings.sort(key=Finding.key)
    return rep


# ---------- rendering ----------

def to_dict(rep: Report, fail_under: int | None) -> dict:
    return {
        "tool": f"manjim {__version__}",
        "root": rep.root,
        "score": rep.score,
        "fail_under": fail_under,
        "passed": fail_under is None or rep.score >= fail_under,
        "files_scanned": rep.files_scanned,
        "findings": [{
            "check": f.check, "severity": CHECKS[f.check].severity, "title": CHECKS[f.check].title,
            "path": f.path, "line": f.line, "detail": f.detail,
            "iso27001_2022": list(CHECKS[f.check].iso27001), "soc2": list(CHECKS[f.check].soc2),
        } for f in rep.findings],
    }


SARIF_LEVEL = {"high": "error", "medium": "warning", "low": "note"}
SECURITY_SEVERITY = {"high": "8.0", "medium": "5.0", "low": "2.0"}  # GitHub code scanning bands


def to_sarif(rep: Report) -> dict:
    ids = sorted(CHECKS)
    rules = [{
        "id": cid,
        "name": cid,
        "shortDescription": {"text": CHECKS[cid].title},
        "helpUri": "https://github.com/manjim-dev/manjim#audit-checks",
        "defaultConfiguration": {"level": SARIF_LEVEL[CHECKS[cid].severity]},
        "properties": {
            "security-severity": SECURITY_SEVERITY[CHECKS[cid].severity],
            "tags": ["security"] + [f"iso27001:2022/{c}" for c in CHECKS[cid].iso27001]
                    + [f"soc2/{c}" for c in CHECKS[cid].soc2],
        },
    } for cid in ids]
    results = []
    for f in rep.findings:
        loc = {"artifactLocation": {"uri": f.path, "uriBaseId": "%SRCROOT%"}}
        if f.line:
            loc["region"] = {"startLine": f.line}
        results.append({
            "ruleId": f.check,
            "ruleIndex": ids.index(f.check),
            "level": SARIF_LEVEL[CHECKS[f.check].severity],
            "message": {"text": CHECKS[f.check].title + (f" ({f.detail})" if f.detail else "")},
            "locations": [{"physicalLocation": loc}],
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "manjim", "version": __version__,
                "informationUri": "https://github.com/manjim-dev/manjim", "rules": rules,
            }},
            "results": results,
            "properties": {"score": rep.score},
        }],
    }


def render(rep: Report, fmt: str, fail_under: int | None) -> str:
    if fmt == "sarif":
        return json.dumps(to_sarif(rep), indent=2, sort_keys=True) + "\n"
    d = to_dict(rep, fail_under)
    if fmt == "json":
        return json.dumps(d, indent=2, sort_keys=True) + "\n"
    status = "" if fail_under is None else (" PASS" if d["passed"] else f" FAIL (< {fail_under})")
    if fmt == "md":
        out = [f"# manjim audit: {d['root']}", "",
               f"**Score:** {d['score']}/100{status}  ", f"**Files scanned:** {d['files_scanned']}", ""]
        if d["findings"]:
            out += ["| Check | Severity | Location | Detail | ISO 27001:2022 | SOC 2 |",
                    "|---|---|---|---|---|---|"]
            for f in d["findings"]:
                loc = f["path"] + (f":{f['line']}" if f["line"] else "")
                det = (f["title"] + (f" ({f['detail']})" if f["detail"] else "")).replace("|", "\\|")
                out.append(f"| {f['check']} | {f['severity']} | `{loc}` | {det} | "
                           f"{', '.join(f['iso27001_2022'])} | {', '.join(f['soc2']) or '-'} |")
        else:
            out.append("No findings.")
        out += ["", "_Control mappings are indicative evidence pointers, not an audit opinion._"]
        return "\n".join(out) + "\n"
    out = [f"manjim audit {d['root']}  score {d['score']}/100{status}  ({d['files_scanned']} files)"]
    for f in d["findings"]:
        loc = f["path"] + (f":{f['line']}" if f["line"] else "")
        ctl = ", ".join(f["iso27001_2022"] + f["soc2"])
        out.append(f"  {f['severity']:<6} {f['check']} {loc}  {f['title']}"
                   + (f" [{f['detail']}]" if f["detail"] else "") + f"  ({ctl})")
    return "\n".join(out) + "\n"
