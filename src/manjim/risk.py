"""Risk register from assets.json, with DPDP Act 2023 (India) obligation flags. Stdlib only.

Scoring: inherent risk = likelihood (1-5) x impact (1-5).
  1-4 low | 5-9 medium | 10-16 high | 20-25 critical
DPDP flags are prompts for review against the Act, not legal advice.
"""
from __future__ import annotations

import csv
import io
import json
import re
from dataclasses import dataclass
from pathlib import Path

from manjim import __version__

RATINGS = ("low", "medium", "high", "critical")
TREATMENTS = ("mitigate", "accept", "transfer", "avoid")
CHILD_CATEGORIES = {"children", "child", "minor", "minors"}

EXAMPLE = {
    "organisation": "Example Pvt Ltd",
    "assets": [
        {
            "id": "A1", "name": "Customer database", "owner": "IT",
            "confidentiality": 3, "integrity": 3, "availability": 2,
            "personal_data": True, "data_categories": ["contact", "financial"],
            "encrypted_at_rest": True, "breach_process": False,
            "retention_days": 365, "cross_border": False,
            "risks": [
                {"id": "R1", "threat": "SQL injection on customer portal", "likelihood": 3, "impact": 5,
                 "controls": ["WAF", "parameterised queries"], "treatment": "mitigate"},
                {"id": "R2", "threat": "Backup restore never tested", "likelihood": 2, "impact": 4,
                 "controls": [], "treatment": "mitigate"},
            ],
        },
        {
            "id": "A2", "name": "Marketing site", "owner": "Marketing",
            "confidentiality": 1, "integrity": 2, "availability": 2,
            "personal_data": False,
            "risks": [
                {"id": "R1", "threat": "Defacement via outdated CMS plugin", "likelihood": 3, "impact": 2,
                 "controls": ["auto-updates"], "treatment": "accept"},
            ],
        },
    ],
}


# audit check -> default (likelihood, impact) for a draft risk; review before relying on them
AUDIT_DEFAULTS = {
    "MJ001": (4, 5), "MJ002": (3, 5), "MJ003": (3, 3), "MJ004": (3, 4),
    "MJ005": (2, 4), "MJ006": (2, 5), "MJ007": (2, 2), "MJ008": (1, 2),
}


class RiskError(Exception):
    """Invalid input: exit 2."""


def rating(score: int) -> str:
    return "low" if score <= 4 else "medium" if score <= 9 else "high" if score <= 16 else "critical"


@dataclass(frozen=True)
class Row:
    asset_id: str
    asset: str
    owner: str
    risk_id: str
    threat: str
    likelihood: int
    impact: int
    score: int
    rating: str
    controls: tuple[str, ...]
    treatment: str


@dataclass(frozen=True)
class Flag:
    asset_id: str
    section: str
    issue: str


# ---------- validation ----------

def _int(obj: dict, key: str, where: str, lo: int, hi: int, default: int | None = None) -> int:
    v = obj.get(key, default)
    if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
        raise RiskError(f"{where}.{key} must be an integer {lo}-{hi}, got {v!r}")
    return v


def _str(obj: dict, key: str, where: str, default: str | None = None) -> str:
    v = obj.get(key, default)
    if not isinstance(v, str) or not v.strip():
        raise RiskError(f"{where}.{key} must be a non-empty string")
    return v.strip()


def _bool(obj: dict, key: str, where: str) -> bool | None:
    v = obj.get(key)
    if v is not None and not isinstance(v, bool):
        raise RiskError(f"{where}.{key} must be true/false")
    return v


def load(path: Path) -> dict:
    try:
        doc = json.loads(path.read_bytes())
    except OSError as e:
        raise RiskError(f"cannot read {path}: {e.strerror}") from None
    except ValueError as e:
        raise RiskError(f"{path} is not valid JSON: {e}") from None
    if not isinstance(doc, dict) or not isinstance(doc.get("assets"), list) or not doc["assets"]:
        raise RiskError('top level must be an object with a non-empty "assets" list')
    return doc


def build(doc: dict) -> tuple[list[Row], list[Flag]]:
    rows: list[Row] = []
    flags: list[Flag] = []
    seen_assets: set[str] = set()
    for i, a in enumerate(doc["assets"]):
        w = f"assets[{i}]"
        if not isinstance(a, dict):
            raise RiskError(f"{w} must be an object")
        aid = _str(a, "id", w)
        if aid in seen_assets:
            raise RiskError(f"{w}.id {aid!r} is duplicated")
        seen_assets.add(aid)
        name = _str(a, "name", w)
        owner = _str(a, "owner", w, default="unassigned")
        for k in ("confidentiality", "integrity", "availability"):
            _int(a, k, w, 1, 3, default=2)
        pd = _bool(a, "personal_data", w) or False
        cats = a.get("data_categories", [])
        if not isinstance(cats, list) or not all(isinstance(c, str) for c in cats):
            raise RiskError(f"{w}.data_categories must be a list of strings")
        enc, breach, xb = (_bool(a, k, w) for k in ("encrypted_at_rest", "breach_process", "cross_border"))
        retention = a.get("retention_days")
        if retention is not None and (isinstance(retention, bool) or not isinstance(retention, int) or retention < 0):
            raise RiskError(f"{w}.retention_days must be a non-negative integer")

        if pd:
            if enc is not True:
                flags.append(Flag(aid, "s.8(5)", "personal data not confirmed encrypted at rest (reasonable security safeguards)"))
            if breach is not True:
                flags.append(Flag(aid, "s.8(6)", "no breach intimation process to the Board and affected Data Principals"))
            if retention is None:
                flags.append(Flag(aid, "s.8(7)", "no retention period defined; erase when purpose is served"))
            if {c.lower() for c in cats} & CHILD_CATEGORIES:
                flags.append(Flag(aid, "s.9", "children's data: verifiable parental consent; no tracking or targeted ads"))
            if xb is True:
                flags.append(Flag(aid, "s.16", "cross-border transfer: check destination is not restricted by the Central Government"))

        risks = a.get("risks", [])
        if not isinstance(risks, list):
            raise RiskError(f"{w}.risks must be a list")
        seen_risks: set[str] = set()
        for j, r in enumerate(risks):
            rw = f"{w}.risks[{j}]"
            if not isinstance(r, dict):
                raise RiskError(f"{rw} must be an object")
            rid = _str(r, "id", rw, default=f"R{j + 1}")
            if rid in seen_risks:
                raise RiskError(f"{rw}.id {rid!r} is duplicated in asset {aid}")
            seen_risks.add(rid)
            lk, im = _int(r, "likelihood", rw, 1, 5), _int(r, "impact", rw, 1, 5)
            ctrls = r.get("controls", [])
            if not isinstance(ctrls, list) or not all(isinstance(c, str) for c in ctrls):
                raise RiskError(f"{rw}.controls must be a list of strings")
            tr = _str(r, "treatment", rw, default="mitigate").lower()
            if tr not in TREATMENTS:
                raise RiskError(f"{rw}.treatment must be one of {', '.join(TREATMENTS)}")
            rows.append(Row(aid, name, owner, rid, _str(r, "threat", rw), lk, im, lk * im,
                            rating(lk * im), tuple(ctrls), tr))

    rows.sort(key=lambda r: (-r.score, r.asset_id, r.risk_id))
    flags.sort(key=lambda f: (f.asset_id, [int(n) for n in re.findall(r"\d+", f.section)]))
    return rows, flags


def worst(rows: list[Row]) -> str | None:
    return max((r.rating for r in rows), key=RATINGS.index, default=None)


# ---------- rendering ----------

def to_dict(doc: dict, rows: list[Row], flags: list[Flag]) -> dict:
    counts = {k: sum(1 for r in rows if r.rating == k) for k in RATINGS}
    return {
        "tool": f"manjim {__version__}",
        "organisation": doc.get("organisation", ""),
        "summary": {"risks": len(rows), **counts, "dpdp_flags": len(flags)},
        "risks": [{
            "asset_id": r.asset_id, "asset": r.asset, "owner": r.owner, "risk_id": r.risk_id,
            "threat": r.threat, "likelihood": r.likelihood, "impact": r.impact, "score": r.score,
            "rating": r.rating, "controls": list(r.controls), "treatment": r.treatment,
        } for r in rows],
        "dpdp": [{"asset_id": f.asset_id, "section": f.section, "issue": f.issue} for f in flags],
    }


def render(doc: dict, rows: list[Row], flags: list[Flag], fmt: str) -> str:
    d = to_dict(doc, rows, flags)
    s = d["summary"]
    if fmt == "json":
        return json.dumps(d, indent=2, sort_keys=True) + "\n"
    if fmt == "csv":
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\n")
        w.writerow(["asset_id", "asset", "owner", "risk_id", "threat", "likelihood", "impact",
                    "score", "rating", "controls", "treatment"])
        for r in d["risks"]:
            w.writerow([r["asset_id"], r["asset"], r["owner"], r["risk_id"], r["threat"], r["likelihood"],
                        r["impact"], r["score"], r["rating"], "; ".join(r["controls"]), r["treatment"]])
        return buf.getvalue()
    head = (f"{s['risks']} risks: {s['critical']} critical, {s['high']} high, "
            f"{s['medium']} medium, {s['low']} low; {s['dpdp_flags']} DPDP flags")
    if fmt == "md":
        esc = lambda t: str(t).replace("|", "\\|")
        out = [f"# Risk register{': ' + esc(d['organisation']) if d['organisation'] else ''}", "", head, "",
               "| Asset | Risk | Threat | L | I | Score | Rating | Controls | Treatment | Owner |",
               "|---|---|---|---|---|---|---|---|---|---|"]
        for r in d["risks"]:
            out.append(f"| {esc(r['asset_id'])} {esc(r['asset'])} | {esc(r['risk_id'])} | {esc(r['threat'])} | "
                       f"{r['likelihood']} | {r['impact']} | {r['score']} | {r['rating']} | "
                       f"{esc('; '.join(r['controls'])) or '-'} | {r['treatment']} | {esc(r['owner'])} |")
        if d["dpdp"]:
            out += ["", "## DPDP Act 2023 flags", "", "| Asset | Section | Issue |", "|---|---|---|"]
            out += [f"| {esc(f['asset_id'])} | {f['section']} | {esc(f['issue'])} |" for f in d["dpdp"]]
        out += ["", "_DPDP flags are prompts for review, not legal advice._"]
        return "\n".join(out) + "\n"
    out = [head]
    for r in d["risks"]:
        out.append(f"  {r['score']:>2} {r['rating']:<8} {r['asset_id']}/{r['risk_id']}  {r['threat']}  "
                   f"[{r['treatment']}, owner {r['owner']}]")
    for f in d["dpdp"]:
        out.append(f"  DPDP {f['section']:<7} {f['asset_id']}  {f['issue']}")
    return "\n".join(out) + "\n"


# ---------- audit -> draft risks ----------

def merge_audit(assets_path: Path, audit_path: Path) -> tuple[str, list[str]]:
    """Add one draft risk per failing audit check to asset REPO-<root>. Existing risks are never changed.
    Returns (asset_id, added_risk_ids)."""
    try:
        audit = json.loads(audit_path.read_bytes())
    except OSError as e:
        raise RiskError(f"cannot read {audit_path}: {e.strerror}") from None
    except ValueError as e:
        raise RiskError(f"{audit_path} is not valid JSON: {e}") from None
    if (not isinstance(audit, dict) or not str(audit.get("tool", "")).startswith("manjim ")
            or not isinstance(audit.get("findings"), list)):
        raise RiskError(f"{audit_path} is not a manjim audit json (run: manjim audit . --format json --out FILE)")

    doc = load(assets_path) if assets_path.exists() else {"assets": []}
    root = str(audit.get("root") or "repo")
    aid = f"REPO-{root}"
    asset = next((a for a in doc["assets"] if isinstance(a, dict) and a.get("id") == aid), None)
    if asset is None:
        asset = {"id": aid, "name": f"Source repository {root}", "owner": "unassigned",
                 "confidentiality": 2, "integrity": 3, "availability": 2, "personal_data": False, "risks": []}
        doc["assets"].append(asset)
    risks = asset.setdefault("risks", [])
    if not isinstance(risks, list):
        raise RiskError(f"asset {aid}: risks must be a list")
    have = {r.get("id") for r in risks if isinstance(r, dict)}

    by_check: dict[str, list[dict]] = {}
    for f in audit["findings"]:
        if isinstance(f, dict) and f.get("check") in AUDIT_DEFAULTS:
            by_check.setdefault(f["check"], []).append(f)
    added = []
    for check in sorted(by_check):
        if check in have:
            continue
        fs = by_check[check]
        paths = sorted({f.get("path", "") for f in fs})
        where = ", ".join(paths[:3]) + (f" +{len(paths) - 3} more" if len(paths) > 3 else "")
        lk, im = AUDIT_DEFAULTS[check]
        risks.append({
            "id": check,
            "threat": f"{fs[0].get('title', check)}: {len(fs)} finding(s) in {where}",
            "likelihood": lk, "impact": im, "controls": [], "treatment": "mitigate",
            "source": "manjim audit (draft: review likelihood/impact)",
        })
        added.append(check)
    build(doc)  # validate the merged result before writing
    assets_path.write_bytes((json.dumps(doc, indent=2, ensure_ascii=False) + "\n").encode("utf-8"))
    return aid, added
