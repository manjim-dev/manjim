<p align="center"><img src="https://raw.githubusercontent.com/manjim-dev/manjim/main/assets/manjim-mark-256.png" alt="manjim" width="128"></p>

# manjim

Zero-dependency GRC / IT audit CLI for Python 3.11+.

```
pip install manjim
manjim init
manjim audit ./project --fail-under 70 --format json --out report.json
manjim risk assets.json --example
manjim risk assets.json --fail-on high --format md --out register.md
manjim keygen audit.key
manjim seal report.json --key audit.key
manjim verify report.json --key audit.key
```

If `manjim` is blocked on Windows (Smart App Control / AppLocker), use `python -m manjim` instead.

> Pre-alpha: all commands work, but output formats may still change before 1.0.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | OK |
| 1 | Findings: audit score below `--fail-under`, risk at/above `--fail-on`, or verify mismatch |
| 2 | Usage error / missing input |
| 3 | Command not implemented yet |

## Audit checks

Score starts at 100. Each failing check deducts its weight once (high 20, medium 10, low 5), plus a quarter-weight for each repeat, capped at 2x the weight per check.

| ID | Check | Severity | ISO 27001:2022 | SOC 2 |
|----|-------|----------|----------------|-------|
| MJ001 | Hard-coded secret (AWS, GitHub, Slack, private key, `password = "..."`) | high | A.5.17, A.8.24 | CC6.1 |
| MJ002 | Sensitive file present (`.env`, `*.pem`, `*.key`, `id_rsa`, ...) | high | A.5.17, A.8.12 | CC6.1 |
| MJ003 | No `.gitignore` | medium | A.8.4 | CC8.1 |
| MJ004 | `.gitignore` misses `.env` / key files | medium | A.8.4, A.8.12 | CC6.1 |
| MJ005 | World-writable file (POSIX) | medium | A.8.3 | CC6.1 |
| MJ006 | CI action pinned to `@main` / `@master` | medium | A.5.21, A.8.30 | CC9.2 |
| MJ007 | No `SECURITY.md` | low | A.5.24, A.8.8 | CC7.1 |
| MJ008 | No `LICENSE` | low | A.5.32 | - |

To accept a known finding, add it to `ignore` in `manjim.toml`:

```toml
ignore = ["MJ008", "MJ001:tests/fixtures/*"]   # check, or check:path-glob
```

Suppressed findings don't count toward the score, but they are still reported: as `suppressed` in json, as a count in text and md, and as dismissed alerts in SARIF. An auditor can always see what was waived.

Secrets are masked in output (`mask_secrets = true`). Files over 1 MiB, binaries, `exclude` paths and `*.seal` files are skipped. The `--fail-under` flag overrides `fail_under` in `manjim.toml`.
Control mappings are indicative evidence pointers, not an audit opinion.

### GitHub code scanning

`--format sarif` writes SARIF 2.1.0, so findings show up in the repo's **Security → Code scanning** tab:

```yaml
permissions:
  security-events: write
steps:
  - uses: actions/checkout@v6
  - run: pipx run manjim audit . --format sarif --out manjim.sarif --fail-under 70
  - uses: github/codeql-action/upload-sarif@v4
    if: always()   # upload even when --fail-under fails the step
    with:
      sarif_file: manjim.sarif
```

Code scanning is free for public repos; private repos need GitHub Advanced Security.

On Windows, use `--out` instead of `>`: PowerShell redirection writes UTF-16, and a sealed report would then fail to verify on other machines.

## Risk register

`manjim risk assets.json` builds a register from your assets. Run `--example` first to get a starter file.

- Each asset has `id`, `name`, `owner`, C/I/A ratings (1-3), and `risks`: `threat`, `likelihood` (1-5), `impact` (1-5), `controls`, `treatment` (mitigate / accept / transfer / avoid).
- Score = likelihood x impact: 1-4 low, 5-9 medium, 10-16 high, 20-25 critical. The register is sorted worst first.
- Output formats: text, json, md, csv. `--fail-on high` exits 1 if any risk is high or worse.
- If `personal_data: true`, manjim flags review points under India's DPDP Act 2023:

| Section | Raised when |
|---------|-------------|
| s.8(5) security safeguards | `encrypted_at_rest` is not `true` |
| s.8(6) breach intimation | `breach_process` is not `true` |
| s.8(7) erasure | no `retention_days` |
| s.9 children's data | `data_categories` includes `children` |
| s.16 cross-border transfer | `cross_border: true` |

DPDP flags are prompts for review, not legal advice.

### From audit to risk register

```
manjim audit . --format json --out audit.json
manjim risk assets.json --from-audit audit.json
```

This adds one draft risk per failing check (risk id = check id) to an asset named `REPO-<folder>`, with default likelihood and impact (for example, a hard-coded secret starts at 4 x 5 = critical). Review the scores before relying on them. Re-running only adds new checks: risks you have already edited are never overwritten, and suppressed findings are skipped.

## Seal semantics

`manjim seal FILE` writes a sidecar `FILE.seal` (JSON) and never modifies `FILE`. The digest covers the raw bytes, so CRLF/LF conversion counts as a change.

- Without `--key`: SHA-256, integrity-only. Detects accidental change, not deliberate tampering. The digest equals `sha256sum FILE`.
- With `--key`: HMAC-SHA256, tamper-evident to anyone who doesn't hold the key. Create a key with `manjim keygen` (256-bit, never commit it).
- `verify --key` rejects an unkeyed seal, so an attacker can't swap a keyed seal for a recomputed SHA-256 one.
- Seal output is deterministic: no timestamps, sorted keys, LF endings. The same input and key always give byte-identical seals.

## Contributing

Issues and pull requests are welcome. See [CONTRIBUTING.md](https://github.com/manjim-dev/manjim/blob/main/CONTRIBUTING.md). Security issues: [SECURITY.md](https://github.com/manjim-dev/manjim/blob/main/SECURITY.md).

## License

Copyright 2026 Krupakar S Bilichod. Licensed under [Apache-2.0](https://github.com/manjim-dev/manjim/blob/main/LICENSE). If you redistribute manjim or a modified version, keep the [NOTICE](https://github.com/manjim-dev/manjim/blob/main/NOTICE) file with it.
