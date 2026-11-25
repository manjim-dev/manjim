<p align="center"><img src="https://raw.githubusercontent.com/manjim-dev/manjim/main/assets/manjim-mark-256.png" alt="manjim" width="128"></p>

# manjim

Zero-dependency GRC / IT audit CLI for Python 3.11+.

```
pip install manjim
manjim init
manjim audit ./project --fail-under 70
manjim risk assets.json
manjim keygen audit.key
manjim seal report.json --key audit.key
manjim verify report.json --key audit.key
```

If `manjim` is blocked on Windows (Smart App Control / AppLocker), use `python -m manjim` instead.

> Pre-alpha. `init`, `keygen`, `seal`, `verify` work; `audit` and `risk` are in progress.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | OK |
| 1 | Findings: hygiene score below `--fail-under`, or verify mismatch |
| 2 | Usage error / missing input |
| 3 | Command not implemented yet |

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
