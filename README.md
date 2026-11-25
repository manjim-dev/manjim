# manjim

Zero-dependency GRC / IT audit CLI for Python 3.11+.

```
pip install manjim
manjim init
manjim audit ./project --fail-under 70
manjim risk assets.json
manjim seal report.json --key audit.key
manjim verify report.json --key audit.key
```

If `manjim` is blocked on Windows (Smart App Control / AppLocker), use `python -m manjim` instead.

> Pre-alpha. Only `init` works today; `audit`, `risk`, `seal`, `verify` are in progress.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | OK |
| 1 | Findings: hygiene score below `--fail-under`, or verify mismatch |
| 2 | Usage error / missing input |
| 3 | Command not implemented yet |

## Seal semantics

Without `--key`, a seal is integrity-only (detects accidental change, not deliberate tampering).
With `--key` (HMAC-SHA256), it is tamper-evident to anyone who doesn't hold the key.

## License

Apache-2.0
