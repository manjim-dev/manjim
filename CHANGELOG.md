# Changelog

## 0.1.0 - unreleased
- `audit`: 8 hygiene checks mapped to ISO 27001:2022 Annex A / SOC 2, score 0-100, text/json/md, `--out`, `--fail-under`, reads `manjim.toml` (exclude, mask_secrets, fail_under). Deterministic output.
- Repo `.gitignore` now excludes `.env` (caught by manjim's own audit).

## 0.0.2 - 2026-11-25
- `seal` / `verify`: sidecar `.seal`, SHA-256 (integrity) or HMAC-SHA256 with `--key` (tamper-evident); deterministic output; keyed verify rejects unkeyed seals.
- `keygen`: random 256-bit key file (0600 on POSIX).
- Logo, NOTICE, CONTRIBUTING, SECURITY.

## 0.0.1 - 2026-11-25
- Project skeleton, `manjim init`, CLI stubs for audit/risk/seal/verify.
