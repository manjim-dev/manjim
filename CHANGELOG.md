# Changelog

## 0.0.2 - 2026-11-25
- `seal` / `verify`: sidecar `.seal`, SHA-256 (integrity) or HMAC-SHA256 with `--key` (tamper-evident); deterministic output; keyed verify rejects unkeyed seals.
- `keygen`: random 256-bit key file (0600 on POSIX).
- Logo, NOTICE, CONTRIBUTING, SECURITY.

## 0.0.1 - 2026-11-25
- Project skeleton, `manjim init`, CLI stubs for audit/risk/seal/verify.
