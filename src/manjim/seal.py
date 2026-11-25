"""Seal / verify reports. Stdlib only.

Seal = sidecar JSON next to the file (<file>.seal). The sealed file is never modified.
- no key:  sha256 over raw bytes      -> integrity only (same value as `sha256sum`)
- key:     HMAC-SHA256 over raw bytes -> tamper-evident to anyone without the key
Output is deterministic: no timestamps, sorted keys, LF line endings.
"""
from __future__ import annotations

import hashlib
import os
import hmac
import json
import secrets
from pathlib import Path

SEAL_VERSION = 1
SEAL_SUFFIX = ".seal"
ALG_SHA256 = "sha256"
ALG_HMAC = "hmac-sha256"
MIN_KEY_BYTES = 16
_CHUNK = 1 << 16


class SealError(Exception):
    """Bad input (usage-level problem): exit 2."""


class VerifyFailed(Exception):
    """Seal does not match: exit 1."""


def default_seal_path(file: Path) -> Path:
    return file.with_name(file.name + SEAL_SUFFIX)


def load_key(path: Path) -> bytes:
    try:
        key = path.read_bytes().strip()  # tolerate trailing newline / CRLF from editors
    except OSError as e:
        raise SealError(f"cannot read key {path}: {e.strerror}") from None
    if len(key) < MIN_KEY_BYTES:
        raise SealError(f"key {path} too short ({len(key)} bytes, need >= {MIN_KEY_BYTES})")
    return key


def generate_key(path: Path, force: bool = False) -> None:
    if path.exists() and not force:
        raise SealError(f"{path} already exists (use --force to overwrite)")
    path.parent.mkdir(parents=True, exist_ok=True)
    data = (secrets.token_hex(32) + "\n").encode()
    # create with 0600 on POSIX; Windows ignores mode bits
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags, 0o600)
    with open(fd, "wb") as f:
        f.write(data)


def _digest(file: Path, key: bytes | None) -> str:
    h = hmac.new(key, digestmod=hashlib.sha256) if key is not None else hashlib.sha256()
    try:
        with file.open("rb") as f:
            while chunk := f.read(_CHUNK):
                h.update(chunk)
    except OSError as e:
        raise SealError(f"cannot read {file}: {e.strerror}") from None
    return h.hexdigest()


def render(file: Path, key: bytes | None) -> bytes:
    doc = {
        "manjim_seal": SEAL_VERSION,
        "algorithm": ALG_HMAC if key is not None else ALG_SHA256,
        "file": file.name,
        "digest": _digest(file, key),
    }
    return (json.dumps(doc, indent=2, sort_keys=True) + "\n").encode("utf-8")


def seal(file: Path, key: bytes | None, out: Path | None = None) -> Path:
    if not file.is_file():
        raise SealError(f"no such file: {file}")
    out = out or default_seal_path(file)
    out.write_bytes(render(file, key))  # bytes: no CRLF translation on Windows
    return out


def verify(file: Path, key: bytes | None, seal_path: Path | None = None) -> str:
    """Return the algorithm on success; raise VerifyFailed / SealError otherwise."""
    if not file.is_file():
        raise SealError(f"no such file: {file}")
    seal_path = seal_path or default_seal_path(file)
    try:
        raw = seal_path.read_bytes()
    except OSError:
        raise SealError(f"no seal found: {seal_path}") from None
    try:
        doc = json.loads(raw)
        version, alg, expected = doc["manjim_seal"], doc["algorithm"], doc["digest"]
    except (ValueError, KeyError, TypeError):
        raise VerifyFailed(f"malformed seal: {seal_path}") from None
    if version != SEAL_VERSION:
        raise SealError(f"unsupported seal version {version!r}")
    if not isinstance(expected, str):
        raise VerifyFailed(f"malformed seal: {seal_path}")

    if alg == ALG_HMAC:
        if key is None:
            raise SealError("seal is keyed (hmac-sha256); pass --key")
    elif alg == ALG_SHA256:
        if key is not None:
            # downgrade guard: someone may have swapped a keyed seal for an unkeyed one
            raise VerifyFailed("expected a keyed seal but found integrity-only sha256 seal")
    else:
        raise VerifyFailed(f"unknown algorithm {alg!r}")

    actual = _digest(file, key if alg == ALG_HMAC else None)
    if not hmac.compare_digest(actual, expected.lower()):
        raise VerifyFailed(f"{file.name}: digest mismatch ({alg})")
    return alg
