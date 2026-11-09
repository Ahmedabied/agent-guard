"""Append-only audit log. One JSON object per line, each one hash-chained to the line before it.

Every entry carries "prev" (the hash of the entry before it) and "hash" (sha256 of the entry's
canonical JSON without the "hash" field). Changing, removing or reordering any line breaks the
chain from that point, and `verify` reports the first line that does not fit.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import fcntl
except ImportError:  # Windows: one writer per log file
    fcntl = None

GENESIS = "0" * 64
DEFAULT_REDACT = [
    "*password*", "*passwd*", "*secret*", "*token*", "*api_key*", "*apikey*", "*access_key*",
    "*private_key*", "*credential*", "*auth*", "*cookie*", "*session*",
]
# Values that look like a secret are redacted whatever their key is called.
SECRET_VALUE = re.compile(
    r"(?i:bearer\s+[a-z0-9._~+/=-]{16,})"
    r"|-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----"
    r"|\bAKIA[0-9A-Z]{16}\b"
    r"|\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pa[t]_[A-Za-z0-9_]{30,})"
    r"|\bsk-[A-Za-z0-9_-]{20,}"
    r"|\bxox[abprs]-[A-Za-z0-9-]{10,}"
    r"|\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"  # JWT
)
DEFAULT_MAX_VALUE_CHARS = 2000


class AuditError(RuntimeError):
    pass


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def entry_hash(entry: dict) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(canonical_bytes(body)).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _norm_key(key: str) -> str:
    # "X-Api-Key", "x_api_key" and "xApiKey" all become "x_api_key"-like for matching.
    key = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", key)
    return key.lower().replace("-", "_")


class Scrubber:
    """Removes secrets and huge values from arguments before they are written to the log."""

    def __init__(self, redact: list[str] | None = None, max_value_chars: int = DEFAULT_MAX_VALUE_CHARS):
        patterns = DEFAULT_REDACT if redact is None else redact
        self._rx = None
        if patterns:
            self._rx = re.compile("|".join(f"(?:{fnmatch.translate(_norm_key(p))})" for p in patterns))
        self.max = max_value_chars

    def __call__(self, value: Any, key: str | None = None) -> Any:
        if key is not None and self._rx is not None and self._rx.match(_norm_key(key)):
            return "[redacted]"
        if isinstance(value, str) and SECRET_VALUE.search(value):
            return "[redacted: looks like a secret]"
        if isinstance(value, dict):
            return {k: self(v, str(k)) for k, v in value.items()}
        if isinstance(value, list):
            return [self(v) for v in value]
        if isinstance(value, str) and self.max and len(value) > self.max:
            digest = hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()
            return f"[{len(value)} chars, sha256 {digest[:16]}] {value[:200]}"
        return value


def _read_last_line(fd: int, size: int) -> bytes:
    if size == 0:
        return b""
    chunk = 4096
    end = size
    buf = b""
    while end > 0:
        start = max(0, end - chunk)
        buf = os.pread(fd, end - start, start) + buf
        end = start
        # The final byte is the newline of the last entry; look for the one before it.
        idx = buf.rfind(b"\n", 0, len(buf) - 1)
        if idx != -1:
            return buf[idx + 1 :]
        chunk *= 2
    return buf


class AuditLog:
    def __init__(self, path: str | Path, fsync: bool = False):
        self.path = Path(path)
        self.fsync = fsync
        self._fd = os.open(self.path, os.O_RDWR | os.O_APPEND | os.O_CREAT, 0o600)
        self._lock = threading.Lock()
        self._size = -1
        self._seq = 0
        self._prev = GENESIS

    def close(self) -> None:
        with self._lock:
            if self._fd >= 0:
                os.close(self._fd)
                self._fd = -1

    def __enter__(self) -> "AuditLog":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    @property
    def head(self) -> str:
        return self._prev

    def _sync_head(self, size: int) -> None:
        last = _read_last_line(self._fd, size)
        if not last:
            self._seq, self._prev = 0, GENESIS
            return
        if not last.endswith(b"\n"):
            raise AuditError(f"{self.path}: the last line is incomplete (crash or disk full?). Run 'agent-guard verify'.")
        try:
            entry = json.loads(last)
            self._seq, self._prev = int(entry["seq"]), str(entry["hash"])
        except (ValueError, KeyError, TypeError):
            raise AuditError(f"{self.path}: the last line is not an audit entry. Run 'agent-guard verify'.") from None

    def append(self, record: dict) -> dict:
        with self._lock:
            if self._fd < 0:
                raise AuditError("audit log is closed")
            if fcntl is not None:
                fcntl.flock(self._fd, fcntl.LOCK_EX)
            try:
                size = os.fstat(self._fd).st_size
                if size != self._size:  # first write, or another process appended
                    self._sync_head(size)
                entry = {"seq": self._seq + 1, "ts": _now(), **record, "prev": self._prev}
                entry["hash"] = entry_hash(entry)
                line = canonical_bytes(entry) + b"\n"
                view = memoryview(line)
                while view:
                    n = os.write(self._fd, view)
                    view = view[n:]
                if self.fsync:
                    os.fsync(self._fd)
                self._seq, self._prev, self._size = entry["seq"], entry["hash"], size + len(line)
                return entry
            finally:
                if fcntl is not None:
                    fcntl.flock(self._fd, fcntl.LOCK_UN)


@dataclass
class VerifyResult:
    ok: bool
    entries: int
    head: str
    line: int = 0
    error: str = ""


def verify(path: str | Path, expect_head: str | None = None) -> VerifyResult:
    prev, seq, n = GENESIS, 0, 0
    with open(path, "rb") as f:
        for n, raw in enumerate(f, 1):
            if not raw.endswith(b"\n"):
                return VerifyResult(False, n - 1, prev, n, "incomplete last line")
            try:
                entry = json.loads(raw)
            except ValueError:
                return VerifyResult(False, n - 1, prev, n, "not valid JSON")
            if not isinstance(entry, dict) or "hash" not in entry:
                return VerifyResult(False, n - 1, prev, n, "not an audit entry")
            if entry.get("seq") != seq + 1:
                return VerifyResult(False, n - 1, prev, n, f"seq is {entry.get('seq')!r}, expected {seq + 1}")
            if entry.get("prev") != prev:
                return VerifyResult(False, n - 1, prev, n, "prev does not match the hash of the line before")
            if entry_hash(entry) != entry["hash"]:
                return VerifyResult(False, n - 1, prev, n, "hash does not match the content (line was edited)")
            prev, seq = entry["hash"], entry["seq"]
    if expect_head is not None and expect_head != prev:
        return VerifyResult(False, seq, prev, seq, "head does not match the expected hash (lines removed from the end?)")
    return VerifyResult(True, seq, prev)


def read_entries(path: str | Path):
    with open(path, "rb") as f:
        for raw in f:
            if raw.strip():
                yield json.loads(raw)
