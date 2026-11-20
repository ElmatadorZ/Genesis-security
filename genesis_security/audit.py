# Copyright 2026 Bunyawat Dechanon (ElmatadorZ)
# SPDX-License-Identifier: Apache-2.0
"""Tamper-evident, append-only audit log (GSX-13).

* Each JSONL entry stores the hash of the previous entry, so editing or
  deleting an entry in the middle breaks the chain.
* With a key, entries are chained with HMAC-SHA256, so an attacker who can
  write the file but lacks the key cannot rewrite the whole chain and
  recompute valid hashes. Without a key a plain SHA-256 chain is used
  (detects accidental edits only).
* ``checkpoint()`` returns ``{"count", "head"}``. Store it somewhere the agents
  cannot write (owner's phone, another machine). ``verify(checkpoint=...)``
  then also detects truncation of the tail or deletion of the whole log.
* Writes are serialized with an OS file lock (POSIX + Windows) and the file
  rotates to ``<name>.<n>`` past ``max_bytes`` without breaking the chain.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional

GENESIS = "GENESIS"
AUDIT_KEY_LABEL = b"genesis-security/audit/v1"

if os.name == "nt":  # Windows
    import msvcrt

    @contextmanager
    def _locked(f) -> Iterator[None]:
        f.seek(0)
        msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, 1)
        try:
            yield
        finally:
            f.seek(0)
            msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
else:  # POSIX
    import fcntl

    @contextmanager
    def _locked(f) -> Iterator[None]:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)


def derive_audit_key(master_key: bytes) -> bytes:
    """Separate key for the audit chain, derived from the gate's HMAC key."""
    return hmac.new(master_key, AUDIT_KEY_LABEL, hashlib.sha256).digest()


def _hash(entry: dict, key: Optional[bytes]) -> str:
    body = json.dumps(entry, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")
    if key:
        return hmac.new(key, body, hashlib.sha256).hexdigest()
    return hashlib.sha256(body).hexdigest()


def _last_hash(path: Path, default: str) -> str:
    """Hash of the last entry, reading only the file tail (O(1) per write)."""
    if not path.exists() or path.stat().st_size == 0:
        return default
    with path.open("rb") as f:
        size = f.seek(0, os.SEEK_END)
        chunk = 4096
        while True:
            start = max(0, size - chunk)
            f.seek(start)
            lines = [ln for ln in f.read(size - start).splitlines() if ln.strip()]
            if lines and (start == 0 or len(lines) > 1):
                return json.loads(lines[-1].decode("utf-8"))["hash"]
            if start == 0:
                return default
            chunk *= 4


class AuditTrail:
    def __init__(self, path: str | Path = "genesis_security_audit.jsonl", max_bytes: int = 10_000_000,
                 key: Optional[bytes] = None):
        self.path = Path(path)
        self.max_bytes = max_bytes
        self.key = key
        self.lock_path = self.path.with_suffix(self.path.suffix + ".lock")

    def record(self, event: str, payload: dict) -> str:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.lock_path, "a+") as lf, _locked(lf):
            prev = GENESIS
            for p in reversed(self.files()):          # newest file that has entries
                prev = _last_hash(p, GENESIS)
                if prev != GENESIS:
                    break
            if self.path.exists() and self.path.stat().st_size >= self.max_bytes:
                self._rotate()
            entry = {"ts": time.time(), "event": event, "payload": payload, "prev": prev,
                     "alg": "hmac-sha256" if self.key else "sha256"}
            entry["hash"] = _hash(entry, self.key)
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
                f.flush()
                os.fsync(f.fileno())
            return entry["hash"]

    def _rotate(self) -> None:
        n = 1
        while self.path.with_name(f"{self.path.name}.{n}").exists():
            n += 1
        self.path.rename(self.path.with_name(f"{self.path.name}.{n}"))

    def files(self) -> list[Path]:
        """All log files in chain order: oldest rotated file first, live file last."""
        rotated = [p for p in self.path.parent.glob(self.path.name + ".*") if p.suffix[1:].isdigit()]
        rotated.sort(key=lambda p: int(p.suffix[1:]))
        return rotated + ([self.path] if self.path.exists() else [])

    def checkpoint(self) -> dict:
        """Current (count, head hash). Store it where agents can't write."""
        ok, n, head = _walk(self.files(), self.key, None)
        if not ok:
            raise RuntimeError("audit chain already broken; investigate before checkpointing")
        return {"count": n, "head": head}

    def verify(self, checkpoint: Optional[dict] = None) -> tuple[bool, int]:
        """Verify the whole chain. With a checkpoint, also detect truncation/deletion."""
        ok, n, _ = _walk(self.files(), self.key, checkpoint)
        return ok, n


def verify_chain(files: list[Path], key: Optional[bytes] = None,
                 checkpoint: Optional[dict] = None) -> tuple[bool, int]:
    ok, n, _ = _walk(files, key, checkpoint)
    return ok, n


def _walk(files: list[Path], key: Optional[bytes], checkpoint: Optional[dict]) -> tuple[bool, int, str]:
    prev, n, seen_head = GENESIS, 0, False
    want_n = int(checkpoint["count"]) if checkpoint else 0
    want_h = checkpoint["head"] if checkpoint else None
    for path in files:
        with path.open(encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    e = json.loads(line)
                    h = e.pop("hash")
                except (ValueError, KeyError, AttributeError):
                    return False, n, prev
                if e.get("prev") != prev or not hmac.compare_digest(_hash(e, key), h):
                    return False, n, prev
                prev, n = h, n + 1
                if checkpoint and n == want_n:
                    if not hmac.compare_digest(h, want_h):
                        return False, n, prev
                    seen_head = True
    if checkpoint and want_n > 0 and not seen_head:
        return False, n, prev          # log shorter than checkpoint: truncated or deleted
    return True, n, prev
