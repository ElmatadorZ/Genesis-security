# Copyright 2026 Bunyawat Dechanon (ElmatadorZ)
# SPDX-License-Identifier: Apache-2.0
"""Tamper-evident, append-only audit log (GSX-13).

Each JSONL entry stores the hash of the previous entry. Editing or deleting any
entry breaks the chain. Writes are serialized with an OS file lock so several
agents can share one log. When the file exceeds ``max_bytes`` it is rotated to
``<name>.<n>`` and the new file's first entry carries the old file's last hash,
so the chain continues across files.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

GENESIS = "GENESIS"

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


def _hash(entry: dict) -> str:
    body = json.dumps(entry, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _last_hash(path: Path) -> str:
    if not path.exists():
        return GENESIS
    last = GENESIS
    with path.open(encoding="utf-8") as f:
        for line in f:
            if line.strip():
                last = json.loads(line)["hash"]
    return last


class AuditTrail:
    def __init__(self, path: str | Path = "genesis_security_audit.jsonl", max_bytes: int = 10_000_000):
        self.path = Path(path)
        self.max_bytes = max_bytes
        self.lock_path = self.path.with_suffix(self.path.suffix + ".lock")

    def record(self, event: str, payload: dict) -> str:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.lock_path, "a+") as lf, _locked(lf):
            prev = _last_hash(self.path)          # re-read under lock: safe for many writers
            if self.path.exists() and self.path.stat().st_size >= self.max_bytes:
                self._rotate()
            entry = {"ts": time.time(), "event": event, "payload": payload, "prev": prev}
            entry["hash"] = _hash(entry)
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
        rotated = sorted(self.path.parent.glob(self.path.name + ".[0-9]*"),
                         key=lambda p: int(p.suffix[1:]) if p.suffix[1:].isdigit() else 0)
        rotated = [p for p in rotated if p.suffix[1:].isdigit()]
        return rotated + ([self.path] if self.path.exists() else [])

    def verify(self) -> tuple[bool, int]:
        """Verify the whole chain across rotated files. Returns (intact, valid_entries)."""
        return verify_chain(self.files())


def verify_chain(files: list[Path]) -> tuple[bool, int]:
    prev, n = GENESIS, 0
    for path in files:
        with path.open(encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    e = json.loads(line)
                    h = e.pop("hash")
                except (ValueError, KeyError):
                    return False, n
                if e.get("prev") != prev or _hash(e) != h:
                    return False, n
                prev, n = h, n + 1
    return True, n
