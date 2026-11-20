# Copyright 2026 Bunyawat Dechanon (ElmatadorZ)
# SPDX-License-Identifier: Apache-2.0
"""Command line: genesis-security {demo, scan, verify-audit, keygen, pin, policy}."""
from __future__ import annotations

import argparse
import hashlib
import secrets
import sys
from importlib import resources
from pathlib import Path

from . import __version__
from .audit import AuditTrail
from .demo import run_demo
from .scanner import scan_injection


def _cmd_scan(a: argparse.Namespace) -> int:
    worst = 0
    rank = {"clean": 0, "suspicious": 1, "injected": 2}
    for p in a.files:
        text = sys.stdin.read() if p == "-" else Path(p).read_text(encoding="utf-8", errors="replace")
        status, gsx, hits = scan_injection(text)
        worst = max(worst, rank[status])
        print(f"{status:<10} {p}  gsx={gsx} hits={hits}")
    return worst  # exit 0 clean, 1 suspicious, 2 injected — handy in CI


def _cmd_verify(a: argparse.Namespace) -> int:
    ok, n = AuditTrail(a.log).verify()
    print(f"intact={ok} entries={n}")
    return 0 if ok else 1


def _cmd_keygen(_: argparse.Namespace) -> int:
    print(secrets.token_hex(32))
    return 0


def _cmd_pin(a: argparse.Namespace) -> int:
    for p in a.files:
        print(f"{hashlib.sha256(Path(p).read_bytes()).hexdigest()}  {p}")
    return 0


def _cmd_policy(_: argparse.Namespace) -> int:
    sys.stdout.write(resources.files("genesis_security").joinpath("default_policy.toml").read_text("utf-8"))
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="genesis-security",
                                 description="Defensive runtime for AI agents and multi-agent systems.")
    ap.add_argument("--version", action="version", version=f"genesis-security {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("demo", help="run the 12-scenario attack demo").set_defaults(fn=lambda a: run_demo())
    s = sub.add_parser("scan", help="scan files (or - for stdin) for prompt injection")
    s.add_argument("files", nargs="+"); s.set_defaults(fn=_cmd_scan)
    v = sub.add_parser("verify-audit", help="verify an audit log hash chain")
    v.add_argument("log"); v.set_defaults(fn=_cmd_verify)
    sub.add_parser("keygen", help="print a new GENESIS_SECURITY_KEY").set_defaults(fn=_cmd_keygen)
    p = sub.add_parser("pin", help="print sha256 pins for skill/plugin files")
    p.add_argument("files", nargs="+"); p.set_defaults(fn=_cmd_pin)
    sub.add_parser("policy", help="print the default policy TOML").set_defaults(fn=_cmd_policy)
    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    raise SystemExit(main())
