# Copyright 2026 Bunyawat Dechanon (ElmatadorZ)
# SPDX-License-Identifier: Apache-2.0
"""Command line: genesis-security {demo, scan, verify-audit, checkpoint, keygen, pin, policy, redteam}."""
from __future__ import annotations

import argparse
import hashlib
import json
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


def _audit(log: str) -> AuditTrail:
    from .audit import derive_audit_key
    from .gate import key_from_env
    try:
        key = derive_audit_key(key_from_env())
    except RuntimeError as e:
        raise SystemExit(f"{e}\n(the audit chain is keyed with the same secret the gate uses)")
    return AuditTrail(log, key=key)


def _cmd_verify(a: argparse.Namespace) -> int:
    cp = json.loads(Path(a.checkpoint).read_text()) if a.checkpoint else None
    ok, n = _audit(a.log).verify(checkpoint=cp)
    print(f"intact={ok} entries={n}" + (f" checkpoint={cp['count']}" if cp else ""))
    return 0 if ok else 1


def _cmd_checkpoint(a: argparse.Namespace) -> int:
    print(json.dumps(_audit(a.log).checkpoint()))
    return 0


def _cmd_keygen(_: argparse.Namespace) -> int:
    print(secrets.token_hex(32))
    return 0


def _cmd_pin(a: argparse.Namespace) -> int:
    for p in a.files:
        print(f"{hashlib.sha256(Path(p).read_bytes()).hexdigest()}  {p}")
    return 0


def _cmd_policy(a: argparse.Namespace) -> int:
    from .policy import Policy, PolicyError
    if a.action is None:
        sys.stdout.write(resources.files("genesis_security").joinpath("default_policy.toml").read_text("utf-8"))
        return 0
    if a.action != "check":
        print(f"unknown policy action {a.action!r}; use: genesis-security policy [check FILE ...]", file=sys.stderr)
        return 2
    if not a.files:
        print("policy check: give at least one policy file", file=sys.stderr)
        return 2
    worst = 0
    for f in a.files:
        try:
            p = Policy.load(f)
        except PolicyError as e:
            worst = 1
            print(f"INVALID  {f}  ({len(e.errors)} problem{'s' if len(e.errors) != 1 else ''})")
            for err in e.errors:
                print(f"  - {err}")
            continue
        print(f"OK       {f}  (version {p.policy_version or 'unset'}; "
              f"{len(p.irreversible_tools)} irreversible tools, {len(p.egress_allowlist)} allowed hosts)")
    return worst


def _utf8_console() -> None:
    """Windows consoles default to cp1252/cp874; verdict text contains → and Thai."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def main(argv: list[str] | None = None) -> int:
    _utf8_console()
    ap = argparse.ArgumentParser(prog="genesis-security",
                                 description="Defensive runtime for AI agents and multi-agent systems.")
    ap.add_argument("--version", action="version", version=f"genesis-security {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("demo", help="run the 12-scenario attack demo").set_defaults(fn=lambda a: run_demo())
    s = sub.add_parser("scan", help="scan files (or - for stdin) for prompt injection")
    s.add_argument("files", nargs="+"); s.set_defaults(fn=_cmd_scan)
    v = sub.add_parser("verify-audit", help="verify an audit log chain (needs GENESIS_SECURITY_KEY)")
    v.add_argument("log")
    v.add_argument("--checkpoint", help="JSON file from `checkpoint`; also detects truncation/deletion")
    v.set_defaults(fn=_cmd_verify)
    k = sub.add_parser("checkpoint", help="print {count, head} — store it where agents can't write")
    k.add_argument("log"); k.set_defaults(fn=_cmd_checkpoint)
    sub.add_parser("keygen", help="print a new GENESIS_SECURITY_KEY").set_defaults(fn=_cmd_keygen)
    p = sub.add_parser("pin", help="print sha256 pins for skill/plugin files")
    p.add_argument("files", nargs="+"); p.set_defaults(fn=_cmd_pin)
    pol = sub.add_parser("policy", help="print the default policy, or `policy check FILE...` to validate")
    pol.add_argument("action", nargs="?", choices=["check"], help="check: validate policy files")
    pol.add_argument("files", nargs="*")
    pol.set_defaults(fn=_cmd_policy)
    sub.add_parser("redteam", help="run the red-team suite (exit code = failures)").set_defaults(
        fn=lambda a: __import__("genesis_security.redteam", fromlist=["main"]).main())
    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    raise SystemExit(main())
