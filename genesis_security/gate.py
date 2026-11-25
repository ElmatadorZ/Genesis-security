# Copyright 2026 Bunyawat Dechanon (ElmatadorZ)
# SPDX-License-Identifier: Apache-2.0
"""GenesisSecurityGate — the L0→L5 loop and the five runtime hooks.

Brain/body split: an optional ``brain`` callable (e.g. Claude running
skill/SKILL.md) may *tighten* a verdict, never loosen it. Any brain error
fails closed (BLOCK). The gate never logs raw tool arguments or content;
HOLD reasons carry a short, secret-redacted preview for the owner.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import shlex
import time
from dataclasses import asdict
from typing import Any, Callable, Iterator, Optional
from urllib.parse import unquote, urlsplit

from .audit import AuditTrail, derive_audit_key
from .policy import Policy, PolicyError
from .scanner import scan_injection
from .tiers import Tainted, Tier, Verdict

Brain = Callable[[dict], Optional[dict]]
OwnerConfirm = Callable[[Verdict, dict], bool]

SHELL_META = re.compile(r"[;&|`$><\n\r]")
URL_RE = re.compile(r"(?i)\b[a-z][a-z0-9+.\-]*://[^\s\"'<>]+")
B64_TOKEN = re.compile(r"[A-Za-z0-9+/_\-]{16,}={0,2}")
HEX_TOKEN = re.compile(r"\b[0-9a-fA-F]{32,}\b")
BAD_NETLOC = re.compile(r"[\\\s\x00-\x1f%]")
BARE_HOST = re.compile(r"(?i)^(//)?([a-z0-9\-]+\.)+[a-z]{2,}(:\d+)?([/?#]|$)")
RULE_LIKE = re.compile(
    r"(?i)\b(always|never|from now on|henceforth|going forward|from here on|you must|must always"
    r"|obey|rule:|treat\s.{0,60}\sas\s(the\s)?(owner|admin|system|trusted))\b"
    r"|ต้อง|ห้าม|จากนี้ไป|ต่อไปนี้|ให้เชื่อ|เชื่อฟัง|ถือว่า")
UNTRUSTED_TAG = re.compile(r"(?i)<\s*(/?)\s*untrusted")
MAX_DECODE_TOKENS = 256
log = logging.getLogger("genesis_security")
DENY_ALL_REASON = "policy failed to load: deny-all (no action is permitted until a valid policy is loaded)"


class GenesisSecurityGate:
    def __init__(self, hmac_key: bytes, policy: Policy | None = None,
                 audit: AuditTrail | None = None, brain: Brain | None = None,
                 owner_confirm: OwnerConfirm | None = None,
                 policy_path: "str | os.PathLike[str] | None" = None):
        """Create a gate.

        ``policy_path`` loads and validates a policy file. If it cannot be loaded, the gate
        does not raise: it enters **deny-all** (ADR-0004 §4) — every action is blocked and
        ``status()["policy_ok"]`` is False — and records one ``policy_load_failed`` audit event.
        """
        if len(hmac_key) < 16:
            raise ValueError("hmac_key must be at least 16 bytes")
        if policy is not None and policy_path is not None:
            raise ValueError("pass either policy or policy_path, not both")
        self.key = hmac_key
        self.audit = audit or AuditTrail()
        if self.audit.key is None:                 # key the audit chain (GSX-13)
            self.audit.key = derive_audit_key(hmac_key)
        self.policy_error: PolicyError | None = None
        if policy_path is not None:
            try:
                policy = Policy.load(policy_path)
            except PolicyError as e:
                self.policy_error = e
        if self.policy_error is not None:
            # Packaged default kept ONLY so secrets are still redacted in logs; it authorizes nothing.
            self.policy = Policy.default()
            log.error("Genesis Security: %s. Errors: %s", DENY_ALL_REASON, "; ".join(self.policy_error.errors))
            self.audit.record("policy_load_failed", {"source": self.policy_error.path,
                                                     "errors": self.policy_error.errors[:50],
                                                     "mode": "deny-all"})
        else:
            self.policy = policy or Policy.default()
        self.brain = brain
        self.owner_confirm = owner_confirm
        self.strikes: dict[str, int] = {}
        self.quarantined: set[str] = set()
        self.task_taint: dict[str, Tier] = {}
        self._seen_nonces: dict[str, float] = {}

    @classmethod
    def from_env(cls, **kw: Any) -> "GenesisSecurityGate":
        """Build a gate with the HMAC key from $GENESIS_SECURITY_KEY (hex or text)."""
        key = key_from_env()
        if "policy" not in kw and "policy_path" not in kw and os.environ.get("GENESIS_SECURITY_POLICY"):
            kw["policy_path"] = os.environ["GENESIS_SECURITY_POLICY"]
        if "audit" not in kw and os.environ.get("GENESIS_SECURITY_AUDIT"):
            kw["audit"] = AuditTrail(os.environ["GENESIS_SECURITY_AUDIT"])
        return cls(key, **kw)

    # ───────── status / deny-all ─────────
    @property
    def policy_ok(self) -> bool:
        return self.policy_error is None

    def status(self) -> dict:
        """Small health summary for `doctor`, dashboards and tests."""
        return {"policy_ok": self.policy_ok,
                "policy_error": str(self.policy_error) if self.policy_error else None,
                "policy_source": None if self.policy_error else self.policy.source,
                "policy_version": None if self.policy_error else self.policy.policy_version,
                "mode": "enforcing" if self.policy_ok else "deny-all",
                "quarantined": sorted(self.quarantined)}

    def _deny_all(self, event: str, ctx: dict) -> Verdict:
        v = Verdict("BLOCK", ["POLICY"], "S2", DENY_ALL_REASON, layer_trace=["L0:policy-load-failed"])
        self.audit.record(event, {"verdict": asdict(v), "ctx": _safe_ctx(ctx)})
        return v

    # ───────── helpers ─────────
    def sign(self, body: str) -> str:
        return hmac.new(self.key, body.encode("utf-8"), hashlib.sha256).hexdigest()

    def _has_secret(self, text: str) -> bool:
        return any(p.search(v) for v in _decoded_views(text) for p in self.policy.secret_patterns)

    def _redact(self, text: str) -> str:
        for p in self.policy.secret_patterns:
            text = p.sub("[REDACTED]", text)
        return text

    def _preview(self, tool: str, raw_args: Any) -> str:
        s = json.dumps(raw_args, ensure_ascii=False, default=str)
        s = self._redact(s)
        return f"{tool} {s[:160]}{'…' if len(s) > 160 else ''}"

    def _finish(self, event: str, v: Verdict, ctx: dict) -> Verdict:
        if self.brain is not None and v.verdict in ("ALLOW", "ALLOW_SANITIZED", "HOLD"):
            try:
                b = self.brain({"event": event, "verdict": asdict(v), "ctx": _safe_ctx(ctx)})
                if b is not None and not isinstance(b, dict):
                    raise TypeError(f"brain returned {type(b).__name__}, expected dict")
                if b and b.get("verdict") in ("HOLD", "BLOCK"):      # brain may only tighten
                    order = {"ALLOW": 0, "ALLOW_SANITIZED": 1, "HOLD": 2, "BLOCK": 3}
                    if order[b["verdict"]] > order[v.verdict]:
                        v.verdict = b["verdict"]
                        v.requires_owner = v.requires_owner or b["verdict"] == "HOLD"
                        v.reason += f" | brain: {str(b.get('reason', ''))[:200]}"
                        v.layer_trace.append(f"brain:{b['verdict']}")
            except Exception as e:  # noqa: BLE001 — fail closed on anything
                v.verdict, v.reason = "BLOCK", f"brain error, fail-closed: {e}"[:200]
                v.layer_trace.append("brain:error")
        if v.verdict == "HOLD" and v.requires_owner and self.owner_confirm is not None:
            try:
                approved = bool(self.owner_confirm(v, ctx))
            except Exception:  # noqa: BLE001
                approved = False
            v.verdict = "ALLOW" if approved else "BLOCK"
            v.layer_trace.append("owner:approved" if approved else "owner:denied")
        agent = ctx.get("agent")
        if agent and v.verdict == "BLOCK" and any(g in v.gsx for g in ("GSX-01", "GSX-02", "GSX-03")):
            self.strikes[agent] = self.strikes.get(agent, 0) + 1
            if self.strikes[agent] >= self.policy.quarantine_after:
                self.quarantined.add(agent)
                v.layer_trace.append(f"quarantine:{agent}")
        v.reason = self._redact(v.reason)
        self.audit.record(event, {"verdict": asdict(v), "ctx": _safe_ctx(ctx)})
        return v

    # ───────── Hook 1: external content enters ─────────
    def on_external_content(self, source: str, content: str, task_id: str = "-") -> tuple[Tainted, Verdict]:
        """Every T3 payload is returned wrapped and escaped so it can't close its own wrapper."""
        status, gsx, hits = scan_injection(content)
        if not self.policy_ok:                     # content is data; still wrapped, still T3
            self.task_taint[task_id] = Tier.T3
            safe = UNTRUSTED_TAG.sub(lambda m: "&lt;" + m.group(1) + "untrusted", content)
            wrapped = f"<untrusted source={json.dumps(source)} scan='{status}'>\n{safe}\n</untrusted>"
            v = Verdict("ALLOW_SANITIZED", gsx, "S2", f"{DENY_ALL_REASON}; content wrapped as T3 data only",
                        layer_trace=["L0:policy-load-failed", "L0:T3", f"L1:{status}"])
            self.audit.record("external_content", {"verdict": asdict(v),
                                                   "ctx": {"source": source[:200], "task_id": task_id}})
            return Tainted(wrapped, Tier.T3, source), v
        self.task_taint[task_id] = Tier.T3
        v = Verdict("ALLOW" if status != "injected" else "ALLOW_SANITIZED", gsx,
                    "S3" if status == "injected" else "S4",
                    f"L1 scan={status} hits={hits}", layer_trace=["L0:T3", f"L1:{status}"])
        safe = UNTRUSTED_TAG.sub(lambda m: "&lt;" + m.group(1) + "untrusted", content)
        wrapped = f"<untrusted source={json.dumps(source)} scan='{status}'>\n{safe}\n</untrusted>"
        v = self._finish("external_content", v, {"source": source, "task_id": task_id})
        return Tainted(wrapped, Tier.T3, source), v

    # ───────── Hook 2: before every tool call ─────────
    def pre_tool_call(self, tool: str, args: dict, ctx: dict) -> Verdict:
        if not self.policy_ok:
            return self._deny_all("tool_call", {"tool": tool, **ctx})
        trace: list[str] = []
        gsx: list[str] = []
        origin = Tier(ctx.get("origin_tier", Tier.T3))
        agent = ctx.get("agent", "main")
        raw_args = _unwrap(args)
        arg_text = json.dumps(raw_args, ensure_ascii=False, default=str)
        arg_tier = Tier(max([t for _, t in _walk(args)] + [Tier.T1]))
        task_tier = self.task_taint.get(ctx.get("task_id", "-"), Tier.T1)
        trace.append(f"L0:origin={origin.name} args={arg_tier.name} task={task_tier.name}")
        c = {"tool": tool, **ctx, "_args_preview": self._preview(tool, raw_args)}

        if agent in self.quarantined:
            return self._finish("tool_call", Verdict("BLOCK", ["GSX-07"], "S2",
                                f"agent '{agent}' is quarantined", layer_trace=trace), c)

        status, g, hits = scan_injection(arg_text)
        trace.append(f"L1:{status}")
        if status == "injected":
            return self._finish("tool_call", Verdict("BLOCK", g, "S2", f"injection in args: {hits}",
                                layer_trace=trace), c)

        if origin >= Tier.T3:
            trace.append("L2:action originates from T3")
            return self._finish("tool_call", Verdict("BLOCK", ["GSX-02", "GSX-05"], "S2",
                                "action requested by untrusted content, not by owner", layer_trace=trace), c)
        trace.append("L2:traces to owner")

        # L3 — egress: any declared egress tool, or any URL anywhere in the args
        leaves = [s for s, _ in _walk(raw_args) if isinstance(s, str)]
        urls = [u for s in leaves for u in URL_RE.findall(s)]
        if tool in self.policy.egress_tools:      # bare "evil.example/x" or "//evil.example" values
            urls += ["http://" + s.strip().lstrip("/") for s in leaves if BARE_HOST.match(s.strip())]
        egress = tool in self.policy.egress_tools or bool(urls)
        open_tool = tool in self.policy.open_tools
        for u in urls:
            host, bad = _host(u)
            if bad:
                gsx.append("GSX-06"); trace.append(f"L3:malformed url {u[:40]!r}")
            elif host not in self.policy.egress_allowlist and not open_tool:
                gsx.append("GSX-06"); trace.append(f"L3:egress host '{host}' not allowlisted")
        if egress and (self._has_secret(arg_text) or self._has_secret("".join(leaves))):
            trace.append("L3:secret in outbound args (incl. base64/hex/url-encoded)")
            return self._finish("tool_call", Verdict("BLOCK", ["GSX-06"], "S1",
                                "secret would leave the system", layer_trace=trace), c)
        if egress and max(arg_tier, task_tier) >= Tier.T3 and ctx.get("touches_private", False):
            gsx.append("GSX-06"); trace.append("L3:lethal trifecta")

        if tool == "shell_exec":
            cmd = str(raw_args.get("cmd", ""))
            reason = self._shell_refusal(cmd)
            if reason:
                trace.append("L3:shell refused")
                return self._finish("tool_call", Verdict("BLOCK", ["GSX-05"], "S2",
                                    f"{reason}: {self._redact(cmd)[:80]}", layer_trace=trace), c)

        irreversible = tool in self.policy.irreversible_tools
        trace.append(f"L4:irreversible={irreversible} flags={sorted(set(gsx))}")
        if irreversible or gsx:
            why = "irreversible action" if irreversible else "risky egress"
            return self._finish("tool_call", Verdict("HOLD", sorted(set(gsx)) or ["GATE"], "S3",
                                f"{why} needs owner confirmation → {c['_args_preview']}",
                                requires_owner=True, layer_trace=trace), c)

        trace.append("L5:ALLOW")
        return self._finish("tool_call", Verdict("ALLOW", [], "S4", "all layers passed", layer_trace=trace), c)

    def _shell_refusal(self, cmd: str) -> Optional[str]:
        if SHELL_META.search(cmd):
            return "shell metacharacter"
        try:
            parts = shlex.split(cmd)
        except ValueError:
            return "unparseable command"
        if not parts or parts[0] not in self.policy.shell_allowlist:
            return "command not allowlisted"
        for bad in self.policy.shell_deny_args.get(parts[0], []):
            for tok in parts[1:]:
                if tok == bad or tok.startswith(bad + "=") or (len(bad) == 2 and tok.startswith(bad)):
                    return f"dangerous option {bad}"
        return None

    # ───────── Hook 3: agent-to-agent messages ─────────
    def make_envelope(self, frm: str, to: str, task_id: str, body: str,
                      scope: list[str], hop: int = 0, taint: Tier = Tier.T2) -> dict:
        env = {"from": frm, "to": to, "task_id": task_id, "capability_scope": list(scope),
               "hop": hop, "taint": int(taint), "ts": time.time(), "nonce": secrets.token_hex(16)}
        env["sig"] = self.sign(json.dumps(env, sort_keys=True) + body)
        return env

    def on_agent_message(self, envelope: dict | None, body: str, granted_scope: set[str],
                         recipient: Optional[str] = None) -> tuple[Tier, Verdict]:
        if not self.policy_ok:
            return Tier.T3, self._deny_all("agent_message", {"agent": str((envelope or {}).get("from"))})
        if not envelope or "sig" not in envelope:
            v = Verdict("ALLOW_SANITIZED", ["GSX-07"], "S3", "no envelope: treated as T3 data",
                        layer_trace=["L0:no-envelope→T3"])
            return Tier.T3, self._finish("agent_message", v, {"from": None})
        env = {k: val for k, val in envelope.items() if k != "sig"}
        sender = str(envelope.get("from", "?"))
        c = {"agent": sender, "to": envelope.get("to"), "task_id": envelope.get("task_id"),
             "hop": envelope.get("hop")}

        def block(gsx: str, sev: str, reason: str, layer: str) -> tuple[Tier, Verdict]:
            return Tier.T3, self._finish("agent_message",
                                         Verdict("BLOCK", [gsx], sev, reason, layer_trace=[layer]), c)

        if not hmac.compare_digest(self.sign(json.dumps(env, sort_keys=True) + body), str(envelope["sig"])):
            return block("GSX-07", "S2", "signature mismatch: impersonation or tampering", "L0:bad-sig")
        now = time.time()
        ts, nonce = envelope.get("ts"), envelope.get("nonce")
        if not isinstance(ts, (int, float)) or not isinstance(nonce, str):
            return block("GSX-07", "S2", "envelope missing ts/nonce", "L0:legacy-envelope")
        if abs(now - ts) > self.policy.max_age_s:
            return block("GSX-07", "S3", f"stale or future message ({now - ts:.0f}s)", "L0:stale")
        for n, t in list(self._seen_nonces.items()):
            if now - t > self.policy.max_age_s:
                del self._seen_nonces[n]
        if nonce in self._seen_nonces:
            return block("GSX-07", "S2", "replayed message", "L0:replay")
        self._seen_nonces[nonce] = ts
        if recipient is not None and envelope.get("to") != recipient:
            return block("GSX-07", "S2", f"addressed to {envelope.get('to')!r}, delivered to {recipient!r}",
                         "L0:wrong-recipient")
        if sender in self.quarantined:
            return block("GSX-07", "S2", "sender quarantined", "L0:quarantined")
        if int(envelope.get("hop", 0)) >= self.policy.hop_budget:
            return block("GSX-10", "S3", f"hop {envelope['hop']} ≥ budget {self.policy.hop_budget}",
                         "L3:hop-budget")
        extra = set(envelope.get("capability_scope", [])) - set(granted_scope)
        if extra:
            return block("GSX-11", "S2", f"scope escalation attempt: {sorted(extra)}", "L3:scope")
        tier = Tier(max(Tier.T2, int(envelope.get("taint", Tier.T2))))
        status, g, hits = scan_injection(body)
        trace = [f"L0:sig-ok tier={tier.name}", f"L1:{status}"]
        if status == "injected":
            return Tier.T3, self._finish("agent_message", Verdict("BLOCK", g, "S2", f"injection: {hits}",
                                         layer_trace=trace), c)
        return tier, self._finish("agent_message", Verdict("ALLOW", [], "S4", "verified",
                                  layer_trace=trace), c)

    # ───────── Hook 4: memory / genome write ─────────
    def on_memory_write(self, path: str, content: str, src_tier: Tier) -> Verdict:
        if not self.policy_ok:
            return self._deny_all("memory_write", {"path": path})
        trace = [f"L0:src={Tier(src_tier).name}"]
        c = {"path": path}
        if self._has_secret(content):
            return self._finish("memory_write", Verdict("BLOCK", ["GSX-06"], "S2", "secret in memory write",
                                layer_trace=trace + ["L3:secret"]), c)
        status, g, hits = scan_injection(content)
        trace.append(f"L1:{status}")
        if src_tier >= Tier.T3:
            if status != "clean" or RULE_LIKE.search(content):
                return self._finish("memory_write", Verdict("BLOCK", g + ["GSX-08"], "S2",
                                    "T3 content tried to write a rule/instruction into memory",
                                    layer_trace=trace + ["L2:rule-from-T3"]), c)
            fact = f"- [fact][source:T3] {content.strip()}"
            return self._finish("memory_write", Verdict("ALLOW_SANITIZED", ["GSX-08"], "S4",
                                "stored as tagged fact only", sanitized_args={"content": fact},
                                layer_trace=trace + ["L5:fact-only"]), c)
        if status == "injected":
            return self._finish("memory_write", Verdict("BLOCK", g, "S3", f"injection: {hits}",
                                layer_trace=trace), c)
        return self._finish("memory_write", Verdict("ALLOW", [], "S4", "trusted source",
                            layer_trace=trace + ["L5:ALLOW"]), c)

    # ───────── Hook 5: skill / plugin load ─────────
    def on_skill_load(self, path: str, content: str, pinned_sha256: Optional[str]) -> Verdict:
        if not self.policy_ok:
            return self._deny_all("skill_load", {"path": path})
        h = hashlib.sha256(content.encode("utf-8")).hexdigest()
        c = {"path": path, "sha256": h}
        if pinned_sha256 and not hmac.compare_digest(h, pinned_sha256):
            return self._finish("skill_load", Verdict("BLOCK", ["GSX-12"], "S2", "hash changed since pin",
                                layer_trace=["L0:hash-mismatch"]), c)
        status, g, hits = scan_injection(content)
        if pinned_sha256:
            # A pinned file was read and approved by the owner; L1 hits are expected in security docs.
            return self._finish("skill_load", Verdict("ALLOW", [], "S4", "pinned (owner-reviewed)",
                                layer_trace=[f"L1:{status}", "L0:hash-ok"]), c)
        if status == "injected":
            return self._finish("skill_load", Verdict("BLOCK", g + ["GSX-12"], "S2", f"injection: {hits}",
                                layer_trace=[f"L1:{status}"]), c)
        return self._finish("skill_load", Verdict("HOLD", ["GSX-12"], "S4",
                            "unpinned skill: owner must read & pin", requires_owner=True,
                            layer_trace=[f"L1:{status}"]), c)

    # ───────── Enforcement decorator ─────────
    def guard(self, tool_name: str):
        """Wrap a tool function. Call it as ``wrapped(args_dict, ctx_dict)``."""
        def deco(fn):
            def wrapper(args: dict, ctx: dict):
                v = self.pre_tool_call(tool_name, args, ctx)
                if not v.allowed:
                    raise PermissionError(f"[GenesisSecurity] {v.verdict} {v.gsx}: {v.reason}")
                return fn(**(v.sanitized_args or _unwrap(args)))
            wrapper.__name__ = getattr(fn, "__name__", tool_name)
            wrapper.__doc__ = fn.__doc__
            return wrapper
        return deco


# ───────── module helpers ─────────
def key_from_env() -> bytes:
    raw = os.environ.get("GENESIS_SECURITY_KEY")
    if not raw:
        raise RuntimeError("Set GENESIS_SECURITY_KEY (generate one with `genesis-security keygen`)")
    try:
        return bytes.fromhex(raw)
    except ValueError:
        return raw.encode()


def _walk(obj: Any, tier: Tier = Tier.T1, depth: int = 0) -> Iterator[tuple[Any, Tier]]:
    """Yield (leaf, tier) for every leaf in nested dict/list/tuple/set/Tainted."""
    if depth > 32:
        yield "<too deep>", Tier.T3
        return
    if isinstance(obj, Tainted):
        yield from _walk(obj.value, Tier(max(tier, obj.tier)), depth + 1)
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk(k, tier, depth + 1)
            yield from _walk(v, tier, depth + 1)
    elif isinstance(obj, (list, tuple, set, frozenset)):
        for v in obj:
            yield from _walk(v, tier, depth + 1)
    else:
        yield obj, tier


def _unwrap(obj: Any) -> Any:
    if isinstance(obj, Tainted):
        return _unwrap(obj.value)
    if isinstance(obj, dict):
        return {k: _unwrap(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return type(obj)(_unwrap(v) for v in obj)
    return obj


def _host(url: str) -> tuple[str, bool]:
    """Return (lowercase host, malformed?). Backslashes, whitespace, %-escapes in netloc = malformed."""
    try:
        parts = urlsplit(url)
        if BAD_NETLOC.search(parts.netloc):
            return "", True
        return (parts.hostname or "").lower(), not parts.hostname
    except ValueError:
        return "", True


def _decoded_views(text: str) -> Iterator[str]:
    """The text plus url-decoded, base64-decoded and hex-decoded views of its tokens."""
    yield text
    u = unquote(text)
    if u != text:
        yield u
    count = 0
    for tok in B64_TOKEN.findall(text):
        count += 1
        if count > MAX_DECODE_TOKENS:
            break
        s = tok.rstrip("=")
        for alt in (tok, s + "=" * (-len(s) % 4)):
            try:
                raw = base64.b64decode(alt.replace("-", "+").replace("_", "/"), validate=False)
                yield raw.decode("utf-8", "ignore")
                break
            except (binascii.Error, ValueError):
                continue
    for tok in HEX_TOKEN.findall(text)[:MAX_DECODE_TOKENS]:
        try:
            yield bytes.fromhex(tok if len(tok) % 2 == 0 else tok[:-1]).decode("utf-8", "ignore")
        except ValueError:
            continue


def _safe_ctx(ctx: dict) -> dict:
    """Keep only small scalar context fields in the audit log (no raw args/content)."""
    out = {}
    for k, v in ctx.items():
        if k.startswith("_"):
            continue
        if isinstance(v, (str, int, float, bool)) or v is None:
            out[k] = v if not isinstance(v, str) else v[:200]
    return out
