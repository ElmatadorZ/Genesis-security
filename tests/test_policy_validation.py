"""P1-03 / GS-AUD-03: policy validation and fail-closed loading (issues #2, #3).

These tests were committed before the fix and fail on v1.0.0, where a partial
or malformed policy silently disabled protections.
"""
import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from genesis_security import AuditTrail, GenesisSecurityGate, Policy, Tier
from genesis_security.cli import main
try:
    from genesis_security.policy import PolicyError
except ImportError:  # v1.0.0 had no PolicyError; keep tests runnable so each failure is visible
    class PolicyError(Exception):
        errors: list = []

OWNER = {"agent": "main", "task_id": "t", "origin_tier": Tier.T1}
VALID = '''
[egress]
allowlist = ["api.anthropic.com"]
tools = ["http_request"]
[tools]
irreversible = ["delete_file"]
[secrets]
patterns = ['sk-[A-Za-z0-9_-]{16,}']
'''


def write(text: str) -> Path:
    p = Path(tempfile.mkdtemp()) / "policy.toml"
    p.write_text(text, encoding="utf-8")
    return p


def errors_for(text: str) -> list[str]:
    with self_raises() as ctx:
        Policy.load(write(text))
    return ctx.exception.errors


@contextlib.contextmanager
def self_raises():
    class Ctx:
        exception = None
    c = Ctx()
    try:
        yield c
    except PolicyError as e:
        c.exception = e
        return
    raise AssertionError("PolicyError not raised")


class SchemaValidationTests(unittest.TestCase):
    def test_default_policy_is_valid(self):
        Policy.default()

    def test_minimal_valid_policy_loads(self):
        p = Policy.load(write(VALID))
        self.assertIn("delete_file", p.irreversible_tools)

    def test_partial_policy_rejected(self):
        """The baseline probe: a policy with only [egress] made delete_file('/') ALLOW."""
        errs = errors_for('[egress]\nallowlist=["evil.example"]\ntools=["http_request"]\n')
        self.assertTrue(any("tools" in e for e in errs), errs)
        self.assertTrue(any("secrets" in e for e in errs), errs)

    def test_typo_section_rejected(self):
        errs = errors_for(VALID.replace("[tools]", "[tool]"))
        self.assertTrue(any("tool" in e and "unknown" in e for e in errs), errs)

    def test_unknown_key_rejected(self):
        errs = errors_for(VALID.replace("allowlist =", "allowlst ="))
        self.assertTrue(any("allowlst" in e for e in errs), errs)

    def test_wrong_type_rejected(self):
        errs = errors_for(VALID + '[agents]\nhop_budget = "5"\n')
        self.assertTrue(any("agents.hop_budget" in e for e in errs), errs)

    def test_bool_is_not_an_int(self):
        errs = errors_for(VALID + "[agents]\nquarantine_after = true\n")
        self.assertTrue(any("agents.quarantine_after" in e for e in errs), errs)

    def test_bad_regex_rejected(self):
        errs = errors_for(VALID.replace("'sk-[A-Za-z0-9_-]{16,}'", "'(unclosed'"))
        self.assertTrue(any("secrets.patterns" in e for e in errs), errs)

    def test_empty_secret_patterns_rejected(self):
        errs = errors_for(VALID.replace("patterns = ['sk-[A-Za-z0-9_-]{16,}']", "patterns = []"))
        self.assertTrue(any("secrets.patterns" in e for e in errs), errs)

    def test_wildcard_host_rejected(self):
        errs = errors_for(VALID.replace('"api.anthropic.com"', '"*.example.com"'))
        self.assertTrue(any("egress.allowlist" in e for e in errs), errs)

    def test_invalid_toml_is_policy_error(self):
        errors_for("[egress\nallowlist = [")

    def test_missing_file_is_policy_error(self):
        with self.assertRaises(PolicyError):
            Policy.load(Path(tempfile.mkdtemp()) / "nope.toml")

    def test_schema_2_needs_v2(self):
        errs = errors_for("schema = 2\n" + VALID)
        self.assertTrue(any("schema" in e for e in errs), errs)

    def test_per_tool_tables_need_schema_2(self):
        errs = errors_for(VALID + '[tools.run_command]\ncapabilities = ["exec"]\n')
        self.assertTrue(any("tools.run_command" in e for e in errs), errs)

    def test_all_errors_reported_at_once(self):
        errs = errors_for('[egress]\nallowlst=[]\n[agents]\nhop_budget="x"\n')
        self.assertGreaterEqual(len(errs), 4, errs)


class FailClosedLoadingTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.audit = AuditTrail(self.dir / "a.jsonl")
        self.bad = write('[egress]\nallowlist=["evil.example"]\ntools=["http_request"]\n')
        self.gate = GenesisSecurityGate(os.urandom(32), policy_path=self.bad, audit=self.audit)

    def test_status_reports_failure(self):
        st = self.gate.status()
        self.assertFalse(st["policy_ok"])
        self.assertIn("tools", st["policy_error"])

    def test_every_tool_call_blocked(self):
        for tool in ("read_file", "delete_file", "http_request", "anything"):
            with self.subTest(tool=tool):
                self.assertEqual(self.gate.pre_tool_call(tool, {"path": "a"}, OWNER).verdict, "BLOCK")

    def test_guard_raises(self):
        @self.gate.guard("read_file")
        def read_file(path):
            return "ran"
        with self.assertRaises(PermissionError):
            read_file({"path": "a"}, OWNER)

    def test_agent_messages_blocked(self):
        env = self.gate.make_envelope("a", "b", "t", "hi", ["s"])
        tier, v = self.gate.on_agent_message(env, "hi", {"s"}, recipient="b")
        self.assertEqual((tier, v.verdict), (Tier.T3, "BLOCK"))

    def test_memory_and_skills_blocked(self):
        self.assertEqual(self.gate.on_memory_write("/m.md", "note", Tier.T1).verdict, "BLOCK")
        import hashlib
        body = "# skill"
        self.assertEqual(self.gate.on_skill_load("s.md", body, hashlib.sha256(body.encode()).hexdigest()).verdict,
                         "BLOCK")

    def test_external_content_still_wrapped(self):
        page, v = self.gate.on_external_content("https://x.example", "hello")
        self.assertEqual(page.tier, Tier.T3)
        self.assertIn("<untrusted", page.value)

    def test_one_policy_load_failed_event(self):
        self.gate.pre_tool_call("read_file", {"path": "a"}, OWNER)
        events = [json.loads(l)["event"] for l in self.audit.path.read_text().splitlines()]
        self.assertEqual(events.count("policy_load_failed"), 1)

    def test_from_env_with_bad_policy_is_deny_all(self):
        os.environ["GENESIS_SECURITY_KEY"] = "ab" * 32
        os.environ["GENESIS_SECURITY_POLICY"] = str(self.bad)
        try:
            g = GenesisSecurityGate.from_env(audit=AuditTrail(self.dir / "b.jsonl"))
        finally:
            del os.environ["GENESIS_SECURITY_KEY"], os.environ["GENESIS_SECURITY_POLICY"]
        self.assertFalse(g.status()["policy_ok"])
        self.assertEqual(g.pre_tool_call("read_file", {"path": "a"}, OWNER).verdict, "BLOCK")

    def test_good_policy_path_works(self):
        g = GenesisSecurityGate(os.urandom(32), policy_path=write(VALID), audit=AuditTrail(self.dir / "c.jsonl"))
        self.assertTrue(g.status()["policy_ok"])
        self.assertEqual(g.pre_tool_call("read_file", {"path": "a"}, OWNER).verdict, "ALLOW")


class PolicyCheckCliTests(unittest.TestCase):
    def run_cli(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            code = main(list(args))
        return code, out.getvalue()

    def test_check_valid(self):
        code, out = self.run_cli("policy", "check", str(write(VALID)))
        self.assertEqual(code, 0, out)

    def test_check_invalid_lists_errors(self):
        code, out = self.run_cli("policy", "check", str(write('[egress]\nallowlst=[]\n')))
        self.assertNotEqual(code, 0)
        self.assertIn("allowlst", out)

    def test_policy_without_args_still_prints_default(self):
        code, out = self.run_cli("policy")
        self.assertEqual(code, 0)
        self.assertIn("[egress]", out)


if __name__ == "__main__":
    unittest.main()
