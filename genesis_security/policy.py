# Copyright 2026 Bunyawat Dechanon (ElmatadorZ)
# SPDX-License-Identifier: Apache-2.0
"""Policy: what is allowed, loaded from TOML (stdlib tomllib) and validated strictly.

A policy object exists only if validation passed (ADR-0004 §1). Missing required
sections, unknown keys, wrong types, invalid regexes and wildcard hosts are load
errors. The gate turns any load error into deny-all (see gate.py).
"""
from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

SUPPORTED_SCHEMA = 1
HOST_RE = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?(?::[0-9]{1,5})?$")
TOOL_NAME_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")


class PolicyError(ValueError):
    """A policy failed to load or validate. ``errors`` lists every problem found."""

    def __init__(self, errors: list[str], path: str | None = None):
        self.errors = list(errors)
        self.path = path
        where = f"{path}: " if path else ""
        super().__init__(where + "; ".join(self.errors))


# ───────── schema 1 ─────────
# key -> (required, checker). Checkers append messages to `errs` and return nothing.

def _list_of_str(path: str, v: Any, errs: list[str], *, item=None, non_empty=False) -> None:
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        errs.append(f"{path}: must be a list of strings")
        return
    if non_empty and not v:
        errs.append(f"{path}: must not be empty")
    for i, x in enumerate(v):
        if not x.strip():
            errs.append(f"{path}[{i}]: must not be blank")
        elif item:
            item(f"{path}[{i}]", x, errs)


def _host(path: str, x: str, errs: list[str]) -> None:
    if "*" in x:
        errs.append(f"{path}: wildcard hosts are not allowed ({x!r}); list each host")
    elif not HOST_RE.match(x.lower()):
        errs.append(f"{path}: not a valid host name ({x!r})")


def _tool(path: str, x: str, errs: list[str]) -> None:
    if not TOOL_NAME_RE.match(x):
        errs.append(f"{path}: not a valid tool name ({x!r})")


def _regex(path: str, x: str, errs: list[str]) -> None:
    try:
        re.compile(x)
    except re.error as e:
        errs.append(f"{path}: invalid regular expression ({e})")


def _int(path: str, v: Any, errs: list[str], *, minimum: int) -> None:
    if isinstance(v, bool) or not isinstance(v, int):
        errs.append(f"{path}: must be an integer")
    elif v < minimum:
        errs.append(f"{path}: must be ≥ {minimum}")


def _number(path: str, v: Any, errs: list[str]) -> None:
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        errs.append(f"{path}: must be a number")
    elif v <= 0:
        errs.append(f"{path}: must be > 0")


def _deny_args(path: str, v: Any, errs: list[str]) -> None:
    if not isinstance(v, dict):
        errs.append(f"{path}: must be a table of command = [options]")
        return
    for cmd, opts in v.items():
        _list_of_str(f"{path}.{cmd}", opts, errs)


SECTIONS: dict[str, tuple[bool, dict[str, tuple[bool, Any]]]] = {
    "egress": (True, {
        "allowlist": (True, lambda p, v, e: _list_of_str(p, v, e, item=_host)),
        "tools": (True, lambda p, v, e: _list_of_str(p, v, e, item=_tool)),
        "open_tools": (False, lambda p, v, e: _list_of_str(p, v, e, item=_tool)),
    }),
    "tools": (True, {
        "irreversible": (True, lambda p, v, e: _list_of_str(p, v, e, item=_tool)),
    }),
    "shell": (False, {
        "allowlist": (False, lambda p, v, e: _list_of_str(p, v, e)),
        "deny_args": (False, _deny_args),
    }),
    "agents": (False, {
        "hop_budget": (False, lambda p, v, e: _int(p, v, e, minimum=1)),
        "quarantine_after": (False, lambda p, v, e: _int(p, v, e, minimum=1)),
        "max_age_s": (False, _number),
    }),
    "secrets": (True, {
        "patterns": (True, lambda p, v, e: _list_of_str(p, v, e, item=_regex, non_empty=True)),
    }),
}
TOP_LEVEL_SCALARS = {"schema", "policy_version"}


def validate(d: dict) -> list[str]:
    """Return every problem with a parsed policy (empty list = valid)."""
    errs: list[str] = []
    if not isinstance(d, dict):
        return ["policy must be a TOML table"]
    schema = d.get("schema", SUPPORTED_SCHEMA)
    if isinstance(schema, bool) or not isinstance(schema, int):
        errs.append("schema: must be an integer")
    elif schema != SUPPORTED_SCHEMA:
        errs.append(f"schema: {schema} is not supported by this version (supports {SUPPORTED_SCHEMA}; "
                    f"schema 2 arrives with Genesis Security v2.0)")
    if "policy_version" in d and not isinstance(d["policy_version"], str):
        errs.append("policy_version: must be a string")
    for key in d:
        if key not in SECTIONS and key not in TOP_LEVEL_SCALARS:
            hint = _suggest(key, list(SECTIONS) + sorted(TOP_LEVEL_SCALARS))
            errs.append(f"{key}: unknown section or key{hint}")
    for name, (required, fields) in SECTIONS.items():
        if name not in d:
            if required:
                errs.append(f"[{name}]: required section is missing")
            continue
        sec = d[name]
        if not isinstance(sec, dict):
            errs.append(f"[{name}]: must be a table")
            continue
        for key, value in sec.items():
            if key not in fields:
                if name == "tools" and isinstance(value, dict):
                    errs.append(f"tools.{key}: per-tool declarations need schema 2 (Genesis Security v2.0)")
                else:
                    errs.append(f"{name}.{key}: unknown key{_suggest(key, list(fields))}")
        for key, (req, check) in fields.items():
            if key not in sec:
                if req:
                    errs.append(f"{name}.{key}: required key is missing")
                continue
            check(f"{name}.{key}", sec[key], errs)
    return errs


def _suggest(word: str, options: list[str]) -> str:
    import difflib
    m = difflib.get_close_matches(word, options, n=1, cutoff=0.6)
    return f" (did you mean {m[0]!r}?)" if m else ""


@dataclass
class Policy:
    egress_allowlist: set[str] = field(default_factory=set)
    egress_tools: set[str] = field(default_factory=set)
    open_tools: set[str] = field(default_factory=set)
    irreversible_tools: set[str] = field(default_factory=set)
    shell_allowlist: set[str] = field(default_factory=set)
    shell_deny_args: dict[str, list[str]] = field(default_factory=dict)
    hop_budget: int = 5
    quarantine_after: int = 2
    max_age_s: float = 300.0
    secret_patterns: list[re.Pattern] = field(default_factory=list)
    policy_version: str | None = None
    source: str | None = None

    @classmethod
    def from_dict(cls, d: dict, *, source: str | None = None) -> "Policy":
        """Validate, then build. Raises PolicyError listing every problem."""
        errs = validate(d)
        if errs:
            raise PolicyError(errs, source)
        eg, sh, ag = d["egress"], d.get("shell", {}), d.get("agents", {})
        return cls(
            egress_allowlist={h.lower() for h in eg["allowlist"]},
            egress_tools=set(eg["tools"]),
            open_tools=set(eg.get("open_tools", [])),
            irreversible_tools=set(d["tools"]["irreversible"]),
            shell_allowlist=set(sh.get("allowlist", [])),
            shell_deny_args={k: list(v) for k, v in sh.get("deny_args", {}).items()},
            hop_budget=int(ag.get("hop_budget", 5)),
            quarantine_after=int(ag.get("quarantine_after", 2)),
            max_age_s=float(ag.get("max_age_s", 300)),
            secret_patterns=[re.compile(p) for p in d["secrets"]["patterns"]],
            policy_version=d.get("policy_version"),
            source=source,
        )

    @classmethod
    def load(cls, path: str | Path | None = None) -> "Policy":
        """Load and validate a policy file; with no path, the packaged default.

        Any problem — missing or unreadable file, invalid TOML, schema errors — raises PolicyError.
        """
        if path is None:
            source = "<packaged default_policy.toml>"
            text = resources.files("genesis_security").joinpath("default_policy.toml").read_text("utf-8")
        else:
            source = str(path)
            try:
                text = Path(path).read_text("utf-8")
            except (OSError, UnicodeDecodeError) as e:
                raise PolicyError([f"cannot read policy file ({e.__class__.__name__}: {e})"], source) from e
        try:
            data = tomllib.loads(text)
        except tomllib.TOMLDecodeError as e:
            raise PolicyError([f"invalid TOML ({e})"], source) from e
        return cls.from_dict(data, source=source)

    @classmethod
    def default(cls) -> "Policy":
        return cls.load()
