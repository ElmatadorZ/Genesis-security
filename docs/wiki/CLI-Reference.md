# CLI Reference

```
genesis-security [--version] COMMAND ...
python -m genesis_security COMMAND ...        # same thing
```

Output is always UTF-8, including on Windows consoles.

| Command | Needs key | Exit code |
|---|---|---|
| [`demo`](#demo) | no | 0 if the demo behaved as expected |
| [`redteam`](#redteam) | no | number of security failures |
| [`scan`](#scan) | no | 0 clean · 1 suspicious · 2 injected (worst file) |
| [`keygen`](#keygen) | no | 0 |
| [`checkpoint`](#checkpoint) | yes | 0, or error if the chain is broken |
| [`verify-audit`](#verify-audit) | yes | 0 intact · 1 broken |
| [`pin`](#pin) | no | 0 |
| [`policy`](#policy) | no | 0 |

## demo

```bash
genesis-security demo
```

Runs 12 attack scenarios through a throwaway gate and audit log in a temp folder, then tampers with that log to show detection.

## redteam

```bash
genesis-security redteam
```

Runs the 45-case red-team suite against the installed package. `PASS` = attack stopped. `MISS` = informational L1 scanner gap. `FAIL` = real bypass. See [Red Team Guide](Red-Team-Guide).

## scan

```bash
genesis-security scan FILE [FILE ...]
genesis-security scan -                 # read stdin
```

Prints `status  file  gsx=[…] hits=[…]` per input.

## keygen

```bash
genesis-security keygen                 # 64 hex chars = 32 random bytes
```

## checkpoint

```bash
genesis-security checkpoint logs/audit.jsonl > cp.json
```

Prints `{"count": N, "head": "…"}`. Needs `GENESIS_SECURITY_KEY` (the chain is keyed).

## verify-audit

```bash
genesis-security verify-audit logs/audit.jsonl
genesis-security verify-audit logs/audit.jsonl --checkpoint cp.json
```

Verifies the live file and all rotated files in order. With `--checkpoint`, it also fails if the log is shorter than the checkpoint or the hash at that position differs.

## pin

```bash
genesis-security pin skill/SKILL.md plugins/*.md
```

Prints `sha256  path` per file, for use with `on_skill_load`.

## policy

```bash
genesis-security policy > my_policy.toml
```

Prints the packaged default policy.
