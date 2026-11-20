# Copyright 2026 Bunyawat Dechanon (ElmatadorZ)
# SPDX-License-Identifier: Apache-2.0
"""L1 injection scanner — heuristic, regex-based.

This is a tripwire, not a wall. A determined attacker can phrase around it.
The structural rules in L2/L3 (gate.py) are what actually stop damage.
"""
from __future__ import annotations

import re
import unicodedata

INJECTION_PATTERNS: list[tuple[str, str, re.Pattern]] = [
    ("GSX-01", "override", re.compile(
        r"(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|rules|prompts?)"
        r"|ลืมคำสั่ง|ไม่ต้องสนใจคำสั่งก่อนหน้า", re.I)),
    ("GSX-01", "role_swap", re.compile(
        r"you\s+are\s+now\s+|act\s+as\s+(an?\s+)?(unrestricted|admin|root|developer\s+mode)|จากนี้ไปคุณคือ", re.I)),
    ("GSX-03", "forged_authority", re.compile(
        r"\[(system|admin|anthropic|owner)\]|<\s*system\s*>|message\s+from\s+(anthropic|the\s+owner|system)"
        r"|owner\s+(has\s+)?approved|safeguards?\s+(are\s+)?(off|disabled)", re.I)),
    ("GSX-02", "ai_directed", re.compile(
        r"(if\s+you\s+are\s+an?\s+(ai|llm|assistant|agent))|(ai\s+agents?\s+(must|should)\s+)"
        r"|ถ้าคุณเป็น\s*ai", re.I)),
    ("GSX-06", "exfil_request", re.compile(
        r"(send|post|upload|forward|email)\s+.{0,40}(api[_\s-]?key|token|password|secret|\.env|credentials)"
        r"|ส่ง.{0,20}(รหัส|คีย์|token)", re.I)),
    ("GSX-13", "audit_tamper", re.compile(
        r"(disable|delete|clear|skip)\s+(the\s+)?(audit|log|logging)|ไม่ต้องบันทึก", re.I)),
    ("GSX-09", "urgency", re.compile(
        r"(urgent|immediately|right\s+now|do\s+not\s+ask|without\s+(asking|confirmation))|ด่วน|ห้ามถาม", re.I)),
]
# Cheap substring prefilter per pattern: skip the regex when none of these appear.
PREFILTER: dict[str, tuple[str, ...]] = {
    "override": ("ignore", "disregard", "forget", "ลืม", "ไม่ต้องสนใจ"),
    "role_swap": ("you are now", "act as", "จากนี้ไป"),
    "forged_authority": ("system", "admin", "anthropic", "owner", "safeguard"),
    "ai_directed": ("you are a", "ai agent", "ถ้าคุณเป็น"),
    "exfil_request": ("send", "post", "upload", "forward", "email", "ส่ง"),
    "audit_tamper": ("audit", "log", "ไม่ต้องบันทึก"),
    "urgency": ("urgent", "immediately", "right now", "do not ask", "without", "ด่วน", "ห้ามถาม"),
}
ZERO_WIDTH = re.compile("[​‌‍⁠﻿]")
HIDDEN_HTML = re.compile(r"<!--.*?-->|display\s*:\s*none|color\s*:\s*(#fff\b|#ffffff|white)", re.I | re.S)
LONG_B64 = re.compile(r"[A-Za-z0-9+/]{80,}={0,2}")
STRONG = {"override", "role_swap", "forged_authority", "exfil_request", "audit_tamper"}


def scan_injection(text: str) -> tuple[str, list[str], list[str]]:
    """Return (status, gsx_ids, hits). status is one of: clean, suspicious, injected."""
    stripped = ZERO_WIDTH.sub("", text)
    # NFKC folds look-alike Latin (fullwidth, ligatures) but splits Thai SARA AM (ำ → ํ + า),
    # so match against both forms.
    norm = unicodedata.normalize("NFKC", stripped)
    views = [stripped] if norm == stripped else [stripped, norm]
    lowered = " ".join(v.lower() for v in views)
    gsx: set[str] = set()
    hits: list[str] = []
    for gid, name, pat in INJECTION_PATTERNS:
        if not any(k in lowered for k in PREFILTER.get(name, ("",))):
            continue
        if any(pat.search(v) for v in views):
            gsx.add(gid)
            hits.append(name)
    if ZERO_WIDTH.search(text):
        gsx.add("GSX-02"); hits.append("zero_width_chars")
    if HIDDEN_HTML.search(text):
        gsx.add("GSX-02"); hits.append("hidden_html")
    if LONG_B64.search(text):
        hits.append("long_base64")
    if STRONG & set(hits) or len(hits) >= 2:
        return "injected", sorted(gsx), hits
    if hits:
        return "suspicious", sorted(gsx), hits
    return "clean", [], []
