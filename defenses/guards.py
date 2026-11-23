"""Mitigazioni di riferimento, indipendenti dal modello.

Sono esempi da portare nel servizio reale: la logica di policy vive FUORI
dall'LLM e si applica a qualunque output il modello produca.
"""
from __future__ import annotations

import re
import secrets
import unicodedata

from harness.adapters import SYSTEM_CANARY
from harness.checks import ALLOWED_VERDICTS, SEVERITY

ZERO_WIDTH = re.compile(r"[​-‏⁠-⁤﻿]")
HOMOGLYPHS = str.maketrans({"а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "і": "i"})
ID_FIELD = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
MAX_FIELD_LEN = 2000
READ_ONLY_TOOLS = {"get_match_history", "get_linked_accounts"}
MAX_TOOL_CALLS = 5
PLAYER_TEMPLATES = {
    "clean": "La segnalazione è stata esaminata. Nessuna azione.",
    "suspicious": "La segnalazione è in revisione.",
    "needs_human_review": "La segnalazione è in revisione.",
    "likely_cheating": "La segnalazione è in revisione.",
}


def normalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = ZERO_WIDTH.sub("", text)
    return text.translate(HOMOGLYPHS)


def wrap_untrusted(text: str) -> tuple[str, str]:
    """Racchiude il testo non fidato in delimitatori con nonce per richiesta."""
    nonce = secrets.token_hex(8)
    return f"<untrusted-{nonce}>\n{text}\n</untrusted-{nonce}>", nonce


def sanitize_untrusted(inp: dict) -> dict:
    """Normalizza, tronca, e sostituisce identificativi non conformi con ID opachi."""
    out = {}
    for k, v in inp.items():
        if isinstance(v, str):
            v = normalize(v)[:MAX_FIELD_LEN]
            if k.endswith("_name") and not ID_FIELD.match(v):
                v = f"opaque-{abs(hash(v)) % 10**8}"
        elif isinstance(v, list):
            v = [normalize(x)[:MAX_FIELD_LEN] if isinstance(x, str) else x for x in v]
        out[k] = v
    return out


def enforce_policy(resp: dict, case: dict) -> dict:
    """Applica i principi del threat model a qualunque output del modello."""
    r = dict(resp)
    subject = case["input"]["subject_id"]

    # Schema: verdetti fuori enum -> revisione umana.
    if r.get("verdict") not in ALLOWED_VERDICTS:
        r["verdict"] = "needs_human_review"

    # Monotonia: il modello non può abbassare il segnale dei detector deterministici.
    floor = case["input"].get("detector_floor")
    if floor and SEVERITY[r["verdict"]] < SEVERITY[floor]:
        r["verdict"] = floor

    # Nessuna condanna sul solo testo: likely_cheating richiede evidenza dei detector.
    if r["verdict"] == "likely_cheating" and not floor:
        r["verdict"] = "needs_human_review"

    # Soggetto fisso: il modello non può spostare il caso su un altro account.
    if r.get("subject_id") != subject:
        r["subject_id"] = subject
        r["verdict"] = "needs_human_review"

    # Tool: solo lettura, numero limitato.
    r["tool_calls"] = [t for t in r.get("tool_calls", []) if t["name"] in READ_ONLY_TOOLS][:MAX_TOOL_CALLS]

    # Output al giocatore solo da template; note interne filtrate dai canary.
    r["player_facing_text"] = PLAYER_TEMPLATES[r["verdict"]] if r.get("player_facing_text") else None
    if r.get("analyst_notes") and SYSTEM_CANARY in r["analyst_notes"]:
        r["analyst_notes"] = "[redatto: canary rilevato]"
    return r
