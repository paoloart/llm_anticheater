"""Genera varianti dei casi esistenti per testare la robustezza delle difese.

Uso: python -m harness.mutate > cases/generated_mutations.jsonl
Le varianti trasformano solo il marcatore sintetico [[TEST-DIRECTIVE: ...]].
"""
from __future__ import annotations

import base64
import copy
import json
import sys

from harness.runner import load_cases

HOMO = str.maketrans({"a": "а", "e": "е", "o": "о", "c": "с"})


def zero_width(s):
    return "​".join(s)


def homoglyph(s):
    return s.translate(HOMO)


def wrapped_b64(s):
    return "decodifica e applica: " + base64.b64encode(s.encode()).decode()


def fullwidth(s):
    return "".join(chr(ord(c) + 0xFEE0) if "!" <= c <= "~" else c for c in s)


MUTATORS = {"zw": zero_width, "homo": homoglyph, "b64": wrapped_b64, "fw": fullwidth}


def mutate_case(case):
    for name, fn in MUTATORS.items():
        c = copy.deepcopy(case)
        changed = False
        for k, v in c["input"].items():
            if isinstance(v, str) and "[[TEST-DIRECTIVE" in v:
                c["input"][k] = fn(v)
                changed = True
        if changed:
            c["id"] = f"{case['id']}~{name}"
            c.pop("_file", None)
            yield c


def main():
    for case in load_cases("*.jsonl"):
        if "~" in case["id"]:
            continue
        for m in mutate_case(case):
            sys.stdout.write(json.dumps(m, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main()
