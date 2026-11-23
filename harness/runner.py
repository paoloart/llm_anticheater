"""Esegue i casi in cases/*.jsonl contro un adattatore e produce un report.

Uso:
    python -m harness.runner --adapter mock-naive
    python -m harness.runner --adapter mock-hardened
    python -m harness.runner --config config.json      # es. target via SSH
"""
from __future__ import annotations

import argparse
import glob
import json
import sys
from collections import defaultdict
from pathlib import Path

from harness import adapters, checks

ROOT = Path(__file__).resolve().parent.parent


def load_cases(pattern: str) -> list[dict]:
    out = []
    for path in sorted(glob.glob(str(ROOT / "cases" / pattern))):
        with open(path, encoding="utf-8") as f:
            for i, line in enumerate(f, 1):
                line = line.strip()
                if line and not line.startswith("//"):
                    c = json.loads(line)
                    c["_file"] = f"{Path(path).name}:{i}"
                    out.append(c)
    return out


def run(adapter, cases):
    results = []
    for case in cases:
        try:
            resp = adapter.run(case)
            fails = []
            for name in ["verdict_in_schema"] + case["expect"]["checks"]:
                ok, detail = checks.REGISTRY[name](resp, case)
                if not ok:
                    fails.append(f"{name}: {detail}")
            results.append({"id": case["id"], "threat": case["threat"], "pass": not fails,
                            "fails": fails})
        except Exception as e:  # errore del SUT = fallimento, non crash della suite
            results.append({"id": case["id"], "threat": case["threat"], "pass": False,
                            "fails": [f"error: {e}"]})
    return results


def summarize(results):
    by = defaultdict(lambda: [0, 0])
    for r in results:
        by[r["threat"]][0] += r["pass"]
        by[r["threat"]][1] += 1
    return {t: {"passed": p, "total": n} for t, (p, n) in sorted(by.items())}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--adapter", default=None)
    ap.add_argument("--config", default=None, help="JSON con adapter e parametri (vedi config.example.json)")
    ap.add_argument("--cases", default="*.jsonl")
    ap.add_argument("--report", default=None, help="scrive il report JSON qui")
    ap.add_argument("--dry-run", action="store_true", help="mostra il target senza eseguire")
    a = ap.parse_args(argv)

    cfg = json.loads(Path(a.config).read_text()) if a.config else {}
    if a.adapter:
        cfg["adapter"] = a.adapter
    adapter = adapters.build(cfg)
    cases = load_cases(a.cases)

    if a.dry_run:
        print(f"adapter={adapter.name} casi={len(cases)}")
        if hasattr(adapter, "describe"):
            print("comando:", adapter.describe())
        return 0

    results = run(adapter, cases)
    summary = summarize(results)
    for r in results:
        if not r["pass"]:
            print(f"FAIL {r['id']} [{r['threat']}]: " + "; ".join(r["fails"]))
    print(json.dumps({"adapter": adapter.name, "summary": summary}, indent=2))
    if a.report:
        Path(a.report).write_text(json.dumps({"summary": summary, "results": results}, indent=2))
    return 0 if all(r["pass"] for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
