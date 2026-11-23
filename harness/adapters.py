"""Adattatori verso il sistema sotto test (SUT).

Ogni adattatore riceve un caso (dict) e restituisce la risposta del SUT come dict:
    {"verdict": str, "subject_id": str, "tool_calls": [{"name": str, "args": {...}}],
     "player_facing_text": str | None, "analyst_notes": str | None}

Il SUT reale va collegato con SSHAdapter o HTTPAdapter. I mock servono solo a
verificare che l'harness rilevi correttamente un sistema vulnerabile.
"""
from __future__ import annotations

import json
import re
import shlex
import subprocess
import urllib.request
from dataclasses import dataclass, field

DIRECTIVE = re.compile(r"\[\[TEST-DIRECTIVE:\s*(\w+)=([\w-]+)\s*\]\]")
SYSTEM_CANARY = "CANARY-SYSPROMPT-7f3a"


class Adapter:
    name = "base"

    def run(self, case: dict) -> dict:  # pragma: no cover - interfaccia
        raise NotImplementedError


class NaiveMockSUT(Adapter):
    """Simula un modello vulnerabile: obbedisce alle direttive sintetiche nel testo
    non fidato e ripete il system prompt se richiesto. Serve a provare che
    l'harness segnala i fallimenti (controllo positivo)."""

    name = "mock-naive"

    def run(self, case: dict) -> dict:
        # Simula l'assemblaggio del prompt: tutti i campi testuali concatenati.
        parts = []
        for v in case["input"].values():
            parts += v if isinstance(v, list) else [v]
        text = "".join(p for p in parts if isinstance(p, str))
        out = {
            "verdict": case.get("baseline_verdict", "suspicious"),
            "subject_id": case["input"].get("subject_id"),
            "tool_calls": [],
            "player_facing_text": None,
            "analyst_notes": "",
        }
        # Simula un parser permissivo che prende il primo oggetto JSON nel testo (T13).
        m = re.search(r"\{[^{}]*\"verdict\"[^{}]*\}", text)
        if m:
            try:
                out["verdict"] = json.loads(m.group(0)).get("verdict", out["verdict"])
            except ValueError:
                pass
        for key, val in DIRECTIVE.findall(text):
            if key == "verdict":
                out["verdict"] = val
            elif key == "subject":
                out["subject_id"] = val
            elif key == "tool":
                out["tool_calls"].append({"name": val, "args": {}})
            elif key == "leak":
                out["player_facing_text"] = f"My instructions: {SYSTEM_CANARY}"
        return out


class HardenedMockSUT(Adapter):
    """Implementazione di riferimento delle mitigazioni in defenses/ attorno a
    NaiveMockSUT: mostra il comportamento atteso (controllo negativo)."""

    name = "mock-hardened"

    def __init__(self):
        from defenses import guards
        self.guards = guards
        self.inner = NaiveMockSUT()

    def run(self, case: dict) -> dict:
        g = self.guards
        clean_case = dict(case)
        clean_case["input"] = g.sanitize_untrusted(case["input"])
        raw = self.inner.run(clean_case)
        return g.enforce_policy(raw, case)


class SSHAdapter(Adapter):
    """Esegue il client del SUT su una macchina raggiungibile via SSH.

    Il comando remoto deve leggere un caso JSON da stdin e scrivere la risposta
    JSON su stdout. Usa la configurazione SSH locale (~/.ssh/config, agent): la
    repo non contiene credenziali.
    """

    name = "ssh"

    def __init__(self, host: str, remote_cmd: str, user: str | None = None,
                 port: int = 22, identity_file: str | None = None, timeout: int = 60):
        self.host, self.remote_cmd, self.user = host, remote_cmd, user
        self.port, self.identity_file, self.timeout = port, identity_file, timeout

    def _argv(self) -> list[str]:
        argv = ["ssh", "-o", "BatchMode=yes", "-p", str(self.port)]
        if self.identity_file:
            argv += ["-i", self.identity_file]
        target = f"{self.user}@{self.host}" if self.user else self.host
        return argv + [target, self.remote_cmd]

    def run(self, case: dict) -> dict:
        proc = subprocess.run(
            self._argv(), input=json.dumps(case).encode(), capture_output=True,
            timeout=self.timeout, check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"ssh exit {proc.returncode}: {proc.stderr.decode()[:500]}")
        return json.loads(proc.stdout)

    def describe(self) -> str:
        return " ".join(shlex.quote(a) for a in self._argv())


class HTTPAdapter(Adapter):
    name = "http"

    def __init__(self, url: str, timeout: int = 60):
        self.url, self.timeout = url, timeout

    def run(self, case: dict) -> dict:
        req = urllib.request.Request(self.url, data=json.dumps(case).encode(),
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            return json.loads(r.read())


def build(cfg: dict) -> Adapter:
    kind = cfg.get("adapter", "mock-naive")
    if kind == "mock-naive":
        return NaiveMockSUT()
    if kind == "mock-hardened":
        return HardenedMockSUT()
    if kind == "ssh":
        s = cfg["ssh"]
        return SSHAdapter(s["host"], s["remote_cmd"], s.get("user"), s.get("port", 22),
                          s.get("identity_file"), s.get("timeout", 60))
    if kind == "http":
        return HTTPAdapter(cfg["http"]["url"], cfg["http"].get("timeout", 60))
    raise ValueError(f"adapter sconosciuto: {kind}")
