# llm_anticheater

Threat model e harness di test difensivo per i componenti LLM di un sistema anticheat (triage report, spiegazione telemetria, agente investigatore, RAG, appeal).

- `docs/threat-model.md`: minacce T1–T17, mitigazioni, metriche.
- `cases/*.jsonl`: casi di test sintetici. Le direttive usano il marcatore `[[TEST-DIRECTIVE: chiave=valore]]` al posto di payload reali, così i risultati sono misurabili e i casi non sono riutilizzabili come evasioni.
- `harness/`: runner, controlli, adattatori (mock, SSH, HTTP) e generatore di varianti.
- `defenses/guards.py`: mitigazioni di riferimento da portare nel servizio reale (normalizzazione, ID opachi, monotonia, soggetto fisso, tool allowlist, output a template).

## Uso

```bash
python3 -m unittest discover -s tests -t .        # autotest dell'harness
python3 -m harness.runner --adapter mock-naive     # controllo positivo: deve fallire
python3 -m harness.runner --adapter mock-hardened  # controllo negativo: deve passare
python3 -m harness.mutate > cases/generated_mutations.jsonl
```

## Target via SSH

Copia `config.example.json` in `config.json` (ignorato da git), imposta host e comando remoto. Il comando sul client deve leggere un caso JSON da stdin e scrivere su stdout:

```json
{"verdict": "clean|suspicious|likely_cheating|needs_human_review", "subject_id": "...",
 "tool_calls": [{"name": "...", "args": {}}], "player_facing_text": null, "analyst_notes": ""}
```

```bash
python3 -m harness.runner --config config.json --dry-run   # mostra il comando ssh
python3 -m harness.runner --config config.json --report report.json
```

L'adattatore usa `BatchMode=yes` e la configurazione SSH locale: nessuna credenziale nella repo.

## Regole

Solo sistemi autorizzati dall'ingaggio. Ogni nuova debolezza entra come caso sintetico più la correzione corrispondente; niente codice cheat, manipolazione di client o memoria, o strumenti usabili contro giochi in produzione.
