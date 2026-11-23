# Come aggiungere una scoperta

Ogni nuova debolezza dello strato LLM entra come **caso sintetico + correzione**, mai come exploit riutilizzabile.

1. **Caso** in `cases/<tema>.jsonl`, una riga JSON:
   - `id`, `threat` (es. `T18`), `input` con i campi non fidati.
   - usa il marcatore sintetico `[[TEST-DIRECTIVE: chiave=valore]]` al posto di un payload reale (`verdict`, `subject`, `tool`, `leak`).
   - `expect.checks`: i controlli da `harness/checks.py` che devono reggere, più i relativi parametri (`min_severity`, `allowed_tools`, ...).
2. **Verifica** che il mock vulnerabile fallisca il caso e quello protetto lo passi:
   ```bash
   python3 -m harness.runner --adapter mock-naive     # deve mostrare il FAIL
   python3 -m harness.runner --adapter mock-hardened  # deve passare
   ```
3. **Correzione** in `defenses/guards.py` (logica fuori dal modello) o, se è un controllo nuovo, in `harness/checks.py`.
4. **Autotest**: aggiungi l'id del caso agli elenchi in `tests/test_harness.py` e lancia `python3 -m unittest discover -s tests -t .`.

Regola di scopo: niente cheat funzionante, nessuna manipolazione di client o memoria di gioco, nessuno strumento usabile contro un gioco di produzione. Il red team qui misura la robustezza del **servizio** che prende le decisioni, non del client del giocatore.
