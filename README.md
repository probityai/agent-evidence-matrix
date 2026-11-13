# Agent evidence conformance matrix

One table of which agent-evidence projects can be read by shared open verifiers and conformance corpora, with a verdict and a replay command for every cell.

For people who maintain a project that records what an AI agent did and want to see how its records and canonicalization compare with the others.

Install the reader as a pinned dependency:

```
pip install agent-evidence-vectors==0.36.3 agent-evidence-verify==0.5.0
```

Rebuild the table and its coverage count:

```
python build_matrix.py
```

It prints `N of 13: 4` today and rewrites `MATRIX.md`. Each cell is marked "their records" (the project's own record bytes were read) or "our adapter" (code in `adapters/` carried their record to our reader, or their code to our corpus), and carries one of five verdicts: agrees, contradicted, cannot-tell, unsupported, not run.

Status: first run from the IETF 127 Hackathon, 10 November 2026. Add a project by opening a pull request with a `matrix.json` entry, the adapter and its run output. CI rebuilds the table daily and replays the RFC 8785 corpus through `adapters/rfc8785_cli.py`.

| Page | What it holds |
|---|---|
| [MATRIX.md](MATRIX.md) | the table |
| [matrix.json](matrix.json) | the cells, source of the table |
| [adapters/](adapters) | the adapters and their recorded runs |
| [libraries/RESULTS.md](libraries/RESULTS.md) | RFC 8785 and DSSE cross-library run at current releases: 20,121 of 20,140 JCS cases agree byte for byte, DSSE PAE agrees 400 of 400 |
