# Agent evidence conformance matrix

One table of which agent-evidence projects can be read by shared open verifiers and conformance corpora, with a verdict and a replay command for every cell.

For people who maintain a project that records what an AI agent did and want to see how its records and canonicalization compare with the others.

Install the reader as a pinned dependency:

```
pip install agent-evidence-vectors==0.36.3 agent-evidence-verify==0.5.1
```

or the whole hash-locked environment the CI uses: `pip install --require-hashes -r requirements.txt`.

Rebuild the table and its coverage counts:

```
python build_matrix.py
```

It prints `N of 25: 24; no record read yet: 1 of 25` today and rewrites `MATRIX.md` and `badges/`; `python build_matrix.py --check` refuses a stale table. Each cell is marked "their records" (the project's own record bytes were read) or "our adapter" (code in `adapters/` carried their record to our reader, or their code to our corpus), and carries one of five verdicts: agrees, contradicted, cannot-tell, unsupported, not run. A contradicted cell names its basis, where the divergence sits and the revision it was judged against; a refusal inside a profile the project declares is unsupported, with the profile named. The builder refuses a cell that breaks these rules and any evidence path that does not resolve in this repository. A properties table beside the cells records independence, edit detection, declared digest inputs and the other cross-project checks.

Reproduce one row: take the project's block under "Replay" in `MATRIX.md`, run it from the repository root, and compare the output with the run file its cells cite. CI replays the recorded runs of five projects on every pull request, and its mutation steps change one record and require the verdict to change, so a comparison that cannot fail is caught.

Link a project's own row from its README with a badge (shields endpoint, one file per project in `badges/`):

```
[![evidence matrix](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/probityai/agent-evidence-matrix/main/badges/<id>.json)](https://github.com/probityai/agent-evidence-matrix/blob/main/MATRIX.md#project-<id>)
```

Status: first run from the IETF 127 Hackathon, 10 November 2026. Propose a project by opening an issue or a pull request with a `matrix.json` entry, the adapter and its run output; its row lands after a maintainer records the review in `reviews.json`. CI rebuilds the table daily, warns when a pinned upstream moved, and replays the RFC 8785 corpus through `adapters/rfc8785_cli.py`. Answer sets are sealed before they are published with `tools/seal.py` (SEAL.sha256 and two RFC 3161 tokens).

| Page | What it holds |
|---|---|
| [MATRIX.md](MATRIX.md) | the table, the properties and the replay commands |
| [matrix.json](matrix.json) | the cells, source of the table |
| [reviews.json](reviews.json) | one review entry per project |
| [adapters/](adapters) | the adapters and their recorded runs |
| [records/](records) | project records kept here because their source expires |
| [libraries/RESULTS.md](libraries/RESULTS.md) | RFC 8785 and DSSE cross-library run at current releases: 20,121 of 20,140 JCS cases agree byte for byte, DSSE PAE agrees 400 of 400 |
