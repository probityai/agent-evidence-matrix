"""Render matrix.json to MATRIX.md and print N of 12 coverage. Fails when a verdict is not a listed code."""
import json
import pathlib
import sys

root = pathlib.Path(__file__).parent
data = json.loads((root / "matrix.json").read_text())
codes = set(data["verdicts"])
rows, run = [], set()
for p in data["projects"]:
    for c in p["cells"]:
        if c["verdict"] not in codes:
            sys.exit(f"unknown verdict {c['verdict']!r} in project {p['id']}")
        if c["verdict"] in ("agrees", "contradicted", "cannot-tell"):
            run.add(p["id"])
        rows.append(f"| {p['id']} | {p['name']} | {c['cell']} | {c['source']} | {c['verdict']}"
                    f"{' (' + c['detail'] + ')' if c.get('detail') else ''} | {c['evidence']} |")
head = (f"# Conformance matrix\n\nReader: agent-evidence-vectors {data['reader']['agent-evidence-vectors']}, "
        f"agent-evidence-verify {data['reader']['agent-evidence-verify']}.\n\n"
        f"Coverage: {len(run)} of {data['total_projects']} projects have at least one cell with a result "
        f"(agrees, contradicted or cannot-tell).\n\n"
        "Source: \"their records\" = the project's own record bytes were read; \"our adapter\" = code in adapters/ carried "
        "their record to our reader or their code to our corpus.\n\n"
        "| # | Project | Cell | Source | Verdict | Evidence |\n|---|---|---|---|---|---|\n")
(root / "MATRIX.md").write_text(head + "\n".join(rows) + "\n")
print(f"N of {data['total_projects']}: {len(run)}")
