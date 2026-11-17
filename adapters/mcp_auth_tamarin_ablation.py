"""Adapter: the ablation lattice of the formal model of MCP authorization, recomputed and read against its table.

usage: mcp_auth_tamarin_ablation.py <published docs/ablation.md> <fresh results/ablation.json>

The fresh JSON is what the project's own scripts/ablate.py writes when it is run inside the project's Dockerfile
image at the pinned commit (the ablation-tamarin workflow does that, one model per job, and merges the lists). This
adapter does not use the project's report script. From the fresh runs it derives, with its own code:

  cell symbols   per (model, context, removed checks) and property: proved, attack (F), attack through an
                 exists-trace lemma (A), no attack in the reduced model (N), timeout (T), missing (?); an
                 all-traces proof in a run that used the reduced model (any A or N in it) counts as proved only in
                 the reduced model (R), except P2 of a run re-proved on the full model; a run whose `executable`
                 lemma fails is vacuous, and one whose `executable` lemma timed out or is missing has unknown
                 vacuity (its row is reported as a difference: nothing says the honest run is possible)
  table          every row of the published tables (model, context and removed checks read from the abbreviation
                 list above each table) compared cell by cell with the fresh symbols and the vacuous mark; the
                 seconds column is a timing and is not compared. A row must carry exactly one cell per property
                 column plus the seconds column, and a fresh run must carry exactly the row's properties; a
                 heading the reader does not know ends the table it was reading, and a "## Problems" section in
                 the published document is reported and fails the reading
  monotonicity   for every pair of runs of one model and context where the removed set S is a proper subset of T and
                 T is known not vacuous: a property that fails (F or A) with S removed must not be proved with T
                 removed; a pair whose T cell is undecided (T, ?, N, R) is counted apart, not as checked
  coverage       property cells with a decided result over all property cells, in the published legend's terms: V,
                 F and A are decided, N and R are not (neither is a proof for the full model), and a V in a vacuous
                 run or one of unknown vacuity is not

Prints one line per finding and a SUMMARY line. Exit 0 when every published cell equals the fresh one and no
monotonicity pair is violated, 1 otherwise, 2 on a crash or unreadable input.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

SYMBOL = {"✅": "V", "❌": "F", "❌ᵃ": "A", "∅": "N", "✅ʳ": "R", "⏱": "T", "?": "?"}
FAILS = {"F", "A"}
SECTION = re.compile(r"^## Model (\d\d)(?: \(([A-Z_]+(?:(?:, |\+)[A-Z_]+)*)\))?\s*$")
CHECK = re.compile(r"([A-Z][A-Z0-9']*) = .*?\(`([A-Z_]+)` removes it\)")
PROP = re.compile(r"`([a-z_]+)`")


def parse_table(text):
    """{(model, context tuple, frozenset of removed flags): {"vacuous": bool, prop: symbol code}} from the md."""
    rows, model, ctx, abbr, props, problems, in_problems = {}, None, (), {}, [], [], False
    for line in text.splitlines():
        m = SECTION.match(line)
        if m:
            model, ctx = m.group(1), tuple(re.split(r", |\+", m.group(2))) if m.group(2) else ()
            abbr, props, in_problems = {}, [], False
            continue
        if line.startswith("## "):
            if line.startswith("## Model"):
                raise ValueError(f"heading {line!r} is not a model heading this reader can read")
            model, in_problems = None, line.strip() == "## Problems"
            continue
        if in_problems and line.startswith("- "):
            problems.append(line[2:].strip())
            continue
        if model is None:
            continue
        if line.startswith("Checks:"):
            abbr = {a: flag for a, flag in CHECK.findall(line)}
            continue
        if line.startswith("| Removed checks"):
            props = PROP.findall(line)
            head = [c.strip() for c in line.strip().strip("|").split("|")]
            if len(head) != len(props) + 2 or head[-1] != "s":
                raise ValueError(f"model {model}: header {line!r} is not removed checks, one column per property, s")
            continue
        if not line.startswith("| ") or line.startswith("|---") or not props:
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) != len(props) + 2:
            raise ValueError(f"model {model}: row {line!r} has {len(cells)} cells, the header {len(props) + 2}")
        first, syms = cells[0], cells[1:1 + len(props)]
        vacuous = "**vacuous**" in first
        first = first.replace("**vacuous**", "").strip()
        names = [] if first.startswith("none") else [x.strip() for x in first.split(",")]
        unknown = [n for n in names if n not in abbr]
        if unknown:
            raise ValueError(f"model {model}: abbreviation {unknown[0]} is not in its Checks line")
        codes = {}
        for p, s in zip(props, syms):
            if s not in SYMBOL:
                raise ValueError(f"model {model}: symbol {s!r} is not in the legend")
            codes[p] = SYMBOL[s]
        key = (model, ctx, frozenset(abbr[n] for n in names))
        if key in rows:
            raise ValueError(f"model {model}: row {first!r} appears twice")
        rows[key] = {"vacuous": vacuous, **codes}
    return rows, problems


def derive(runs):
    """{(model, context, removed): {"vacuous": bool, prop: code}} from the fresh JSON, with the reduced-model rule."""
    out = {}
    for r in runs:
        st = dict(r["status"])
        reduced = any(v in ("A", "N") for k, v in st.items() if k != "executable")
        full_p2 = bool(r.get("full_model_p2"))
        for k, v in list(st.items()):
            if reduced and k != "executable" and v == "V" and not (k == "rs_accepts_only_consented" and full_p2):
                st[k] = "R"
        executable = st.pop("executable", None)
        vacuous = True if executable == "F" else False if executable == "V" else None  # None: not known
        key = (r["model"], tuple(r["context"]), frozenset(r["removed"]))
        if key in out:
            raise ValueError(f"run {r.get('name')} appears twice")
        out[key] = {"vacuous": vacuous, **st}
    return out


def monotonicity(fresh):
    checked, undecided, broken = 0, 0, []
    for (m, c, s), a in fresh.items():
        for (m2, c2, t), b in fresh.items():
            if (m, c) != (m2, c2) or not s < t or b["vacuous"] is not False:
                continue
            for p, v in a.items():
                if p == "vacuous" or v not in FAILS:
                    continue
                if b.get(p) not in FAILS | {"V"}:
                    undecided += 1
                    continue
                checked += 1
                if b.get(p) == "V":
                    broken.append(f"model {m} {p}: fails with {sorted(s)} removed, proved with {sorted(t)} removed")
    return checked, undecided, broken


def name(key):
    m, c, r = key
    return f"{m}{'(' + '+'.join(c) + ')' if c else ''}[{','.join(sorted(r)) or 'none'}]"


def main(argv):
    if len(argv) != 2:
        sys.exit(__doc__)
    table, published_problems = parse_table(Path(argv[0]).read_text(encoding="utf-8"))
    fresh = derive(json.loads(Path(argv[1]).read_text(encoding="utf-8")))
    same = differ = rows_differ = 0
    for key, row in sorted(table.items(), key=lambda kv: name(kv[0])):
        got = fresh.get(key)
        if got is None:
            differ += len(row) - 1
            rows_differ += 1
            print(f"MISSING  {name(key)}: no fresh run")
            continue
        if got["vacuous"] != row["vacuous"]:
            rows_differ += 1
            fresh_v = "unknown (executable timed out or missing)" if got["vacuous"] is None else got["vacuous"]
            print(f"DIFF     {name(key)} vacuous: table {row['vacuous']}, fresh {fresh_v}")
        unlisted = sorted(set(got) - set(row))
        if unlisted:
            rows_differ += 1
            print(f"DIFF     {name(key)}: fresh properties with no table column: {unlisted}")
        for p, code in row.items():
            if p == "vacuous":
                continue
            if got.get(p) == code and got["vacuous"] == row["vacuous"]:
                same += 1
            else:
                differ += 1
                if got.get(p) != code:  # an equal symbol under a vacuity mismatch is named by the vacuous line
                    print(f"DIFF     {name(key)} {p}: table {code}, fresh {got.get(p)}")
    extra = sorted(name(k) for k in set(fresh) - set(table))
    for e in extra:
        print(f"EXTRA    {e}: fresh run with no table row")
    checked, undecided, broken = monotonicity(fresh)
    for b in broken:
        print(f"MONOTONE {b}")
    for pp in published_problems:
        print(f"PUBLISHED-PROBLEM {pp}")
    cells = [(v, row["vacuous"]) for row in fresh.values() for p, v in row.items() if p != "vacuous"]
    decided = sum(v in FAILS or (v == "V" and vac is False) for v, vac in cells)
    print(f"INFO     coverage: {decided} of {len(cells)} property cells decided in the fresh runs (V, F, A; a V only "
          "in a run known not vacuous)")
    print(f"INFO     monotonicity: {checked} failing cells checked against every non-vacuous superset run; "
          f"{len(broken)} violated; {undecided} pairs not checked (superset cell undecided)")
    ok = differ == 0 and rows_differ == 0 and not broken and not extra and not published_problems
    print(f"SUMMARY  table cells equal: {same} of {same + differ}; rows {len(table)} ({rows_differ} differ), "
          f"fresh runs {len(fresh)}; monotonicity violations {len(broken)}")
    return 0 if ok else 1


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 -- any crash exits 2, never a comparison result
        print(f"setup: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(2)
