"""The ablation reader compares every published cell with the fresh runs and finds monotonicity breaks itself.

A small table in the published format (abbreviations above the table, a seconds column that is a timing) and fresh
runs in ablate.py's JSON form. The cases: an equal lattice passes; a changed cell, a run with no table row and a
fresh proof that reappears after more checks are removed each fail; the reduced-model rule turns a proof in a run
that used an exists-trace lemma into R; and a vacuous run is left out of monotonicity.
"""
import copy
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
ADAPTER = ROOT / "adapters" / "mcp_auth_tamarin_ablation.py"

TABLE = """# Ablation

## Model 01

Checks: BIND = issuer binding (`NO_BINDING` removes it), META = metadata issuer check (`UNVALIDATED_ISSUER` removes it)

| Removed checks | P1 `client_credential_secrecy` | P3 `token_secrecy` | s |
|---|---|---|---|
| none (all checks on) | ✅ | ✅ | 0 |
| BIND | ❌ | ❌ᵃ | 1 |
| META | ✅ʳ | ∅ | 1 |
| BIND, META **vacuous** | ✅ | ✅ | 1 |
"""


def run_rec(removed, p1, p3, executable="V"):
    return {"model": "01", "context": [], "removed": removed, "name": "x" + "+".join(removed),
            "status": {"client_credential_secrecy": p1, "token_secrecy": p3, "executable": executable}}


RUNS = [run_rec([], "V", "V"), run_rec(["NO_BINDING"], "F", "A"), run_rec(["UNVALIDATED_ISSUER"], "V", "N"),
        run_rec(["NO_BINDING", "UNVALIDATED_ISSUER"], "V", "V", executable="F")]


def run(tmp_path, runs, table=TABLE):
    (tmp_path / "ablation.md").write_text(table, encoding="utf-8")
    (tmp_path / "ablation.json").write_text(json.dumps(runs))
    out = subprocess.run([sys.executable, "-I", str(ADAPTER), str(tmp_path / "ablation.md"),
                          str(tmp_path / "ablation.json")], capture_output=True, text=True, check=False)
    return out.returncode, out.stdout + out.stderr


def test_an_equal_lattice_passes_and_the_vacuous_run_is_not_a_monotonicity_break(tmp_path):
    """META's proof of P1 sits in a run with no attack in the reduced model, so it reads as R, as published."""
    rc, out = run(tmp_path, RUNS)
    assert rc == 0, out
    assert "table cells equal: 8 of 8" in out and "monotonicity violations 0" in out


def test_a_changed_cell_differs(tmp_path):
    runs = copy.deepcopy(RUNS)
    runs[0]["status"]["client_credential_secrecy"] = "F"
    rc, out = run(tmp_path, runs)
    assert rc == 1 and "DIFF     01[none] client_credential_secrecy: table V, fresh F" in out


def test_a_proof_that_reappears_after_more_checks_are_removed_breaks_monotonicity(tmp_path):
    table = TABLE.replace("| BIND, META **vacuous** | ✅ | ✅ | 1 |", "| BIND, META | ✅ | ✅ | 1 |")
    runs = copy.deepcopy(RUNS)
    runs[3]["status"]["executable"] = "V"
    rc, out = run(tmp_path, runs, table)
    assert rc == 1
    assert "MONOTONE model 01 client_credential_secrecy: fails with ['NO_BINDING'] removed" in out


def test_a_run_with_no_table_row_fails(tmp_path):
    runs = copy.deepcopy(RUNS) + [{**run_rec(["NO_BINDING"], "F", "F"), "context": ["PUBLIC"]}]
    rc, out = run(tmp_path, runs)
    assert rc == 1 and "EXTRA    01(PUBLIC)[NO_BINDING]" in out


def test_an_unknown_abbreviation_is_a_crash_not_a_result(tmp_path):
    rc, out = run(tmp_path, RUNS, TABLE.replace("| META | ✅ʳ | ∅ | 1 |", "| METAX | ✅ʳ | ∅ | 1 |"))
    assert rc == 2 and "abbreviation METAX" in out


# Second break pass: each of these exited 0 (or counted wrongly) before the fix.

def test_a_row_short_of_the_header_is_unreadable_not_partly_compared(tmp_path):
    """A row with one symbol cell and no seconds column compared one of two cells and passed."""
    short = TABLE.replace("| none (all checks on) | ✅ | ✅ | 0 |", "| none (all checks on) | ✅ |")
    rc, out = run(tmp_path, RUNS, short)
    assert rc == 2 and "has 2 cells, the header 4" in out


def test_a_vacuity_mismatch_fails_the_reading(tmp_path):
    runs = copy.deepcopy(RUNS)
    runs[3]["status"]["executable"] = "V"
    rc, out = run(tmp_path, runs)
    assert rc == 1 and "DIFF     01[NO_BINDING,UNVALIDATED_ISSUER] vacuous: table True, fresh False" in out
    assert "(1 differ)" in out


def test_an_executable_lemma_that_timed_out_leaves_vacuity_unknown(tmp_path):
    runs = copy.deepcopy(RUNS)
    runs[0]["status"]["executable"] = "T"
    rc, out = run(tmp_path, runs)
    assert rc == 1 and "fresh unknown (executable timed out or missing)" in out


def test_a_fresh_property_with_no_table_column_differs(tmp_path):
    runs = copy.deepcopy(RUNS)
    runs[0]["status"]["session_integrity"] = "F"
    rc, out = run(tmp_path, runs)
    assert rc == 1 and "fresh properties with no table column: ['session_integrity']" in out


def test_coverage_counts_reduced_model_results_and_vacuous_proofs_as_undecided(tmp_path):
    """The published legend: R and N are not proofs for the full model; a V in a vacuous row means nothing."""
    rc, out = run(tmp_path, RUNS)
    assert rc == 0, out
    assert "coverage: 4 of 8 property cells decided" in out


def test_an_undecided_superset_cell_is_not_counted_as_checked(tmp_path):
    """BIND fails P1; the superset BIND, META is vacuous, so no pair is checked; META's R is not a superset."""
    table = TABLE.replace("| BIND, META **vacuous** | ✅ | ✅ | 1 |", "| BIND, META | ⏱ | ❌ | 1 |")
    runs = copy.deepcopy(RUNS)
    runs[3]["status"] = {"client_credential_secrecy": "T", "token_secrecy": "F", "executable": "V"}
    rc, out = run(tmp_path, runs, table)
    assert rc == 0, out
    assert "monotonicity: 1 failing cells checked" in out and "1 pairs not checked" in out


def test_a_problems_section_in_the_published_document_fails_the_reading(tmp_path):
    rc, out = run(tmp_path, RUNS, TABLE + "\n## Problems\n\n- MONOTONICITY 01 x: fails with [] removed\n")
    assert rc == 1 and "PUBLISHED-PROBLEM MONOTONICITY 01 x" in out


def test_a_context_heading_in_the_report_spelling_is_read(tmp_path):
    """ablation_report.py joins a context of several flags with ', '; the reader read only '+'."""
    table = TABLE.replace("## Model 01", "## Model 01 (PUBLIC, OTHER)")
    runs = [{**r, "context": ["PUBLIC", "OTHER"]} for r in copy.deepcopy(RUNS)]
    rc, out = run(tmp_path, runs, table)
    assert rc == 0 and "table cells equal: 8 of 8" in out, out
