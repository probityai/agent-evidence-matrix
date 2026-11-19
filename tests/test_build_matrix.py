"""The matrix builder refuses mislabelled cells, unreviewed projects and paths a reader cannot open.

Each fixture is one mislabel class that a published matrix carried before the schema existed: a
refusal inside a declared profile shown as a contradiction, an expected rejection counted as a
contradiction, a contradiction with no stated basis, and evidence that pointed at one laptop.
"""
import copy
import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import build_matrix as bm  # noqa: E402


def cell(**kw):
    base = {"cell": "c", "source": "their records", "verdict": "agrees", "evidence": "adapters/rfc8785_cli.py"}
    base.update(kw)
    return base


def project(pid=1, cells=None, **kw):
    p = {"id": pid, "name": f"p{pid}", "cells": cells or [cell()],
         "upstream": {"url": f"https://github.com/example/p{pid}", "sha": "a" * 40}, "replay": "true"}
    p.update(kw)
    return p


def matrix(*projects):
    return {"reader": {"agent-evidence-vectors": "0", "agent-evidence-verify": "0"},
            "verdicts": ["agrees", "contradicted", "cannot-tell", "unsupported", "not run"],
            "total_projects": len(projects), "projects": list(projects)}


def reviews(*ids, frozen=None):
    out = [{"project": i, "review": f"R-{i}", "date": "2026-11-15", "state": "published"} for i in ids]
    for p in frozen or []:
        out.append({"project": p["id"], "review": "R-f", "date": "2026-11-15", "state": "frozen",
                    "digest": bm.project_digest(p)})
    return {"reviews": out}


def check(*projects, frozen=()):
    ids = [p["id"] for p in projects if p not in frozen]
    return bm.problems(matrix(*projects), reviews(*ids, frozen=list(frozen)), ROOT)


def test_the_live_matrix_is_clean():
    data = json.loads((ROOT / "matrix.json").read_text())
    rev = json.loads((ROOT / "reviews.json").read_text())
    assert bm.problems(data, rev, ROOT) == []


def test_a_project_without_a_review_is_refused():
    out = bm.problems(matrix(project(1)), {"reviews": []}, ROOT)
    assert any("no review entry" in line for line in out)


def test_a_frozen_project_keeps_its_bytes():
    p = project(1)
    assert check(p, frozen=[p]) == []
    changed = copy.deepcopy(p)
    changed["cells"][0]["detail"] = "edited"
    out = bm.problems(matrix(changed), reviews(frozen=[p]), ROOT)
    assert any("frozen and the entry changed" in line for line in out)


def test_a_frozen_contradicted_cell_without_a_basis_is_refused():
    p = project(1, [cell(verdict="contradicted")])
    out = check(p, frozen=[p])
    for key in ("basis", "divergence_in", "declared_revision"):
        assert any("(frozen)" in line and f"needs {key}" in line for line in out)


def test_a_frozen_contradicted_cell_with_a_basis_passes():
    tagged = cell(verdict="contradicted", basis="defect", divergence_in="their code", declared_revision="draft-01")
    p = project(1, [tagged])
    assert check(p, frozen=[p]) == []


def test_a_contradiction_needs_basis_divergence_and_revision():
    out = check(project(1, [cell(verdict="contradicted")]))
    for key in ("basis", "divergence_in", "declared_revision"):
        assert any(f"needs {key}" in line for line in out)
    ok = cell(verdict="contradicted", basis="defect", divergence_in="their spec", declared_revision="draft-x-01")
    assert check(project(1, [ok])) == []


def test_a_refusal_inside_a_declared_profile_is_unsupported_not_contradicted():
    # The 1e20 and 1e21 refusals of an integer-only profile were published as a contradiction.
    wrong = cell(verdict="contradicted", basis="declared-profile", divergence_in="their code",
                 declared_revision="r", profile="integers below 2^53")
    assert any("not contradicted" in line for line in check(project(1, [wrong])))
    right = cell(verdict="unsupported", basis="declared-profile", profile="integers below 2^53")
    assert check(project(1, [right])) == []
    assert any("requires the profile" in line
               for line in check(project(1, [cell(verdict="unsupported", basis="declared-profile")])))


@pytest.mark.parametrize("verdict,ok", [("agrees", True), ("contradicted", False)])
def test_an_expected_rejection_that_is_rejected_agrees(verdict, ok):
    # A tampered fixture that declares REJECT and is rejected was counted as contradicted.
    c = cell(verdict=verdict, expected="REJECT", observed="REJECT", expected_source="the fixture's expect member",
             basis="defect", divergence_in="their records", declared_revision="r")
    assert (check(project(1, [c])) == []) is ok


def test_an_outcome_different_from_the_declared_one_is_never_agreement():
    c = cell(verdict="agrees", expected="SATISFIED", observed="VIOLATED", expected_source="fixture")
    assert any("differs from expected" in line for line in check(project(1, [c])))


def test_evidence_must_resolve_in_the_tree():
    out = check(project(1, [cell(evidence="adapters/no-such-run.txt")]))
    assert any("does not resolve" in line for line in out)


@pytest.mark.parametrize("evidence", ["_raw/kenosian-retry2.log", "/home/someone/run.txt", "~/x/run.txt",
                                      "see probity-lanes/x"])
def test_evidence_on_one_machine_is_refused(evidence):
    assert any("one machine" in line for line in check(project(1, [cell(evidence=evidence)])))


def test_a_result_needs_an_upstream_pin_and_a_replay():
    p = project(1)
    del p["replay"]
    assert any("needs upstream.url" in line for line in check(p))
    bare = {"id": 2, "name": "n", "cells": [cell(verdict="unsupported", source="none", evidence="no records")]}
    assert check(bare) == []


def test_two_projects_never_share_an_upstream():
    a, b = project(1), project(2)
    b["upstream"] = dict(a["upstream"])
    assert any("share the upstream" in line for line in check(a, b))


def test_columns_use_listed_names_and_need_evidence_for_a_result():
    bad = project(1, columns={"vibes": {"verdict": "agrees"}})
    assert any("unknown column" in line for line in check(bad))
    no_ev = project(1, columns={"edit detection": {"verdict": "agrees"}})
    assert any("no evidence" in line for line in check(no_ev))
    ok = project(1, columns={"edit detection": {"verdict": "not run"}})
    assert check(ok) == []


def test_frozen_projects_get_no_badge():
    a, b = project(1), project(2)
    _, badges = bm.render(matrix(a, b), reviews(1, frozen=[b]))
    assert set(badges) == {"badges/1.json"}
    assert json.loads(badges["badges/1.json"])["message"] == "1 agrees / 1 cells"


def test_freshness_reports_a_moved_upstream_and_a_failed_read():
    data = matrix(project(1), project(2))

    def fetch(owner, repo):
        if repo == "p2":
            raise RuntimeError("HTTP 404")
        return "b" * 40

    lines = bm.freshness(data, fetch)
    assert any("project 1: upstream-moved" in line for line in lines)
    assert any("project 2: freshness not checked" in line for line in lines)
    assert bm.freshness(matrix(project(1)), lambda o, r: "a" * 40) == []


def test_unread_count_counts_projects_with_no_result():
    c = bm.counts(matrix(project(1), {"id": 2, "name": "n", "cells": [cell(verdict="not run")]}))
    assert c["unread"] == {2} and c["run"] == {1}


# Counter-examples from the adversarial read of the schema gate (each was accepted before the fix).

def test_an_evidence_path_that_climbs_out_of_the_tree_is_refused():
    out = check(project(1, [cell(evidence="see records/../../../../../../../../etc/hostname")]))
    assert any("leaves this tree" in line for line in out)


def test_a_new_project_may_not_take_a_frozen_projects_upstream():
    frozen = project(3)
    taker = project(1)
    taker["upstream"] = dict(frozen["upstream"])
    assert any("share the upstream" in line for line in check(taker, frozen, frozen=[frozen]))


@pytest.mark.parametrize("spelling", ["https://github.com/example/p1.git", "https://github.com/Example/P1",
                                      "https://github.com/example/p1/"])
def test_one_upstream_spelled_two_ways_is_still_shared(spelling):
    a, b = project(1), project(2)
    b["upstream"] = {"url": spelling, "sha": "b" * 40}
    assert any("share the upstream" in line for line in check(a, b))


@pytest.mark.parametrize("url,sha", [
    ("https://github.com/a/b (hackathon pack) and https://github.com/a/c", "a" * 40),
    ("https://github.com/a/b.git", "a" * 40),
    ("https://github.com/a/b", "b c5d4194f4a5fbd0a117d3ed9b4ca0bd164822132; c fade5e0ac1223b7ff13339b7c9bcf973b699f9a7"),
    ("https://github.com/a/b", "6ea9afb (verifier core)"),
])
def test_an_upstream_is_one_repository_at_one_commit(url, sha):
    p = project(1)
    p["upstream"] = {"url": url, "sha": sha}
    assert check(p) != []


def test_further_inputs_go_in_also_and_prose_in_note():
    p = project(1)
    p["upstream"]["also"] = [{"url": "https://github.com/example/other", "sha": "c" * 40},
                             {"url": "https://www.ietf.org/archive/id/draft-x-08.txt", "sha256": "d" * 64}]
    p["upstream"]["note"] = "the second repository carries the corpus"
    assert check(p) == []
    p["upstream"]["also"].append({"url": "https://github.com/example/third"})
    assert any("upstream.also[2]" in line for line in check(p))
    p["upstream"]["also"].pop()
    p["upstream"]["kit"] = "prose"
    assert any("unknown keys" in line for line in check(p))


def test_freshness_never_reads_an_empty_or_non_commit_answer_as_fresh():
    for answer in ("", "null", "a" * 12):
        lines = bm.freshness(matrix(project(1)), lambda o, r, a=answer: a)
        assert lines and all("freshness not checked" in line for line in lines), answer


def test_freshness_reads_every_pinned_repository_of_a_project():
    p = project(1)
    p["upstream"]["also"] = [{"url": "https://github.com/example/other", "sha": "c" * 40}]
    lines = bm.freshness(matrix(p), lambda o, r: "a" * 40)
    assert lines == ["project 1: upstream-moved, pinned cccccccccccc, example/other head aaaaaaaaaaaa"]


def _withheld(**kw):
    p = project(21, cells=[cell(verdict="contradicted", basis="defect", divergence_in="their code",
                                declared_revision="r")], replay="node x.mjs CHECKER.mjs")
    del p["upstream"]
    p["withheld"] = {"reason": "below the size line", "inputs": [{"what": "checker", "sha256": "b" * 64}]}
    p.update(kw)
    return p


def test_a_withheld_project_with_a_result_passes_without_an_upstream():
    assert bm.problems(matrix(_withheld()), reviews(21)) == []
    # our own corpus may be named, because the replay clones it
    ok = _withheld(replay="git clone https://github.com/probityai/agent-evidence-vectors ../aev && node x.mjs C.mjs")
    assert bm.problems(matrix(ok), reviews(21)) == []


@pytest.mark.parametrize("change,needle", [
    ({"withheld": {"reason": "", "inputs": []}}, "withheld needs a reason"),
    ({"withheld": {"reason": "r", "inputs": [{"what": "x", "sha256": "short"}]}}, "64-hex sha256"),
    ({"upstream": {"url": "https://github.com/example/p21", "sha": "a" * 40}}, "carries no upstream"),
    ({"name": "named after https://github.com/someone/project"}, "names no repository URL"),
    # the withheld block itself renders into MATRIX.md, so it is held to the same rule
    ({"withheld": {"reason": "see https://github.com/someone/project", "inputs": [{"what": "x", "sha256": "b" * 64}]}},
     "names no repository URL"),
    ({"withheld": {"reason": "r", "inputs": [{"what": "checker from github.com/someone/project", "sha256": "b" * 64}]}},
     "names no repository URL"),
    ({"name": "the gitlab.com/someone/project receipts"}, "names no repository URL"),
    ({"name": "git@github.com:someone/project.git"}, "names no repository URL"),
    ({"name": "the site https://someone.dev"}, "names no repository URL"),
    ({"replay": ""}, "needs a replay over the withheld bytes"),
])
def test_a_withheld_project_is_refused_when_it_still_points_at_the_project(change, needle):
    out = bm.problems(matrix(_withheld(**change)), reviews(21))
    assert any(needle in line for line in out), out


@pytest.mark.parametrize("rec,needle", [
    ({"function": "f", "kind": "magic", "input": "parsed value", "parse_layer": "not probed"}, "kind"),
    ({"function": "f", "kind": "hand-rolled", "input": "bytes", "parse_layer": "not probed"}, "input"),
    ({"function": "f", "kind": "hand-rolled", "input": "text", "parse_layer": "accepted"}, "names no run"),
    ({"function": "f", "kind": "hand-rolled", "input": "text", "parse_layer": "refused",
      "evidence": "adapters/no-such-run.txt"}, "no-such-run"),
    # a function that takes a parsed value never sees the parse layer, so it can neither refuse nor accept it
    ({"function": "f", "kind": "hand-rolled", "input": "parsed value", "parse_layer": "accepted",
      "evidence": "adapters/rfc8785_cli.py"}, "never sees the parse layer"),
    ({"function": "f", "kind": "hand-rolled", "input": "received bytes", "parse_layer": "parsed before it",
      "evidence": "adapters/rfc8785_cli.py"}, "the parse layer reaches it"),
    ({"function": "f", "kind": "hand-rolled", "input": "text", "parse_layer": "not probed",
      "evidence": "adapters/rfc8785_cli.py"}, "not probed and cites a run"),
    ({"function": "f", "kind": "hand-rolled", "input": "text", "duplicates": "refused"}, "unknown keys"),
])
def test_a_canonicalizer_record_states_kind_input_and_the_run_behind_its_parse_layer_claim(rec, needle):
    out = bm.problems(matrix(project(1, canonicalizer=rec)), reviews(1))
    assert any(needle in line for line in out), out


def test_a_canonicalizer_record_with_its_run_passes():
    rec = {"function": "f", "kind": "rfc8785 library", "input": "received bytes", "parse_layer": "refused",
           "evidence": "adapters/rfc8785_cli.py"}
    assert bm.problems(matrix(project(1, canonicalizer=rec)), reviews(1)) == []


@pytest.mark.parametrize("producer,ok", [(None, False), ("cell 1", True), ("cell 2", False), ("cell 9", False),
                                         ("none: the drafts define no format and no code", True), ("later", False),
                                         ("none: ", False), ("none:   ", False), ("cell 0", False)])
def test_no_records_emitted_names_its_producer_route(producer, ok):
    empty = cell(verdict="unsupported", source="none", evidence="no records emitted")
    if producer is not None:
        empty["producer"] = producer
    out = bm.problems(matrix(project(1, cells=[cell(), empty])), reviews(1))
    assert (out == []) is ok, out


def test_readme_counts_are_rewritten_and_a_missing_block_is_refused():
    data = matrix(project(1), project(2, cells=[cell(verdict="not run", source="none")]))
    text = bm.readme_with_counts("a\n<!-- counts:start -->\nold\n<!-- counts:end -->\nb\n", data)
    assert "N of 2: 1; no record read yet: 1 of 2" in text and "(project 2)" in text and "old" not in text
    with pytest.raises(ValueError):
        bm.readme_with_counts("no markers", data)
    twice = "a\n<!-- counts:start -->\nold\n<!-- counts:end -->\n<!-- counts:start -->\nstale\n<!-- counts:end -->\n"
    with pytest.raises(ValueError):
        bm.readme_with_counts(twice, data)


def test_two_no_records_cells_cannot_name_each_other_as_producer():
    def empty(producer):
        return cell(verdict="unsupported", source="none", evidence="no records emitted", producer=producer)

    out = bm.problems(matrix(project(1, cells=[empty("cell 2"), empty("cell 1")])), reviews(1))
    assert sum("itself says" in line for line in out) == 2, out


@pytest.mark.parametrize("evidence", ["No records emitted.", "no records were emitted by the build",
                                      "  NO RECORDS EMITTED"])
def test_no_records_emitted_is_caught_however_it_is_written(evidence):
    empty = cell(verdict="unsupported", source="none", evidence=evidence)
    out = bm.problems(matrix(project(1, cells=[cell(), empty])), reviews(1))
    assert any("names its producer route" in line for line in out), out


@pytest.mark.parametrize("evidence", [None, ["adapters/x.txt"], 7])
def test_a_cell_whose_evidence_is_not_text_is_named_not_a_crash(evidence):
    out = bm.problems(matrix(project(1, cells=[cell(), cell(evidence=evidence)])), reviews(1))
    assert any("evidence is missing" in line for line in out), out


# Counter-examples from the adversarial read of 17 Nov 2026 (each was accepted before the fix).

@pytest.mark.parametrize("evidence", ["run `/home/someone/x.json`", "see:/home/someone/x", '"/tmp/run.txt"',
                                      "$HOME/run.txt", "${HOME}/run.txt", "/root/run.txt", "(/Users/a/run.txt)",
                                      "/var/folders/xy/run.txt", "C:\\Users\\a\\run.txt"])
def test_a_one_machine_path_after_punctuation_is_refused(evidence):
    assert any("one machine" in line for line in check(project(1, [cell(evidence=evidence)])))


@pytest.mark.parametrize("evidence", ["https://github.com/home/x", "records/tmp/../../adapters/rfc8785_cli.py"])
def test_a_url_or_tree_path_that_contains_a_machine_word_is_not_one_machine(evidence):
    assert not any("one machine" in line for line in check(project(1, [cell(evidence=evidence)])))


def test_a_dot_slash_evidence_path_is_resolved_not_skipped():
    out = check(project(1, [cell(evidence="see ./records/no-such-run.txt")]))
    assert any("does not resolve" in line for line in out)
    out = check(project(1, [cell(evidence="see ../records/x.txt")]))
    assert any("leaves this tree" in line for line in out)


def test_a_project_with_no_id_is_refused_even_with_a_review_that_names_none():
    p = project(1)
    del p["id"]
    rv = {"reviews": [{"review": "R", "date": "2026-11-17", "state": "published"}]}
    out = bm.problems(matrix(p), rv, ROOT)
    assert any("not positive integers" in line for line in out)
    assert any("a project id is a positive integer" in line for line in out)


@pytest.mark.parametrize("bad", ["1", 0, -2, True, 1.0])
def test_a_project_id_is_a_positive_integer(bad):
    a, b = project(1), project(2)
    b["id"] = bad
    rv = {"reviews": [{"project": 1, "review": "R", "date": "d", "state": "published"},
                      {"project": bad, "review": "R", "date": "d", "state": "published"}]}
    out = bm.problems(matrix(a, b), rv, ROOT)
    assert any("not positive integers" in line for line in out)


def test_a_frozen_project_whose_cited_file_is_gone_is_refused():
    p = project(3, [cell(evidence="records/no-such-frozen-record.json")])
    out = check(p, frozen=[p])
    assert any("(frozen): evidence path records/no-such-frozen-record.json does not resolve" in line for line in out)
    kept = project(3)
    assert check(kept, frozen=[kept]) == []
