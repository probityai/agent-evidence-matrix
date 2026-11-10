"""Adapter: replay WEXP Core-02 corpora through the wexp_check appraiser and compare with the frozen expectations.

usage: wexp_adapter.py <wexp-check root> <corpus.json> [<corpus.json> ...]
Their records (the corpus inputs and expected appraisals), their code (wexp_check.appraise); the harness is ours.
Per case: agrees (appraisal equals the frozen expectation), contradicted (differs), cannot-tell (the appraiser raised).
Prints one line per corpus and the verdict counts. Exit 0 only when no case is contradicted or cannot-tell.
"""
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1]).resolve()
sys.path.insert(0, str(root))
from wexp_check import appraise  # noqa: E402

SET_FIELDS = {'qualifiers','profile_identifiers','basis_refs','reasons','limitations','base_findings','qualifier_findings','recorder_relations','counter_evidence','evaluation_scope','profile_evaluation_gaps','inherited_limitations','fatal_conditions','affected_claims','fatal_reasons','substantive_reasons','evaluation_gaps','evaluation_gap_entries','supported_claims','maximal_supported_claims','support_entries','support_relations'}


def enc(v):
    return json.dumps(v, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False)


def logical(v, f=None):
    """Collections the harness defines as sets compare as sets (same rule as the project's compare_corpora.py)."""
    if isinstance(v, dict):
        return {k: logical(x, k) for k, x in v.items()}
    if isinstance(v, list):
        items = [logical(x) for x in v]
        return sorted(items, key=enc) if f in SET_FIELDS else items
    return v


bad = 0
for path in sys.argv[2:]:
    corpus = json.loads(pathlib.Path(path).read_bytes())
    tally = {"agrees": 0, "contradicted": 0, "cannot-tell": 0}
    for case in corpus["cases"]:
        try:
            got = appraise(json.loads(json.dumps(case["input"])), json.loads(json.dumps(case.get("profiles", corpus["profiles"]))))
        except Exception:
            tally["cannot-tell"] += 1
            continue
        tally["agrees" if enc(logical(got)) == enc(logical(case["expected"])) else "contradicted"] += 1
    bad += tally["contradicted"] + tally["cannot-tell"]
    print(corpus["id"], len(corpus["cases"]), json.dumps(tally))
sys.exit(1 if bad else 0)
