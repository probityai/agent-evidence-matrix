"""Replay existing AIREP bytes; no producer or verifier source is changed.

From the matrix root (Python 3.12; bundled wheels target Linux x86_64):
  git clone https://github.com/halvrenofviryel/ai-runtime-evidence-protocol ../ai-runtime-evidence-protocol
  git -C ../ai-runtime-evidence-protocol checkout 3d62af2a3c217939a3556b741550c2563430322f
  python3.12 -m venv ../airep-venv
  ../airep-venv/bin/python -m pip install --no-index --require-hashes \
    --find-links ../ai-runtime-evidence-protocol/spec/airep/v0.2/class-verification/offline-python-deps/wheels \
    -r ../ai-runtime-evidence-protocol/spec/airep/v0.2/class-verification/offline-python-deps/requirements.lock
  ../airep-venv/bin/python -B adapters/airep_adapter.py ../ai-runtime-evidence-protocol

Keep this environment separate: the matrix reader pins require a newer
cryptography than AIREP's historical reproduction environment.

Three comparisons, all labelled "our adapter":
1. Complete reconciler JSON versus committed first-party expected JSON. An
   expected MISSING/FAILURE/INDETERMINATE is agreement, not cannot-tell.
2. One named predicate: all applicable authorized/executed action digests are
   equal. The existing toctou check supplies equality, inequality, or an
   unevaluated comparison because Execution evidence is absent. This is not
   a general mapping from AIREP states to matrix verdicts.
3. The independently implemented consumer/verifier's run_case against the
   original handoff corpus v0.1, plus explicitly scoped projection comparisons.
   The six verifier modules are loaded byte-exact from the licensed deposit;
   only the runner's final sys.exit(main()) invocation is omitted to avoid its
   historical absolute paths. run_case itself is unchanged. No source is copied
   into this repository; the upstream licence and scope notices remain there.

Exit 0 means replay completed and matched the recorded regression evidence,
including the known contradiction and cannot-tell. Exit 1 means regression
evidence differed; exit 2 means input/setup failure. Inspect the verdicts.
"""
import argparse
import ast
from collections import Counter
import hashlib
from importlib.metadata import version
import json
from pathlib import Path
import platform
import subprocess
import sys
import types

COMMIT = "3d62af2a3c217939a3556b741550c2563430322f"
SOURCE = "https://github.com/halvrenofviryel/ai-runtime-evidence-protocol"
DEPOSIT = "external-evidence/certisyn-2026-09"
CORPUS = "interop/independent-verifier-corpus/v0.1"
LIFECYCLE = "reports/beta-2026-09-08/release-validation/lifecycle"
IMPL_SHA = "2aef1212adeaab5a1dc7f07c3f240183db97478b247c008c5fcc0e177fbfeca8"
RAW_SHA = "f4a2b23ab1b996ac3daa4b5985fd90f96467bbe84b6ad878832cf09f73d36f92"
VERDICTS = ("agrees", "contradicted", "cannot-tell")
CHANNELS = ("authenticated_failures", "authenticated_withheld",
            "authenticated_caveats", "witnessed_failures", "witnessed_withheld")
CASES = ("complete", "no-receipt", "no-execution", "toctou-mismatch",
         "no-effect", "same-executor", "unproven-independent",
         "broken-decision", "broken-control", "broken-execution", "broken-effect")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def enc(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def read(root, relative):
    raw = (root / relative).read_bytes()
    print(f"input {relative} sha256:{sha(raw)}")
    return raw


def tally(label, verdicts):
    counts = Counter(verdicts)
    print(label, enc({v: counts[v] for v in VERDICTS}))


def lifecycle(root):
    sys.path.insert(0, str(root))
    from tools.airep_v02.reconcile import reconcile
    from tools.airep_v02.verify import operator_inputs
    from tools.airep_v02.json_input import loads

    for name in ("bindings", "revocation", "independence"):
        read(root, f"{LIFECYCLE}/{name}.json")
    results, verdicts = {}, []
    for name in CASES:
        raw = read(root, f"examples/v02/fixtures/{name}.json")
        expected_path = ("reconciliation.json" if name == "complete"
                         else f"variants/{name}.result.json")
        expected = json.loads(read(root, f"{LIFECYCLE}/{expected_path}"))
        ops = operator_inputs(
            bindings=str(root / LIFECYCLE / "bindings.json"),
            revocation=str(root / LIFECYCLE / "revocation.json"),
            independence_policy=None if name == "unproven-independent" else
            str(root / LIFECYCLE / "independence.json"))
        got = reconcile(loads(raw), ops=ops)
        results[name] = got
        verdict = "agrees" if got == expected else "contradicted"
        verdicts.append(verdict)
        print(f"lifecycle/{name} {verdict} summary={enc(got['summary'])} "
              f"result-json-sha256:{sha(enc(got).encode())}")
    tally("lifecycle-vs-expected", verdicts)

    # Only this named equality predicate is mapped; other states stay intact.
    digest_verdicts = []
    for name in ("complete", "toctou-mismatch", "no-execution"):
        checks = [c for c in results[name]["checks"] if c["check"] == "toctou"]
        if len(checks) != 1:
            raise ValueError("expected exactly one named TOCTOU comparison")
        state = checks[0]["state"]
        verdict = {"SATISFIED": "agrees", "FAILURE": "contradicted",
                   "NOT_EVALUATED": "cannot-tell"}[state]
        digest_verdicts.append(verdict)
        print(f"authorized-vs-executed/{name} {verdict} state={state} "
              f"detail={checks[0]['detail']}")
    tally("authorized-vs-executed", digest_verdicts)
    return all(v == "agrees" for v in verdicts)


def load_external(raw):
    if sha(raw) != IMPL_SHA:
        raise ValueError("external implementation digest mismatch")
    lines = raw.splitlines(keepends=True)
    tree = ast.parse(raw)
    starts = [n.lineno - 1 for n in tree.body if isinstance(n, ast.Expr)
              and isinstance(n.value, ast.Constant)
              and isinstance(n.value.value, str)] + [len(lines)]
    names = ("jcs", "ed25519", "airep", "jsonlex", "jsonschema_min",
             "classverify", "airep_external_runner")
    if len(starts) != len(names) + 1:
        raise ValueError("unexpected concatenated module layout")
    for name, start, end in zip(names, starts, starts[1:]):
        source = b"".join(lines[start:end])
        if name == names[-1]:
            invocation = b"sys.exit(main())\n"
            if not source.endswith(invocation):
                raise ValueError("unexpected runner entry point")
            source = source[:-len(invocation)]
        module = types.ModuleType(name)
        sys.modules[name] = module
        exec(compile(source, name + ".py", "exec"), module.__dict__)
    return module


def projection(result):
    """Only process/class/channels/observer and producer-signature-stage outcome.

    This is a comparison projection for the pinned 18 cases, not a wire field
    or a general AIREP verifier. Revoked/missing binding never becomes PASS.
    Signing-input reconstruction is not inferred from a process exit code.
    """
    v = result.get("verdict")
    crypto = "NOT_EVALUATED"
    if v is not None:
        if "producer-signature-invalid" in v["authenticated_failures"]:
            crypto = "FAIL"
        elif v["class"] in ("AIREP-Authenticated", "AIREP-Witnessed"):
            crypto = "PASS"
        elif not ("producer-binding-revoked" in v["authenticated_failures"]
                  or "producer-binding-missing" in v["authenticated_withheld"]):
            raise ValueError("unhandled producer signature gate in pinned corpus")
    return {"process_exit": result["exit"],
            "airep_class": v["class"] if v else None,
            "reason_channels": {k: v[k] for k in CHANNELS} if v else None,
            "observer_assessment": v["observer_assessment"] if v else "not_applicable",
            "cryptographic_result": crypto}


def external(root):
    pkg = root / CORPUS
    read(root, f"{CORPUS}/manifests/FILES.json")
    check = subprocess.run([sys.executable, "-B", str(pkg / "tools/verify_package.py")],
                           capture_output=True, text=True, check=True)
    print(check.stdout.strip())
    runner = load_external(read(root, f"{DEPOSIT}/AIREP-verifier-source.txt"))
    recorded = read(root, f"{DEPOSIT}/AIREP-observed-verdicts.txt")
    if sha(recorded) != RAW_SHA:
        raise ValueError("external recorded verdict digest mismatch")
    index = json.loads(read(root, f"{CORPUS}/CASE_INDEX.json"))["cases"]
    expected = {r["package_case_id"]: r for r in map(json.loads,
                read(root, f"{CORPUS}/expected/expected_results.jsonl").splitlines())}
    store = runner.SchemaStore(str(pkg / "normative_basis/schemas"))
    observed, verdicts = {}, []
    for case in index:
        cid = case["package_case_id"]
        code, value, reason = runner.run_case(cid, str(pkg / "cases" / cid), store)
        result = {"exit": code}
        if value is not None:
            result["verdict"] = value
        if reason:
            result["reason"] = reason
        observed[cid] = result
        got = projection(result)
        want = {k: expected[cid][k] for k in got}
        differences = {k: {"expected": want[k], "observed": got[k]}
                       for k in got if got[k] != want[k]}
        verdict = "contradicted" if differences else "agrees"
        verdicts.append(verdict)
        print(f"external/{cid} {verdict} exit={code} "
              f"class={got['airep_class']} producer-crypto={got['cryptographic_result']} "
              f"differences={enc(differences)}")
    tally("external-vs-frozen-expectations", verdicts)
    # The original runner emits sorted indent=1 JSON without a trailing newline.
    encoded = json.dumps(observed, indent=1, sort_keys=True).encode()
    same = encoded == recorded
    print(f"external-raw-reproduction {'agrees' if same else 'contradicted'} "
          f"sha256:{sha(encoded)} cases={len(observed)}")
    return same


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("airep_root", type=Path)
    args = parser.parse_args()
    root = args.airep_root.resolve()
    git = ["git", "-c", f"safe.directory={root}", "-C", str(root)]
    head = subprocess.check_output(git + ["rev-parse", "HEAD"], text=True).strip()
    if head != COMMIT or subprocess.check_output(git + ["status", "--porcelain"]):
        raise ValueError("requires a clean checkout at the pinned AIREP commit")
    print(f"source {SOURCE}\ncommit {COMMIT}\nwire-version 0.2")
    print("lifecycle-target v0.2.0-beta.1; external-target earlier r1 handoff corpus v0.1")
    print("command: python -B adapters/airep_adapter.py ../ai-runtime-evidence-protocol")
    print(f"environment Python {platform.python_version()} "
          f"cryptography {version('cryptography')} jsonschema {version('jsonschema')}")
    print("source-label: our adapter; reads existing AIREP record bytes and verifier code")
    print("No network access, current clock, live runtime, or artifact generation in replay.")
    lifecycle_ok = lifecycle(root)
    external_ok = external(root)
    print("Limits: scoped replay, not the shared agent-evidence-verify reader or its corpus.")
    print("Lifecycle fixtures/policies and expected results are first-party test evidence.")
    print("Absent reports do not prove non-events; valid hashes/signatures do not prove truth.")
    print("External: independently implemented consumer/verifier; not expected-blind.")
    print("Frozen report: 17 AGREE / 1 DISAGREE; CLS-XT1 is an expected-projection defect.")
    print("No same-version producer-to-consumer interoperability, deployment-safety,")
    print("IETF/SCITT endorsement or conformance, or full protocol correctness claim.")
    print("No v0.1 producer result is combined with this v0.2 consumer result.")
    print("Six fixed vectors and other external mutation probes are not replayed here.")
    return 0 if lifecycle_ok and external_ok else 1


if __name__ == "__main__":
    sys.dont_write_bytecode = True
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, ImportError, subprocess.SubprocessError) as exc:
        print(f"replay setup/evaluation error: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(2)
