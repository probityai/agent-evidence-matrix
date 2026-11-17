"""Replay the project's own records of dps-scitt-decision-layer with the project's own verifiers (cells E to H).

usage (any Python 3.12 venv with cbor2, cryptography, jsonschema and asn1crypto==1.5.1; no network once cloned):
  git clone https://github.com/Laurent-Lemonnier/dps-scitt-decision-layer ../dps-scitt-decision-layer
  git -C ../dps-scitt-decision-layer checkout 615c0e07039fab5503feed330bf3ff4f1f5ef68e
  git clone https://github.com/decision-provenance-standard/standard ../dps-standard
  git -C ../dps-standard checkout "$(cat ../dps-scitt-decision-layer/interop/aqta/approval-record/DPS_STANDARD_COMMIT)"
  venv/bin/python -I adapters/lemonnier_own_records_adapter.py ../dps-scitt-decision-layer ../dps-standard

The matrix reader (agent-evidence-vectors) has no reader for these formats, so nothing here is "our reader". Each cell
runs the project's verifier, from a copy in a temporary directory with python -I, on the record bytes committed in the
project's tree, and compares what this run prints with the figures the project's README states:
  E  the refund chain across four drafts (interop/one-chain): all verified, 12 joins true, 22 failing cases caught
  F  the same chain with a real passkey approval (interop/one-chain-real): the WebAuthn-ES256 assertion verified by the
     Decision Provenance Standard's reference check, 8 failing cases caught
  G  the four receipts of a second Transparency Service for the same statements (registration/second-log): 4 of 4
  H  a ts.isoluce.net receipt that signs its tree size and leaf index (interop/receipt-size): of 8,255 edited
     (size, index) pairs, a plain RFC 9942 receipt read alone is accepted for 31 others, the signed-size receipt for none
Exit 0 when every comparison agrees; 1 when any differs. Nothing is written in the project's tree.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

failures = []


def note(ok, line):
    print(("agrees      " if ok else "DIFFERS     ") + line)
    if not ok:
        failures.append(line)


def run(work, script, env=None):
    """The project's script, from the copy, with python -I; its folder is put on sys.path as a plain run would."""
    folder = str(Path(script).parent)
    code = ("import sys, runpy; sys.path.insert(0, %r); sys.argv=[%r]; runpy.run_path(%r, run_name='__main__')"
            % (folder, script, script))
    proc = subprocess.run([sys.executable, "-I", "-c", code], cwd=work, capture_output=True, text=True, timeout=1800,
                          env={**os.environ, **(env or {})})
    return proc.returncode, proc.stdout, proc.stderr


def last_json(text):
    return json.loads(text[text.find("{"):])


def chain(work, env, name, letter, joins_claimed, negatives_claimed):
    print("== %s. %s: the project's build.py and negatives.py, run here" % (letter, name))
    rc, out, err = run(work, "%s/build.py" % name, env)
    print("build exit", rc)
    built = last_json(out) if rc == 0 else {}
    note(rc == 0 and built.get("all_verified") is True, "%s build: all_verified true" % letter)
    joins = (built.get("positive") or {}).get("joins") or {}
    note(sum(1 for v in joins.values() if v is True) == joins_claimed and len(joins) == joins_claimed,
         "%s joins true fresh=%d claimed=%d" % (letter, sum(1 for v in joins.values() if v is True), joins_claimed))
    note((built.get("stated_negative") or {}).get("as_expected") is True, "%s stated negative chain as expected" % letter)
    rc, out, err = run(work, "%s/negatives.py" % name, env)
    last = out.strip().splitlines()[-1] if out.strip() else "(none) " + err[-200:]
    print("negatives exit", rc, "| stdout-last-line:", last)
    m = re.match(r"(\d+)/(\d+) failing cases caught where expected", last)
    note(rc == 0 and m is not None and m.group(1) == m.group(2) == str(negatives_claimed),
         "%s failing cases caught fresh=%s claimed=%d" % (letter, m.group(1) if m else "?", negatives_claimed))
    return built


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    project, standard = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
    head = subprocess.run(["git", "-C", str(project), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    print("project commit", head, "| standard commit",
          subprocess.run(["git", "-C", str(standard), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip())
    with tempfile.TemporaryDirectory() as tmp:
        shutil.copytree(project, Path(tmp) / "project", ignore=shutil.ignore_patterns(".git", "__pycache__", "attestation-spec", "dps-standard"))
        work = Path(tmp) / "project" / "interop"
        env = {"DPS_STANDARD": str(standard)}
        chain(work, env, "one-chain", "E", 12, 22)
        real = chain(work, env, "one-chain-real", "F", 12, 8)
        approval = (real.get("positive_link_results") or {}).get("dps_a2_person_approval") or {}
        note(all(approval.get(k) == "verified" for k in ("status", "signature", "subject", "key_state", "identity")),
             "F real approval (WebAuthn-ES256): status, signature, subject, key_state, identity = %s"
             % [approval.get(k) for k in ("status", "signature", "subject", "key_state", "identity")])
        print("== G. second log: the project's verify_witness.py on the four receipts of witness.agentactioncapsule.org")
        rc, out, err = run(work, "one-chain/registration/second-log/verify_witness.py")
        last = out.strip().splitlines()[-1] if out.strip() else "(none) " + err[-200:]
        print("exit", rc, "| stdout-last-line:", last)
        note(rc == 0 and last == "ALL FOUR VERIFIED", "G receipts verified fresh=%s claimed=4" % (4 if last == "ALL FOUR VERIFIED" else "?"))
        print("== H. receipt-size: the project's check.py on a plain and a signed-size receipt of ts.isoluce.net")
        rc, out, err = run(work, "receipt-size/check.py")
        print("exit", rc, "| stdout-last-line:", out.strip().splitlines()[-1] if out.strip() else "(none) " + err[-200:])
        res = json.loads((work / "receipt-size" / "results.json").read_text()) if rc == 0 else {}
        plain, signed = res.get("receipt-plain") or {}, res.get("receipt-signed-size") or {}
        committed = json.loads((project / "interop" / "receipt-size" / "results.json").read_text())
        note(res == committed, "H results of this run equal the committed results.json")
        note(len(plain.get("other_pairs_accepted_alone", [])) == 31 and plain.get("pairs_tried") == 8255,
             "H plain receipt read alone: other pairs accepted fresh=%d claimed=31 of 8255" % len(plain.get("other_pairs_accepted_alone", [0])))
        note(plain.get("other_pairs_accepted_with_checkpoint") == [], "H plain receipt with the signed tree head: issued pair only")
        note(signed.get("size_and_index_signed") is True and signed.get("other_pairs_accepted_alone") == [],
             "H signed-size receipt read alone: issued pair only")
    print("SUMMARY: %d comparisons differ" % len(failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
