"""Cell for project 25: the pinned authority-at-dispatch reader on the 8 case records of the Proofable packet.

usage (python -I, in an environment with agent-evidence-vectors==0.36.3):
  git clone https://github.com/proofable/docs ../proofable-docs
  git -C ../proofable-docs checkout 513cd308c9f943e5cb4b096912806ad6fa3146e8
  python -I adapters/proofable_reader_cell.py ../proofable-docs

The packet's trace.jsonl names the authority-at-dispatch/v1 contract. This script hands each of its 8 records,
byte for byte, to the shipped reader of that contract (agent_evidence_vectors.authoritydispatch.verify, the
reader behind the corpus vectors-authority-at-dispatch) and prints what the reader answers. It reads the
envelopes' qHashes from portable-proofs.json to name which of the 15 envelopes each record cites. Nothing is
written in the packet's tree. Exit 0 when the run completes, 2 when the reader cannot be imported.
"""
import json
import pathlib
import sys
import tempfile

PACKET = pathlib.Path("public/evidence/aaif/authority-at-dispatch/2026-11-02-suite")
MEMBERS = ("contractId", "decisionTime", "approvedAction", "dispatch", "delegation", "authorityEvidence")


def cited(record):
    """Every qHash the record cites."""
    out = set()
    for key in ("delegation_qHash", "authority_decision_qHash", "next_authority_decision_qHash"):
        if record.get(key):
            out.add(record[key])
    out.update(record.get("authority_decision_qHashes", []))
    if record.get("terminal_receipt"):
        out.add(record["terminal_receipt"]["qHash"])
    return out


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: proofable_reader_cell.py <proofable/docs checkout>")
        return 2
    try:
        from agent_evidence_vectors import authoritydispatch as reader
    except ImportError as exc:
        print(f"setup error: agent-evidence-vectors is not installed: {exc}")
        return 2
    packet = pathlib.Path(sys.argv[1]) / PACKET
    envelopes = {e["qHash"] for e in json.loads((packet / "portable-proofs.json").read_text(encoding="utf-8"))}
    records = [json.loads(line) for line in (packet / "trace.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    print(f"reader agent_evidence_vectors authoritydispatch, contract {reader.CONTRACT_ID}")
    named = same = answered = 0
    seen = set()
    for record in records:
        seen |= cited(record) & envelopes
        named += "contractId" in record
        same += record.get("contractId") == reader.CONTRACT_ID
        missing = [m for m in MEMBERS if m not in record]
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "record.json"
            path.write_text(json.dumps(record), encoding="utf-8")
            try:
                answer = reader.verify(path)
                answered += 1
                result = f"decision={answer['decision']} reason={answer['reason']}"
            except Exception as exc:  # the reader's own failure on a record it cannot read is the result
                result = f"no decision ({type(exc).__name__}: {exc})"
        print(f"{record['case_id']:<28} members missing: {','.join(missing) or 'none'} | reader: {result}")
    print()
    print(f"records {len(records)}; contractId present {named} and equal to the reader's {same}; reader decisions {answered} of {len(records)}")
    print(f"envelopes cited by the records: {len(seen)} of {len(envelopes)}")
    print("EXIT=0")
    return 0


if __name__ == "__main__":
    sys.exit(main())
