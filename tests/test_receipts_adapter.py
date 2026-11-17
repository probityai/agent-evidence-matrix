"""The draft -03 receipts adapter admits a receipt only when the draft lets a verifier accept it.

Counter-examples (tests/counterexamples/receipts-v1-must-refuse.json): eight receipts signed with
the published test keys that the draft says a verifier MUST (or, R5, SHOULD) reject: an uppercase
hash, an absent hash under either payload rule, an unknown formatVersion, a present caller
signature that does not verify, a negative latency, a 129-character signature and an omitted
failureType. The adapter used to print AGREE on six of them, because it compared signature
validity with the stated value and never decided whether the receipt was admitted.
R2b states no signature validity: the draft does not define the payload when a member is absent,
and the receipt is refused before that question matters.
A ninth class is built in the test: a receipt that names another agent's DID, signed with the
translator's key. The adapter verified every receipt under the fixed agent key and admitted it.
"""
import copy
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
ADAPTER = ROOT / "adapters" / "xaip_receipts_adapter.py"
FORGED = json.loads((ROOT / "tests" / "counterexamples" / "receipts-v1-must-refuse.json").read_text())


def run(tmp_path, admitted):
    doc = copy.deepcopy(FORGED)
    for v in doc["receiptVectors"]:
        v["expect"]["admitted"] = admitted
    where = tmp_path / "docs" / "spec" / "test-vectors"
    where.mkdir(parents=True)
    (where / "receipts-v1-vectors.json").write_text(json.dumps(doc))
    return subprocess.run([sys.executable, "-I", str(ADAPTER), str(tmp_path)], capture_output=True, text=True)


def test_every_forged_receipt_is_refused(tmp_path):
    out = run(tmp_path, False)
    assert out.returncode == 0, out.stdout
    assert "SUMMARY 8 of 8 vectors agree" in out.stdout
    assert out.stdout.count("receipt refused") == 8


def test_the_admission_decision_is_what_is_compared(tmp_path):
    out = run(tmp_path, True)
    assert out.returncode == 1
    assert "SUMMARY 0 of 8 vectors agree" in out.stdout


def resign(receipt, pkcs8_hex):
    from cryptography.hazmat.primitives.serialization import load_der_private_key
    sys.path.insert(0, str(ROOT / "adapters"))
    import xaip_receipts_adapter as xa
    key = load_der_private_key(bytes.fromhex(pkcs8_hex), password=None)
    receipt["signature"] = key.sign(xa.payload(receipt)).hex()
    return receipt


def test_a_receipt_naming_another_agent_is_refused(tmp_path):
    """Signed correctly, by a key the set holds, but the receipt names a DID the key is not bound to."""
    doc = copy.deepcopy(FORGED)
    base = next(v for v in doc["receiptVectors"] if v["name"] == "BRK-R4_present_caller_signature_invalid")
    good = copy.deepcopy(base)
    good["name"] = "control_translator_signs_as_itself"
    good["receipt"].pop("callerSignature", None)
    resign(good["receipt"], doc["keys"]["agent"]["privateKeyPkcs8Hex"])
    good["expect"] = {"admitted": True}
    other = copy.deepcopy(good)
    other["name"] = "translator_key_claims_another_agent"
    other["receipt"]["agentDid"] = "did:web:other-agent.example"
    resign(other["receipt"], doc["keys"]["agent"]["privateKeyPkcs8Hex"])
    other["expect"] = {"admitted": False}
    doc["receiptVectors"] = [good, other]
    where = tmp_path / "docs" / "spec" / "test-vectors"
    where.mkdir(parents=True)
    (where / "receipts-v1-vectors.json").write_text(json.dumps(doc))
    out = subprocess.run([sys.executable, "-I", str(ADAPTER), str(tmp_path)], capture_output=True, text=True)
    assert out.returncode == 0, out.stdout
    assert "SUMMARY 2 of 2 vectors agree" in out.stdout
    assert "names no single key in the key set" in out.stdout
