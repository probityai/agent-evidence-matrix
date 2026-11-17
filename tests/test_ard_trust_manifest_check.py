"""Nine signed-catalog cases the strict ARD checks must decide, built from fixed seeds.

Cases 01 to 06 and 08 were accepted by the first, lenient reading (json.load, sort_keys bytes, no
key-authority check); 07 was refused by it although its bytes are correct; 09 is an unsigned
attestation moved onto another publisher's entry, which a digest-pin-only check still accepts.
"""
import base64
import copy
import hashlib
import json
import pathlib
import subprocess
import sys

import pytest
import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ADAPTERS = pathlib.Path(__file__).resolve().parents[1] / "adapters"
VICTIM = "did:web:victim.example"
KID = VICTIM + "#k1"


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def key(seed):
    sk = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(seed.encode()).digest())
    return sk, sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def did_doc(did, kid, pk, assertion=True):
    doc = {"id": did, "verificationMethod": [{"id": kid, "type": "JsonWebKey2020", "controller": did,
           "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": b64u(pk)}}]}
    doc["assertionMethod" if assertion else "keyAgreement"] = [kid]
    return doc


def entry(identifier="urn:air:victim.example:server:mcp", identity=VICTIM):
    return {"identifier": identifier, "type": "application/mcp-server-card+json",
            "url": "https://example.test/mcp.json", "displayName": "x",
            "trustManifest": {"identity": identity, "identityType": "did"}}


def sign(sk, e, hdr, payload=None):
    body_obj = copy.deepcopy(e)
    body_obj["trustManifest"].pop("signature", None)
    raw = payload if payload is not None else rfc8785.dumps(body_obj)
    h = b64u(json.dumps(hdr, separators=(",", ":")).encode())
    body = raw if hdr.get("b64") is False else b64u(raw).encode()
    e["trustManifest"]["signature"] = h + ".." + b64u(sk.sign(h.encode() + b"." + body))
    return e


def cases():
    sk, pk = key("break-11-victim")
    good_did = did_doc(VICTIM, KID, pk)
    hdr = {"alg": "EdDSA", "kid": KID}
    out = {}
    clean = sign(sk, entry(), hdr)
    text = json.dumps({"entries": [clean]}, indent=1)
    out["01-duplicate-identifier"] = (text.replace('"identifier": "urn:air:victim',
                                                   '"identifier": "urn:air:evil.example:server:mcp", '
                                                   '"identifier": "urn:air:victim', 1), good_did,
                                      "DOCUMENT REFUSED duplicate_member:identifier")
    ask, apk = key("break-11-attacker")
    out["02-kid-not-under-identity"] = ({"entries": [sign(ask, entry(), {"alg": "EdDSA", "kid": "did:web:evil.example#k1"})]},
                                        did_doc("did:web:evil.example", "did:web:evil.example#k1", apk),
                                        "REFUSED kid_not_under_identity")
    out["03-key-not-assertion-method"] = ({"entries": [sign(sk, entry(), hdr)]}, did_doc(VICTIM, KID, pk, False),
                                          "REFUSED key_not_assertion_method")
    out["04-b64-without-crit"] = ({"entries": [sign(sk, entry(), dict(hdr, b64=False))]}, good_did,
                                  "REFUSED b64_without_crit")
    out["05-unknown-crit"] = ({"entries": [sign(sk, entry(), dict(hdr, crit=["x-policy"], **{"x-policy": "eu"}))]},
                              good_did, "REFUSED crit_unsupported")
    out["06-alg-key-mismatch"] = ({"entries": [sign(sk, entry(), dict(hdr, alg="ES256"))]}, good_did,
                                  "REFUSED alg_key_mismatch")
    e7 = entry()
    e7["x-labels"] = {"": "private-use", "\U0001f600": "emoji"}
    out["07-utf16-member-order-valid"] = ({"entries": [sign(sk, e7, hdr)]}, good_did, "L=True")
    e8 = entry()
    e8["x-quota"] = 9007199254740993
    rounded = copy.deepcopy(e8)
    rounded["x-quota"] = 9007199254740992.0  # the double a JavaScript signer holds
    out["08-inexact-integer"] = ({"entries": [sign(sk, e8, hdr, payload=rfc8785.dumps(rounded))]}, good_did,
                                 "REFUSED no_canonical_form")
    return out


def run(tmp_path, name, catalog, did):
    d = tmp_path / name
    d.mkdir()
    (d / "catalog.json").write_text(catalog if isinstance(catalog, str) else json.dumps(catalog, indent=1, ensure_ascii=False))
    (d / "did.json").write_text(json.dumps(did))
    out = subprocess.run([sys.executable, "-I", str(ADAPTERS / "ard_trust_manifest_check.py"),
                          str(d / "catalog.json"), str(d / "did.json")], capture_output=True, text=True)
    return out.stdout


@pytest.mark.parametrize("name", sorted(cases()))
def test_each_case_gets_its_decision(tmp_path, name):
    catalog, did, want = cases()[name]
    assert want in run(tmp_path, name, catalog, did)


def test_the_clean_record_verifies_under_the_whole_entry_input(tmp_path):
    sk, pk = key("break-11-victim")
    out = run(tmp_path, "clean", {"entries": [sign(sk, entry(), {"alg": "EdDSA", "kid": KID})]}, did_doc(VICTIM, KID, pk))
    assert "L=True" in out and "exact_match=True" in out


def test_a_transplanted_unsigned_attestation_is_not_bound(tmp_path):
    """Case 09: the digest pin still matches after the attestation moves to another entry."""
    sarif = b'{"version":"2.1.0","runs":[]}'
    folder = tmp_path / "conformance" / "examples" / "moved"
    folder.mkdir(parents=True)
    (folder / "scan.sarif").write_bytes(sarif)
    moved = {"identifier": "urn:air:evil.example:server:invoice-reader", "url": "https://evil.example/r.json",
             "trustManifest": {"identity": "spiffe://tools.example/r", "attestations": [
                 {"type": "agent-threat-scan", "uri": "https://tools.example/scan.sarif",
                  "digest": "sha256:" + hashlib.sha256(sarif).hexdigest()}]}}
    (folder / "ard.json").write_text(json.dumps({"entries": [moved]}))
    out = subprocess.run([sys.executable, "-I", str(ADAPTERS / "ard_examples_adapter.py"), str(tmp_path)],
                         capture_output=True, text=True).stdout
    assert "attestation-digest\tagrees" in out
    line = next(x for x in out.splitlines() if "\tdraft-bu-00\t" in x)
    assert "contradicted" in line and "top-level digest" in line and "signed attestation statement" in line


# Counter-examples from the adversarial read: altered signature strings verified, a malformed header
# crashed the whole run, and a DID document carrying one key id twice was read last-wins.

def _signed():
    sk, pk = key("break-11-victim")
    return sign(sk, entry(), {"alg": "EdDSA", "kid": KID}), did_doc(VICTIM, KID, pk)


@pytest.mark.parametrize("alter", [lambda s: s[:10] + "!!!!" + s[10:], lambda s: s + "==",
                                   lambda s: s[:10] + "!" + s[10:], lambda s: s.replace("-", "+").replace("_", "/")
                                   if ("-" in s or "_" in s) else s[:5] + "+" + s[6:]])
def test_a_signature_string_outside_strict_base64url_is_refused(tmp_path, alter):
    e, did = _signed()
    h, _, s = e["trustManifest"]["signature"].split(".")
    e["trustManifest"]["signature"] = h + ".." + alter(s)
    out = run(tmp_path, "alt", {"entries": [e]}, did)
    assert "REFUSED not_base64url" in out and "L=True" not in out


def test_a_malformed_entry_is_one_refusal_line_and_the_others_are_still_read(tmp_path):
    e, did = _signed()
    bad = copy.deepcopy(e)
    bad["trustManifest"]["signature"] = b64u(b"[]") + ".." + e["trustManifest"]["signature"].split(".")[2]
    out = run(tmp_path, "hdr", {"entries": [bad, "not an object", {"trustManifest": []}, e]}, did)
    lines = out.splitlines()
    assert lines[0].endswith("REFUSED header_not_object")
    assert lines[1].endswith("REFUSED object_not_json_object")
    assert lines[2].endswith("REFUSED trust_manifest_not_object")
    assert "L=True" in lines[3]


def test_a_non_boolean_b64_is_refused(tmp_path):
    sk, pk = key("break-11-victim")
    e = sign(sk, entry(), {"alg": "EdDSA", "kid": KID, "b64": "false", "crit": ["b64"]})
    assert "REFUSED b64_not_boolean" in run(tmp_path, "b64s", {"entries": [e]}, did_doc(VICTIM, KID, pk))


@pytest.mark.parametrize("signer_first", [True, False])
def test_a_did_document_naming_one_key_id_twice_is_refused_whatever_the_order(tmp_path, signer_first):
    e, did = _signed()
    _, other = key("break-11-other")
    twin = {"id": KID, "type": "JsonWebKey2020", "controller": VICTIM,
            "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": b64u(other)}}
    did["verificationMethod"].insert(1 if signer_first else 0, twin)
    out = run(tmp_path, "dup%s" % signer_first, {"entries": [e]}, did)
    assert "DOCUMENT REFUSED duplicate_verification_method" in out


@pytest.mark.parametrize("stated,verdict", [("upper", "agrees"), ("short", "cannot-tell")])
def test_an_attestation_digest_is_read_as_hex_without_case(tmp_path, stated, verdict):
    """Counter-example: the right digest written in upper case read as contradicted, and a truncated one
    as a plain mismatch rather than an unreadable digest."""
    sarif = b'{"version":"2.1.0","runs":[]}'
    folder = tmp_path / "conformance" / "examples" / "case"
    folder.mkdir(parents=True)
    (folder / "scan.sarif").write_bytes(sarif)
    hexd = hashlib.sha256(sarif).hexdigest()
    digest = hexd.upper() if stated == "upper" else hexd[:40]
    e = {"identifier": "urn:air:x.example:server:r", "trustManifest": {"identity": "did:web:x.example", "attestations": [
        {"type": "scan", "uri": "https://x.example/scan.sarif", "digest": "sha256:" + digest}]}}
    (folder / "ard.json").write_text(json.dumps({"entries": [e]}))
    out = subprocess.run([sys.executable, "-I", str(ADAPTERS / "ard_examples_adapter.py"), str(tmp_path)],
                         capture_output=True, text=True).stdout
    assert f"attestation-digest\t{verdict}" in out


def test_a_header_that_is_not_json_or_not_utf8_or_a_non_string_identifier_is_one_line(tmp_path):
    """Second break pass: each of these crashed the run with a traceback (exit 1) before strict_loads refused
    non-JSON and too-deep text, the header decode refused non-UTF-8 bytes, and publisher_of_urn read only strings."""
    e, did = _signed()
    s = e["trustManifest"]["signature"].split(".")[2]
    entries = []
    for header in (b"not json", b"[" * 100000 + b"]" * 100000, b"\xff\xfe"):
        bad = copy.deepcopy(e)
        bad["trustManifest"]["signature"] = b64u(header) + ".." + s
        entries.append(bad)
    sk, pk = key("break-11-victim")
    entries.append(sign(sk, entry(identifier=5), {"alg": "EdDSA", "kid": KID}))
    lines = run(tmp_path, "crash", {"entries": entries}, did).splitlines()
    assert len(lines) == 4, lines
    assert "REFUSED not_json:" in lines[0]
    assert lines[1].endswith("REFUSED nested_too_deep")
    assert lines[2].endswith("REFUSED header_not_utf8")
    assert "L=True" in lines[3] and "publisher=None" in lines[3]
