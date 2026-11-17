"""The cell-2 ARD reader verifies a well-formed signed entry and names the check each altered copy fails.

Every entry here is built in the test with fresh keys (an ES256 key in a did:web document, an Ed25519 key for the
COSE_Sign1 record), so nothing depends on the pack. The altered copies are the classes section 3.5 rules out: a
transplanted attestation (a record whose subject claim names another entry), a pinned document replaced after
signing, a manifest signed under a key outside its identity, an embedded payload that is not the manifest, and a
URL nobody can fetch offline (unverified, never failed or verified).
"""
import base64
import copy
import hashlib
import json
import pathlib
import subprocess
import sys

import rfc8785
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

ROOT = pathlib.Path(__file__).resolve().parents[1]
ADAPTER = ROOT / "adapters" / "aep_ard_cell2.py"
ID = "urn:air:example.org:agent:a"
NOW = "2026-11-14T12:00:00Z"


def b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def head(major, n):
    if n < 24:
        return bytes([major << 5 | n])
    for info, size in ((24, 1), (25, 2), (26, 4)):
        if n < 1 << (8 * size):
            return bytes([major << 5 | info]) + n.to_bytes(size, "big")
    raise ValueError(n)


def cbor(v):
    if isinstance(v, bool) or v is None:
        return bytes([0xF5 if v is True else 0xF4 if v is False else 0xF6])
    if isinstance(v, int):
        return head(0, v) if v >= 0 else head(1, -1 - v)
    if isinstance(v, bytes):
        return head(2, len(v)) + v
    if isinstance(v, str):
        return head(3, len(v.encode())) + v.encode()
    if isinstance(v, list):
        return head(4, len(v)) + b"".join(cbor(x) for x in v)
    return head(5, len(v)) + b"".join(cbor(k) + cbor(x) for k, x in v.items())


def record(key, subject):
    protected = cbor({1: -8, 3: "application/cbor", 4: b"rec-key"})
    payload = cbor({"version": 1, "subject": subject})
    to_sign = cbor(["Signature1", protected, b"", payload])
    return bytes([0xD2]) + cbor([protected, {}, payload, key.sign(to_sign)])


def sign_manifest(tm, key, kid, embedded=False):
    body = rfc8785.dumps({k: v for k, v in tm.items() if k != "signature"})
    h = b64u(json.dumps({"alg": "ES256", "kid": kid}).encode())
    r, s = decode_dss_signature(key.sign((h + "." + b64u(body)).encode(), ec.ECDSA(hashes.SHA256())))
    sig = b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
    tm["signature"] = "{}.{}.{}".format(h, b64u(body) if embedded else "", sig)


def pack(tmp_path):
    """A pack directory with one example entry; returns (dir, keys, the entry) for the test to alter."""
    es = ec.generate_private_key(ec.SECP256R1())
    ed = Ed25519PrivateKey.generate()
    nums = es.public_key().public_numbers()
    did = {"documents": {"did:web:example.org": {
        "id": "did:web:example.org",
        "verificationMethod": [{"id": "did:web:example.org#k1", "type": "JsonWebKey",
                                "controller": "did:web:example.org",
                                "publicKeyJwk": {"kty": "EC", "crv": "P-256", "x": b64u(nums.x.to_bytes(32, "big")),
                                                 "y": b64u(nums.y.to_bytes(32, "big"))}}],
        "assertionMethod": ["did:web:example.org#k1"]}}}
    raw_pub = ed.public_key().public_bytes_raw()
    artifact = b"agent config\n"
    digest = "sha256:" + hashlib.sha256(artifact).hexdigest()
    rec = record(ed, {"identifier": ID, "digest": digest})
    for sub in ("vectors", "examples", "keys", "files"):
        (tmp_path / sub).mkdir()
    (tmp_path / "keys" / "did.json").write_text(json.dumps(did))
    (tmp_path / "keys" / "rec.jwk.json").write_text(json.dumps({"kty": "OKP", "crv": "Ed25519", "x": b64u(raw_pub)}))
    (tmp_path / "files" / "artifact.txt").write_bytes(artifact)
    (tmp_path / "files" / "rec.cose").write_bytes(rec)
    (tmp_path / "context.json").write_text(json.dumps({
        "now": NOW, "did_documents": "keys/did.json", "attestation_keys": {"rec-key": "keys/rec.jwk.json"},
        "local_files": {"https://example.org/a.txt": "files/artifact.txt",
                        "https://example.org/rec.cose": "files/rec.cose"}}))
    entry = {"identifier": ID, "type": "text/plain", "url": "https://example.org/a.txt", "digest": digest,
             "trustManifest": {"identity": "did:web:example.org", "issuedAt": "2026-11-14T00:00:00Z",
                               "subject": {"identifier": ID, "type": "text/plain", "digest": digest},
                               "attestations": [{"type": "https://example.org/rec", "uri": "https://example.org/rec.cose",
                                                 "mediaType": 'application/cose; cose-type="cose-sign1"',
                                                 "digest": "sha256:" + hashlib.sha256(rec).hexdigest()}]}}
    sign_manifest(entry["trustManifest"], es, "did:web:example.org#k1")
    (tmp_path / "examples" / "example.json").write_text(json.dumps(entry))
    return tmp_path, es, ed, entry


def run(tmp_path, vectors):
    index = {"now": NOW, "vectors": []}
    for name, entry in vectors.items():
        (tmp_path / "vectors" / (name + ".json")).write_text(entry if isinstance(entry, str) else json.dumps(entry))
        index["vectors"].append({"id": name, "file": name + ".json"})
    (tmp_path / "vectors" / "index.json").write_text(json.dumps(index))
    out = subprocess.run([sys.executable, "-I", str(ADAPTER), str(tmp_path)], capture_output=True, text=True,
                         check=False)
    lines = {ln.split()[1]: ln.split()[2:] for ln in out.stdout.splitlines() if ln.startswith(("vector", "control"))}
    return out.returncode, lines, out


def test_the_built_entry_verifies_and_each_alteration_names_its_check(tmp_path):
    d, es, ed, entry = pack(tmp_path)
    embedded = copy.deepcopy(entry)
    sign_manifest(embedded["trustManifest"], es, "did:web:example.org#k1", embedded=True)
    wrong_payload = copy.deepcopy(embedded)
    h, _, s = wrong_payload["trustManifest"]["signature"].split(".")
    wrong_payload["trustManifest"]["signature"] = "{}.{}.{}".format(h, b64u(b'{"identity":"x"}'), s)
    transplant = copy.deepcopy(entry)
    other = record(ed, {"identifier": "urn:air:example.org:agent:b", "digest": entry["digest"]})
    (d / "files" / "other.cose").write_bytes(other)
    ctx = json.loads((d / "context.json").read_text())
    ctx["local_files"]["https://example.org/other.cose"] = "files/other.cose"
    (d / "context.json").write_text(json.dumps(ctx))
    att = transplant["trustManifest"]["attestations"][0]
    att["uri"], att["digest"] = "https://example.org/other.cose", "sha256:" + hashlib.sha256(other).hexdigest()
    sign_manifest(transplant["trustManifest"], es, "did:web:example.org#k1")
    replaced = copy.deepcopy(entry)
    replaced["trustManifest"]["attestations"][0]["digest"] = "sha256:" + "0" * 64
    sign_manifest(replaced["trustManifest"], es, "did:web:example.org#k1")
    foreign = copy.deepcopy(entry)
    foreign["trustManifest"]["identity"] = "did:web:other.example"
    sign_manifest(foreign["trustManifest"], es, "did:web:example.org#k1")
    offline = copy.deepcopy(entry)
    offline["url"] = "https://example.org/not-mapped.txt"
    rc, lines, out = run(d, {
        "ok": entry, "embedded": embedded, "wrong_payload": wrong_payload, "transplant": transplant,
        "replaced": replaced, "foreign": foreign, "offline": offline,
        "dup": '{"identifier":"a","identifier":"b"}'})
    assert rc == 0, out.stdout + out.stderr
    assert lines["example"][0] == "verified"
    assert lines["ok"] == ["verified", "all-checks-pass"]
    assert lines["embedded"] == ["verified", "all-checks-pass"]
    assert lines["wrong_payload"] == ["failed", "jws-embedded-payload-not-the-manifest"]
    assert lines["transplant"] == ["failed", "attestation-subject-identifier-mismatch"]
    assert lines["replaced"] == ["failed", "attestation-digest-mismatch"]
    assert lines["foreign"][0] == "failed" and lines["foreign"][1].startswith("jws-refused:kid_not_under_identity")
    assert lines["offline"][0] == "unverified" and lines["offline"][1].startswith("not-fetchable")
    assert lines["dup"][0] == "unverified" and lines["dup"][1].startswith("load-refused")


def test_a_control_that_does_not_verify_fails_the_run(tmp_path):
    d, es, _, entry = pack(tmp_path)
    broken = copy.deepcopy(entry)
    broken["digest"] = "sha256:" + "1" * 64
    broken["trustManifest"]["subject"]["digest"] = broken["digest"]
    sign_manifest(broken["trustManifest"], es, "did:web:example.org#k1")
    (d / "examples" / "example.json").write_text(json.dumps(broken))
    rc, lines, out = run(d, {"ok": entry})
    assert rc == 1 and "NOT all verified" in out.stdout
    assert lines["example"] == ["failed", "entry-digest-mismatch"]


def with_record(d, es, entry, name, rec):
    """A copy of the entry whose one attestation is `rec`, stored under its own URL so the control is untouched."""
    (d / "files" / (name + ".cose")).write_bytes(rec)
    ctx = json.loads((d / "context.json").read_text())
    ctx["local_files"]["https://example.org/" + name + ".cose"] = "files/" + name + ".cose"
    (d / "context.json").write_text(json.dumps(ctx))
    out = copy.deepcopy(entry)
    att = out["trustManifest"]["attestations"][0]
    att["uri"], att["digest"] = "https://example.org/" + name + ".cose", "sha256:" + hashlib.sha256(rec).hexdigest()
    sign_manifest(out["trustManifest"], es, "did:web:example.org#k1")
    return out


def cose(ed, protected, unprotected, subject):
    payload = cbor({"subject": subject})
    sig = ed.sign(cbor(["Signature1", protected, b"", payload]))
    return bytes([0xD2]) + cbor([protected, unprotected, payload, sig])


def test_malformed_input_is_an_outcome_for_that_entry_never_a_crash_or_a_pass(tmp_path):
    """Second break pass: each of these was verified, or crashed the whole run (exit 2), before the fix."""
    d, es, ed, entry = pack(tmp_path)
    subject = {"identifier": ID, "digest": entry["digest"]}
    vectors = {
        # RFC 9052 section 3: a label in both buckets makes the message malformed (was verified)
        "kid_both": with_record(d, es, entry, "kb", cose(ed, cbor({1: -8, 4: b"rec-key"}), {4: b"other"}, subject)),
        "alg_both": with_record(d, es, entry, "ab", cose(ed, cbor({1: -8, 4: b"rec-key"}), {1: -7}, subject)),
        # RFC 9052 section 3.1: kid is a bstr (a text kid was verified)
        "kid_text": with_record(d, es, entry, "kt", cose(ed, cbor({1: -8, 4: "rec-key"}), {}, subject)),
        # 200000 nested arrays (RecursionError, exit 2)
        "deep_cbor": with_record(d, es, entry, "dc", b"\x81" * 200000 + b"\x00"),
    }
    for name, field, value in (("bad_month", "issuedAt", "2026-13-01T00:00:00Z"),
                               ("leap", "expiresAt", "2026-12-31T23:59:60Z")):
        v = copy.deepcopy(entry)
        v["trustManifest"][field] = value
        sign_manifest(v["trustManifest"], es, "did:web:example.org#k1")
        vectors[name] = v
    v = copy.deepcopy(entry)
    v["identifier"] = v["trustManifest"]["subject"]["identifier"] = 5
    sign_manifest(v["trustManifest"], es, "did:web:example.org#k1")
    vectors["identifier_int"] = v
    for name, header in (("header_not_json", b"not json"), ("header_deep", b"[" * 100000 + b"]" * 100000)):
        v = copy.deepcopy(entry)
        _, p, s = v["trustManifest"]["signature"].split(".")
        v["trustManifest"]["signature"] = b64u(header) + "." + p + "." + s
        vectors[name] = v
    rc, lines, out = run(d, vectors)
    assert rc == 0, out.stdout + out.stderr
    assert lines["kid_both"] == ["failed", "cose-malformed:label-in-both-buckets:4"]
    assert lines["alg_both"] == ["failed", "cose-malformed:label-in-both-buckets:1"]
    assert lines["kid_text"] == ["failed", "cose-malformed:kid-not-bstr"]
    assert lines["deep_cbor"] == ["failed", "cose-malformed:nesting-too-deep"]
    assert lines["bad_month"] == ["failed", "issuedAt-not-a-calendar-time"]
    assert lines["leap"] == ["unverified", "expiresAt-leap-second-not-implemented"]
    assert lines["identifier_int"] == ["failed", "identifier-not-urn-air"]
    assert lines["header_not_json"][:1] == ["failed"] and lines["header_not_json"][1].startswith("jws-refused:not_json")
    assert lines["header_deep"] == ["failed", "jws-refused:nested_too_deep"]
