"""Adapter: XAIP receipts (xkumakichi/xaip-protocol), draft-xkumakichi-xaip-receipts-03, recomputed from the draft text.

Reads docs/spec/test-vectors/receipts-v1-vectors.json from a checkout (argument 1) and recomputes, with no code of
theirs:
  preimageVectors   Section 3.5: text hashes its raw UTF-8 bytes, structured JSON hashes its RFC 8785 bytes, absent
                    or null hashes the empty string; expectedCanonical and wrongHashJsonForm where stated
  payloadVectors    Section 3.1: RFC 8785 of the nine base fields plus formatVersion when present; signature,
                    callerSignature and toolMetadata excluded
  receiptVectors    Sections 3.2 and 3.3: Ed25519 over the UTF-8 payload, against the embedded test SPKI keys
                    (DID resolution is out of band, as the vectors file says); also the Section 3.3 fail-closed checks
                    on formatVersion "1" receipts, reported beside the signature result. Admission takes each key
                    by the DID the receipt names (agentDid, and callerDid for a callerSignature): a receipt that
                    names a DID with no key in the set is refused, never checked under another party's key
  rejectionVectors  Section 3.3 fail-closed checks (64 lowercase hex hashes; failureType "" when success is true and
                    non-empty when it is false), the reason compared with the stated mustReject
Prints one line per vector and a summary; exit 0 iff every recomputed value equals the stated one.
"""
import hashlib
import json
import pathlib
import re
import sys

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_der_public_key

HEX64 = re.compile(r"[0-9a-f]{64}")
BASE = ("agentDid", "callerDid", "failureType", "latencyMs", "resultHash", "success", "taskHash", "timestamp",
        "toolName")


def hash_value(v):
    if v is None:
        pre = b""
    elif isinstance(v, str):
        pre = v.encode("utf-8")
    else:
        pre = rfc8785.dumps(v)
    return hashlib.sha256(pre).hexdigest()


def payload(fields):
    obj = {k: fields[k] for k in BASE if k in fields}
    if "formatVersion" in fields:
        obj["formatVersion"] = fields["formatVersion"]
    return rfc8785.dumps(obj)


FULL = BASE + ("formatVersion",)


def violation(f, full=False):
    if full:
        for k in FULL:
            if k not in f:
                return "%s is missing" % k
    for k in ("taskHash", "resultHash"):
        if (full or k in f) and not (isinstance(f.get(k), str) and HEX64.fullmatch(f[k])):
            return "%s is not 64 lowercase hex characters" % k
    if "failureType" in f and not isinstance(f["failureType"], str):
        return "failureType must be a string"
    if f.get("success") is True and f.get("failureType", "") != "":
        return 'failureType must be "" when success is true'
    if f.get("success") is False and not f.get("failureType"):
        return "failureType is required when success is false"
    lat = f.get("latencyMs")
    if full and not (type(lat) is int and 0 <= lat <= 2**53 - 1):
        return "latencyMs is not an integer in [0, 2^53-1]"
    return None


def admit(r, keys):
    fv = r.get("formatVersion")
    if fv is not None and fv != "1":
        return False, "unknown formatVersion %r" % fv
    if fv == "1":
        bad = violation(r, full=True)
        if bad:
            return False, bad
    msg = payload(r)
    agent = key_for(keys, r.get("agentDid"))
    if agent is None:
        return False, "agentDid %r names no single key in the key set" % r.get("agentDid")
    if not verify(msg, r.get("signature"), agent):
        return False, "agent signature does not verify"
    if "callerSignature" in r:
        caller = key_for(keys, r.get("callerDid"))
        if caller is None:
            return False, "callerDid %r names no single key in the key set" % r.get("callerDid")
        if not verify(msg, r["callerSignature"], caller):
            return False, "callerSignature is present and does not verify"
    return True, None


def key_for(keys, did):
    """The SPKI of the one key entry bound to ``did`` in the vectors' key set, else None.

    The receipt names its signer by DID; verifying under a fixed role key instead would admit a receipt that
    claims another agent while carrying this agent's signature."""
    found = [k["publicKeySpkiHex"] for k in keys.values() if isinstance(k, dict) and k.get("did") == did]
    return found[0] if isinstance(did, str) and len(found) == 1 else None


def verify(msg, sig_hex, spki_hex):
    if not (isinstance(sig_hex, str) and re.fullmatch(r"[0-9a-f]{128}", sig_hex)):
        return False
    try:
        load_der_public_key(bytes.fromhex(spki_hex)).verify(bytes.fromhex(sig_hex), msg)
        return True
    except InvalidSignature:
        return False


def main(argv):
    d = json.loads((pathlib.Path(argv[1]) / "docs/spec/test-vectors/receipts-v1-vectors.json").read_bytes())
    n = ok = 0

    def out(name, good, detail):
        nonlocal n, ok
        n += 1
        ok += good
        print("%s %s %s" % ("AGREE" if good else "DIFF ", name, detail))

    for v in d["preimageVectors"]:
        if "valueSpellingA" in v:
            a, b = hash_value(v["valueSpellingA"]), hash_value(v["valueSpellingB"])
            out(v["name"], a == b == v["expectedHash"], "both spellings hash %s" % a[:16])
            continue
        h = hash_value(v["value"])
        good = h == v["expectedHash"]
        det = "hash %s" % h[:16]
        if "expectedCanonical" in v:
            good &= rfc8785.dumps(v["value"]).decode("utf-8") == v["expectedCanonical"]
            det += ", canonical form equal"
        if "wrongHashJsonForm" in v:
            w = hashlib.sha256(json.dumps(v["value"], ensure_ascii=False).encode("utf-8")).hexdigest()
            good &= w == v["wrongHashJsonForm"] and w != v["expectedHash"]
            det += ", JSON-form hash is the stated wrong answer"
        out(v["name"], good, det)
    for v in d["payloadVectors"]:
        p = payload(v["fields"]).decode("utf-8")
        out(v["name"], p == v["expectedPayload"], "payload %d bytes" % len(p.encode("utf-8")))
    keys = d["keys"]
    for v in d["receiptVectors"]:
        r, e = v["receipt"], v["expect"]
        msg = payload(r)
        got, parts = {}, []
        if "agentSignatureValid" in e:
            got["agentSignatureValid"] = verify(msg, r.get("signature"), keys["agent"]["publicKeySpkiHex"])
        if "callerSignatureValid" in e:
            got["callerSignatureValid"] = verify(msg, r.get("callerSignature"), keys["caller"]["publicKeySpkiHex"])
        for k in got:
            parts.append("%s %s (stated %s)" % (k, got[k], e[k]))
        admitted, why = admit(r, keys)
        parts.append("receipt %s%s" % ("admitted" if admitted else "refused", "" if admitted else ": " + why))
        good = all(got[k] == e[k] for k in got)
        if "admitted" in e:
            good &= admitted == e["admitted"]
        out(v["name"], good, "; ".join(parts))
    for v in d["rejectionVectors"]:
        got = violation(v["receiptFragment"])
        out(v["name"], got == v["mustReject"], "rejects: %s" % got)
    print("SUMMARY %d of %d vectors agree" % (ok, n))
    return 0 if ok == n else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
