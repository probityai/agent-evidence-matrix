"""Adapter: read ATX conformance records and check the two layers that need only the test key each record carries.

A record is one fixture file of opena2a-standards/atx-conformance: a wrapper
(name, verifierState, expected) around one ATX credential (the `atx` member).
Layer 1: the canonical signing bytes are reproducible from the credential alone.
         atcVersion "1.0": the eleven-field pipe string of atx-spec core.md 1.3a.1
         atcVersion "1.1": RFC 8785 of the to-be-signed projection of core.md 1.3a.2
Layer 2: every Ed25519 entry of signatures[] verifies over those bytes with the
         public key the record's verifierState.publicKeys names for its keyId.
         The keys are TEST-ONLY keys (the records say so; issuer-primary is the
         RFC 8032 section 7.1 Test 1 key).
NOT read here: ML-DSA-65 entries (no key library pinned in this repository), the
validity window, the trusted-issuer set, revocation, and the distinct-authority
count of core.md 1.3 step 7. A credential in a form this adapter does not project
(a declaredPurpose, a scanSummary.techniques member, a timestamp written with an
offset or a fraction, a behavioralProfile outside its three members) is reported
cannot-tell, never coerced.
Verdict per record: agrees (both layers hold), contradicted (a layer fails),
cannot-tell (unreadable, key missing, or a form not projected here). The record's
own expectation (expected.verifyResult) is printed beside the verdict and plays no
part in it.
usage: atx_layers.py <record.json | directory> ...
Needs rfc8785 (requirements.txt) and cryptography (a dependency of agent-evidence-verify).
"""
import base64
import hashlib
import json
import pathlib
import re
import sys

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

UTC_SECONDS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
SCAN_STRINGS = ("hma", "secretless", "cryptoServe", "oasbLevel")
SCAN_INTEGERS = ("criticalFindings", "highFindings")
SCAN_MEMBERS = set(SCAN_STRINGS) | set(SCAN_INTEGERS)
PROFILE_MEMBERS = {"checksum", "generatedAt", "observationDays"}


class Unprojected(Exception):
    """A member in a form this adapter does not project."""


def _no_duplicates(pairs):
    seen = set()
    for key, _ in pairs:
        if key in seen:
            raise ValueError(f"duplicate member {key!r}")
        seen.add(key)
    return dict(pairs)


def _integer(value, name):
    if isinstance(value, bool) or not isinstance(value, int):
        raise Unprojected(f"{name} is not an integer")
    return value


def _utc_seconds(value, name):
    if not isinstance(value, str) or not UTC_SECONDS.match(value):
        raise Unprojected(f"{name} is not written as YYYY-MM-DDTHH:MM:SSZ")
    return value


def legacy_payload(atx):
    """core.md 1.3a.1: eleven pipe-delimited fields; the last is the literal 1.0."""
    return "|".join(
        [
            atx["agentId"],
            atx["agentDid"],
            atx["version"],
            atx["contentHash"],
            atx.get("buildAttestation") or "",
            atx["issuerDid"],
            str(_integer(atx["trustLevel"], "trustLevel")),
            "%.6f" % float(atx["trustScore"]),
            _utc_seconds(atx["issuedAt"], "issuedAt"),
            _utc_seconds(atx["expiresAt"], "expiresAt"),
            "1.0",
        ]
    ).encode("utf-8")


def tbs_v11(atx):
    """core.md 1.3a.2: the explicit projection, rules 1 to 7, for the forms projected here."""
    if atx.get("declaredPurpose") not in (None, {}):
        raise Unprojected("declaredPurpose is not projected by this adapter")
    scan = atx.get("scanSummary")
    if not isinstance(scan, dict) or set(scan) - SCAN_MEMBERS:
        raise Unprojected("scanSummary outside the six members")
    scan_out = {}
    for name in SCAN_STRINGS:
        value = scan.get(name, "")
        if value is None:
            value = ""
        if not isinstance(value, str):
            raise Unprojected(f"scanSummary.{name} is not a string")
        scan_out[name] = value
    for name in SCAN_INTEGERS:
        value = scan.get(name, 0)
        if value is None:
            value = 0
        scan_out[name] = _integer(value, f"scanSummary.{name}")
    profile = atx.get("behavioralProfile")
    if profile is not None:
        if not isinstance(profile, dict) or set(profile) != PROFILE_MEMBERS:
            raise Unprojected("behavioralProfile outside its three members")
        if not isinstance(profile["checksum"], str):
            raise Unprojected("behavioralProfile.checksum is not a string")
        profile = {
            "checksum": profile["checksum"],
            "generatedAt": _utc_seconds(profile["generatedAt"], "behavioralProfile.generatedAt"),
            "observationDays": _integer(profile["observationDays"], "behavioralProfile.observationDays"),
        }
    capabilities = atx.get("capabilities") or []
    chain = atx.get("issuerChain") or []
    if not all(isinstance(x, str) for x in capabilities + chain):
        raise Unprojected("capabilities or issuerChain holds a non-string")
    return {
        "atcVersion": atx["atcVersion"],
        "agentId": atx["agentId"],
        "agentDid": atx["agentDid"],
        "publisher": atx.get("publisher") or "",
        "publisherDid": atx.get("publisherDid") or "",
        "version": atx["version"],
        "contentHash": atx["contentHash"],
        "buildAttestation": atx.get("buildAttestation") or "",
        "capabilities": list(capabilities),
        "behavioralProfile": profile,
        "scanSummary": scan_out,
        "trustScore": "%.6f" % float(atx["trustScore"]),
        "trustLevel": _integer(atx["trustLevel"], "trustLevel"),
        "issuedAt": _utc_seconds(atx["issuedAt"], "issuedAt"),
        "expiresAt": _utc_seconds(atx["expiresAt"], "expiresAt"),
        "issuerDid": atx["issuerDid"],
        "issuerChain": list(chain),
    }


def signing_bytes(atx):
    version = atx.get("atcVersion")
    if version == "1.0":
        return legacy_payload(atx), "legacy-form"
    if version == "1.1":
        return rfc8785.dumps(tbs_v11(atx)), "jcs-form"
    raise Unprojected(f"atcVersion {version!r} is not projected by this adapter")


def layers(path):
    try:
        record = json.loads(path.read_bytes().decode("utf-8"), object_pairs_hook=_no_duplicates)
        atx = record["atx"]
        expected = record.get("expected", {}).get("verifyResult", "?")
        keys = {
            (k["keyId"], k["algorithm"]): k["publicKeyHex"]
            for k in record["verifierState"]["publicKeys"]
        }
        payload, form = signing_bytes(atx)
        verified, failed, not_read = 0, 0, 0
        for entry in atx["signatures"]:
            if entry["algorithm"] != "Ed25519":
                not_read += 1
                continue
            hex_key = keys.get((entry["keyId"], "Ed25519"))
            if hex_key is None:
                return "cannot-tell", f"no Ed25519 key for {entry['keyId']}"
            key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(hex_key))
            try:
                key.verify(base64.b64decode(entry["value"], validate=True), payload)
                verified += 1
            except InvalidSignature:
                failed += 1
        if verified + failed == 0:
            return "cannot-tell", f"{form}; no Ed25519 entry"
    except Unprojected as exc:
        return "cannot-tell", str(exc)
    except Exception as exc:
        return "cannot-tell", type(exc).__name__
    detail = f"{form} ed25519 {verified}/{verified + failed} verified"
    if not_read:
        detail += f"; {not_read} ML-DSA-65 entry not read"
    detail += f"; record expects {expected}"
    return ("agrees" if failed == 0 else "contradicted"), detail


def main(args):
    paths = []
    for arg in args:
        p = pathlib.Path(arg)
        paths.extend(sorted(p.glob("*.json")) if p.is_dir() else [p])
    for p in paths:
        verdict, why = layers(p)
        digest = hashlib.sha256(p.read_bytes()).hexdigest()
        print(f"{p.name}\t{verdict}\t{why}\tsha256={digest}")


if __name__ == "__main__":
    main(sys.argv[1:])
