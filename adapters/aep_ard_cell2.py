"""Adapter: the signed ARD entries of the IETF 127 hackathon pack (aep-sandbox hackathon/ietf127/ard), read from
draft-bu-dawn-ard-discovery-00 section 3.5 with no code of the pack's.

usage: aep_ard_cell2.py <ard dir>      (the directory that holds context.json, vectors/ and examples/)

Each entry gets one outcome in the pack's words (OUTCOMES.md): verified (every check passed), failed (one check
failed; the reason names it) or unverified (a check could not be made, or the file could not be loaded). The checks,
in order, stop at the first one that does not pass:

  load          strict I-JSON parse (a duplicate member, NaN or Infinity is a load refusal: unverified)
  manifests     trustManifest (object) or trustManifests (non-empty array); not both, at least one (3.5)
  fields        each manifest: identity (string), subject (object), signature (string) (3.5)
  signature     JWS compact ES256 or EdDSA, payload detached (RFC 7515 Appendix F) or embedded; the signing input is
                RFC 8785 of the manifest minus `signature`, and an embedded payload must be exactly those bytes;
                kid is a DID URL under `identity`, listed under assertionMethod of the resolved DID document,
                and its key type matches alg; jku, jwk, x5u, x5c and an unknown crit are refused (3.5, 3.5.1 c)
  time          issuedAt not after now, expiresAt (when present) after now, both RFC 3339 UTC; now from context.json
  subject       subject identifier, type and digest equal the entry's, and version equals the entry's when
                either carries one (3.5.1 a)
  publisher     at least one manifest whose identity is did:web:<publisher> of urn:air:<publisher>:... (3.5.1 b);
                a third-party manifest does not substitute for it
  entry digest  an entry with url carries a top-level digest, and SHA-256 of the bytes at url equals it (3.5.2 1)
  pins          every attestations[].digest equals SHA-256 of the bytes at its uri (3.5.2 2)
  binding       every attestation is a COSE_Sign1 record (RFC 9052, tag 18 or untagged) whose EdDSA signature
                verifies under the key its kid names, and whose CBOR payload carries a subject claim whose
                identifier and digest (each one present, at least one) equal the entry's (3.5.2 1, anti-transplant);
                a label in both header buckets, a kid that is not a bstr, or CBOR nested deeper than 64 levels
                is malformed (RFC 9052 sections 3 and 3.1): failed

A malformed value is an outcome for its entry, never a crash of the run: a JWS header that is not JSON, a time that
is not a calendar time (a leap second, which the comparison cannot represent, is unverified) and a non-string
identifier each name the check they fail.

Bytes at a URL come from context.json local_files; a URL it does not map cannot be fetched offline and makes the
entry unverified, as does a digest algorithm other than sha256 or an attestation media type other than COSE_Sign1.
The examples are run as controls: the pack calls them the intended case, so each must come out verified.
Prints one line per entry and a summary. Exit 0 when every control is verified, 1 when one is not, 2 on a crash.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import pathlib
import re
import sys
from datetime import datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

HERE = pathlib.Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("ard_trust_manifest_check", HERE / "ard_trust_manifest_check.py")
atm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(atm)

DIGEST = re.compile(r"([a-z0-9-]+):([0-9a-f]+)")
RFC3339_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z")
COSE_MEDIA = 'application/cose; cose-type="cose-sign1"'


class Failed(Exception):
    """One check failed: the outcome is failed."""


class Unverified(Exception):
    """A check could not be made: the outcome is unverified."""


# ---- CBOR (RFC 8949): definite lengths only, which COSE_Sign1 records use

MAX_DEPTH = 64  # nesting of arrays, maps and tags; a COSE_Sign1 record and its claims need a handful


def cbor_item(b, i, depth=0):
    if depth > MAX_DEPTH:
        raise Failed("cose-malformed:nesting-too-deep")
    if i >= len(b):
        raise Failed("cose-malformed:truncated")
    ib = b[i]
    major, info = ib >> 5, ib & 31
    i += 1
    if info < 24:
        arg = info
    elif info in (24, 25, 26, 27):
        n = 1 << (info - 24)
        if i + n > len(b):
            raise Failed("cose-malformed:truncated")
        arg = int.from_bytes(b[i:i + n], "big")
        i += n
    else:
        raise Failed("cose-malformed:indefinite-or-reserved-length")
    if major == 0:
        return arg, i
    if major == 1:
        return -1 - arg, i
    if major in (2, 3):
        if i + arg > len(b):
            raise Failed("cose-malformed:truncated")
        raw = b[i:i + arg]
        if major == 3:
            try:
                return raw.decode("utf-8"), i + arg
            except UnicodeDecodeError:
                raise Failed("cose-malformed:text-not-utf8")
        return bytes(raw), i + arg
    if major == 4:
        out = []
        for _ in range(arg):
            v, i = cbor_item(b, i, depth + 1)
            out.append(v)
        return out, i
    if major == 5:
        out = {}
        for _ in range(arg):
            k, i = cbor_item(b, i, depth + 1)
            v, i = cbor_item(b, i, depth + 1)
            if isinstance(k, (list, dict)) or k in out:
                raise Failed("cose-malformed:map-key")
            out[k] = v
        return out, i
    if major == 6:
        v, i = cbor_item(b, i, depth + 1)
        return ("tag", arg, v), i
    simple = {20: False, 21: True, 22: None}
    if info in simple:
        return simple[info], i
    raise Failed("cose-malformed:unsupported-simple-or-float")


def cbor_decode(b):
    v, i = cbor_item(b, 0)
    if i != len(b):
        raise Failed("cose-malformed:trailing-bytes")
    return v


def cbor_head(major, n):
    for info, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 24:
            return bytes([major << 5 | n])
        if n < 1 << (8 * size):
            return bytes([major << 5 | info]) + n.to_bytes(size, "big")
    raise ValueError(n)


def cbor_bstr(x):
    return cbor_head(2, len(x)) + x


def sig_structure(protected, payload):
    """RFC 9052 section 4.4: ["Signature1", body_protected, external_aad (empty), payload]."""
    ctx = b"Signature1"
    return cbor_head(4, 4) + cbor_head(3, len(ctx)) + ctx + cbor_bstr(protected) + cbor_bstr(b"") + cbor_bstr(payload)


# ---- context and fetching

def load_context(ard):
    ctx = atm.strict_loads((ard / "context.json").read_text(encoding="utf-8"))
    did_docs = atm.strict_loads((ard / ctx["did_documents"]).read_text(encoding="utf-8"))["documents"]
    att_keys = {}
    for kid, path in ctx.get("attestation_keys", {}).items():
        jwk = atm.strict_loads((ard / path).read_text(encoding="utf-8"))
        if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
            raise ValueError(f"attestation key {kid} is not Ed25519")
        att_keys[kid] = Ed25519PublicKey.from_public_bytes(atm.b64u(jwk["x"]))
    return ctx, did_docs, att_keys


def fetch(ctx, ard, url):
    path = ctx.get("local_files", {}).get(url)
    if path is None:
        raise Unverified(f"not-fetchable:{url}")
    return (ard / path).read_bytes()


def digest_ok(spec, data, what):
    m = DIGEST.fullmatch(spec) if isinstance(spec, str) else None
    if m is None:
        raise Failed(f"{what}-digest-malformed")
    if m.group(1) != "sha256":
        raise Unverified(f"{what}-digest-alg-not-implemented:{m.group(1)}")
    if len(m.group(2)) != 64:
        raise Failed(f"{what}-digest-malformed")
    if hashlib.sha256(data).hexdigest() != m.group(2):
        raise Failed(f"{what}-digest-mismatch")


def when(s, what):
    if not (isinstance(s, str) and RFC3339_UTC.fullmatch(s)):
        raise Failed(f"{what}-not-rfc3339-utc")
    if s[17:19] == "60":
        # RFC 3339 5.6 allows a leap second; the comparison below cannot represent one.
        raise Unverified(f"{what}-leap-second-not-implemented")
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        raise Failed(f"{what}-not-a-calendar-time")


# ---- the checks

def check_signature(tm, did_docs):
    sig = tm["signature"]
    parts = sig.split(".")
    if len(parts) != 3:
        raise Failed("jws-not-compact")
    h, p, s = parts
    try:
        hdr = atm.strict_loads(atm.b64u(h).decode("utf-8"))
        identity = tm["identity"]
        kid = hdr.get("kid") if isinstance(hdr, dict) else None
        if isinstance(kid, str) and atm.did_of(kid) != identity:
            # A key outside the manifest's identity fails whether or not that identity resolves.
            raise atm.Refusal(f"kid_not_under_identity:{atm.did_of(kid)}!={identity}")
        doc = did_docs.get(identity)
        if doc is None:
            raise Unverified(f"did-not-resolved:{identity}")
        methods, assertion = atm.load_keys(doc)
        alg, key, kid = atm.header_checks(hdr, tm, doc, methods, assertion)
        unsigned = copy.deepcopy(tm)
        del unsigned["signature"]
        body = atm.canon(unsigned)
        if hdr.get("b64") is False:
            raise Failed("jws-b64-false-not-in-profile")
        encoded = base64.urlsafe_b64encode(body).rstrip(b"=").decode()
        if p and p != encoded:
            raise Failed("jws-embedded-payload-not-the-manifest")
        ok = atm.verify_raw(alg, key, atm.b64u(s), (h + "." + encoded).encode())
    except atm.Refusal as exc:
        raise Failed(f"jws-refused:{exc}")
    except UnicodeDecodeError:
        raise Failed("jws-header-not-utf8")
    except RecursionError:
        raise Failed("jws-refused:nested_too_deep")
    if not ok:
        raise Failed("signature-invalid")


def check_time(tm, now):
    if "issuedAt" in tm and when(tm["issuedAt"], "issuedAt") > now:
        raise Failed("issued-after-now")
    if "expiresAt" in tm and when(tm["expiresAt"], "expiresAt") <= now:
        raise Failed("expired")


def check_subject(tm, entry):
    sub = tm["subject"]
    for k in ("identifier", "type", "digest"):
        if sub.get(k) != entry.get(k):
            raise Failed(f"subject-{k}-mismatch")
    if ("version" in sub or "version" in entry) and sub.get("version") != entry.get("version"):
        raise Failed("subject-version-mismatch")


def check_binding(data, entry, att_keys):
    item = cbor_decode(data)
    if isinstance(item, tuple):
        if item[1] != 18:
            raise Failed(f"cose-malformed:tag-{item[1]}")
        item = item[2]
    if not (isinstance(item, list) and len(item) == 4):
        raise Failed("cose-malformed:not-cose-sign1")
    protected, unprotected, payload, sig = item
    if not (isinstance(protected, bytes) and isinstance(unprotected, dict) and isinstance(payload, bytes)
            and isinstance(sig, bytes)):
        raise Failed("cose-malformed:member-types")
    hdr = cbor_decode(protected) if protected else {}
    if not isinstance(hdr, dict):
        raise Failed("cose-malformed:protected-not-map")
    both = sorted(set(hdr) & set(unprotected), key=repr)
    if both:
        # RFC 9052 section 3: a label never occurs in both buckets, and a message where one does is malformed.
        raise Failed(f"cose-malformed:label-in-both-buckets:{both[0]}")
    if hdr.get(1) != -8:
        raise Unverified(f"alg-not-implemented:{hdr.get(1)}")
    if 2 in hdr:
        raise Failed("crit-not-understood")
    kid = hdr.get(4, unprotected.get(4))
    if kid is not None and not isinstance(kid, bytes):
        raise Failed("cose-malformed:kid-not-bstr")  # RFC 9052 section 3.1, label 4: bstr
    try:
        kid = kid.decode("utf-8") if kid is not None else None
    except UnicodeDecodeError:
        raise Unverified("attestation-key-unknown:kid-not-utf8")
    key = att_keys.get(kid)
    if key is None:
        raise Unverified(f"attestation-key-unknown:{kid}")
    try:
        key.verify(sig, sig_structure(protected, payload))
    except InvalidSignature:
        raise Failed("attestation-signature-invalid")
    claim = cbor_decode(payload)
    sub = claim.get("subject") if isinstance(claim, dict) else None
    if not isinstance(sub, dict) or not ({"identifier", "digest"} & set(sub)):
        raise Failed("attestation-no-subject-claim")
    for k in ("identifier", "digest"):
        if k in sub and sub[k] != entry.get(k):
            raise Failed(f"attestation-subject-{k}-mismatch")


def judge(path, ctx, did_docs, att_keys, ard, now):
    try:
        entry = atm.strict_loads(path.read_text(encoding="utf-8"))
    except (atm.Refusal, ValueError, UnicodeDecodeError) as exc:
        return "unverified", f"load-refused:{str(exc)[:60]}"
    try:
        if not isinstance(entry, dict):
            raise Failed("entry-not-object")
        if "trustManifest" in entry and "trustManifests" in entry:
            raise Failed("both-trustManifest-and-trustManifests")
        mans = [entry["trustManifest"]] if "trustManifest" in entry else entry.get("trustManifests")
        if not (isinstance(mans, list) and mans):
            raise Failed("no-trust-manifest")
        for tm in mans:
            if not (isinstance(tm, dict) and isinstance(tm.get("identity"), str) and isinstance(tm.get("subject"), dict)
                    and isinstance(tm.get("signature"), str)):
                raise Failed("manifest-required-field")
            check_signature(tm, did_docs)
            check_time(tm, now)
            check_subject(tm, entry)
        pub = atm.publisher_of_urn(entry.get("identifier"))  # None for a non-string identifier
        if pub is None:
            raise Failed("identifier-not-urn-air")
        if not any(tm["identity"] == "did:web:" + pub for tm in mans):
            raise Failed(f"no-publisher-manifest:{pub}")
        if "url" in entry:
            if "digest" not in entry:
                raise Failed("entry-url-without-digest")
            digest_ok(entry["digest"], fetch(ctx, ard, entry["url"]), "entry")
        for tm in mans:
            atts = tm.get("attestations", [])
            if not isinstance(atts, list):
                raise Failed("attestations-not-array")
            for att in atts:
                if not (isinstance(att, dict) and isinstance(att.get("uri"), str) and "digest" in att):
                    raise Failed("attestation-not-hash-pinned")
                data = fetch(ctx, ard, att["uri"])
                digest_ok(att["digest"], data, "attestation")
                if att.get("mediaType") != COSE_MEDIA:
                    raise Unverified("attestation-media-type-not-implemented:{}".format(att.get("mediaType")))
                check_binding(data, entry, att_keys)
    except Failed as exc:
        return "failed", str(exc)
    except Unverified as exc:
        return "unverified", str(exc)
    return "verified", "all-checks-pass"


def main(argv):
    if len(argv) != 1:
        sys.exit(__doc__)
    ard = pathlib.Path(argv[0])
    ctx, did_docs, att_keys = load_context(ard)
    index = atm.strict_loads((ard / "vectors" / "index.json").read_text(encoding="utf-8"))
    now = when(index["now"], "now")
    if now != when(ctx["now"], "now"):
        sys.exit("context.json and vectors/index.json name different times")
    controls_ok = True
    for ex in sorted((ard / "examples").glob("*.json")):
        outcome, reason = judge(ex, ctx, did_docs, att_keys, ard, now)
        controls_ok &= outcome == "verified"
        print(f"control {ex.stem:<28} {outcome:<11} {reason}")
    counts = {}
    for v in index["vectors"]:
        outcome, reason = judge(ard / "vectors" / v["file"], ctx, did_docs, att_keys, ard, now)
        counts[outcome] = counts.get(outcome, 0) + 1
        print(f"vector  {v['id']:<28} {outcome:<11} {reason}")
    tally = ", ".join(f"{k} {n}" for k, n in sorted(counts.items()))
    print(f"SUMMARY controls {'all verified' if controls_ok else 'NOT all verified'}; vectors {tally}")
    return 0 if controls_ok else 1


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 -- any crash exits 2, never an outcome
        print(f"setup: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(2)
