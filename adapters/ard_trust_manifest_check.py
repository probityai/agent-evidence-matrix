"""Strict read-only check of signed ARD and AI Catalog trust manifests.

usage: ard_trust_manifest_check.py catalog.json did.json

Prints one line per signed object (the catalog host and each entry). Each rule below is pinned by a
case in tests/test_ard_trust_manifest_check.py:
  * strict I-JSON parse: a duplicate member, NaN or Infinity refuses the document (a last-wins
    parser lets a record carrying two `identifier` members verify); a DID document naming one
    verification method id twice is refused (a last-wins reader picks whichever key came last);
  * base64url is the strict RFC 7515 alphabet with no padding and a canonical final character
    (a lenient decoder drops stray characters, so altered signature strings still verify);
  * the protected header is a JSON object and `b64`, when present, is a JSON boolean;
  * RFC 8785 through the pinned rfc8785 package (members in UTF-16 order, ECMAScript number form,
    an integer that is not an exact double refused), never json.dumps(sort_keys=True);
  * JWS header: alg is EdDSA or ES256 and matches the key type; `crit` may name only `b64`; `b64`
    without `crit` is refused (RFC 7797 section 6); `jku`, `jwk`, `x5u`, `x5c` are refused;
  * key authority: the DID part of `kid` equals trustManifest.identity and the did.json `id`, and
    the method is listed under `assertionMethod`;
  * the publisher is read from the authenticated `kid` DID, never from the unsigned `identity`.
Two signing inputs are reported side by side: L = the object minus trustManifest.signature (the
whole-entry practice) and D = the trustManifest minus its signature (draft-bu-dawn-ard-discovery-00
section 3.5). A refusal before the signature check is reported once.
"""
import base64
import copy
import json
import re
import sys

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature


class Refusal(ValueError):
    pass


B64URL = re.compile(r"[A-Za-z0-9_-]*")


def b64u(s):
    """Strict base64url (RFC 7515 section 2): the url-safe alphabet, no padding, canonical last character."""
    if not isinstance(s, str) or not B64URL.fullmatch(s) or len(s) % 4 == 1:
        raise Refusal("not_base64url")
    raw = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != s:
        raise Refusal("not_base64url:non_canonical")
    return raw


def strict_loads(text):
    def pairs(items):
        out = {}
        for k, v in items:
            if k in out:
                raise Refusal("duplicate_member:%s" % k)
            out[k] = v
        return out

    def const(name):
        raise Refusal("non_json_constant:%s" % name)

    try:
        return json.loads(text, object_pairs_hook=pairs, parse_constant=const)
    except Refusal:
        raise
    except RecursionError as exc:
        raise Refusal("nested_too_deep") from exc
    except ValueError as exc:  # json.JSONDecodeError: the text is not JSON
        raise Refusal("not_json:%s" % getattr(exc, "msg", type(exc).__name__)) from exc


def canon(obj):
    try:
        return rfc8785.dumps(obj)
    except Exception as exc:  # IntegerDomainError, FloatDomainError, CanonicalizationError
        raise Refusal("no_canonical_form:%s" % type(exc).__name__) from exc


def did_of(kid):
    return kid.split("#", 1)[0]


def load_keys(did):
    ids = [vm.get("id") for vm in did.get("verificationMethod", []) if isinstance(vm, dict)]
    ids += [m.get("id") for m in did.get("assertionMethod", []) if isinstance(m, dict)]
    dup = sorted({i for i in ids if i is not None and ids.count(i) > 1})
    if dup:
        raise Refusal("duplicate_verification_method:%s" % dup[0])
    assertion = set()
    for item in did.get("assertionMethod", []):
        assertion.add(item if isinstance(item, str) else item.get("id"))
    methods = {vm["id"]: vm for vm in did.get("verificationMethod", []) if "id" in vm}
    for item in did.get("assertionMethod", []):
        if isinstance(item, dict) and "id" in item:
            methods[item["id"]] = item
    return methods, assertion


def public_key(vm):
    jwk = vm.get("publicKeyJwk") or {}
    if jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519":
        return "EdDSA", Ed25519PublicKey.from_public_bytes(b64u(jwk["x"]))
    if jwk.get("kty") == "EC" and jwk.get("crv") == "P-256":
        x = int.from_bytes(b64u(jwk["x"]), "big")
        y = int.from_bytes(b64u(jwk["y"]), "big")
        return "ES256", ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    raise Refusal("key_type_unsupported")


def verify_raw(alg, key, sig, msg):
    try:
        if alg == "EdDSA":
            key.verify(sig, msg)
        else:
            if len(sig) != 64:
                return False
            der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
            key.verify(der, msg, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def header_checks(hdr, tm, did, methods, assertion):
    if not isinstance(hdr, dict):
        raise Refusal("header_not_object")
    if "b64" in hdr and not isinstance(hdr["b64"], bool):
        raise Refusal("b64_not_boolean")
    alg = hdr.get("alg")
    if alg not in ("EdDSA", "ES256"):
        raise Refusal("alg_not_allowed:%s" % alg)
    for banned in ("jku", "jwk", "x5u", "x5c"):
        if banned in hdr:
            raise Refusal("key_source_in_header:%s" % banned)
    crit = hdr.get("crit")
    if crit is not None:
        if not isinstance(crit, list) or not crit or any(c != "b64" for c in crit):
            raise Refusal("crit_unsupported:%s" % crit)
        if "b64" not in hdr:
            raise Refusal("crit_names_absent_param")
    if "b64" in hdr and (crit is None or "b64" not in crit):
        raise Refusal("b64_without_crit")
    kid = hdr.get("kid")
    if not isinstance(kid, str) or "#" not in kid:
        raise Refusal("kid_missing_or_not_did_url")
    identity = tm.get("identity")
    if did_of(kid) != identity:
        raise Refusal("kid_not_under_identity:%s!=%s" % (did_of(kid), identity))
    if did.get("id") != identity:
        raise Refusal("did_document_not_identity:%s" % did.get("id"))
    if kid not in methods:
        raise Refusal("kid_not_in_did_document")
    if kid not in assertion:
        raise Refusal("key_not_assertion_method")
    key_alg, key = public_key(methods[kid])
    if key_alg != alg:
        raise Refusal("alg_key_mismatch:%s/%s" % (alg, key_alg))
    return alg, key, kid


def signing_input(h, hdr, obj):
    raw = canon(obj)
    body = raw if hdr.get("b64") is False else base64.urlsafe_b64encode(raw).rstrip(b"=")
    return h.encode() + b"." + body


def publisher_of_urn(urn):
    if not isinstance(urn, str):
        return None
    parts = urn.split(":")
    return parts[2] if len(parts) > 2 and parts[0] == "urn" and parts[1] == "air" else None


def check_object(name, obj, did, methods, assertion):
    if not isinstance(obj, dict):
        return "%s REFUSED object_not_json_object" % name
    tm = obj.get("trustManifest", {})
    if not isinstance(tm, dict):
        return "%s REFUSED trust_manifest_not_object" % name
    sig = tm.get("signature")
    if sig is None:
        return "%s UNSIGNED" % name
    if not isinstance(sig, str):
        return "%s STRUCTURED-SIGNATURE (AI Catalog construction; out of scope here)" % name
    parts = sig.split(".")
    if len(parts) != 3 or parts[1] != "":
        return "%s REFUSED jws_not_detached_compact" % name
    h, _, s = parts
    try:
        hdr = strict_loads(b64u(h).decode("utf-8"))
        alg, key, kid = header_checks(hdr, tm, did, methods, assertion)
        whole = copy.deepcopy(obj)
        del whole["trustManifest"]["signature"]
        tm_only = copy.deepcopy(tm)
        del tm_only["signature"]
        ok_l = verify_raw(alg, key, b64u(s), signing_input(h, hdr, whole))
        ok_d = verify_raw(alg, key, b64u(s), signing_input(h, hdr, tm_only))
    except Refusal as exc:
        return "%s REFUSED %s" % (name, exc)
    except UnicodeDecodeError:
        return "%s REFUSED header_not_utf8" % name
    signer_host = did_of(kid).split(":", 2)[2] if did_of(kid).startswith("did:web:") else None
    pub = publisher_of_urn(obj.get("identifier"))
    exact = None if pub is None else signer_host == pub
    return "%s L=%s D=%s subject=%s entry.digest=%s authenticated_signer=%s publisher=%s exact_match=%s alg=%s" % (
        name, ok_l, ok_d, "subject" in tm, "digest" in obj, signer_host, pub, exact, alg)


def main(cat_path, did_path):
    try:
        cat = strict_loads(open(cat_path, encoding="utf-8").read())
        did = strict_loads(open(did_path, encoding="utf-8").read())
        methods, assertion = load_keys(did)
    except Refusal as exc:
        print("DOCUMENT REFUSED", exc)
        return 3
    objs = [("host", cat["host"])] if "host" in cat else []
    objs += [("entries[%d]" % i, e) for i, e in enumerate(cat.get("entries", []))]
    for name, obj in objs:
        print(check_object(name, obj, did, methods, assertion))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
