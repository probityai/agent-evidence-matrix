"""Adapter: read EATF .aep packages and check the two layers that need no key.

Layer 1: sha256(canonical.bin) == hash.sha256
Layer 2: canonical.bin == response.txt || LF || RFC 8785 (metadata.json)
         (the current AEP profile, docs/aep-format.md step 3; the legacy
         response-only form is reported as 'legacy', not as agreement)
Signature, RFC 3161 and ML-DSA layers are NOT read here.
Verdict per package: agrees (both layers hold), contradicted (a layer fails),
cannot-tell (package unreadable or entry missing).
usage: aep_layers.py <test-vectors dir with valid/ and invalid/>
"""
import hashlib
import json
import pathlib
import sys
import zipfile

import rfc8785


def layers(path):
    try:
        with zipfile.ZipFile(path) as z:
            names = set(z.namelist())
            need = {"response.txt", "canonical.bin", "hash.sha256", "metadata.json"}
            if not need <= names:
                return "cannot-tell", "missing " + ",".join(sorted(need - names))
            e = {n: z.read(n) for n in need}
        meta = json.loads(e["metadata.json"].decode("utf-8"))
        l1 = hashlib.sha256(e["canonical.bin"]).hexdigest() == e["hash.sha256"].decode().strip()
        want = e["response.txt"] + b"\n" + rfc8785.dumps(meta)
        l2 = e["canonical.bin"] == want
        legacy = e["canonical.bin"] == e["response.txt"]
    except Exception as exc:
        return "cannot-tell", type(exc).__name__
    if l1 and l2:
        return "agrees", "hash+jcs"
    if l1 and legacy:
        return "agrees", "legacy response-only form"
    return "contradicted", f"hash={l1} jcs-form={l2}"


def main(root):
    rows = []
    for label in ("valid", "invalid"):
        for p in sorted(pathlib.Path(root, label).glob("*/package.aep")):
            v, why = layers(p)
            rows.append((label, p.parent.name, v, why))
            print(f"{label}/{p.parent.name}\t{v}\t{why}")
    return rows


if __name__ == "__main__":
    main(sys.argv[1])
