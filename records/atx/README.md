# ATX sample records

Five conformance fixtures of the ATX specification (Agent Trust eXtension, a
signed credential about an agent build), copied byte for byte from
`fixtures/` of https://github.com/opena2a-standards/atx-conformance at commit
5f260e15eaadd92b290303e54384a3a30342f804, under that repository's Apache-2.0
licence. Their SHA-256 digests are the ones that commit's `MANIFEST.sha256`
pins; `adapters/atx-layers-run.txt` prints each digest beside its verdict.

Each record wraps one credential (`atx`) with the verifier state the fixture
pins (`verifierState`: clock, trusted issuers, public keys) and the outcome a
conforming verifier reaches (`expected`). Every key is a TEST-ONLY key: the
primary Ed25519 key is RFC 8032 section 7.1 Test 1, and the ML-DSA-65 key is
derived from a published seed. Nothing here is a production credential.

| Record | Form | Expected | What it shows |
|---|---|---|---|
| baseline-valid.json | v1.0, pipe-delimited signing string (core.md 1.3a.1) | ACCEPT | one Ed25519 signature over the legacy form |
| v1_1-baseline-valid.json | v1.1, RFC 8785 of the to-be-signed projection (core.md 1.3a.2) | ACCEPT | capabilities, scanSummary, issuerChain and publisher are under the signature |
| v1_1-baseline-valid-hybrid.json | v1.1, same bytes | ACCEPT | Ed25519 and ML-DSA-65 (FIPS 204) signatures over the same bytes |
| tampered-signature.json | v1.0 | REJECT (SIGNATURE_INVALID) | one bit of the Ed25519 signature flipped after signing |
| v1_1-tampered-capabilities.json | v1.1 | REJECT (SIGNATURE_INVALID) | capabilities escalated after signing; the recomputed bytes no longer match |

## Read them with the adapter in this repository

```
pip install rfc8785==0.1.4 cryptography
python adapters/atx_layers.py records/atx
```

The adapter recomputes the signing bytes from the credential alone and verifies
the Ed25519 entries with the test key the record names. It does not read
ML-DSA-65 entries, the validity window, the trusted-issuer set, revocation or
the distinct-authority count.

## Read them with the project's reference verifiers

Both verifiers cover ML-DSA-65, expiry, revocation and the trusted-issuer set,
and compare their verdict with `expected`. With Go 1.22 or later and nothing
cloned (the first run downloads the module):

```
go run github.com/opena2a-standards/atx-conformance/cmd/atx-verify@5f260e15eaadd92b290303e54384a3a30342f804 records/atx/baseline-valid.json
```

With Python 3.11 or later, from a clone of the project at that commit:

```
python3 -m pip install -r verifiers/python/requirements.txt
python3 verifiers/python/verify.py records/atx
```

Specification: https://github.com/opena2a-standards/atx-spec (core.md, sections
1.1, 1.3, 1.3a and 12). The suite's scope, and what it does not verify, is in
docs/scope.md of the conformance repository.
