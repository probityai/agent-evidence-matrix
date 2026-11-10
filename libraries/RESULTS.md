# Cross-implementation results

JCS cases: 20140; implementations: rust-jcs-admit, go-gowebpki-jcs, py-rfc8785, node-canonicalize

| family | cases | all four agree, same bytes | all four refuse | split |
|---|---|---|---|---|
| aer1-kit | 85 | 84 | 0 | 1 |
| invalid-utf8-or-bom | 3 | 0 | 2 | 1 |
| numbers | 20022 | 20017 | 2 | 3 |
| rfc8785-testdata | 6 | 6 | 0 | 0 |
| strings | 9 | 7 | 2 | 0 |
| structure | 15 | 7 | 5 | 3 |
| **total** | 20140 | 20121 | 11 | 8 |

jcs-admit output differing from the RFC 8785 reference expected output: 0 (none)

## Every split case

| case | rust-jcs-admit | go-gowebpki-jcs | py-rfc8785 | node-canonicalize |
|---|---|---|---|---|
| num/20005 | [9007199254740992] | [9007199254740992] | REFUSE IntegerDomainError: 9007199254740992 exceeds safe integer domain for JSON floats | [9007199254740992] |
| num/20006 | [9007199254740992] | [9007199254740992] | REFUSE IntegerDomainError: 9007199254740993 exceeds safe integer domain for JSON floats | [9007199254740992] |
| num/20014 | [1.2345678901234568e+29] | [1.2345678901234568e+29] | REFUSE IntegerDomainError: 123456789012345678901234567890 exceeds safe integer domain for  | [1.2345678901234568e+29] |
| bytes/2 | REFUSE Syntax { offset: 0, reason: "expected a JSON value" } | REFUSE Unexpected non-ASCII character | REFUSE JSONDecodeError: Unexpected UTF-8 BOM (decode using utf-8-sig): line 1 column 1 (ch | {} |
| struct/0 | REFUSE DuplicateMember { name: "a", offset: 7 } | REFUSE Duplicate key: "a" | {"a":2} | {"a":2} |
| struct/1 | REFUSE TooDeep { limit: 128, offset: 128 } | [[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[ | REFUSE RecursionError: maximum recursion depth exceeded | [[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[ |
| struct/2 | REFUSE TooDeep { limit: 128, offset: 128 } | [[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[ | REFUSE RecursionError: maximum recursion depth exceeded | [[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[ |
| aer1/base/test-vectors/invalid/duplicate-member-name.json | REFUSE DuplicateMember { name: "output_hash", offset: 436 } | REFUSE Duplicate key: "output_hash" | {"canonical_bytes":"eyJpbnB1dHMiOnt9LCJvdXRwdXRzIjp7IngiOjEyM30sInRvb2wiOiJ0In0=","created | {"canonical_bytes":"eyJpbnB1dHMiOnt9LCJvdXRwdXRzIjp7IngiOjEyM30sInRvb2wiOiJ0In0=","created |

## DSSE

PAE byte agreement across rust dsse, Go securesystemslib, Python securesystemslib: 400 of 400

| direction | verified | of |
|---|---|---|
| rust-sign.go-verify | 343 | 400 |
| go-sign.rust-verify | 343 | 400 |
| rust-sign.rust-verify | 343 | 400 |
| tampered.rust-verify | 0 | 343 |
| tampered.go-verify | 0 | 343 |
