# Conformance matrix

Reader: agent-evidence-vectors 0.36.3, agent-evidence-verify 0.5.0.

Coverage: 4 of 13 projects have at least one cell with a result (agrees, contradicted or cannot-tell).

Source: "their records" = the project's own record bytes were read; "our adapter" = code in adapters/ carried their record to our reader or their code to our corpus.

| # | Project | Cell | Source | Verdict | Evidence |
|---|---|---|---|---|---|
| 1 | AER-1 execution receipts | whole | none | not run | not run in this matrix |
| 2 | Action Evidence Packages | JCS function against vectors-a2a-jcs-v01 (rfc8785 target) | our adapter | contradicted (2 of 53) | adapters/eatf-jcs-run.txt: A5-002 (1e21) and A5-012 (1e20) refused, 51 of 53 agree |
| 2 | Action Evidence Packages | .aep packages, hash and JCS layers | their records | agrees (11 of 13; 1 cannot-tell; 1 contradicted (the intended tamper)) | adapters/aep-layers-run.txt |
| 2 | Action Evidence Packages | signatures, timestamp, ML-DSA | none | not run | adapter reads no keys |
| 3 | Agent credential conformance | whole | none | not run | not run in this matrix |
| 4 | Agent action evidence interop | audit-record and approval-binding readers in the champion's CI | their records | not run | the project reports 217/217 and 37/37 in its own interop README; not reproduced here |
| 5 | Agent memory integrity | results/report-v01.json through --read-w3c-report | their records | agrees | adapters/agmi-w3c-report-run.txt: conforms, exit 0 |
| 5 | Agent memory integrity | submissions/w3c-agent-conformance-v1.json | their records | unsupported | refused on shape: a different wrapper than report/v0.1 |
| 6 | Independent time anchoring | whole | none | not run | not run in this matrix |
| 7 | TTTPS and AUDIT testbed | whole | none | not run | not run in this matrix |
| 8 | WEXP Appraisal Core with SCITT | Core-02 corpora 001 and 002 (89 + 35 cases) through wexp_check against the frozen expectations | their records | agrees (124 of 124) | adapters/wexp-run.txt (adapters/wexp_adapter.py) |
| 8 | WEXP Appraisal Core with SCITT | an agent-audit-record member mapped to a normalized Core-02 input | our adapter | not run | mapping needs the champion's input; row ADP-WEXP-1 |
| 9 | Formal model of MCP Authorization | Tamarin model | none | unsupported | no records emitted |
| 10 | DNS Based Agent Discovery | whole | none | unsupported | discovery records, not evidence records |
| 11 | DAWN ARD | whole | none | unsupported | manifests, not evidence records |
| 12 | ICON observability | whole | none | unsupported | no signed or hashed record format read |
| 14 | AI Runtime Evidence Protocol (AIREP) | v0.2 beta lifecycle fixtures through the reference reconciler versus committed expected JSON | our adapter | agrees (11 of 11; expected FAILURE/MISSING/NOT_EVALUATED/INDETERMINATE preserved) | adapters/airep-run.txt (adapters/airep_adapter.py) |
| 14 | AI Runtime Evidence Protocol (AIREP) | authorized/executed action digest equality: complete fixture | our adapter | agrees (supplied digests equal; no event-truth claim) | adapters/airep-run.txt (adapters/airep_adapter.py) |
| 14 | AI Runtime Evidence Protocol (AIREP) | authorized/executed action digest equality: toctou-mismatch fixture | our adapter | contradicted (intentional unequal digests, despite valid signatures) | adapters/airep-run.txt (adapters/airep_adapter.py) |
| 14 | AI Runtime Evidence Protocol (AIREP) | authorized/executed action digest equality: no-execution fixture | our adapter | cannot-tell (Execution absent; comparison NOT_EVALUATED; not proof of non-execution) | adapters/airep-run.txt (adapters/airep_adapter.py) |
| 14 | AI Runtime Evidence Protocol (AIREP) | Certisyn consumer/verifier on original v0.2 handoff corpus v0.1: process, class, channels, observer and producer-crypto projection | our adapter | contradicted (17 agree, 1 contradicted (CLS-XT1 expected-projection defect); all 18 raw outputs reproduced byte-exact) | adapters/airep-run.txt (adapters/airep_adapter.py) |
| 14 | AI Runtime Evidence Protocol (AIREP) | AIREP records through the shared agent-evidence-verify reader | none | not run | adapters/airep_adapter.py: only scoped AIREP replay; no general cross-format interoperability claim |
