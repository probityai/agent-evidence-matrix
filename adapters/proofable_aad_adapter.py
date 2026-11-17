"""Adapter: Proofable authority-at-dispatch packet (proofable/docs, public/evidence/aaif/authority-at-dispatch/2026-11-02-suite).

Reads the packet from a checkout of proofable/docs (argument 1) and checks it three ways:
  sums     SHA256SUMS: every listed file's SHA-256 recomputed here with hashlib, no code of theirs
  verify   their offline verifier verify-portable-proofs.mjs (@proofable/sdk, installed in the packet
           directory as its README says) on their 15 CAIP-380 envelopes: every signature and qHash, and
           the signer the README names
  tamper   for each envelope, one digit of its signed content is changed in a scratch copy and the same
           verifier is run again; it must refuse exactly that envelope and exit 1
Also reports the case coverage the manifest states against the records in trace.jsonl.
Prints one line per check and a summary; exit 0 iff every check holds.
"""
import hashlib
import json
import pathlib
import re
import shutil
import subprocess
import sys

PACKET = pathlib.Path("public/evidence/aaif/authority-at-dispatch/2026-11-02-suite")
SIGNER = "0xa41494e1e5f9e5eaf786961e6ef84cd1a3071eec"
VERIFIER = "verify-portable-proofs.mjs"


def run_verifier(directory: pathlib.Path) -> tuple[int, dict[str, str]]:
    """Run their verifier in `directory`; {qHash: 'PASS <signer>' or 'FAIL'} and the exit code."""
    out = subprocess.run(["node", VERIFIER], cwd=directory, capture_output=True, text=True)
    lines = {}
    for line in (out.stdout + out.stderr).splitlines():
        m = re.match(r"PASS (0x[0-9a-f]{64}) (0x[0-9a-fA-F]{40})", line)
        if m:
            lines[m.group(1)] = f"PASS {m.group(2).lower()}"
            continue
        m = re.match(r"(0x[0-9a-f]{64}) ", line)
        if m:
            lines[m.group(1)] = "FAIL"
    return out.returncode, lines


def change_one_digit(text: str) -> str:
    """The same string with its first decimal digit replaced by a different digit."""
    m = re.search(r"[0-9]", text)
    if not m:
        raise SystemExit("setup error: no digit to change in an envelope's content")
    d = m.group(0)
    return text[: m.start()] + ("1" if d != "1" else "2") + text[m.end():]


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: proofable_aad_adapter.py <proofable/docs checkout>")
        return 2
    packet = pathlib.Path(sys.argv[1]) / PACKET
    # npm installs into the nearest package.json root, which in a full proofable/docs checkout is above the packet.
    if not any((d / "node_modules" / "@proofable" / "sdk").is_dir() for d in (packet, *packet.parents)):
        print(f"setup error: install the SDK first: (cd {packet} && npm install --no-save @proofable/sdk@0.1.11)")
        return 2
    ok = True

    # sums
    listed = [line.split(None, 1) for line in (packet / "SHA256SUMS").read_text().splitlines() if line.strip()]
    sums_ok = 0
    for digest, name in listed:
        name = name.lstrip("*").strip()
        got = hashlib.sha256((packet / name).read_bytes()).hexdigest()
        good = got == digest
        sums_ok += good
        print(f"{'ok  ' if good else 'DIFF'}  sums    {name}")
    ok &= sums_ok == len(listed)

    # verify
    envelopes = json.loads((packet / "portable-proofs.json").read_text(encoding="utf-8"))
    code, seen = run_verifier(packet)
    verify_ok = 0
    for env in envelopes:
        good = seen.get(env["qHash"]) == f"PASS {SIGNER}"
        verify_ok += good
        kind = json.loads(env["data"]["content"]).get("kind")
        print(f"{'ok  ' if good else 'DIFF'}  verify  {env['qHash']}  {kind}")
    ok &= code == 0 and verify_ok == len(envelopes)

    # tamper
    scratch = packet / ".matrix-scratch"
    tamper_ok = 0
    try:
        scratch.mkdir(exist_ok=True)
        shutil.copy(packet / VERIFIER, scratch / VERIFIER)
        for i, env in enumerate(envelopes):
            edited = json.loads(json.dumps(envelopes))
            edited[i]["data"]["content"] = change_one_digit(edited[i]["data"]["content"])
            (scratch / "portable-proofs.json").write_text(json.dumps(edited, indent=2), encoding="utf-8")
            tcode, tseen = run_verifier(scratch)
            others_pass = all(tseen.get(e["qHash"], "").startswith("PASS") for j, e in enumerate(envelopes) if j != i)
            good = tcode == 1 and tseen.get(env["qHash"]) == "FAIL" and others_pass
            tamper_ok += good
            print(f"{'ok  ' if good else 'DIFF'}  tamper  {env['qHash']}  refused={tseen.get(env['qHash'])}")
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    ok &= tamper_ok == len(envelopes)

    # coverage (reported, as the manifest states it)
    manifest = json.loads((packet / "manifest.json").read_text(encoding="utf-8"))
    trace = [json.loads(line) for line in (packet / "trace.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    print(f"info  coverage  manifest case_coverage={json.dumps(manifest.get('case_coverage'))}; trace.jsonl records={len(trace)}")

    print()
    print(f"sums {sums_ok} of {len(listed)}; verify {verify_ok} of {len(envelopes)}; tamper refused {tamper_ok} of {len(envelopes)}")
    print(f"EXIT={0 if ok else 1}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
