"""Adapter: the Python rfc8785 package behind the a2a-jcs-v01 verifier contract.

Contract (agent-evidence-vectors docs/reference/corpus-readers.md):
  <verifier> rfc8785 <input.json>   exit 0 and {"canonical_utf8_hex": ...} on stdout,
                                    exit 1 when the input has no canonical form.
The canonicalizer is the Python rfc8785 package.
Nothing of ours is mixed in.
"""
import json
import os
import sys


import rfc8785  # noqa: E402


def main(argv):
    if len(argv) != 3 or argv[1] not in ("rfc8785", "card-signing-input"):
        print("usage: rfc8785_cli.py rfc8785 <input.json>", file=sys.stderr)
        return 2
    raw = open(argv[2], "rb").read()
    try:
        value = json.loads(raw.decode("utf-8"), parse_constant=_refuse)
        out = rfc8785.dumps(value)
    except Exception as exc:  # any refusal means: no canonical form
        print(type(exc).__name__, file=sys.stderr)
        return 1
    print(json.dumps({"canonical_utf8_hex": out.hex()}))
    return 0


def _refuse(token):
    raise ValueError(token)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
