"""Render matrix.json to MATRIX.md and badges/, and refuse a matrix whose cells break the schema.

    python build_matrix.py              rewrite MATRIX.md and badges/, print the coverage counts
    python build_matrix.py --check      exit 1 when MATRIX.md or badges/ differ from what matrix.json renders
    python build_matrix.py --freshness  compare each pinned upstream commit with the upstream default branch
                                        (GitHub only, read-only GETs through `gh api`); prints warnings, exit 0

The schema rules, each a refusal (exit 1 with every problem named):

- every project has a review entry in reviews.json, and every project id (in matrix.json and in reviews.json) is a
  positive integer; a project under a frozen review must keep the exact bytes its review recorded (its digest), and of
  the rules below only one applies to it: every repository path it cites still resolves inside this tree;
- a verdict is one of the listed codes and a source one of "their records", "our adapter", "none";
- a contradicted cell carries basis, divergence_in and declared_revision; a refusal inside a declared
  profile is not a contradiction, so basis "declared-profile" requires verdict unsupported and a profile;
- every repository path an evidence string cites resolves to a file or directory inside this tree (a path
  that climbs out through `..` or a symlink is refused), and no evidence string cites a path that exists on
  one machine only;
- a project with a result (agrees, contradicted or cannot-tell) names its upstream pin and a replay command;
- an upstream is one repository: `url` is https://<host>/<owner>/<repo> (no `.git`, no trailing slash, no
  prose) and `sha` its 40-hex commit; further inputs go in `also` (each a url with a 40-hex `sha` for a
  repository or a 64-hex `sha256` for a fetched file) and free text in `note`;
- two projects never share one upstream: compared without case, over every project, frozen ones included;
- property columns use the listed names and verdict codes;
- a project that withholds its source (the small-project rule: a project far below the citation line is never named)
  carries `withheld` instead of an upstream: the reason and the SHA-256 of every input its cells read, and a replay
  that runs on a copy of those bytes; it carries no upstream, and its name and cells must not name the project;
- a `canonicalizer` record names the function a project canonicalizes with, its kind, what it takes (a parsed value,
  text or the received bytes) and, in `parse_layer`, what it did with the four probes that have no canonical form at
  the parse or decode layer (two duplicate members, a surrogate written as UTF-8 bytes, a raw 0xFF byte): refused
  (all four), accepted (any one), "parsed before it" (a function that takes a parsed value never sees them, so their
  outcome belongs to whatever parses before it), or not probed; anything but not probed needs the run that showed it;
- a cell whose evidence is "no records emitted" names its producer route: `producer` is the cell of this project that
  reads records the project's own code produced (producer mode), or "none" with the reason no producer exists;
- README.md carries the coverage counts between its counts markers, and --check refuses a README that disagrees.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).parent

RESULT = ("agrees", "contradicted", "cannot-tell")
SOURCES = ("their records", "our adapter", "none")
BASIS = ("defect", "adapter", "upstream-moved", "revision-skew", "declared-profile")
DIVERGENCE_IN = ("their records", "their code", "their spec", "corpus", "our adapter", "our reader")
INDEPENDENCE = ("author", "same-owner", "co-author", "non-author")
COLUMNS = (
    "edit detection",
    "digest input declared",
    "authorized = executed",
    "declared versus acted",
    "verdict re-derived",
    "re-proven by us",
)
REVIEW_STATES = ("published", "frozen")
PATH = re.compile(r"(?<![\w/.-])((?:\.{1,2}/)*(?:adapters|records|libraries|tests|tools|badges)/[\w.@+/-]*[\w@+-])")
ONE_MACHINE = re.compile(r"(?<![\w.~/-])(?:/home/|/Users/|/root/|/tmp/|/private/|/var/folders/|/mnt/|~/)"
                         r"|\$HOME\b|\$\{HOME\}|(?i:\b[a-z]:\\users\\)|_raw/|probity-lanes")
REPO_URL = re.compile(r"https://[a-z0-9.-]+\.[a-z]{2,}/[\w.-]+/[\w.-]+")
FILE_URL = re.compile(r"https://[a-z0-9.-]+\.[a-z]{2,}/\S+")
SHA1 = re.compile(r"[0-9a-f]{40}")
CANON_KINDS = ("rfc8785 library", "vendored rfc8785", "hand-rolled", "own serialization, not RFC 8785")
CANON_INPUTS = ("parsed value", "text", "received bytes")
CANON_PARSE_LAYER = ("refused", "accepted", "parsed before it", "not probed")
NO_RECORDS = "no records emitted"
COUNTS_START, COUNTS_END = "<!-- counts:start -->", "<!-- counts:end -->"
SHA256 = re.compile(r"[0-9a-f]{64}")
# Anything that locates a repository or a site: a scheme URL, an scp-style git remote, or host.tld/path with no scheme.
# A withheld project carries none of them anywhere in its entry, its withheld block included; only our own corpus
# (github.com/probityai/...) may be named, because a replay clones it.
ANY_LOCATOR = re.compile(r"(?i)(?:\b[a-z][a-z0-9+.-]*://[^\s)\]\"']+|\b[\w.-]+@[a-z0-9.-]+\.[a-z]{2,}:[\w./-]+"
                         r"|(?<![\w@/.-])(?:[a-z0-9-]+\.)+[a-z]{2,}/[^\s)\]\"']*)")
OWN_LOCATOR = re.compile(r"(?i)^(?:https://)?github\.com/probityai/")


def project_digest(project: dict) -> str:
    """SHA-256 over the project entry's sorted, compact JSON form; a frozen review records it."""
    text = json.dumps(project, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def esc(text) -> str:
    """Keep a pipe inside a cell from splitting the Markdown table row."""
    return str(text).replace("|", "\\|").replace("\n", " ")


def _evidence_problems(where: str, evidence: str, root: pathlib.Path) -> list[str]:
    out = []
    if ONE_MACHINE.search(evidence):
        out.append(f"{where}: evidence cites a path that exists on one machine only: {evidence[:120]!r}")
    top = root.resolve()
    for path in PATH.findall(evidence):
        target = (root / path).resolve()
        if not target.is_relative_to(top):
            out.append(f"{where}: evidence path {path} leaves this tree")
        elif not target.exists():
            out.append(f"{where}: evidence path {path} does not resolve in this tree")
    return out


def upstream_key(url: str) -> str:
    """The form two upstream URLs are compared in: without case, `.git` or a trailing slash."""
    key = (url or "").strip().lower().rstrip("/")
    return key[:-4] if key.endswith(".git") else key


def _repo_url_ok(url) -> bool:
    return (isinstance(url, str) and REPO_URL.fullmatch(url) is not None and not url.endswith(".git")
            and url == url.strip())


def _upstream_problems(pid, up: dict) -> list[str]:
    out = []
    if "url" in up and not _repo_url_ok(up["url"]):
        out.append(f"project {pid}: upstream.url {str(up['url'])[:80]!r} is not one repository URL "
                   "https://<host>/<owner>/<repo>; put further inputs in upstream.also and prose in upstream.note")
    if "sha" in up and not (isinstance(up["sha"], str) and SHA1.fullmatch(up["sha"])):
        out.append(f"project {pid}: upstream.sha {str(up['sha'])[:60]!r} is not a 40-hex commit")
    unknown = set(up) - {"url", "sha", "also", "note", "released"}
    if unknown:
        out.append(f"project {pid}: upstream has unknown keys {sorted(unknown)}")
    if "note" in up and not (isinstance(up["note"], str) and up["note"].strip()):
        out.append(f"project {pid}: upstream.note is a non-empty string")
    also = up.get("also", [])
    if not isinstance(also, list):
        return out + [f"project {pid}: upstream.also is a list"]
    for i, item in enumerate(also):
        where = f"project {pid}: upstream.also[{i}]"
        if not isinstance(item, dict) or set(item) not in ({"url", "sha"}, {"url", "sha256"}):
            out.append(f"{where} is {{url, sha}} for a repository or {{url, sha256}} for a fetched file")
        elif "sha" in item and not (_repo_url_ok(item["url"]) and isinstance(item["sha"], str)
                                    and SHA1.fullmatch(item["sha"])):
            out.append(f"{where}: a repository input needs a repository URL and a 40-hex sha")
        elif "sha256" in item and not (isinstance(item["url"], str) and FILE_URL.fullmatch(item["url"])
                                       and isinstance(item["sha256"], str) and SHA256.fullmatch(item["sha256"])):
            out.append(f"{where}: a file input needs an https URL and a 64-hex sha256")
    return out


def _contradiction_problems(where: str, cell: dict) -> list[str]:
    """A contradicted cell names its basis, where the divergence sits and the revision it was judged against."""
    if cell.get("verdict") != "contradicted":
        return []
    out = [f"{where}: a contradicted cell needs {key}"
           for key in ("basis", "divergence_in", "declared_revision") if not cell.get(key)]
    if cell.get("basis") == "declared-profile":
        out.append(f"{where}: a refusal inside a declared profile is unsupported, not contradicted")
    return out


def _cell_problems(where: str, cell: dict, codes: set[str], root: pathlib.Path) -> list[str]:
    out = []
    verdict = cell.get("verdict")
    if verdict not in codes:
        out.append(f"{where}: unknown verdict {verdict!r}")
    if cell.get("source") not in SOURCES:
        out.append(f"{where}: source {cell.get('source')!r} is not one of {list(SOURCES)}")
    for key in ("cell", "evidence"):
        if not isinstance(cell.get(key), str) or not cell[key].strip():
            out.append(f"{where}: {key} is missing")
    basis = cell.get("basis")
    if basis is not None and basis not in BASIS:
        out.append(f"{where}: basis {basis!r} is not one of {list(BASIS)}")
    if cell.get("divergence_in") is not None and cell["divergence_in"] not in DIVERGENCE_IN:
        out.append(f"{where}: divergence_in {cell['divergence_in']!r} is not one of {list(DIVERGENCE_IN)}")
    out += _contradiction_problems(where, cell)
    if basis == "declared-profile":
        if verdict != "unsupported":
            out.append(f"{where}: basis declared-profile requires verdict unsupported")
        if not cell.get("profile"):
            out.append(f"{where}: basis declared-profile requires the profile it names")
    if "expected" in cell and not cell.get("expected_source"):
        out.append(f"{where}: expected needs expected_source")
    if "expected" in cell and "observed" in cell:
        # A record that declares the outcome it should get, and gets it, agrees, even when that
        # outcome is a refusal; a different outcome is never agreement.
        if cell["expected"] == cell["observed"] and verdict != "agrees":
            out.append(f"{where}: observed equals expected ({cell['observed']!r}), so the verdict is agrees")
        if cell["expected"] != cell["observed"] and verdict == "agrees":
            out.append(f"{where}: observed {cell['observed']!r} differs from expected {cell['expected']!r}")
    if "read_their_code" in cell and not isinstance(cell["read_their_code"], bool):
        out.append(f"{where}: read_their_code is true or false")
    if isinstance(cell.get("evidence"), str):
        out += _evidence_problems(where, cell["evidence"], root)
    return out


def _withheld_problems(pid, project: dict) -> list[str]:
    held = project["withheld"]
    out = []
    if not isinstance(held, dict) or not isinstance(held.get("reason"), str) or not held["reason"].strip():
        return [f"project {pid}: withheld needs a reason"]
    inputs = held.get("inputs")
    if not isinstance(inputs, list) or not inputs:
        out.append(f"project {pid}: withheld needs the inputs its cells read")
    for i, item in enumerate(inputs or []):
        if not (isinstance(item, dict) and isinstance(item.get("what"), str) and item["what"].strip()
                and isinstance(item.get("sha256"), str) and SHA256.fullmatch(item["sha256"])):
            out.append(f"project {pid}: withheld.inputs[{i}] needs what and a 64-hex sha256")
    if project.get("upstream"):
        out.append(f"project {pid}: a withheld project carries no upstream")
    text = json.dumps(project, ensure_ascii=False)
    found = sorted({m.group(0) for m in ANY_LOCATOR.finditer(text) if not OWN_LOCATOR.match(m.group(0))})
    if found:
        out.append(f"project {pid}: a withheld project names no repository URL or site, its withheld block included "
                   f"(found {found[:3]})")
    return out


def _canonicalizer_problems(pid, rec, root: pathlib.Path) -> list[str]:
    where = f"project {pid}: canonicalizer"
    if not isinstance(rec, dict):
        return [f"{where} is an object"]
    out = []
    if not isinstance(rec.get("function"), str) or not rec["function"].strip():
        out.append(f"{where} needs the function it names")
    if rec.get("kind") not in CANON_KINDS:
        out.append(f"{where} kind {rec.get('kind')!r} is not one of {list(CANON_KINDS)}")
    if rec.get("input") not in CANON_INPUTS:
        out.append(f"{where} input {rec.get('input')!r} is not one of {list(CANON_INPUTS)}")
    unknown = set(rec) - {"function", "kind", "input", "parse_layer", "evidence"}
    if unknown:
        out.append(f"{where} has unknown keys {sorted(unknown)}")
    layer = rec.get("parse_layer")
    if layer not in CANON_PARSE_LAYER:
        out.append(f"{where} parse_layer {layer!r} is not one of {list(CANON_PARSE_LAYER)}")
        return out
    if rec.get("input") == "parsed value" and layer in ("refused", "accepted"):
        out.append(f"{where} takes a parsed value, so it never sees the parse layer: parse_layer is "
                   "\"parsed before it\" or \"not probed\", never " + repr(layer))
    if layer == "parsed before it" and rec.get("input") in CANON_INPUTS and rec["input"] != "parsed value":
        out.append(f"{where} takes {rec['input']}, so the parse layer reaches it: parse_layer is refused, accepted or "
                   "not probed")
    if layer == "not probed":
        if rec.get("evidence"):
            out.append(f"{where} is not probed and cites a run")
    elif not isinstance(rec.get("evidence"), str) or not rec["evidence"].strip():
        out.append(f"{where} says {layer} and names no run that showed it")
    else:
        out += _evidence_problems(where, rec["evidence"], root)
    return out


def _says_no_records(cell) -> bool:
    """A cell whose evidence says the project emitted no records, however it is capitalised or punctuated."""
    ev = cell.get("evidence") if isinstance(cell, dict) else None
    return isinstance(ev, str) and re.match(r"(?i)\s*no records (?:were )?emitted\b", ev) is not None


def _project_problems(project: dict, codes: set[str], root: pathlib.Path) -> list[str]:
    pid = project.get("id")
    out = []
    cells = project.get("cells") or []
    if not cells:
        out.append(f"project {pid}: no cells")
    for i, cell in enumerate(cells, 1):
        out += _cell_problems(f"project {pid} cell {i}", cell, codes, root)
        if _says_no_records(cell):
            producer = cell.get("producer")
            target = re.fullmatch(r"cell (\d+)", producer) if isinstance(producer, str) else None
            n = int(target.group(1)) if target else 0
            if not isinstance(producer, str) or not producer.strip():
                out.append(f"project {pid} cell {i}: \"{NO_RECORDS}\" names its producer route (a cell reading "
                           "records the project's own code produced, or none with the reason)")
            elif target and (n == i or not 1 <= n <= len(cells)):
                out.append(f"project {pid} cell {i}: producer {producer!r} is not another cell of this project")
            elif target and _says_no_records(cells[n - 1]):
                # two "no records" cells naming each other would each claim a producer route and neither reads one
                out.append(f"project {pid} cell {i}: producer {producer!r} itself says \"{NO_RECORDS}\"; the "
                           "producer cell reads records the project's own code produced")
            elif not target and not re.fullmatch(r"none: \S.*", producer.strip()):
                out.append(f"project {pid} cell {i}: producer {producer!r} is neither another cell of this project "
                           "nor \"none: <reason>\"")
    has_result = any(c.get("verdict") in RESULT for c in cells)
    up = project.get("upstream") or {}
    if "withheld" in project:
        out += _withheld_problems(pid, project)
        if has_result and not project.get("replay"):
            out.append(f"project {pid}: a withheld project with a result needs a replay over the withheld bytes")
    elif has_result and not (up.get("url") and up.get("sha") and project.get("replay")):
        out.append(f"project {pid}: a project with a result needs upstream.url, upstream.sha and replay")
    if "canonicalizer" in project:
        out += _canonicalizer_problems(pid, project["canonicalizer"], root)
    out += _upstream_problems(pid, up)
    if project.get("independence") is not None and project["independence"] not in INDEPENDENCE:
        out.append(f"project {pid}: independence {project['independence']!r} is not one of {list(INDEPENDENCE)}")
    released = up.get("released")
    if released is not None:
        if not (isinstance(released, dict) and released.get("registry") and released.get("version")
                and isinstance(released.get("same_as_source"), bool)):
            out.append(f"project {pid}: upstream.released needs registry, version and same_as_source")
    for name, value in (project.get("columns") or {}).items():
        if name not in COLUMNS:
            out.append(f"project {pid}: unknown column {name!r}")
            continue
        if not isinstance(value, dict) or value.get("verdict") not in codes:
            out.append(f"project {pid}: column {name!r} needs a verdict code")
        elif value.get("evidence"):
            out += _evidence_problems(f"project {pid} column {name!r}", value["evidence"], root)
        if isinstance(value, dict) and value.get("verdict") in RESULT and not value.get("evidence"):
            out.append(f"project {pid}: column {name!r} has a result and no evidence")
    return out


def problems(data: dict, reviews: dict, root: pathlib.Path = ROOT) -> list[str]:
    """Every schema refusal for ``data`` (matrix.json) under ``reviews`` (reviews.json)."""
    codes = set(data.get("verdicts") or [])
    out = []
    by_project = {}
    for entry in reviews.get("reviews") or []:
        pid = entry.get("project")
        if not _is_id(pid):
            out.append(f"reviews.json: a review names project {pid!r}; a project id is a positive integer")
        if pid in by_project:
            out.append(f"reviews.json: project {pid} reviewed twice")
        by_project[pid] = entry
        if entry.get("state") not in REVIEW_STATES:
            out.append(f"reviews.json: project {pid} state {entry.get('state')!r} is not one of {list(REVIEW_STATES)}")
        if not entry.get("review") or not entry.get("date"):
            out.append(f"reviews.json: project {pid} needs a review id and a date")
    ids = [p.get("id") for p in data.get("projects") or []]
    bad_ids = [i for i in ids if not _is_id(i)]
    if bad_ids:
        out.append(f"matrix.json: project ids {bad_ids!r} are not positive integers (a missing id, or \"1\" beside 1, "
                   "renders as a second row under one number)")
    if len(ids) != len(set(ids)):
        out.append("matrix.json: two projects share an id")
    if data.get("total_projects") != len(ids):
        out.append(f"matrix.json: total_projects {data.get('total_projects')} but {len(ids)} projects listed")
    if set(by_project) - set(ids):
        out.append(f"reviews.json: reviews for projects not in the matrix: {sorted(set(by_project) - set(ids))}")
    seen_upstream = {}
    for project in data.get("projects") or []:
        pid = project.get("id")
        # Uniqueness holds over every project: a frozen entry keeps its bytes, and a new or edited one
        # may still not take its upstream.
        url = (project.get("upstream") or {}).get("url")
        if url:
            key = upstream_key(url)
            if key in seen_upstream:
                out.append(f"projects {seen_upstream[key]} and {pid} share the upstream {url}")
            seen_upstream.setdefault(key, pid)
        review = by_project.get(pid)
        if review is None:
            out.append(f"project {pid}: no review entry in reviews.json; a project lands after its review")
            continue
        if review.get("state") == "frozen":
            if review.get("digest") != project_digest(project):
                out.append(f"project {pid}: its review is frozen and the entry changed "
                           f"(recorded {str(review.get('digest'))[:12]}, now {project_digest(project)[:12]})")
            # The digest pins the entry's bytes, not the files it cites: a frozen row still needs its evidence.
            out += _frozen_path_problems(pid, project, root)
            # The freeze fixes the bytes, not the labelling rule: a contradicted cell still names its basis.
            for i, cell in enumerate(project.get("cells") or [], 1):
                out += _contradiction_problems(f"project {pid} (frozen) cell {i}", cell)
            continue
        out += _project_problems(project, codes, root)
    return out


def _is_id(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _frozen_path_problems(pid, project: dict, root: pathlib.Path) -> list[str]:
    """Every repository path a frozen entry cites, anywhere in it, must still resolve inside this tree."""
    top = root.resolve()
    out = []
    for path in sorted(set(PATH.findall(json.dumps(project, ensure_ascii=False)))):
        target = (root / path).resolve()
        if not target.is_relative_to(top):
            out.append(f"project {pid} (frozen): evidence path {path} leaves this tree")
        elif not target.exists():
            out.append(f"project {pid} (frozen): evidence path {path} does not resolve in this tree; the review "
                       "froze the entry, and the file it cites was removed or renamed")
    return out


def _frozen(reviews: dict) -> set:
    return {r["project"] for r in reviews.get("reviews") or [] if r.get("state") == "frozen"}


def _verdict_text(cell: dict) -> str:
    text = cell["verdict"]
    tags = []
    if cell.get("basis"):
        tags.append(f"basis: {cell['basis']}")
    if cell.get("divergence_in"):
        tags.append(f"divergence in: {cell['divergence_in']}")
    if cell.get("declared_revision"):
        tags.append(f"against: {cell['declared_revision']}")
    if cell.get("profile"):
        tags.append(f"profile: {cell['profile']}")
    if cell.get("expected"):
        tags.append(f"expected: {cell['expected']} ({cell.get('expected_source', '')})")
    if "read_their_code" in cell:
        tags.append("read their code" if cell["read_their_code"] else "did not read their code")
    if tags:
        text += " [" + "; ".join(esc(t) for t in tags) + "]"
    if cell.get("detail"):
        text += " (" + esc(cell["detail"]) + ")"
    return text


def counts(data: dict) -> dict:
    """Coverage counts: projects with a result, and projects with no record our reader opened."""
    run, unread = set(), set()
    for p in data["projects"]:
        verdicts = {c["verdict"] for c in p["cells"]}
        if verdicts & set(RESULT):
            run.add(p["id"])
        if verdicts <= {"unsupported", "not run"}:
            unread.add(p["id"])
    return {"run": run, "unread": unread, "total": data["total_projects"]}


def badge(project: dict) -> dict:
    """A shields.io endpoint document: agreeing cells out of all cells of one project."""
    cells = project["cells"]
    agree = sum(c["verdict"] == "agrees" for c in cells)
    contra = sum(c["verdict"] == "contradicted" for c in cells)
    color = "red" if contra else ("brightgreen" if agree == len(cells) else ("green" if agree else "lightgrey"))
    return {"schemaVersion": 1, "label": "evidence matrix", "message": f"{agree} agrees / {len(cells)} cells",
            "color": color}


def render(data: dict, reviews: dict) -> tuple[str, dict[str, str]]:
    """MATRIX.md text and the badge files (path to text) for the current data."""
    frozen = _frozen(reviews)
    reader = data["reader"]
    c = counts(data)
    rows, replay = [], []
    for p in data["projects"]:
        for i, cell in enumerate(p["cells"]):
            num = f"<a id=\"project-{p['id']}\"></a>{p['id']}" if i == 0 else str(p["id"])
            rows.append(f"| {num} | {esc(p['name'])} | {esc(cell['cell'])} | {cell['source']} | "
                        f"{_verdict_text(cell)} | {esc(cell['evidence'])} |")
        if p.get("replay"):
            up = p.get("upstream") or {}
            pin = f"Upstream: {up.get('url', '')} at {up.get('sha', '')}\n\n" if up else ""
            for item in up.get("also", []):
                pin += f"Also read: {item['url']} at {item.get('sha') or 'sha256 ' + item['sha256']}\n\n"
            if up.get("note"):
                pin += f"Note: {up['note']}\n\n"
            rel = up.get("released")
            if rel:
                same = "the same bytes as the pinned source" if rel["same_as_source"] else "different bytes from the pinned source"
                pin += f"Released: {rel['registry']} {rel['version']}, {same}.\n\n"
            held = p.get("withheld")
            if held:
                pin += f"Withheld: {held['reason']}\n\n"
                for item in held["inputs"]:
                    pin += f"Input: {item['what']}, sha256 {item['sha256']}\n\n"
            replay.append(f"### {p['id']}. {p['name']}\n\n{pin}```\n{p['replay']}\n```\n")
    props = []
    for p in data["projects"]:
        if p["id"] in frozen:
            continue
        cols = p.get("columns") or {}
        vals = []
        for name in COLUMNS:
            v = cols.get(name)
            if v is None:
                vals.append("not run")
            else:
                text = v["verdict"] + (f" ({esc(v['detail'])})" if v.get("detail") else "")
                if v.get("evidence"):
                    text += f"; {esc(v['evidence'])}"
                vals.append(text)
        props.append(f"| {p['id']} | {esc(p['name'])} | {esc(p.get('independence', 'not stated'))} | "
                     + " | ".join(vals) + " |")
    head = (f"# Conformance matrix\n\nReader: agent-evidence-vectors {reader['agent-evidence-vectors']}, "
            f"agent-evidence-verify {reader['agent-evidence-verify']}.\n\n"
            f"Coverage: {len(c['run'])} of {c['total']} projects have at least one cell with a result "
            f"(agrees, contradicted or cannot-tell). No record read yet: {len(c['unread'])} of {c['total']} "
            f"(every cell unsupported or not run: projects {', '.join(str(i) for i in sorted(c['unread'])) or 'none'}).\n\n"
            "Source: \"their records\" = the project's own record bytes were read; \"our adapter\" = code in adapters/ carried "
            "their record to our reader or their code to our corpus.\n\n"
            "A contradicted cell names its basis (defect, adapter, upstream-moved, revision-skew), where the divergence "
            "sits, and the revision it was judged against. A refusal inside a profile the project declares is "
            "unsupported with the profile named, never contradicted.\n\n"
            "| # | Project | Cell | Source | Verdict | Evidence |\n|---|---|---|---|---|---|\n")
    text = head + "\n".join(rows) + "\n"
    if props:
        text += ("\n## Properties\n\nOne verdict per project and property, for every project whose review is not frozen. "
                 "Independence says who wrote the adapter or record relative to the project: author, same-owner, co-author "
                 "or non-author. Edit detection: six edits to a committed log (drop, swap, a status flip, a rewritten link, "
                 "a body edit, a cut tail), judged by a verifier of the format. Digest input declared: the record names its "
                 "digest algorithm and the exact bytes it covers. Authorized = executed: the record of what ran equals the "
                 "record of what was allowed. Declared versus acted: a recorded run used only what the discovery record "
                 "declared. Verdict re-derived: a verdict a record carries is recomputed from its recorded inputs. "
                 "Re-proven by us: the project's own proof or test run repeated here with the binaries' digests recorded.\n\n"
                 "| # | Project | Independence | " + " | ".join(COLUMNS) + " |\n|---|---|---|"
                 + "---|" * len(COLUMNS) + "\n" + "\n".join(props) + "\n")
    canon = [p for p in data["projects"] if p.get("canonicalizer") and p["id"] not in frozen]
    if canon:
        lines = []
        for p in canon:
            r = p["canonicalizer"]
            dup = r["parse_layer"] + (f" ({esc(r['evidence'])})" if r.get("evidence") else "")
            lines.append(f"| {p['id']} | {esc(p['name'])} | {esc(r['function'])} | {r['kind']} | {r['input']} | {dup} |")
        text += ("\n## Canonicalizers\n\nThe function each project canonicalizes with, and what it does with an input that "
                 "has no RFC 8785 canonical form at the parse or decode layer: two duplicate members, a surrogate written "
                 "as UTF-8 bytes and a raw 0xFF byte. A canonicalizer that takes a parsed value cannot see them: the parse "
                 "already kept one of two duplicate values and decoded the bytes, so the column says \"parsed before it\" "
                 "and the refusal has to happen on the received bytes, before canonicalization. CI holds the matrix's own "
                 "reader to that, and every recorded column to the probe lines of its run (tests/test_canonicalizers.py).\n\n"
                 "| # | Project | Function | Kind | Takes | Parse-layer inputs |\n|---|---|---|---|---|---|\n"
                 + "\n".join(lines) + "\n")
    if replay:
        text += ("\n## Replay\n\nEach command runs from the repository root with the pinned reader installed "
                 "(`pip install -r requirements.txt` into `venv/`).\n\n" + "\n".join(replay))
    badges = {}
    for p in data["projects"]:
        if p["id"] in frozen:
            continue
        badges[f"badges/{p['id']}.json"] = json.dumps(badge(p), indent=2) + "\n"
    return text, badges


def _github(url: str):
    m = re.match(r"https://github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?(?:[\s/]|$)", url or "")
    return (m.group(1), m.group(2)) if m else None


def freshness(data: dict, fetch=None) -> list[str]:
    """One line per GitHub repository (upstream and `also`) whose default branch moved past its pin.

    An answer that is not a 40-hex commit is a failed read, reported as not checked, never as fresh."""
    def gh_head(owner: str, repo: str) -> str:
        out = subprocess.run(["gh", "api", f"repos/{owner}/{repo}/commits/HEAD", "--jq", ".sha"],
                             capture_output=True, text=True, check=False)
        if out.returncode != 0:
            raise RuntimeError(out.stderr.strip() or f"gh api exit {out.returncode}")
        return out.stdout.strip()
    fetch = fetch or gh_head
    lines = []
    for p in data["projects"]:
        up = p.get("upstream") or {}
        pins = [(up.get("url", ""), up.get("sha"))] + [(a.get("url", ""), a.get("sha")) for a in up.get("also", [])
                                                        if isinstance(a, dict)]
        for url, pinned in pins:
            repo = _github(url)
            if not repo or not pinned:
                continue
            try:
                head = fetch(*repo)
            except RuntimeError as exc:
                lines.append(f"project {p['id']}: freshness not checked for {repo[0]}/{repo[1]} ({exc})")
                continue
            if not (isinstance(head, str) and SHA1.fullmatch(head)):
                lines.append(f"project {p['id']}: freshness not checked for {repo[0]}/{repo[1]} "
                             f"(the read returned {str(head)[:40]!r}, not a commit)")
            elif head != pinned:
                lines.append(f"project {p['id']}: upstream-moved, pinned {pinned[:12]}, "
                             f"{repo[0]}/{repo[1]} head {head[:12]}")
    return lines


def counts_text(data: dict) -> str:
    """The README's coverage sentence, between its counts markers."""
    c = counts(data)
    unread = ", ".join(str(i) for i in sorted(c["unread"])) or "none"
    held = sorted(p["id"] for p in data["projects"] if "withheld" in p)
    text = (f"`python build_matrix.py` prints `N of {c['total']}: {len(c['run'])}; no record read yet: "
            f"{len(c['unread'])} of {c['total']}` today. Rows with no record we can open: {len(c['unread'])} of "
            f"{c['total']} ({'project' if len(c['unread']) == 1 else 'projects'} {unread}): every cell is unsupported or not run.")
    if held:
        text += (f" Rows whose source is withheld under the small-project rule: {len(held)} "
                 f"({'project' if len(held) == 1 else 'projects'} {', '.join(map(str, held))}); their inputs are named by SHA-256 "
                 "under Replay in MATRIX.md.")
    return text


def readme_with_counts(readme: str, data: dict) -> str:
    """README text with the counts block rewritten; ValueError when the markers are missing."""
    a, b = readme.find(COUNTS_START), readme.find(COUNTS_END)
    if readme.count(COUNTS_START) != 1 or readme.count(COUNTS_END) != 1 or b < a:
        # a second block would never be rewritten or checked, so a stale count could sit in it
        raise ValueError(f"README.md needs exactly one {COUNTS_START} ... {COUNTS_END} block")
    return readme[: a + len(COUNTS_START)] + "\n" + counts_text(data) + "\n" + readme[b:]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="refuse when the rendered files differ")
    ap.add_argument("--freshness", action="store_true", help="report upstreams that moved past their pin")
    args = ap.parse_args(argv)
    data = json.loads((ROOT / "matrix.json").read_text(encoding="utf-8"))
    reviews = json.loads((ROOT / "reviews.json").read_text(encoding="utf-8"))
    if args.freshness:
        for line in freshness(data):
            print(line)
        return 0
    bad = problems(data, reviews)
    if bad:
        print("\n".join(bad), file=sys.stderr)
        return 1
    text, badges = render(data, reviews)
    readme_now = (ROOT / "README.md").read_text(encoding="utf-8")
    try:
        readme = readme_with_counts(readme_now, data)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 1
    if args.check:
        stale = [] if (ROOT / "MATRIX.md").read_text(encoding="utf-8") == text else ["MATRIX.md"]
        stale += [] if readme_now == readme else ["README.md (counts)"]
        on_disk = {f"badges/{f.name}" for f in (ROOT / "badges").glob("*.json")} if (ROOT / "badges").is_dir() else set()
        stale += sorted(on_disk ^ set(badges))
        stale += [k for k, v in badges.items() if (ROOT / k).exists() and (ROOT / k).read_text(encoding="utf-8") != v]
        if stale:
            print("stale, run python build_matrix.py: " + ", ".join(stale), file=sys.stderr)
            return 1
    else:
        (ROOT / "MATRIX.md").write_text(text, encoding="utf-8")
        (ROOT / "README.md").write_text(readme, encoding="utf-8")
        (ROOT / "badges").mkdir(exist_ok=True)
        for f in (ROOT / "badges").glob("*.json"):
            if f"badges/{f.name}" not in badges:
                f.unlink()
        for k, v in badges.items():
            (ROOT / k).write_text(v, encoding="utf-8")
    c = counts(data)
    print(f"N of {c['total']}: {len(c['run'])}; no record read yet: {len(c['unread'])} of {c['total']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
