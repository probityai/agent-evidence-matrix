"""Render matrix.json to MATRIX.md and badges/, and refuse a matrix whose cells break the schema.

    python build_matrix.py              rewrite MATRIX.md and badges/, print the coverage counts
    python build_matrix.py --check      exit 1 when MATRIX.md or badges/ differ from what matrix.json renders
    python build_matrix.py --freshness  compare each pinned upstream commit with the upstream default branch
                                        (GitHub only, read-only GETs through `gh api`); prints warnings, exit 0

The schema rules, each a refusal (exit 1 with every problem named):

- every project has a review entry in reviews.json; a project under a frozen review must keep the
  exact bytes its review recorded (its digest), and the rules below are not applied to it;
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
- the reader the matrix names (matrix.json "reader") is the reader requirements.in pins, the reader the
  hash-locked requirements.txt installs, and every reader pin a workflow installs by name, package for package and
  version for version, so the stated reader and the installed one cannot drift apart.
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
PATH = re.compile(r"(?<![\w/.-])((?:adapters|records|libraries|tests|tools|badges)/[\w.@+/-]*[\w@+-])")
ONE_MACHINE = re.compile(r"(?:^|[\s(])(?:/home/|/Users/|~/|/tmp/)|_raw/|probity-lanes")
REPO_URL = re.compile(r"https://[a-z0-9.-]+\.[a-z]{2,}/[\w.-]+/[\w.-]+")
FILE_URL = re.compile(r"https://[a-z0-9.-]+\.[a-z]{2,}/\S+")
SHA1 = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")


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
    if verdict == "contradicted":
        for key in ("basis", "divergence_in", "declared_revision"):
            if not cell.get(key):
                out.append(f"{where}: a contradicted cell needs {key}")
        if basis == "declared-profile":
            out.append(f"{where}: a refusal inside a declared profile is unsupported, not contradicted")
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


def _project_problems(project: dict, codes: set[str], root: pathlib.Path) -> list[str]:
    pid = project.get("id")
    out = []
    cells = project.get("cells") or []
    if not cells:
        out.append(f"project {pid}: no cells")
    for i, cell in enumerate(cells, 1):
        out += _cell_problems(f"project {pid} cell {i}", cell, codes, root)
    has_result = any(c.get("verdict") in RESULT for c in cells)
    up = project.get("upstream") or {}
    if has_result and not (up.get("url") and up.get("sha") and project.get("replay")):
        out.append(f"project {pid}: a project with a result needs upstream.url, upstream.sha and replay")
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
        if pid in by_project:
            out.append(f"reviews.json: project {pid} reviewed twice")
        by_project[pid] = entry
        if entry.get("state") not in REVIEW_STATES:
            out.append(f"reviews.json: project {pid} state {entry.get('state')!r} is not one of {list(REVIEW_STATES)}")
        if not entry.get("review") or not entry.get("date"):
            out.append(f"reviews.json: project {pid} needs a review id and a date")
    ids = [p.get("id") for p in data.get("projects") or []]
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
            continue
        out += _project_problems(project, codes, root)
    return out


PIN = re.compile(r"([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9][A-Za-z0-9.+!_-]*)")


def _dist(name: str) -> str:
    """A distribution name in PEP 503 normal form."""
    return re.sub(r"[-_.]+", "-", name).lower()


def pins_in(text: str, workflow: bool = False) -> dict[str, set[str]]:
    """{normalised name: versions pinned with ==} in a requirements file, or in a workflow's pip install lines."""
    out: dict[str, set[str]] = {}
    for line in text.splitlines():
        line = line.split("#", 1)[0]
        if workflow and "pip install" not in line:
            continue
        found = PIN.findall(line) if workflow else [m.groups() for m in [PIN.match(line.strip())] if m]
        for name, version in found:
            out.setdefault(_dist(name), set()).add(version)
    return out


def reader_problems(reader: dict, sources: dict[str, str]) -> list[str]:
    """Refusals when the reader matrix.json names differs from a pin of the same package.

    `sources` maps a file name to its text: requirements.in and requirements.txt must each pin every reader
    package with == at the named version (exactly one version), and a workflow (a name under .github/) that
    installs a reader package by name must install that version."""
    out = []
    if not reader:
        out.append("matrix.json: no reader named")
    for src, text in sorted(sources.items()):
        workflow = src.startswith(".github/")
        pins = pins_in(text, workflow)
        for name, version in sorted((reader or {}).items()):
            got = pins.get(_dist(name))
            if got is None:
                if not workflow:
                    out.append(f"matrix.json: reader {name} {version} is not pinned with == in {src}")
            elif got != {version}:
                out.append(f"matrix.json: reader {name} {version} but {src} pins {', '.join(sorted(got))}")
    return out


def reader_sources(root: pathlib.Path = ROOT) -> dict[str, str]:
    files = [root / "requirements.in", root / "requirements.txt"] + sorted((root / ".github").rglob("*.y*ml"))
    return {str(f.relative_to(root)): f.read_text(encoding="utf-8") for f in files if f.is_file()}


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
    bad = problems(data, reviews) + reader_problems(data.get("reader"), reader_sources())
    if bad:
        print("\n".join(bad), file=sys.stderr)
        return 1
    text, badges = render(data, reviews)
    if args.check:
        stale = [] if (ROOT / "MATRIX.md").read_text(encoding="utf-8") == text else ["MATRIX.md"]
        on_disk = {f"badges/{f.name}" for f in (ROOT / "badges").glob("*.json")} if (ROOT / "badges").is_dir() else set()
        stale += sorted(on_disk ^ set(badges))
        stale += [k for k, v in badges.items() if (ROOT / k).exists() and (ROOT / k).read_text(encoding="utf-8") != v]
        if stale:
            print("stale, run python build_matrix.py: " + ", ".join(stale), file=sys.stderr)
            return 1
    else:
        (ROOT / "MATRIX.md").write_text(text, encoding="utf-8")
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
