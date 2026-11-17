"""The agentops adapter binds each hash to the copy the analyzer reads, and refuses what it cannot read.

Counter-examples the first adapter accepted: an inline-attribute edit (the hash binds only the stored
copy), a session with no events (0 of 0 read as a pass) and a duplicate member (a last-wins parse).
"""
import hashlib
import json
import pathlib
import subprocess
import sys

ADAPTER = pathlib.Path(__file__).resolve().parents[1] / "adapters" / "icon_agentops.py"


def h(body):
    return "sha256:" + hashlib.sha256(json.dumps(body, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def session(n=10):
    events, evidence = [], {}
    for i in range(n):
        attrs = {"route": "B", "step": i}
        rid = f"clean:e{i:03d}:evidence"
        events.append({"event_id": f"clean:e{i:03d}", "status": "ok", "parent_event_ids": [],
                       "attributes": attrs, "evidence": [{"id": rid, "hash": h(attrs)}]})
        evidence[rid] = dict(attrs)
    return events, evidence


def run(tmp_path, events, evidence, raw_events=None):
    d = tmp_path / "agentops" / "examples" / "results" / "clean"
    d.mkdir(parents=True)
    (d / "events.json").write_text(raw_events if raw_events is not None else json.dumps(events))
    (d / "evidence.json").write_text(json.dumps(evidence))
    out = subprocess.run([sys.executable, "-I", str(ADAPTER), str(tmp_path / "agentops")], capture_output=True, text=True)
    return out.returncode, out.stdout


def test_a_clean_session_passes(tmp_path):
    rc, out = run(tmp_path, *session())
    assert rc == 0 and "PASS  agentops/evidence-hash: 10 of 10" in out


def test_an_inline_edit_of_the_consumed_copy_is_caught(tmp_path):
    events, evidence = session()
    events[4]["attributes"]["route"] = "A"
    rc, out = run(tmp_path, events, evidence)
    assert rc == 1 and "differs from the attributes the analyzer reads" in out


def test_no_events_is_not_a_pass(tmp_path):
    rc, out = run(tmp_path, [], {})
    assert rc == 1 and "DIFF  agentops/evidence-hash: 0 of 0" in out


def test_a_duplicate_member_refuses_the_file(tmp_path):
    events, evidence = session()
    raw = json.dumps(events).replace('"status": "ok"', '"status": "ok", "status": "error"', 1)
    rc, out = run(tmp_path, events, evidence, raw_events=raw)
    assert rc == 1 and "1 files refused" in out


def test_a_refused_session_is_reported_and_the_run_still_finishes(tmp_path):
    """Counter-example: a duplicate member in one session crashed the later readings (traceback, no SUMMARY,
    edit detection never ran), and the crash exited 1 like a comparison result."""
    events, evidence = session()
    run(tmp_path, events, evidence)
    other = tmp_path / "agentops" / "examples" / "results" / "s2"
    other.mkdir()
    (other / "events.json").write_text(json.dumps(events[:1]))
    (other / "evidence.json").write_text('{"clean:e000:evidence":{"route":"B","step":0},'
                                         '"clean:e000:evidence":{"route":"B","step":0}}')
    out = subprocess.run([sys.executable, "-I", str(ADAPTER), str(tmp_path / "agentops")], capture_output=True, text=True)
    assert out.returncode == 1 and "Traceback" not in out.stderr
    assert "1 files refused" in out.stdout and "1 sessions refused" in out.stdout
    assert "agentops/edit-detection: the project's hash rule detects" in out.stdout
    assert out.stdout.splitlines()[-1].startswith("SUMMARY")


def test_no_events_is_a_reported_difference_not_a_crash(tmp_path):
    """Counter-example: the empty session passed its test only because edit detection indexed events[5]
    and crashed with exit 1; edit detection now finds its events by id and says which are missing."""
    d = tmp_path / "agentops" / "examples" / "results" / "clean"
    d.mkdir(parents=True)
    (d / "events.json").write_text("[]")
    (d / "evidence.json").write_text("{}")
    out = subprocess.run([sys.executable, "-I", str(ADAPTER), str(tmp_path / "agentops")], capture_output=True, text=True)
    assert out.returncode == 1 and "Traceback" not in out.stderr
    assert "DIFF  agentops/edit-detection: the clean session has no" in out.stdout


def regen_run(tmp_path, change):
    """A committed session and a regenerated copy of it; `change` edits the regenerated analysis.json."""
    events, evidence = session()
    run(tmp_path, events, evidence)
    analysis = {"assertions": [
        {"assertion_id": "call-latency", "result": "violation", "measured_value": 86, "boundary_value": 50,
         "timestamp": "2026-11-06T07:26:44.235Z"},
        {"assertion_id": "route-intent", "result": "pass", "measured_value": "B", "boundary_value": "B"}],
        "diagnosis": {"record": {"created_at": "2026-11-06T07:26:44.136Z", "root_cause_event_id": "clean:e004"}}}
    committed = tmp_path / "agentops" / "examples" / "results" / "clean"
    (committed / "analysis.json").write_text(json.dumps(analysis))
    regen = tmp_path / "regen" / "clean"
    regen.mkdir(parents=True)
    for name in ("events.json", "evidence.json"):
        (regen / name).write_text((committed / name).read_text())
    change(analysis)
    (regen / "analysis.json").write_text(json.dumps(analysis))
    out = subprocess.run([sys.executable, "-I", str(ADAPTER), str(tmp_path / "agentops"), "--regenerated",
                          str(tmp_path / "regen")], capture_output=True, text=True)
    return out.returncode, out.stdout


def test_a_regenerated_analysis_differing_only_in_clock_readings_passes(tmp_path):
    """The recorded regeneration differed only in diagnosis.record.created_at and call-latency's measured_value,
    which agentops copies from the event's duration_ms; both are clock readings."""
    def change(a):
        a["assertions"][0]["measured_value"] = 81
        a["diagnosis"]["record"]["created_at"] = "2026-11-16T06:00:00.000Z"
    rc, out = regen_run(tmp_path, change)
    assert rc == 0 and "PASS  agentops/analysis.json-normalized: 1 of 1" in out


def test_a_regenerated_analysis_with_another_verdict_differs(tmp_path):
    """Dropping call-latency's measured value must not drop its result, the analyzer's verdict."""
    def change(a):
        a["assertions"][0]["result"] = "pass"
    rc, out = regen_run(tmp_path, change)
    assert rc == 1 and "DIFF  agentops/analysis.json-normalized: 0 of 1" in out


def test_a_measured_value_that_is_not_a_clock_reading_is_compared(tmp_path):
    """Only an assertion whose measured_value copies a duration is exempt; route-intent's route is compared."""
    def change(a):
        a["assertions"][1]["measured_value"] = "C"
    rc, out = regen_run(tmp_path, change)
    assert rc == 1 and "$.assertions[*].measured_value" in out


def test_a_regenerated_slow_call_that_was_fast_differs(tmp_path):
    """Second break pass: with the measured value dropped and the verdict copied, a regeneration whose slow call took
    3 ms still read as equal. The regenerated result must follow from the regenerated reading by the pinned rule."""
    def change(a):
        a["assertions"][0]["measured_value"] = 3
    rc, out = regen_run(tmp_path, change)
    assert rc == 1 and "DIFF  agentops/analysis.json-normalized: 0 of 1" in out
    assert "result (does not follow measured_value 3)" in out
