"""Replays what n8n W2/W3/W5 do, against the mock backend + the real AI service. Proves the contract is consistent."""
from fastapi.testclient import TestClient

import mock_backend as mb
from app.main import app as ai_app

be, ai = TestClient(mb.app), TestClient(ai_app)


def run_w2(event_id):
    """Same steps / same order as n8n workflow W2."""
    if be.post(f"/events/{event_id}/claim", json={}).status_code != 200:
        return "skipped"
    ev = be.get(f"/events/{event_id}").json()
    r = ai.post("/analyze", json={"event": ev})
    if r.status_code != 200:
        be.patch(f"/events/{event_id}/status", json={"status": "failed", "error": r.text})
        return "failed"
    out = r.json()
    be.post("/analysis-results/bulk", json={"event_id": event_id, "results": out["results"]})
    be.patch(f"/events/{event_id}/status", json={"status": "analyzed"})
    return out["final"]


def setup_function():
    for v in mb.DB.values():
        v.clear()


def test_full_flow_and_idempotency():
    seeded = be.post("/dev/seed-demo?limit=40").json()["seeded"]
    assert seeded >= 41
    pending = be.get("/events?status=pending&limit=100").json()           # W3 sweeper
    assert len(pending) == seeded
    finals = {e["event_id"]: run_w2(e["event_id"]) for e in pending}
    assert all(f != "failed" for f in finals.values())
    assert be.get("/events?status=pending").json() == []
    assert run_w2(pending[0]["event_id"]) == "skipped"                     # double trigger is harmless (409)
    n = len(mb.DB["results"]); assert n == seeded * 3
    be.post("/analysis-results/bulk", json={"event_id": pending[0]["event_id"],
            "results": [r for r in mb.DB["results"] if r["event_id"] == pending[0]["event_id"]]})
    assert len(mb.DB["results"]) == n                                      # upsert, no duplicates
    assert any(f != "skipped" and f["severity"] == "critical" for f in finals.values())


def test_failure_path_marks_failed():
    be.post("/events", json={"event_id": "bad1", "source": "drone", "event_type": "wifi_beacon"})  # no timestamp -> 422
    assert run_w2("bad1") == "failed"
    assert be.get("/events/bad1").json()["status"] == "failed"


def test_report_flow_w5():
    be.post("/dev/seed-demo?limit=60")
    for e in be.get("/events?status=pending&limit=100").json():
        run_w2(e["event_id"])
    mid = "mission-demo-001"
    payload = {"mission": be.get(f"/missions/{mid}").json(), "events": be.get(f"/missions/{mid}/events").json(),
               "results": be.get(f"/missions/{mid}/analysis-results?agent=risk").json()}
    md = ai.post("/report", json=payload).json()["markdown"]
    assert "rogue_ap" in md and "DE:AD:BE:EF:00:01" in md
