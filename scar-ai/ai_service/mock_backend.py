"""MOCK backend implementing the SCAR contract in memory.
Use it to test the n8n workflows BEFORE the real FastAPI backend is ready:
    uvicorn mock_backend:app --port 8000
    curl -X POST localhost:8000/dev/seed-demo      # loads a simulated drone mission (status=pending)
This is NOT the real backend. The real one must expose the same endpoints (see docs/contracts.md)."""
import uuid
from datetime import datetime, timezone

from fastapi import Body, FastAPI, HTTPException

app = FastAPI(title="SCAR mock backend")
DB = {"events": {}, "results": [], "runs": [], "alerts": [], "reports": [], "missions": {}}


def now():
    return datetime.now(timezone.utc).isoformat()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/events", status_code=201)
def create_event(ev: dict = Body(...)):
    ev = dict(ev)
    ev["event_id"] = ev.get("event_id") or str(uuid.uuid4())
    if ev["event_id"] in DB["events"]:
        return DB["events"][ev["event_id"]]            # idempotent
    ev.update(status="pending", created_at=now())
    DB["events"][ev["event_id"]] = ev
    return ev


@app.get("/events")
def list_events(status: str | None = None, limit: int = 50):
    rows = [e for e in DB["events"].values() if status in (None, e["status"])]
    return rows[:limit]


@app.get("/events/{eid}")
def get_event(eid: str):
    if eid not in DB["events"]:
        raise HTTPException(404, "event not found")
    return DB["events"][eid]


@app.post("/events/{eid}/claim")
def claim(eid: str):
    e = DB["events"].get(eid)
    if not e:
        raise HTTPException(404, "event not found")
    if e["status"] != "pending":
        raise HTTPException(409, f"already {e['status']}")
    e.update(status="processing", claimed_at=now())
    return e


@app.patch("/events/{eid}/status")
def set_status(eid: str, body: dict = Body(...)):
    e = get_event(eid)
    if body["status"] not in ("pending", "processing", "analyzed", "failed"):
        raise HTTPException(422, "bad status")
    e["status"], e["status_error"] = body["status"], body.get("error")
    return e


@app.post("/events/requeue-stuck")
def requeue(body: dict = Body(default={})):
    limit = body.get("older_than_seconds", 300)
    n = 0
    for e in DB["events"].values():
        if e["status"] == "processing" and (datetime.now(timezone.utc) - datetime.fromisoformat(e["claimed_at"])).total_seconds() > limit:
            e["status"] = "pending"; n += 1
    return {"requeued": n}


@app.post("/analysis-results/bulk", status_code=201)
def save_results(body: dict = Body(...)):
    for r in body["results"]:       # upsert on (event_id, agent, model_version)
        DB["results"] = [x for x in DB["results"] if (x["event_id"], x["agent"], x["model_version"]) !=
                         (r["event_id"], r["agent"], r["model_version"])]
        DB["results"].append(dict(r, created_at=now()))
    return {"saved": len(body["results"])}


@app.post("/missions", status_code=201)
def create_mission(m: dict = Body(...)):
    DB["missions"][m["mission_id"]] = m
    return m


@app.get("/missions/{mid}")
def get_mission(mid: str):
    return DB["missions"].get(mid) or {"mission_id": mid}


@app.get("/missions/{mid}/events")
def mission_events(mid: str):
    return [e for e in DB["events"].values() if e.get("mission_id") == mid]


@app.get("/missions/{mid}/analysis-results")
def mission_results(mid: str, agent: str | None = None):
    ids = {e["event_id"] for e in DB["events"].values() if e.get("mission_id") == mid}
    return [r for r in DB["results"] if r["event_id"] in ids and agent in (None, r["agent"])]


@app.post("/workflow-runs", status_code=201)
def run_log(b: dict = Body(...)):
    DB["runs"].append(dict(b, finished_at=now())); return {"ok": True}


@app.post("/alerts", status_code=201)
def alert(b: dict = Body(...)):
    DB["alerts"].append(dict(b, created_at=now())); return {"ok": True}


@app.post("/reports", status_code=201)
def report(b: dict = Body(...)):
    DB["reports"].append(dict(b, created_at=now())); return {"ok": True}


@app.get("/dev/state")
def state():
    return {k: (len(v)) for k, v in DB.items()}


@app.post("/dev/seed-demo")
def seed(limit: int = 60):
    from app import synthetic
    DB["missions"]["mission-demo-001"] = {"mission_id": "mission-demo-001", "drone_id": "scar-01", "zone_id": "zone-demo"}
    evs = synthetic.generate_events()
    # make sure every kind of AP is represented in the first `limit` events
    pick = evs[:limit] + [next(e for e in evs if e["raw_payload"]["sim_ap"] == k) for k in ("rogue", "shadow", "legacy", "hidden")]
    unique = {e["event_id"]: e for e in pick}.values()
    for e in unique:
        create_event(e)
    return {"seeded": len(unique)}


@app.get("/dev/dump")
def dump():
    return {k: (list(v.values()) if isinstance(v, dict) else v) for k, v in DB.items() if k != "events"} | \
           {"event_status": {s: sum(1 for e in DB["events"].values() if e["status"] == s)
                             for s in ("pending", "processing", "analyzed", "failed")}}
