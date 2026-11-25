import os
import threading
import time
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

from . import report as report_mod
from . import risk, rules, twin
from .baseline import get_baseline, load_file_baseline, save_file_baseline
from .prediction import PredictionAgent
from .schemas import (AnalyzeRequest, AnalyzeResponse, AuthorizedAsset, Context, Event, ReportRequest, TwinRequest)
from .sentinel import SentinelAgent

app = FastAPI(title="SCAR AI Service", version="0.1.0")
_prediction = PredictionAgent()
_sentinel = SentinelAgent()


def check_key(x_api_key: Optional[str] = Header(default=None)) -> None:
    expected = os.getenv("AI_API_KEY")
    if expected and x_api_key != expected:
        raise HTTPException(status_code=401, detail="invalid api key")


@app.get("/health")
def health():
    return {"status": "ok", "llm_enabled": _sentinel.llm_enabled, "prediction_model": "iforest-v0.1"}


@app.post("/analyze", response_model=AnalyzeResponse, dependencies=[Depends(check_key)])
def analyze(req: AnalyzeRequest):
    """Full pipeline for one event: rules -> Sentinel -> Prediction -> Risk fusion."""
    baseline = get_baseline(req.context)
    rule_out = rules.evaluate(req.event, baseline)
    s = _sentinel.analyze(req.event, baseline, rule_out)
    p = _prediction.predict(req.event, baseline)
    r = risk.fuse(s, p)
    return AnalyzeResponse(event_id=req.event.event_id, results=[s, p, r], final=risk.to_final(r))


@app.post("/predict", dependencies=[Depends(check_key)])
def predict(req: AnalyzeRequest):
    return _prediction.predict(req.event, get_baseline(req.context))


@app.post("/sentinel", dependencies=[Depends(check_key)])
def sentinel(req: AnalyzeRequest):
    baseline = get_baseline(req.context)
    return _sentinel.analyze(req.event, baseline, rules.evaluate(req.event, baseline))


@app.post("/report", dependencies=[Depends(check_key)])
def report(req: ReportRequest):
    return {"mission_id": req.mission.get("mission_id"),
            "markdown": report_mod.build_report(req.mission, req.events, req.results)}


@app.post("/twin/build", dependencies=[Depends(check_key)])
def twin_build(req: TwinRequest):
    return twin.build_twin(req.zone, req.events, get_baseline(req.context), req.risk_by_bssid, req.cell_m)


@app.get("/baseline", dependencies=[Depends(check_key)])
def get_base():
    return load_file_baseline()


@app.put("/baseline", dependencies=[Depends(check_key)])
def put_base(assets: list[AuthorizedAsset]):
    save_file_baseline(assets)
    return {"saved": len(assets)}


# --- alert de-duplication (atomic: n8n runs many executions in parallel, so static data can't be trusted) ---
_seen: dict[str, float] = {}
_lock = threading.Lock()


class DedupeRequest(BaseModel):
    key: str
    cooldown_seconds: int = 600


@app.post("/dedupe", dependencies=[Depends(check_key)])
def dedupe(req: DedupeRequest):
    """First caller for a key gets send=true; everyone else within the cooldown gets send=false."""
    now = time.monotonic()
    with _lock:
        last = _seen.get(req.key)
        if last is not None and now - last < req.cooldown_seconds:
            return {"send": False}
        _seen[req.key] = now
        for k in [k for k, t in _seen.items() if now - t > 86400]:
            del _seen[k]
    return {"send": True}
