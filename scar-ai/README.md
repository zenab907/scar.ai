# SCAR - AI & Automation package (MVP)

```
ai_service/      FastAPI AI service: Sentinel + Prediction + Risk fusion + Report + Digital-Twin builder  (20 tests)
ai_service/mock_backend.py   in-memory stand-in for the real backend (test n8n before the backend is ready)
n8n/             6 importable workflows (W1..W6) + build_workflows.py (regenerates them)
db/schema.sql    PostgreSQL schema (events, analysis_results, workflow_runs, alerts, reports, twin_*, missions...)
docs/contracts.md   API + data contracts to sign off with the team      docs/workflows.md   inputs/outputs/failure cases
twin/demo.py     digital-twin demo -> twin_demo.html (heatmap + AP markers) and twin_sample.json (JSON shape for React)
```

## Run it (5 min, no Docker)
```bash
cd ai_service && pip install -r requirements.txt && python -m pytest -q        # all green
uvicorn app.main:app --port 8001            # AI service      (http://localhost:8001/docs)
uvicorn mock_backend:app --port 8000        # mock backend    (in a 2nd terminal)
curl -X POST localhost:8000/dev/seed-demo   # 44 simulated drone observations, status=pending
python ../twin/demo.py                      # writes twin/twin_demo.html
```
With Docker: `cp .env.example .env && docker compose up --build`  (n8n on :5678).

## Then in n8n
1. Import `n8n/W*.json`. 2. Edit the **Config** node of each workflow. 3. Add the Telegram credential. 4. Activate W2, W4, then W3/W1/W5/W6.
5. Test: `curl -X POST localhost:5678/webhook/scar/analyze -H 'content-type: application/json' -d '{"event_id":"<id from mock backend>"}'`

## Scope
Passive only (Zero-Exploit). Nothing here scans, probes, or connects to any network. LLM is optional (`ANTHROPIC_API_KEY`); without it Sentinel runs deterministic rules.

## Known limitations (be honest in the demo)
- ML is trained on **simulated** flights; retrain on real, clean customer data (`PredictionAgent._training_matrix`).
- Rare-but-legitimate configs (e.g. the only 5 GHz/WPA3 AP) can get a high ML score; fusion (60/40) dampens it.
- Twin AP positions are weighted-centroid estimates (±~30 m on the 25 m flight grid), not surveyed positions.
- Verified on a real n8n 2.35.7: all 6 import; W1, W2, W3, W4, W5 executed end-to-end against the mock backend + AI service (63 events analyzed, 0 failed, report built, alerts de-duplicated).
- NOT verified: Telegram delivery (needs your bot credential; without it alerts are stored with delivery='failed'), W6 (needs Telegram), and the real backend (only the mock).
- The AI-service `/dedupe` cache is in-memory (resets on restart; fine for MVP, use Redis/DB for production).
