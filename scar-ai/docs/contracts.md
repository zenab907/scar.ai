# SCAR - Data & API Contracts (v0.1)

Status: **DRAFT for team sign-off on Day 1.** Anything marked ⚠ needs the Backend team's explicit "agreed".
All timestamps ISO-8601 UTC. All bodies JSON. Auth header on every call: `X-API-Key: <key>`.

## 1. Flow

```
Backend saves event (status=pending) ──push──► n8n W2 webhook {event_id}
        ▲                                         │ claim → get → AI /analyze → save results → mark analyzed
        └──── W3 sweeper (every 30s) re-triggers any event still `pending` (safety net)
Risk >= threshold ──► W4 alert (Telegram + alerts table)         Mission completed ──► W5 report
```

Event status machine: `pending → processing → analyzed | failed`  (`failed`/stuck `processing` > 5 min → back to `pending`).

## 2. Event (table `events`) - what the AI team consumes

| Field | Type | Notes |
|---|---|---|
| event_id | string (unique) | backend generates if missing; **idempotency key** |
| mission_id | string? | FK missions |
| source | `wazuh` \| `zeek` \| `drone` | |
| event_type | string | `wifi_beacon`, `wazuh_alert`, `notice`, ... |
| timestamp | datetime | observation time |
| bssid, ssid | string? | Wi-Fi observations. hidden SSID = `null` |
| rssi | int? | dBm |
| channel | int? | |
| encryption | `Open`\|`WEP`\|`WPA`\|`WPA2`\|`WPA3`\|`Unknown` | |
| lat, lon, altitude | float? | drone position at observation |
| raw_payload | object | original Wazuh/Zeek/drone record, untouched |
| status | enum | see state machine |

Wazuh events: AI reads `raw_payload.rule.level` (0-15) and `rule.description`. Zeek: `event_type` starting with `notice` and `raw_payload.msg`.

## 3. Analysis result (table `analysis_results`) - what the AI team returns

One event → **3 rows** (one per agent): `sentinel`, `prediction`, `risk` (the fused final one; dashboard shows this).

| Field | Type | Notes |
|---|---|---|
| event_id | string | FK |
| agent | `sentinel`\|`prediction`\|`risk` | |
| model_version | string | e.g. `sentinel-rules-v0.1`, `iforest-v0.1`, `risk-fusion-v0.1` |
| severity | `low`\|`medium`\|`high`\|`critical` | <30 / <60 / <80 / ≥80 |
| risk_score | int 0-100 | |
| category | `rogue_ap`\|`weak_encryption`\|`unknown_device`\|`hidden_ssid`\|`host_alert`\|`network_alert`\|`benign` | |
| confidence | float 0-1 | |
| explanation | string | human-readable "why" (explainable risk) |
| recommended_action | string | defensive only |
| features | object | model inputs / score breakdown (debug + explainability) |
| processing_ms | int | |
| error | string? | e.g. `llm_failed: Timeout` when fallback was used |

Unique key `(event_id, agent, model_version)` → backend must **upsert** (re-runs never duplicate).

## 4. Endpoints

### 4.1 Backend must provide ⚠

| Method & path | Purpose | Notes |
|---|---|---|
| `POST /events` | create event | returns the stored event incl. `event_id`; idempotent on `event_id` |
| `GET /events?status=pending&limit=50` | W3 sweeper | **JSON array**, oldest first |
| `GET /events/{id}` | W2 | |
| `POST /events/{id}/claim` | atomic pending→processing | `200` event · **`409`** if not pending (SQL in schema.sql) |
| `PATCH /events/{id}/status` | `{status, error?}` | |
| `POST /events/requeue-stuck` | `{older_than_seconds}` → `{requeued:n}` | optional; a cron works too |
| `POST /analysis-results/bulk` | `{event_id, results:[...3 rows]}` | upsert |
| `GET /missions/{id}` · `GET /missions/{id}/events` | W5 | arrays for events |
| `GET /missions/{id}/analysis-results?agent=risk` | W5 / dashboard | |
| `POST /workflow-runs` | log of every workflow run | see `workflow_runs` table |
| `POST /alerts` | stored alerts | dashboard shows open ones |
| `POST /reports` | `{mission_id, format, content}` | |
| `GET /health` | `{status:"ok"}` | |
| webhook caller | after saving an event: `POST http://n8n:5678/webhook/scar/analyze` `{event_id}` | fire-and-forget |

### 4.2 AI service provides (already implemented, `ai_service/`)

| Endpoint | In → Out |
|---|---|
| `POST /analyze` | `{event, context?}` → `{event_id, results:[3 rows], final}` |
| `POST /sentinel` · `POST /predict` | same input → one `AgentResult` |
| `POST /report` | `{mission, events[], results[]}` → `{mission_id, markdown}` |
| `POST /twin/build` | `{zone, events[], risk_by_bssid?, cell_m?}` → `{assets[], readings[], heatmap}` |
| `GET/PUT /baseline` | authorized-AP list (customer baseline) |
| `GET /health` | status |

`context.authorized_assets: [{bssid, ssid}]` overrides the stored baseline. **Without a baseline the AI cannot detect rogue/unknown APs** → Samuel/Omar: agree where the customer's authorized list comes from (table `authorized_assets`).

## 5. Ownership / open questions ⚠

1. Who writes `authorized_assets` (customer baseline)? Needed for `rogue_ap` / `unknown_device`.
2. Does the backend push to n8n, or do we rely only on the 30 s sweeper? (push recommended)
3. Drone telemetry fields (lat/lon/altitude/rssi) - confirm names with Abdelrhman / Menna Emad.
4. Alert channel for the demo: Telegram assumed.
5. Digital twin storage: `twin_zones`, `twin_assets`, `twin_readings` (see schema.sql); AI `/twin/build` computes them, backend persists (upsert on `(zone_id,bssid)`).
