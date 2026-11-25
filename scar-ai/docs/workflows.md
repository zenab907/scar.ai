# n8n workflows - inputs / outputs / failure cases / status

Import each file: n8n → *Workflows* → *Import from file*. In every workflow open the **Config** node and edit the values
(backend URL, keys, webhook URLs, Telegram chat id). Telegram nodes: create a credential "Telegram API" (bot token from @BotFather).
Activate **W2 and W4 first** (others call them via production webhook URLs, `/webhook/...` not `/webhook-test/...`).

| # | Workflow | Trigger | Input | Output / side effects |
|---|---|---|---|---|
| W1 | Event Ingestion | `POST /webhook/scar/ingest` | `{source:'wazuh'\|'zeek'\|'drone', payload:{...}, mission_id?}` | normalized event → backend `POST /events` → triggers W2 |
| W2 | Event Analysis | `POST /webhook/scar/analyze` | `{event_id}` | claim → AI `/analyze` → `analysis_results` (3 rows) → status `analyzed` → W4 if risk ≥ threshold |
| W3 | Pending Sweeper | every 30 s | - | requeues stuck events, re-triggers W2 for each `pending` event |
| W4 | Alerting | `POST /webhook/scar/alert` | final-risk object + event_id, mission_id, bssid, ssid | Telegram message (de-duplicated via AI service `/dedupe` per mission+AP+category for `alert_cooldown_s`), row in `alerts` |
| W5 | Mission Report | `POST /webhook/scar/mission-report` | `{mission_id}` | Markdown report → `reports` |
| W6 | Health Check | every 5 min | - | Telegram message only when state changes (down / recovered) |

## Failure cases (what actually happens)

| Failure | Behaviour |
|---|---|
| Event already claimed (push + sweeper race) | backend `409` → W2 stops quietly ("Skip" node). No duplicate analysis. |
| AI service down / 5xx / timeout | 2 retries (2 s apart) → event marked `failed` (+ reason) → row in `workflow_runs`. W3 does **not** retry `failed` (avoid loops) - requeue manually or via backend. |
| LLM down / invalid JSON | handled **inside** AI service: deterministic rules fallback, `error` field says `llm_failed:...`. Pipeline continues. |
| Backend save fails | 2 retries → event marked `failed`. |
| Telegram fails | alert still stored with `delivery='failed'`. |
| n8n restarts mid-run | event stays `processing` → W3 requeues after 5 min (needs `/events/requeue-stuck`). |
| Alert storm (same rogue AP seen 80×) | W4 asks the AI service `/dedupe` (atomic, in-memory) -> one alert per (mission, AP, category) per cooldown. Tested with 61 parallel events: 4 alerts for 4 bad APs. |

## Security notes
- SSIDs/payloads are attacker-controlled: alerts are sent as **plain text**, the LLM treats them as data, and the LLM output is validated and clamped (it can never lower a strong rule hit below 70 % of its score).
- Policy: **passive only (Zero-Exploit)**. No workflow here scans, probes, deauths or connects to any network.
- Do not commit real keys: Config values `CHANGE_ME_*` are placeholders; use n8n credentials / env for real deployments.
