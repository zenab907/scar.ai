"""Generates the importable n8n workflows (W1..W6). Run:  python build_workflows.py
Every workflow starts from a `Config` node: edit URLs/keys there (no env vars needed)."""
import json
import uuid
from pathlib import Path

OUT = Path(__file__).parent
NS = uuid.UUID("5ca2d0de-0000-4000-8000-000000000000")


def nid(wf: str, name: str) -> str:
    return str(uuid.uuid5(NS, wf + name))


class WF:
    def __init__(self, name: str):
        self.name, self.nodes, self.conns, self.x = name, [], {}, 0

    def add(self, name, type_, tv, params, y=300, step=260, **extra):
        self.x += step
        node = {"parameters": params, "id": nid(self.name, name), "name": name, "type": type_,
                "typeVersion": tv, "position": [self.x, y]}
        node.update(extra)
        self.nodes.append(node)
        return name

    def link(self, a, b, out=0):
        outs = self.conns.setdefault(a, {"main": []})["main"]
        while len(outs) <= out:
            outs.append([])
        outs[out].append({"node": b, "type": "main", "index": 0})

    def chain(self, *names):
        for a, b in zip(names, names[1:]):
            self.link(a, b)

    def save(self, fname):
        data = {"id": "scar" + fname.split("_")[0], "name": self.name, "nodes": self.nodes, "connections": self.conns, "active": False,
                "settings": {"executionOrder": "v1"}, "pinData": {}}
        (OUT / fname).write_text(json.dumps(data, indent=2, ensure_ascii=False))


CFG = "$('Config').first().json."


def config(wf, extra=None):
    vals = {"backend_url": "http://backend:8000", "backend_key": "CHANGE_ME_BACKEND_KEY",
            "ai_url": "http://ai-service:8001", "ai_key": "CHANGE_ME_AI_KEY",
            "analysis_webhook_url": "http://n8n:5678/webhook/scar/analyze",
            "alert_webhook_url": "http://n8n:5678/webhook/scar/alert",
            "alert_threshold": 70, "alert_cooldown_s": 600, "telegram_chat_id": "CHANGE_ME_CHAT_ID"}
    vals.update(extra or {})
    assigns = [{"id": str(uuid.uuid4()), "name": k, "value": v, "type": "number" if isinstance(v, int) else "string"}
               for k, v in vals.items()]
    return wf.add("Config", "n8n-nodes-base.set", 3.4,
                  {"assignments": {"assignments": assigns}, "includeOtherFields": True, "options": {}})


def webhook(wf, path):
    return wf.add("Webhook", "n8n-nodes-base.webhook", 2,
                  {"httpMethod": "POST", "path": path, "responseMode": "onReceived", "options": {}},
                  webhookId=nid(wf.name, "wh"))


def http(wf, name, method, url, body=None, key="backend_key", on_error=None, retry=0, timeout=None, y=300):
    params = {"method": method, "url": url, "sendHeaders": True,
              "headerParameters": {"parameters": [{"name": "X-API-Key", "value": "={{ " + CFG + key + " }}"}]},
              "options": {"timeout": timeout} if timeout else {}}
    if body is not None:
        params.update({"sendBody": True, "specifyBody": "json", "jsonBody": body})
    extra = {}
    if on_error:
        extra["onError"] = on_error
    if retry:
        extra.update({"retryOnFail": True, "maxTries": retry, "waitBetweenTries": 2000})
    return wf.add(name, "n8n-nodes-base.httpRequest", 4.2, params, y=y, **extra)


def B(path):  # backend url expression
    return "={{ " + CFG + "backend_url }}" + path


def A(path):  # ai url expression
    return "={{ " + CFG + "ai_url }}" + path


def telegram(wf, name, text_expr, on_error=None, y=300):
    extra = {"credentials": {"telegramApi": {"id": "REPLACE_ME", "name": "SCAR Telegram Bot"}}}
    if on_error:
        extra["onError"] = on_error
    return wf.add(name, "n8n-nodes-base.telegram", 1.2,
                  {"chatId": "={{ " + CFG + "telegram_chat_id }}", "text": text_expr,
                   "additionalFields": {"appendAttribution": False}}, y=y, **extra)


def code(wf, name, js, y=300):
    return wf.add(name, "n8n-nodes-base.code", 2, {"jsCode": js}, y=y)


def log_run(wf, name, wname, status, eid_expr, err_expr=None, y=300, extra_fields=""):
    body = ("={{ { workflow_name: '" + wname + "', event_id: " + eid_expr + ", n8n_execution_id: $execution.id, status: '"
            + status + "', attempts: 1" + (", error_message: " + err_expr if err_expr else "") + extra_fields + " } }}")
    return http(wf, name, "POST", B("/workflow-runs"), body, on_error="continueRegularOutput", y=y)


# --------------------------------------------------------------------------------------------- W1
def w1():
    wf = WF("SCAR W1 - Event Ingestion")
    wh = webhook(wf, "scar/ingest")
    cfg = config(wf)
    norm = code(wf, "Normalize event", r"""// Accepts {source:'wazuh'|'zeek'|'drone', payload:{...}, mission_id?} and outputs the standard SCAR event.
const b = $('Webhook').first().json.body || {};
const now = new Date().toISOString();
const p = b.payload || b;
let ev;
if (b.source === 'wazuh') {
  ev = { source: 'wazuh', event_type: 'wazuh_alert', timestamp: p.timestamp || now, raw_payload: p };
} else if (b.source === 'zeek') {
  ev = { source: 'zeek', event_type: p._path === 'notice' ? 'notice' : (p._path || 'zeek_log'),
         timestamp: p.ts ? new Date(p.ts * 1000).toISOString() : now, raw_payload: p };
} else if (b.source === 'drone') {
  ev = { source: 'drone', event_type: p.event_type || 'wifi_beacon', timestamp: p.timestamp || now,
         bssid: p.bssid || null, ssid: p.ssid || null, rssi: p.rssi ?? null, channel: p.channel ?? null,
         encryption: p.encryption || null, lat: p.lat ?? null, lon: p.lon ?? null, altitude: p.altitude ?? null,
         raw_payload: p.raw || {} };
} else {
  throw new Error('unknown source: ' + b.source);
}
ev.mission_id = p.mission_id || b.mission_id || null;
if (b.event_id) ev.event_id = b.event_id;      // otherwise the backend generates it
ev.status = 'pending';
return [{ json: ev }];""")
    create = http(wf, "Create event (backend)", "POST", B("/events"), "={{ $json }}", on_error="continueErrorOutput", retry=3)
    trig = http(wf, "Trigger analysis (W2)", "POST", "={{ " + CFG + "analysis_webhook_url }}",
                "={{ { event_id: $json.event_id } }}", key="backend_key", on_error="continueRegularOutput")
    fail = log_run(wf, "Log failure", "W1_ingestion", "failed", "null",
                   "($json.error && $json.error.message) || 'create event failed'", y=500)
    wf.chain(wh, cfg, norm, create)
    wf.link(create, trig, 0)
    wf.link(create, fail, 1)
    wf.save("W1_event_ingestion.json")


# --------------------------------------------------------------------------------------------- W2
def w2():
    wf = WF("SCAR W2 - Event Analysis")
    EID = "$('Webhook').first().json.body.event_id"
    wh = webhook(wf, "scar/analyze")
    cfg = config(wf)
    claim = http(wf, "Claim event", "POST", B("/events/{{ " + EID + " }}/claim"), "={{ {} }}", on_error="continueErrorOutput")
    skip = wf.add("Skip (already claimed)", "n8n-nodes-base.noOp", 1, {}, y=520)
    get = http(wf, "Get event", "GET", B("/events/{{ " + EID + " }}"))
    ai = http(wf, "Call AI service", "POST", A("/analyze"), "={{ { event: $json } }}", key="ai_key",
              on_error="continueErrorOutput", retry=2, timeout=60000)
    save = http(wf, "Save results", "POST", B("/analysis-results/bulk"),
                "={{ { event_id: " + EID + ", results: $('Call AI service').first().json.results } }}",
                on_error="continueErrorOutput", retry=2)
    done = http(wf, "Mark analyzed", "PATCH", B("/events/{{ " + EID + " }}/status"),
                "={{ { status: 'analyzed' } }}", on_error="continueRegularOutput")
    ok = log_run(wf, "Log success", "W2_analysis", "success", EID)
    gate = wf.add("High risk?", "n8n-nodes-base.if", 2, {
        "conditions": {"options": {"caseSensitive": True, "leftValue": "", "typeValidation": "loose"},
                       "conditions": [{"id": str(uuid.uuid4()),
                                       "leftValue": "={{ $('Call AI service').first().json.final.risk_score }}",
                                       "rightValue": "={{ " + CFG + "alert_threshold }}",
                                       "operator": {"type": "number", "operation": "gte"}}],
                       "combinator": "and"}, "options": {}})
    alert = http(wf, "Send alert (W4)", "POST", "={{ " + CFG + "alert_webhook_url }}",
                 "={{ Object.assign({}, $('Call AI service').first().json.final, { event_id: " + EID +
                 ", mission_id: $('Get event').first().json.mission_id, bssid: $('Get event').first().json.bssid, "
                 "ssid: $('Get event').first().json.ssid }) }}", on_error="continueRegularOutput")
    prep = wf.add("Prepare failure", "n8n-nodes-base.set", 3.4, {
        "assignments": {"assignments": [{"id": str(uuid.uuid4()), "name": "error_message", "type": "string",
                                         "value": "={{ ($json.error && ($json.error.message || JSON.stringify($json.error))) || 'unknown error' }}"}]},
        "includeOtherFields": False, "options": {}}, y=520)
    failed = http(wf, "Mark failed", "PATCH", B("/events/{{ " + EID + " }}/status"),
                  "={{ { status: 'failed', error: $json.error_message } }}", on_error="continueRegularOutput", y=520)
    flog = log_run(wf, "Log failure", "W2_analysis", "failed", EID, "$('Prepare failure').first().json.error_message", y=520)
    wf.chain(wh, cfg, claim)
    wf.link(claim, get, 0)
    wf.link(claim, skip, 1)
    wf.link(get, ai)
    wf.link(ai, save, 0)
    wf.link(ai, prep, 1)
    wf.link(save, done, 0)
    wf.link(save, prep, 1)
    wf.chain(done, ok, gate)
    wf.link(gate, alert, 0)
    wf.chain(prep, failed, flog)
    wf.save("W2_event_analysis.json")


# --------------------------------------------------------------------------------------------- W3
def w3():
    wf = WF("SCAR W3 - Pending Sweeper (polling fallback)")
    sch = wf.add("Every 30s", "n8n-nodes-base.scheduleTrigger", 1.2,
                 {"rule": {"interval": [{"field": "seconds", "secondsInterval": 30}]}})
    cfg = config(wf)
    requeue = http(wf, "Requeue stuck events", "POST", B("/events/requeue-stuck"),
                   "={{ { older_than_seconds: 300 } }}", on_error="continueRegularOutput")
    pending = http(wf, "Get pending events", "GET", B("/events?status=pending&limit=50"), on_error="continueRegularOutput")
    trig = http(wf, "Trigger analysis (W2)", "POST", "={{ " + CFG + "analysis_webhook_url }}",
                "={{ { event_id: $json.event_id } }}", on_error="continueRegularOutput")
    wf.chain(sch, cfg, requeue, pending, trig)
    wf.nodes[[n["name"] for n in wf.nodes].index("Requeue stuck events")]["executeOnce"] = True
    wf.nodes[[n["name"] for n in wf.nodes].index("Get pending events")]["executeOnce"] = True
    wf.save("W3_pending_sweeper.json")


# --------------------------------------------------------------------------------------------- W4
def w4():
    wf = WF("SCAR W4 - Alerting")
    wh = webhook(wf, "scar/alert")
    cfg = config(wf)
    fmt = code(wf, "Format message", r"""// One alert per (mission, source device, category) per cooldown window: the AI service decides (atomic).
const a = $('Webhook').first().json.body;
const icon = { critical: '[CRITICAL]', high: '[HIGH]', medium: '[MEDIUM]', low: '[LOW]' }[a.severity] || '[ALERT]';
// plain text on purpose: SSIDs are attacker-controlled, never render them as HTML/Markdown
const text = [
  `SCAR ALERT ${icon} score ${a.risk_score}/100`,
  `Category: ${a.category}`,
  a.bssid ? `AP: ${a.ssid || '(hidden)'} / ${a.bssid}` : null,
  a.mission_id ? `Mission: ${a.mission_id}` : null,
  `Why: ${a.explanation}`,
  `Action: ${a.recommended_action}`,
  `Event: ${a.event_id}`
].filter(Boolean).join('\n').slice(0, 3500);
const key = [a.mission_id || '-', a.bssid || a.event_id, a.category].join('|');
return [{ json: { text, alert: a, dedupe_key: key } }];""")
    dd = http(wf, "Check duplicate (AI service)", "POST", A("/dedupe"),
              "={{ { key: $json.dedupe_key, cooldown_seconds: " + CFG + "alert_cooldown_s } }}", key="ai_key",
              on_error="continueRegularOutput")
    gate = wf.add("Is new alert?", "n8n-nodes-base.if", 2, {
        "conditions": {"options": {"caseSensitive": True, "leftValue": "", "typeValidation": "loose"},
                       "conditions": [{"id": str(uuid.uuid4()), "leftValue": "={{ $json.send !== false }}",
                                       "rightValue": True, "operator": {"type": "boolean", "operation": "true", "singleValue": True}}],
                       "combinator": "and"}, "options": {}})
    F = "$('Format message').first().json"
    tg = telegram(wf, "Send Telegram", "={{ " + F + ".text }}", on_error="continueErrorOutput")
    def save_body(delivery):
        return ("={{ { event_id: " + F + ".alert.event_id, severity: " + F + ".alert.severity, risk_score: " + F +
                ".alert.risk_score, category: " + F + ".alert.category, message: " + F + ".text, channel: 'telegram', delivery: '"
                + delivery + "' } }}")
    saved = http(wf, "Save alert (sent)", "POST", B("/alerts"), save_body("sent"), on_error="continueRegularOutput")
    savedf = http(wf, "Save alert (failed)", "POST", B("/alerts"), save_body("failed"), on_error="continueRegularOutput", y=520)
    wf.chain(wh, cfg, fmt, dd, gate)
    wf.link(gate, tg, 0)
    wf.link(tg, saved, 0)
    wf.link(tg, savedf, 1)
    wf.save("W4_alerting.json")


# --------------------------------------------------------------------------------------------- W5
def w5():
    wf = WF("SCAR W5 - Mission Report")
    MID = "$('Webhook').first().json.body.mission_id"
    wh = webhook(wf, "scar/mission-report")
    cfg = config(wf)
    gm = http(wf, "Get mission", "GET", B("/missions/{{ " + MID + " }}"))
    ge = http(wf, "Get events", "GET", B("/missions/{{ " + MID + " }}/events"))
    pe = wf.add("Pack events", "n8n-nodes-base.aggregate", 1,
                {"aggregate": "aggregateAllItemData", "destinationFieldName": "data", "options": {}})
    gr = http(wf, "Get risk results", "GET", B("/missions/{{ " + MID + " }}/analysis-results?agent=risk"))
    pr = wf.add("Pack results", "n8n-nodes-base.aggregate", 1,
                {"aggregate": "aggregateAllItemData", "destinationFieldName": "data", "options": {}})
    rep = http(wf, "Build report (AI service)", "POST", A("/report"),
               "={{ { mission: $('Get mission').first().json, events: $('Pack events').first().json.data, "
               "results: $('Pack results').first().json.data } }}", key="ai_key", on_error="continueErrorOutput", timeout=60000)
    save = http(wf, "Save report", "POST", B("/reports"),
                "={{ { mission_id: " + MID + ", format: 'markdown', content: $json.markdown } }}",
                on_error="continueRegularOutput")
    flog = log_run(wf, "Log failure", "W5_report", "failed", "null", "'report build failed'", y=520,
                   extra_fields=", mission_id: " + MID)
    wf.chain(wh, cfg, gm, ge, pe, gr, pr, rep)
    wf.link(rep, save, 0)
    wf.link(rep, flog, 1)
    wf.save("W5_mission_report.json")


# --------------------------------------------------------------------------------------------- W6
def w6():
    wf = WF("SCAR W6 - Health Check")
    sch = wf.add("Every 5 min", "n8n-nodes-base.scheduleTrigger", 1.2,
                 {"rule": {"interval": [{"field": "minutes", "minutesInterval": 5}]}})
    cfg = config(wf)
    cb = http(wf, "Check backend", "GET", B("/health"), on_error="continueRegularOutput")
    ca = http(wf, "Check AI service", "GET", A("/health"), key="ai_key", on_error="continueRegularOutput")
    ev = code(wf, "Evaluate (alert on state change only)", r"""const down = [];
const b = $('Check backend').first().json, a = $('Check AI service').first().json;
if (!b || b.error) down.push('backend');
if (!a || a.error || a.status !== 'ok') down.push('ai-service');
const sd = $getWorkflowStaticData('global');
const state = down.sort().join(',');
if (sd.last === state) return [];                       // nothing changed -> stay quiet
const first = sd.last === undefined;
sd.last = state;
if (first && !state) return [];                          // first run and healthy -> no message
const text = state ? `SCAR health: DOWN -> ${state}` : 'SCAR health: all services recovered';
return [{ json: { text } }];""")
    tg = telegram(wf, "Send Telegram", "={{ $json.text }}", on_error="continueRegularOutput")
    wf.chain(sch, cfg, cb, ca, ev, tg)
    wf.save("W6_health_check.json")


if __name__ == "__main__":
    for f in (w1, w2, w3, w4, w5, w6):
        f()
    print("generated:", sorted(p.name for p in OUT.glob("W*.json")))
