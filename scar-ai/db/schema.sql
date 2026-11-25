-- SCAR MVP schema (PostgreSQL 13+)  --  run once:  psql -U scar -d scar -f schema.sql
-- Owners: events/missions -> Backend; analysis_results/workflow_runs/alerts/reports -> AI & Automation; twin_* -> Twin.
BEGIN;

CREATE TABLE IF NOT EXISTS missions (
    mission_id   TEXT PRIMARY KEY,
    drone_id     TEXT,
    zone_id      TEXT,
    status       TEXT NOT NULL DEFAULT 'planned' CHECK (status IN ('planned','in_flight','completed','aborted')),
    started_at   TIMESTAMPTZ,
    ended_at     TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS twin_zones (
    zone_id      TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    floor        TEXT,
    origin_lat   DOUBLE PRECISION NOT NULL,
    origin_lon   DOUBLE PRECISION NOT NULL,
    width_m      DOUBLE PRECISION NOT NULL,
    height_m     DOUBLE PRECISION NOT NULL,
    boundary     JSONB,                       -- GeoJSON polygon (geo-fence)
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS events (
    event_id     TEXT PRIMARY KEY,
    mission_id   TEXT REFERENCES missions(mission_id),
    source       TEXT NOT NULL CHECK (source IN ('wazuh','zeek','drone')),
    event_type   TEXT NOT NULL,
    timestamp    TIMESTAMPTZ NOT NULL,
    bssid        TEXT,
    ssid         TEXT,
    rssi         INTEGER,
    channel      INTEGER,
    encryption   TEXT,
    lat          DOUBLE PRECISION,
    lon          DOUBLE PRECISION,
    altitude     DOUBLE PRECISION,
    raw_payload  JSONB NOT NULL DEFAULT '{}'::jsonb,
    status       TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','processing','analyzed','failed')),
    status_error TEXT,
    claimed_at   TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_events_status_created ON events (status, created_at);
CREATE INDEX IF NOT EXISTS idx_events_mission        ON events (mission_id);
CREATE INDEX IF NOT EXISTS idx_events_bssid          ON events (bssid);

CREATE TABLE IF NOT EXISTS analysis_results (
    result_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id           TEXT NOT NULL REFERENCES events(event_id) ON DELETE CASCADE,
    agent              TEXT NOT NULL CHECK (agent IN ('sentinel','prediction','risk')),
    model_version      TEXT NOT NULL,
    severity           TEXT NOT NULL CHECK (severity IN ('low','medium','high','critical')),
    risk_score         INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    category           TEXT NOT NULL CHECK (category IN
                         ('rogue_ap','weak_encryption','unknown_device','hidden_ssid','host_alert','network_alert','benign')),
    confidence         REAL NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    explanation        TEXT NOT NULL,
    recommended_action TEXT NOT NULL,
    features           JSONB NOT NULL DEFAULT '{}'::jsonb,
    processing_ms      INTEGER,
    error              TEXT,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- idempotency: re-running a workflow must not create duplicate rows (use INSERT .. ON CONFLICT DO UPDATE)
    CONSTRAINT uq_result_per_agent_version UNIQUE (event_id, agent, model_version)
);
CREATE INDEX IF NOT EXISTS idx_results_event    ON analysis_results (event_id);
CREATE INDEX IF NOT EXISTS idx_results_risk     ON analysis_results (agent, risk_score DESC);

CREATE TABLE IF NOT EXISTS workflow_runs (
    run_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workflow_name     TEXT NOT NULL,
    event_id          TEXT,
    mission_id        TEXT,
    n8n_execution_id  TEXT,
    status            TEXT NOT NULL CHECK (status IN ('success','failed','skipped')),
    attempts          INTEGER NOT NULL DEFAULT 1,
    error_message     TEXT,
    started_at        TIMESTAMPTZ,
    finished_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_runs_event ON workflow_runs (event_id);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id      TEXT NOT NULL REFERENCES events(event_id) ON DELETE CASCADE,
    severity      TEXT NOT NULL CHECK (severity IN ('low','medium','high','critical')),
    risk_score    INTEGER NOT NULL,
    category      TEXT NOT NULL,
    message       TEXT NOT NULL,
    channel       TEXT NOT NULL DEFAULT 'telegram',
    delivery      TEXT NOT NULL DEFAULT 'sent' CHECK (delivery IN ('sent','failed')),
    acknowledged  BOOLEAN NOT NULL DEFAULT FALSE,
    acknowledged_by TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_alerts_open ON alerts (acknowledged, created_at DESC);

CREATE TABLE IF NOT EXISTS reports (
    report_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    mission_id   TEXT NOT NULL REFERENCES missions(mission_id),
    format       TEXT NOT NULL DEFAULT 'markdown',
    content      TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS twin_assets (
    asset_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_type         TEXT NOT NULL CHECK (asset_type IN ('access_point','device','drone')),
    bssid              TEXT NOT NULL,
    ssid               TEXT,
    encryption         TEXT,
    zone_id            TEXT REFERENCES twin_zones(zone_id),
    x                  DOUBLE PRECISION,           -- local metres from zone origin (for the 2D map)
    y                  DOUBLE PRECISION,
    lat                DOUBLE PRECISION,
    lon                DOUBLE PRECISION,
    authorized         BOOLEAN,                    -- NULL = unknown (no baseline)
    observations       INTEGER NOT NULL DEFAULT 0,
    max_rssi           INTEGER,
    current_risk_score INTEGER NOT NULL DEFAULT 0,
    first_seen         TIMESTAMPTZ,
    last_seen          TIMESTAMPTZ,
    CONSTRAINT uq_asset UNIQUE (zone_id, bssid)    -- upsert key
);

CREATE TABLE IF NOT EXISTS twin_readings (
    reading_id  BIGSERIAL PRIMARY KEY,
    bssid       TEXT NOT NULL,
    mission_id  TEXT REFERENCES missions(mission_id),
    rssi        INTEGER NOT NULL,
    x           DOUBLE PRECISION,
    y           DOUBLE PRECISION,
    lat         DOUBLE PRECISION,
    lon         DOUBLE PRECISION,
    timestamp   TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_readings_mission ON twin_readings (mission_id, bssid);

-- Customer baseline of legitimate APs (shared with the AI service; /baseline endpoint can sync it)
CREATE TABLE IF NOT EXISTS authorized_assets (
    bssid      TEXT PRIMARY KEY,
    ssid       TEXT,
    zone_id    TEXT REFERENCES twin_zones(zone_id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Atomic claim used by POST /events/{id}/claim  (prevents double analysis when push + polling race):
--   UPDATE events SET status='processing', claimed_at=now()
--   WHERE event_id = $1 AND status = 'pending' RETURNING *;      -- 0 rows -> respond 409
COMMIT;
