-- =============================================================================
-- Enterprise AI Security Platform — TimescaleDB Schema
-- PostgreSQL extension of TimescaleDB for time-series network telemetry.
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS timescaledb;
CREATE EXTENSION IF NOT EXISTS pgcrypto;      -- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS vector;        -- pgvector payload/rule embeddings
CREATE EXTENSION IF NOT EXISTS inet_minmax_ops;

-- 1. Incidents Core Table -----------------------------------------------------
CREATE TABLE IF NOT EXISTS incidents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title VARCHAR(255) NOT NULL,
    sector VARCHAR(64) NOT NULL,               -- Firewall_IPS, Detection_IDS, DDoS_Mitigation, AppSec...
    tier_level INT CHECK (tier_level IN (1, 2, 3)),
    status VARCHAR(32) NOT NULL,               -- Ingested, Investigating, Pending_Approval, Resolved
    attack_class VARCHAR(32) DEFAULT 'NONE',   -- NONE, VOLUMETRIC, PROTOCOL, APPLICATION
    ciso_confidence_score FLOAT CHECK (ciso_confidence_score BETWEEN 0.0 AND 1.0),
    summary TEXT DEFAULT '',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    resolved_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_incidents_sector_status ON incidents(sector, status);

-- 2. Raw Telemetry, IDS/IPS, Firewall & DDoS Logs (hypertable) -----------------
CREATE TABLE IF NOT EXISTS network_attack_telemetry_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID REFERENCES incidents(id) ON DELETE CASCADE,
    source_system VARCHAR(128) NOT NULL,       -- Suricata, Zeek, PaloAlto_NGFW, Cloudflare_Scrubbing, eBPF
    log_type VARCHAR(64) NOT NULL,             -- IDS_ALERT, IPS_DROP, FIREWALL_DENY, PCAP_TRACE, DDOS_VOLUME_SPIKE
    src_ip INET NOT NULL,
    dst_ip INET NOT NULL,
    src_port INT,
    dst_port INT,
    protocol VARCHAR(16),
    signature_id VARCHAR(128),                 -- e.g., "ET WEB_SERVER SQLi Attempt" or "DDoS_SYN_FLOOD"
    traffic_volume_bps BIGINT,                 -- Critical for DDoS visibility
    packets_per_second BIGINT,                 -- Critical for DDoS visibility
    raw_payload TEXT,
    payload_embedding VECTOR(768),             -- pgvector: high-throughput packet payload embeddings
    parsed_entities JSONB NOT NULL DEFAULT '{}',
    observed_at TIMESTAMPTZ NOT NULL,
    is_adversarial_pattern BOOLEAN DEFAULT FALSE
);

SELECT create_hypertable('network_attack_telemetry_logs', 'observed_at',
    chunk_time_interval => INTERVAL '1 hour', if_not_exists => TRUE);

CREATE INDEX IF NOT EXISTS idx_tel_incident ON network_attack_telemetry_logs(incident_id, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_tel_ddos_spike ON network_attack_telemetry_logs(traffic_volume_bps DESC, packets_per_second DESC)
    WHERE log_type = 'DDOS_VOLUME_SPIKE';
CREATE INDEX IF NOT EXISTS idx_tel_sig ON network_attack_telemetry_logs(signature_id, observed_at DESC);

-- Continuous aggregate: per-minute DDoS visibility rollup (bps/pps baselines)
CREATE MATERIALIZED VIEW IF NOT EXISTS ddos_visibility_1m
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 minute', observed_at) AS bucket,
    dst_ip,
    SUM(traffic_volume_bps)  AS total_bps,
    MAX(packets_per_second)  AS peak_pps,
    COUNT(*)                 AS alert_count
FROM network_attack_telemetry_logs
WHERE log_type IN ('DDOS_VOLUME_SPIKE','IDS_ALERT','IPS_DROP')
GROUP BY bucket, dst_ip
WITH NO DATA;

-- 3. Firewall, IPS & DDoS Policy History ---------------------------------------
CREATE TABLE IF NOT EXISTS firewall_policy_changes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID REFERENCES incidents(id),
    device_id VARCHAR(128) NOT NULL,
    rule_type VARCHAR(32) NOT NULL,            -- DROP, REJECT, ALLOW, RATE_LIMIT, SCRUB_REDIRECT
    rule_definition JSONB NOT NULL,            -- {"src":"...","port":"...","proto":"...","action":"rate_limit_100pps"}
    enforcement_layer VARCHAR(64) NOT NULL,    -- eBPF, IPTABLES, NGFW_API, CLOUDFLARE_WAF, BGP_FLOWSPEC
    applied_by_agent VARCHAR(64) NOT NULL,
    approved_by_human VARCHAR(128),
    rolled_back BOOLEAN DEFAULT FALSE,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_fw_active ON firewall_policy_changes(expires_at)
    WHERE rolled_back = FALSE;

-- 4. Agent Execution & Reasoning Traces ----------------------------------------
CREATE TABLE IF NOT EXISTS agent_decision_traces (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID REFERENCES incidents(id) ON DELETE CASCADE,
    agent_name VARCHAR(64) NOT NULL,
    step_number INT NOT NULL,
    prompt_context JSONB NOT NULL,
    llm_thought_process TEXT NOT NULL,
    tool_calls_executed JSONB NOT NULL,
    hypotheses_evaluated JSONB NOT NULL,
    confidence_delta FLOAT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (incident_id, agent_name, step_number)
);

-- 5. Human Approval & RLHF Feedback History ------------------------------------
CREATE TABLE IF NOT EXISTS human_action_reviews (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID REFERENCES incidents(id),
    proposal_id VARCHAR(64) NOT NULL,
    proposed_action JSONB NOT NULL,
    business_impact_analysis JSONB NOT NULL,
    action_taken VARCHAR(32) NOT NULL,         -- Approved, Modified, Rejected
    reviewer_id VARCHAR(128) NOT NULL,
    human_feedback_notes TEXT,
    reviewed_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_reviews_proposal ON human_action_reviews(proposal_id);

-- 6. Scraped Threat Intelligence (feeds + pgvector corpus) ----------------------
CREATE TABLE IF NOT EXISTS threat_feed_entries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    feed VARCHAR(64) NOT NULL,                 -- ET_OPEN_RULES, SNORT_COMMUNITY, YARA, ABUSEIPDB, OTX, CISA_KEV, CF_RADAR, AKAMAI_SOTI
    entry_type VARCHAR(32) NOT NULL,           -- SURICATA_RULE, YARA, CVE, BAD_IP, PLAYBOOK
    identifier VARCHAR(255) NOT NULL,
    summary TEXT,
    severity VARCHAR(16) DEFAULT 'medium',
    content TEXT,
    embedding_ref VARCHAR(128),                -- link into pgvector / ClickHouse corpus
    scraped_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (feed, identifier)
);

-- 7. Fine-Tuning Pipeline Runs ---------------------------------------------------
CREATE TABLE IF NOT EXISTS training_jobs (
    job_id VARCHAR(64) PRIMARY KEY,
    dataset_kind VARCHAR(16) NOT NULL,         -- SFT | DPO
    sample_count INT DEFAULT 0,
    verified_review_count INT DEFAULT 0,
    base_model VARCHAR(128) DEFAULT 'llama-3.1-8b-instruct',
    method VARCHAR(64) DEFAULT 'LoRA/QLoRA (Unsloth + trl)',
    status VARCHAR(16) DEFAULT 'QUEUED',
    triggered_at TIMESTAMPTZ DEFAULT NOW()
);
