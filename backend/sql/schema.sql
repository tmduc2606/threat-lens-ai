-- ThreatLensAI — Database Schema Reference
--
-- NOTE: This file is for documentation/reference only.
-- The actual schema is managed by SQLAlchemy's Base.metadata.create_all()
-- in backend/app/main.py:on_startup(). SQLAlchemy generates the correct
-- DDL for whichever database backend is configured (PostgreSQL or SQLite).
--
-- This file uses standard SQL that works on both PostgreSQL and SQLite.

CREATE TABLE IF NOT EXISTS otx_pulses (
    pulse_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT,
    author TEXT,
    created_at TIMESTAMP,
    modified_at TIMESTAMP,
    tlp TEXT,
    tags TEXT,
    malware_families TEXT,
    attack_ids TEXT,
    industries TEXT,
    countries TEXT,
    indicators_count INTEGER DEFAULT 0,
    subscribers INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS cve_vulnerabilities (
    cve_id TEXT PRIMARY KEY,
    vendor_project TEXT,
    product TEXT,
    vulnerability_name TEXT,
    date_added DATE,
    short_description TEXT,
    required_action TEXT,
    due_date DATE,
    known_ransomware_campaign_use TEXT,
    cwes TEXT,
    cvss_v3_score REAL,
    cvss_v3_vector TEXT,
    enriched_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS malicious_domains (
    domain TEXT PRIMARY KEY,
    tld TEXT,
    domain_length INTEGER,
    has_numbers BOOLEAN DEFAULT FALSE,
    has_hyphen BOOLEAN DEFAULT FALSE,
    registrar TEXT,
    creation_date DATE,
    last_update_date DATE,
    reputation REAL,
    malicious_votes INTEGER DEFAULT 0,
    suspicious_votes INTEGER DEFAULT 0,
    harmless_votes INTEGER DEFAULT 0,
    undetected_votes INTEGER DEFAULT 0,
    total_engines INTEGER DEFAULT 0,
    threat_severity TEXT,
    categories TEXT,
    popularity_rank INTEGER,
    last_analysis_date DATE,
    whois_summary TEXT,
    data_source TEXT,
    enriched_at TIMESTAMP,
    enrichment_breakdown TEXT
);

CREATE TABLE IF NOT EXISTS malicious_ips (
    ip TEXT PRIMARY KEY,
    country TEXT,
    continent TEXT,
    asn TEXT,
    owner TEXT,
    network TEXT,
    malicious_votes INTEGER DEFAULT 0,
    suspicious_votes INTEGER DEFAULT 0,
    harmless_votes INTEGER DEFAULT 0,
    undetected_votes INTEGER DEFAULT 0,
    total_reports INTEGER DEFAULT 0,
    reputation_score REAL,
    threat_label TEXT,
    threat_category TEXT,
    regional_registry TEXT,
    whois_summary TEXT,
    tor_node BOOLEAN DEFAULT FALSE,
    times_submitted INTEGER DEFAULT 0,
    last_analysis_date DATE,
    threat_severity TEXT,
    data_source TEXT DEFAULT 'csv_import',
    enriched_at TIMESTAMP,
    enrichment_breakdown TEXT
);

CREATE TABLE IF NOT EXISTS intel_index (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_type TEXT NOT NULL,
    source_key TEXT NOT NULL,
    title TEXT,
    summary TEXT,
    severity TEXT,
    score REAL,
    tags TEXT,
    created_at TIMESTAMP,
    updated_at TIMESTAMP,
    UNIQUE (source_type, source_key)
);

-- API response cache
CREATE TABLE IF NOT EXISTS api_cache (
    cache_key TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    response_json TEXT NOT NULL,
    queried_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL
);

-- Enrichment audit log
CREATE TABLE IF NOT EXISTS enrichment_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator_type TEXT NOT NULL,
    indicator_value TEXT NOT NULL,
    api_source TEXT NOT NULL,
    success BOOLEAN DEFAULT TRUE,
    error_message TEXT,
    enriched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    latency_ms INTEGER
);

-- Training data growth tracking
CREATE TABLE IF NOT EXISTS training_metadata (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator_type TEXT NOT NULL,
    total_records INTEGER NOT NULL,
    api_enriched_records INTEGER NOT NULL,
    exported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    model_version TEXT,
    notes TEXT
);

CREATE INDEX IF NOT EXISTS idx_intel_index_source_type ON intel_index(source_type);
CREATE INDEX IF NOT EXISTS idx_intel_index_source_key ON intel_index(source_key);
CREATE INDEX IF NOT EXISTS idx_intel_index_updated_at ON intel_index(updated_at);
