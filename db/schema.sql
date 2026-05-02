-- db/schema.sql
--
-- GRC Vendor Risk Engine — PostgreSQL 16 Schema
-- Implements a tamper-evident audit log pattern alongside the core
-- assessment tables. All timestamps are stored in UTC (TIMESTAMPTZ).

BEGIN;

-- ---------------------------------------------------------------------------
-- Extensions
-- ---------------------------------------------------------------------------

CREATE EXTENSION IF NOT EXISTS "pgcrypto";   -- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS "pg_trgm";    -- trigram indexes for vendor search

-- ---------------------------------------------------------------------------
-- Enum types
-- ---------------------------------------------------------------------------

CREATE TYPE risk_band AS ENUM ('LOW', 'MEDIUM', 'HIGH');

CREATE TYPE audit_action AS ENUM (
    'ASSESSMENT_CREATED',
    'ASSESSMENT_READ',
    'VENDOR_HISTORY_QUERIED',
    'REPORT_GENERATED'
);

-- ---------------------------------------------------------------------------
-- Core tables
-- ---------------------------------------------------------------------------

CREATE TABLE vendors (
    vendor_id     TEXT         PRIMARY KEY,
    display_name  TEXT,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE assessments (
    assessment_id    UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    vendor_id        TEXT         NOT NULL REFERENCES vendors(vendor_id) ON DELETE RESTRICT,
    composite_score  NUMERIC(5,2) NOT NULL CHECK (composite_score BETWEEN 0 AND 100),
    risk_band        risk_band    NOT NULL,

    -- Dimension scores stored as JSONB for schema flexibility
    dimension_scores JSONB        NOT NULL DEFAULT '{}',
    failures         JSONB        NOT NULL DEFAULT '{}',

    -- Full assessment payload for forensic reproducibility
    raw_payload      JSONB        NOT NULL DEFAULT '{}',

    submitted_by     TEXT,
    assessed_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_dimension_scores_not_empty CHECK (dimension_scores != '{}')
);

-- Partial index: quickly surface all HIGH-risk vendors
CREATE INDEX idx_assessments_high_risk
    ON assessments (vendor_id, assessed_at DESC)
    WHERE risk_band = 'HIGH';

-- Composite index for vendor history queries (most recent first)
CREATE INDEX idx_assessments_vendor_history
    ON assessments (vendor_id, assessed_at DESC);

-- ---------------------------------------------------------------------------
-- Materialized view: latest assessment per vendor
-- ---------------------------------------------------------------------------

CREATE MATERIALIZED VIEW latest_vendor_risk AS
SELECT DISTINCT ON (vendor_id)
    vendor_id,
    assessment_id,
    composite_score,
    risk_band,
    dimension_scores,
    assessed_at
FROM assessments
ORDER BY vendor_id, assessed_at DESC;

CREATE UNIQUE INDEX ON latest_vendor_risk (vendor_id);

-- Refresh with: REFRESH MATERIALIZED VIEW CONCURRENTLY latest_vendor_risk;

-- ---------------------------------------------------------------------------
-- Immutable audit log
-- Rows are INSERT-only; no UPDATE or DELETE is permitted via RLS.
-- ---------------------------------------------------------------------------

CREATE TABLE audit_log (
    log_id       UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    action       audit_action  NOT NULL,
    actor        TEXT          NOT NULL,
    vendor_id    TEXT,
    assessment_id UUID,
    request_id   TEXT,
    ip_address   INET,
    occurred_at  TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    metadata     JSONB         NOT NULL DEFAULT '{}'
);

-- Fast lookups by actor and time window
CREATE INDEX idx_audit_log_actor_time
    ON audit_log (actor, occurred_at DESC);

CREATE INDEX idx_audit_log_assessment
    ON audit_log (assessment_id)
    WHERE assessment_id IS NOT NULL;

-- ---------------------------------------------------------------------------
-- Row Level Security — enforce append-only on audit_log
-- ---------------------------------------------------------------------------

ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;

-- Application role may only INSERT; no UPDATE / DELETE
CREATE POLICY audit_log_insert_only
    ON audit_log
    FOR INSERT
    TO app_role
    WITH CHECK (true);

CREATE POLICY audit_log_select
    ON audit_log
    FOR SELECT
    TO app_role
    USING (true);

-- ---------------------------------------------------------------------------
-- Updated_at trigger for vendors
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_vendors_updated_at
    BEFORE UPDATE ON vendors
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

COMMIT;
