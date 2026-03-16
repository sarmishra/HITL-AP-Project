"""
scripts/init_db.py
==================
Initializes the PostgreSQL audit database schema for the HITL-AP
Audit Logger component.

Creates the audit_log table with hash-chain integrity columns
matching the cryptographic non-repudiation design in §VI.D of
the paper.

Usage:
    python scripts/init_db.py
    python scripts/init_db.py --drop-existing   # WARNING: destroys all audit data
"""

import argparse
import hashlib
import hmac
import os
import sys
from datetime import datetime

try:
    import psycopg2
    from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
except ImportError:
    print("ERROR: psycopg2 not installed. Run: pip install psycopg2-binary")
    sys.exit(1)

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://hitlap:hitlap_dev@localhost:5432/hitlap"
)


# ─── Schema Definitions ───────────────────────────────────────────────────────

CREATE_AUDIT_LOG_TABLE = """
CREATE TABLE IF NOT EXISTS audit_log (
    id                  BIGSERIAL PRIMARY KEY,

    -- Event identity
    event_id            UUID NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    run_id              VARCHAR(128),
    session_id          VARCHAR(128),

    -- Pipeline stage and action
    pipeline_layer      VARCHAR(64)  NOT NULL,
    event_type          VARCHAR(64)  NOT NULL,
    action              TEXT,
    tool_name           VARCHAR(128),

    -- Reasoning trace (RTC metric)
    reasoning_trace     JSONB,
    rtc_complete        BOOLEAN DEFAULT FALSE,

    -- Risk assessment
    risk_level          VARCHAR(16),
    risk_score          NUMERIC(5,4),
    policy_decision     VARCHAR(16),
    policy_deny_reasons JSONB,

    -- Human oversight (IL metric)
    hitl_triggered      BOOLEAN DEFAULT FALSE,
    hitl_trigger_time   TIMESTAMPTZ,
    hitl_decision_time  TIMESTAMPTZ,
    hitl_decision       VARCHAR(16),
    hitl_reviewer_id    VARCHAR(128),
    il_ms               NUMERIC(10,3),

    -- Payload
    input_payload       JSONB,
    output_result       JSONB,

    -- Timestamps
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    executed_at         TIMESTAMPTZ,

    -- Cryptographic integrity (HMAC-SHA256 hash chain)
    -- Each entry signs its content + previous entry hash
    entry_hash          VARCHAR(64)  NOT NULL,
    prev_entry_hash     VARCHAR(64),
    hmac_signature      VARCHAR(64)  NOT NULL,
    signing_key_version INTEGER      NOT NULL DEFAULT 1
);
"""

CREATE_PIPELINE_EVENTS_TABLE = """
CREATE TABLE IF NOT EXISTS pipeline_events (
    id              BIGSERIAL PRIMARY KEY,
    event_id        UUID NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    run_id          VARCHAR(128),
    event_type      VARCHAR(64)  NOT NULL,
    event_subtype   VARCHAR(64),
    payload         JSONB,
    signed          BOOLEAN DEFAULT FALSE,
    entry_hash      VARCHAR(64),
    hmac_signature  VARCHAR(64),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"""

CREATE_EVALUATION_RUNS_TABLE = """
CREATE TABLE IF NOT EXISTS evaluation_runs (
    id              BIGSERIAL PRIMARY KEY,
    run_id          VARCHAR(128) NOT NULL UNIQUE,
    system          VARCHAR(64)  NOT NULL,
    condition       VARCHAR(64),
    rtc_score       NUMERIC(6,3),
    il_ms           NUMERIC(10,3),
    acs_score       NUMERIC(6,3),
    total_events    INTEGER DEFAULT 0,
    signed_events   INTEGER DEFAULT 0,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMPTZ,
    notes           TEXT
);
"""

CREATE_POLICY_VIOLATIONS_TABLE = """
CREATE TABLE IF NOT EXISTS policy_violations (
    id              BIGSERIAL PRIMARY KEY,
    event_id        UUID REFERENCES audit_log(event_id),
    violation_type  VARCHAR(64)  NOT NULL,
    risk_level      VARCHAR(16)  NOT NULL,
    deny_reason     TEXT         NOT NULL,
    pipeline_layer  VARCHAR(64),
    action          TEXT,
    resolved        BOOLEAN DEFAULT FALSE,
    resolved_by     VARCHAR(128),
    resolved_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"""

CREATE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_audit_log_run_id     ON audit_log(run_id);",
    "CREATE INDEX IF NOT EXISTS idx_audit_log_event_type ON audit_log(event_type);",
    "CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at);",
    "CREATE INDEX IF NOT EXISTS idx_audit_log_risk_level ON audit_log(risk_level);",
    "CREATE INDEX IF NOT EXISTS idx_audit_log_hitl       ON audit_log(hitl_triggered) WHERE hitl_triggered = TRUE;",
    "CREATE INDEX IF NOT EXISTS idx_pipeline_run_id      ON pipeline_events(run_id);",
    "CREATE INDEX IF NOT EXISTS idx_eval_system          ON evaluation_runs(system);",
]

DROP_TABLES = """
DROP TABLE IF EXISTS policy_violations CASCADE;
DROP TABLE IF EXISTS audit_log CASCADE;
DROP TABLE IF EXISTS pipeline_events CASCADE;
DROP TABLE IF EXISTS evaluation_runs CASCADE;
"""

VERIFY_QUERY = """
SELECT table_name, pg_size_pretty(pg_total_relation_size(quote_ident(table_name))) AS size
FROM information_schema.tables
WHERE table_schema = 'public'
ORDER BY table_name;
"""


# ─── Initialization ───────────────────────────────────────────────────────────

def connect(database_url: str):
    """Connect to PostgreSQL and return connection."""
    try:
        conn = psycopg2.connect(database_url)
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        return conn
    except psycopg2.OperationalError as e:
        print(f"\nERROR: Cannot connect to database.")
        print(f"  URL: {database_url}")
        print(f"  Details: {e}")
        print(f"\n  Ensure PostgreSQL is running. Try: docker-compose up -d postgres")
        sys.exit(1)


def init_db(drop_existing: bool = False):
    """Initialize the HITL-AP audit database schema."""
    print(f"\n{'='*60}")
    print(f"  HITL-AP Database Initialization")
    print(f"{'='*60}")
    print(f"  Database: {DATABASE_URL.split('@')[-1]}")
    print(f"  Time:     {datetime.utcnow().isoformat()}")

    conn = connect(DATABASE_URL)
    cur = conn.cursor()

    if drop_existing:
        print(f"\n  WARNING: Dropping existing tables...")
        cur.execute(DROP_TABLES)
        print(f"  Tables dropped.")

    print(f"\n  Creating tables...")
    cur.execute(CREATE_AUDIT_LOG_TABLE)
    print(f"  ✓ audit_log")

    cur.execute(CREATE_PIPELINE_EVENTS_TABLE)
    print(f"  ✓ pipeline_events")

    cur.execute(CREATE_EVALUATION_RUNS_TABLE)
    print(f"  ✓ evaluation_runs")

    cur.execute(CREATE_POLICY_VIOLATIONS_TABLE)
    print(f"  ✓ policy_violations")

    print(f"\n  Creating indexes...")
    for idx_sql in CREATE_INDEXES:
        cur.execute(idx_sql)
    print(f"  ✓ {len(CREATE_INDEXES)} indexes created")

    # Insert initialization record
    cur.execute("""
        INSERT INTO audit_log (
            pipeline_layer, event_type, action,
            entry_hash, prev_entry_hash, hmac_signature,
            signing_key_version, risk_level, rtc_complete
        ) VALUES (
            'SYSTEM', 'DB_INIT', 'Database schema initialized',
            %s, 'GENESIS', %s, 1, 'LOW', FALSE
        )
    """, (
        hashlib.sha256(b"HITLAP_GENESIS_BLOCK").hexdigest(),
        hmac.new(
            b"init_key",
            b"HITLAP_GENESIS_BLOCK",
            hashlib.sha256
        ).hexdigest()
    ))
    print(f"\n  ✓ Genesis audit entry written")

    # Verify
    print(f"\n  Verifying schema...")
    cur.execute(VERIFY_QUERY)
    tables = cur.fetchall()
    for table_name, size in tables:
        print(f"  ✓ {table_name:<30} {size}")

    cur.close()
    conn.close()

    print(f"\n{'='*60}")
    print(f"  Database initialization complete.")
    print(f"  Next step: Start the Risk Analyzer")
    print(f"  Command:   uvicorn aocp.risk_analyzer:app --reload --port 8000")
    print(f"{'='*60}\n")


# ─── Entry Point ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Initialize the HITL-AP PostgreSQL audit database"
    )
    parser.add_argument(
        "--drop-existing",
        action="store_true",
        help="Drop and recreate all tables (WARNING: destroys all audit data)"
    )
    args = parser.parse_args()

    if args.drop_existing:
        confirm = input("\n  WARNING: This will destroy all existing audit data.\n  Type 'yes' to confirm: ")
        if confirm.strip().lower() != "yes":
            print("  Aborted.")
            sys.exit(0)

    init_db(drop_existing=args.drop_existing)
