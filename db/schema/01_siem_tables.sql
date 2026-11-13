-- 01_siem_tables.sql
-- The nine SIEM tables, copied from the ER/Relational Schema document (§2, §4).
-- Every table is in BCNF except alert_logs (documented 2NF exception, ER doc §5.3).
-- The partitioned tables (logs, logs_archive) are created in 03_partitions.sql;
-- their indexes in 04_indexes.sql; the partial unique indexes in 05_constraints.sql.

SET search_path TO siem, public;

-- 2.1 USER : SIEM operators only (admin / analyst / viewer). Not demo visitors.
CREATE TABLE users (
    user_id       serial       PRIMARY KEY,
    username      varchar(50)  NOT NULL UNIQUE,
    email         varchar(100) NOT NULL UNIQUE,
    password_hash varchar(255) NOT NULL,
    role          varchar(10)  NOT NULL CHECK (role IN ('admin', 'analyst', 'viewer')),
    is_active     boolean      NOT NULL DEFAULT true,
    created_at    timestamptz  NOT NULL DEFAULT now()
);

-- 2.2 LOG_SOURCE : where a stream of logs comes from.
CREATE TABLE log_sources (
    source_id    serial       PRIMARY KEY,
    source_name  varchar(100) NOT NULL,
    source_type  varchar(50)  NOT NULL,
    api_key_hash varchar(255) NOT NULL,
    created_at   timestamptz  NOT NULL DEFAULT now()
);

-- 2.4 ALERT_RULE : admin-defined threshold or pattern rule.
CREATE TABLE alert_rules (
    rule_id         serial       PRIMARY KEY,
    rule_name       varchar(100) NOT NULL,
    rule_type       varchar(10)  NOT NULL CHECK (rule_type IN ('threshold', 'pattern')),
    event_type      varchar(50),               -- threshold rules: the event counted
    threshold_count integer,                    -- threshold rules: count that triggers
    pattern         text,                       -- pattern rules: regex on payload
    window_seconds  integer      NOT NULL,
    severity        varchar(10)  NOT NULL CHECK (severity IN ('low', 'medium', 'high')),
    enabled         boolean      NOT NULL DEFAULT true,
    created_by      integer      NOT NULL REFERENCES users (user_id),
    -- a threshold rule needs event_type + threshold_count; a pattern rule needs pattern
    CONSTRAINT rule_shape CHECK (
        (rule_type = 'threshold' AND event_type IS NOT NULL AND threshold_count IS NOT NULL)
        OR (rule_type = 'pattern' AND pattern IS NOT NULL)
    )
);

-- 2.5 ALERT : one firing of a rule against a source IP.
CREATE TABLE alerts (
    alert_id     serial      PRIMARY KEY,
    rule_id      integer     NOT NULL REFERENCES alert_rules (rule_id),
    src_ip       inet        NOT NULL,
    status       varchar(6)  NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'closed')),
    raised_at    timestamptz NOT NULL DEFAULT now(),
    closed_by    integer     REFERENCES users (user_id),   -- null until closed
    closed_at    timestamptz,
    closing_note text
);

-- TRIGGERS (M:N) : links an alert to the logs that triggered it.
-- Deliberately NO foreign key to logs (ER doc §4.3): partitions get detached and
-- archived, and an FK would block that. ts is copied so a lookup hits the right
-- logs partition directly. This is the documented 2NF exception (§5.3).
CREATE TABLE alert_logs (
    alert_id integer     NOT NULL REFERENCES alerts (alert_id),
    log_id   bigint      NOT NULL,
    ts       timestamptz NOT NULL,
    PRIMARY KEY (alert_id, log_id, ts)
);

-- 2.6 BLOCKED_IP : an IP blocked after an analyst confirmed an alert.
-- alert_id is UNIQUE -> an alert leads to at most one block (1:0..1).
CREATE TABLE blocked_ips (
    block_id     serial      PRIMARY KEY,
    alert_id     integer     NOT NULL UNIQUE REFERENCES alerts (alert_id),
    ip_address   inet        NOT NULL,
    blocked_by   integer     NOT NULL REFERENCES users (user_id),
    blocked_at   timestamptz NOT NULL DEFAULT now(),
    unblocked_at timestamptz                       -- null while the block is active
);

-- 2.7 SYSTEM_SETTING : standalone configuration (retention_months, partitions_ahead).
CREATE TABLE system_settings (
    setting_key   varchar(50)  PRIMARY KEY,
    setting_value varchar(100) NOT NULL
);
