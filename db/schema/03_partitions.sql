-- 03_partitions.sql
-- The core fact table, partitioned by month on ts (FR11).
-- Composite PK (log_id, ts): PostgreSQL requires the partition column in every
-- unique constraint on a partitioned table (ER doc §4.5, §5.4). log_id comes from
-- a sequence so it is unique in practice; the DB enforces only the pair.

SET search_path TO siem, public;

CREATE SEQUENCE IF NOT EXISTS logs_log_id_seq;

CREATE TABLE logs (
    log_id         bigint      NOT NULL DEFAULT nextval('logs_log_id_seq'),
    ts             timestamptz NOT NULL,
    source_id      integer     NOT NULL REFERENCES log_sources (source_id),
    actor_username varchar(50),                 -- as the source reported it; may be null
    src_ip         inet        NOT NULL,
    event_type     varchar(50) NOT NULL,
    status         integer,                     -- HTTP-style result code
    user_agent     text,
    payload        text,
    PRIMARY KEY (log_id, ts)
) PARTITION BY RANGE (ts);

ALTER SEQUENCE logs_log_id_seq OWNED BY logs.log_id;

-- Archive table: same columns as logs plus archived_at. NOT partitioned; rows are
-- moved here from detached partitions by the archive job (FR21). No FK from
-- alert_logs to either table, so evidence lookups check logs then logs_archive.
CREATE TABLE logs_archive (
    log_id         bigint      NOT NULL,
    ts             timestamptz NOT NULL,
    source_id      integer     NOT NULL,
    actor_username varchar(50),
    src_ip         inet        NOT NULL,
    event_type     varchar(50) NOT NULL,
    status         integer,
    user_agent     text,
    payload        text,
    archived_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (log_id, ts)
);

-- DEFAULT partition catches any row whose ts falls outside a declared month,
-- so ingestion never fails for a stray timestamp (FR11).
CREATE TABLE logs_default PARTITION OF logs DEFAULT;

-- Create monthly partitions for the window [now-1 month, now+3 months].
-- The scheduler (app/partitions.py) keeps creating ahead at runtime; this just
-- guarantees the current and next few months exist from first boot.
DO $$
DECLARE
    m     date := date_trunc('month', now())::date - interval '1 month';
    stop  date := date_trunc('month', now())::date + interval '4 months';
    pname text;
BEGIN
    WHILE m < stop LOOP
        pname := 'logs_' || to_char(m, 'YYYY_MM');
        EXECUTE format(
            'CREATE TABLE IF NOT EXISTS siem.%I PARTITION OF siem.logs
                 FOR VALUES FROM (%L) TO (%L)',
            pname, m, (m + interval '1 month')::date
        );
        m := (m + interval '1 month')::date;
    END LOOP;
END $$;
