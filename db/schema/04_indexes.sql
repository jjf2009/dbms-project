-- 04_indexes.sql
-- Indexes that make search return in under 1 s on >= 1M rows (FR12, NFR2).
-- Declared on the partitioned parent, so PostgreSQL creates a matching index on
-- every current and future partition automatically.

SET search_path TO siem, public;

-- BRIN on ts: tiny, ideal for the naturally time-ordered append-only log stream;
-- powers time-range search.
CREATE INDEX IF NOT EXISTS logs_ts_brin      ON logs USING brin (ts);

-- B-tree composites for the two most common filtered-by-time searches.
CREATE INDEX IF NOT EXISTS logs_srcip_ts     ON logs (src_ip, ts);
CREATE INDEX IF NOT EXISTS logs_event_ts     ON logs (event_type, ts);

-- Trigram GIN on payload: substring / fuzzy text search over raw payloads.
CREATE INDEX IF NOT EXISTS logs_payload_trgm ON logs USING gin (payload gin_trgm_ops);

-- Username search (optional field on a log).
CREATE INDEX IF NOT EXISTS logs_actor        ON logs (actor_username);

-- Archive mirrors the same access patterns for "include archived" searches.
CREATE INDEX IF NOT EXISTS arch_ts_brin      ON logs_archive USING brin (ts);
CREATE INDEX IF NOT EXISTS arch_srcip_ts     ON logs_archive (src_ip, ts);
CREATE INDEX IF NOT EXISTS arch_payload_trgm ON logs_archive USING gin (payload gin_trgm_ops);

-- Supporting indexes for alert and block lookups.
CREATE INDEX IF NOT EXISTS alerts_status     ON alerts (status);
CREATE INDEX IF NOT EXISTS alert_logs_alert  ON alert_logs (alert_id);
