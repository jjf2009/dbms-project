-- 05_constraints.sql
-- Business rules enforced at the database level (ER doc §4.5). The application
-- relies on these and catches the unique-violation rather than re-checking in Python.

SET search_path TO siem, public;

-- At most one OPEN alert per (rule, source IP) at a time.
-- Business rule: "No second open alert is raised for the same rule and IP" (FR16).
CREATE UNIQUE INDEX IF NOT EXISTS one_open_alert
    ON alerts (rule_id, src_ip)
    WHERE status = 'open';

-- At most one ACTIVE block per IP.
-- Business rule: "an IP has at most one active block".
CREATE UNIQUE INDEX IF NOT EXISTS one_active_block
    ON blocked_ips (ip_address)
    WHERE unblocked_at IS NULL;
