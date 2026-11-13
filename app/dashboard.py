"""Live dashboard + summary report + retention setting (FR20, FR22-FR24)."""
from app import buffer
from app.db import execute, query, query_one


def dashboard_data() -> dict:
    """Metrics for the auto-refreshing dashboard (FR22). Kept cheap so each
    refresh completes well under 2 s even on millions of rows (NFR3): the
    all-time total uses the planner's row estimate, not a full count."""
    per_sec = query(
        "SELECT to_char(date_trunc('second', ts), 'HH24:MI:SS') AS sec, count(*) AS n "
        "FROM siem.logs WHERE ts > now() - interval '60 seconds' "
        "GROUP BY 1 ORDER BY 1"
    )
    top_ips = query(
        "SELECT src_ip::text AS ip, count(*) AS n FROM siem.logs "
        "WHERE ts > now() - interval '5 minutes' GROUP BY 1 ORDER BY n DESC LIMIT 8"
    )
    top_events = query(
        "SELECT event_type, count(*) AS n FROM siem.logs "
        "WHERE ts > now() - interval '5 minutes' GROUP BY 1 ORDER BY n DESC LIMIT 6"
    )
    partitions = partition_status()
    total_est = sum(p["approx_rows"] for p in partitions if p["kind"] == "live")

    counts = query_one(
        """
        SELECT
          (SELECT count(*) FROM siem.logs WHERE ts > now() - interval '60 seconds') AS last_min,
          (SELECT count(*) FROM alerts WHERE status='open') AS open_alerts,
          (SELECT count(*) FROM alerts WHERE status='open' AND raised_at > now() - interval '24 hours') AS open_24h,
          (SELECT count(*) FROM blocked_ips WHERE unblocked_at IS NULL) AS active_blocks,
          (SELECT count(*) FROM alert_rules WHERE enabled) AS rules_enabled,
          (SELECT count(*) FROM alert_rules) AS rules_total,
          (SELECT count(*) FROM log_sources) AS sources
        """
    )
    by_sev = query(
        "SELECT r.severity, count(*) AS n FROM alerts a JOIN alert_rules r ON r.rule_id=a.rule_id "
        "WHERE a.status='open' GROUP BY r.severity"
    )
    sev = {"high": 0, "medium": 0, "low": 0}
    for row in by_sev:
        sev[row["severity"]] = row["n"]
    recent_alerts = query(
        "SELECT a.alert_id, a.src_ip, a.status, a.raised_at, r.rule_name, r.severity "
        "FROM alerts a JOIN alert_rules r ON r.rule_id=a.rule_id "
        "ORDER BY a.raised_at DESC LIMIT 6"
    )
    return {
        "per_sec": per_sec,
        "top_ips": top_ips,
        "top_events": top_events,
        "partitions": partitions,
        "total_est": total_est,
        "counts": counts,
        "sev": sev,
        "recent_alerts": recent_alerts,
        "ingest": buffer.stats(),
    }


def partition_status() -> list[dict]:
    live = query(
        """
        SELECT c.relname AS name, 'live' AS kind,
               (SELECT reltuples::bigint FROM pg_class WHERE oid = c.oid) AS approx_rows
        FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
        WHERE i.inhparent = 'siem.logs'::regclass
        ORDER BY c.relname
        """
    )
    archived = query_one("SELECT count(*) AS n FROM siem.logs_archive")
    live.append({"name": "logs_archive", "kind": "archived", "approx_rows": archived["n"]})
    return live


def summary_report(ts_from, ts_to) -> dict:
    """Admin summary of alerts + ingestion for a period (FR24)."""
    alerts_by_sev = query(
        "SELECT r.severity, count(*) AS n FROM alerts a JOIN alert_rules r ON r.rule_id=a.rule_id "
        "WHERE a.raised_at BETWEEN %s AND %s GROUP BY r.severity ORDER BY r.severity",
        (ts_from, ts_to),
    )
    alerts_by_rule = query(
        "SELECT r.rule_name, count(*) AS n FROM alerts a JOIN alert_rules r ON r.rule_id=a.rule_id "
        "WHERE a.raised_at BETWEEN %s AND %s GROUP BY r.rule_name ORDER BY n DESC",
        (ts_from, ts_to),
    )
    ingest_total = query_one(
        "SELECT count(*) AS n FROM siem.logs WHERE ts BETWEEN %s AND %s", (ts_from, ts_to)
    )["n"]
    blocks = query_one(
        "SELECT count(*) AS n FROM blocked_ips WHERE blocked_at BETWEEN %s AND %s", (ts_from, ts_to)
    )["n"]
    return {
        "alerts_by_sev": alerts_by_sev,
        "alerts_by_rule": alerts_by_rule,
        "ingest_total": ingest_total,
        "blocks": blocks,
    }


def get_retention() -> int:
    row = query_one("SELECT setting_value FROM system_settings WHERE setting_key='retention_months'")
    return int(row["setting_value"]) if row else 6


def set_retention(months: int) -> None:
    execute(
        "INSERT INTO system_settings (setting_key, setting_value) VALUES ('retention_months', %s) "
        "ON CONFLICT (setting_key) DO UPDATE SET setting_value = EXCLUDED.setting_value",
        (str(months),),
    )
