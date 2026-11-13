"""Detection engine (FR15-FR16).

run_detection() evaluates every enabled rule over its own time window:
  threshold rule -> count of an event_type per src_ip within the window;
  pattern rule   -> payload matches a POSIX regex within the window.
Each match raises one alert and links all triggering logs via alert_logs.
The partial unique index one_open_alert guarantees at most one open alert per
(rule, src_ip): we catch its violation and attach new evidence to the existing
open alert instead of raising a duplicate.
"""
from app.db import get_conn

# triggering logs for a threshold rule: all matching events from that IP in window
_THRESHOLD_LOGS = """
    SELECT log_id, ts, src_ip
    FROM siem.logs
    WHERE event_type = %(event_type)s
      AND ts > now() - make_interval(secs => %(window)s)
      AND src_ip = %(src_ip)s
"""

# IPs that crossed the threshold in the window
_THRESHOLD_HITS = """
    SELECT src_ip, count(*) AS n
    FROM siem.logs
    WHERE event_type = %(event_type)s
      AND ts > now() - make_interval(secs => %(window)s)
    GROUP BY src_ip
    HAVING count(*) >= %(threshold)s
"""

# pattern rule: logs whose payload matches the regex in the window
_PATTERN_HITS = """
    SELECT log_id, ts, src_ip
    FROM siem.logs
    WHERE payload ~ %(pattern)s
      AND ts > now() - make_interval(secs => %(window)s)
"""


def _raise_or_attach(cur, rule_id: int, src_ip, trigger_logs: list[tuple]) -> int:
    """Return alert_id for (rule, src_ip), creating the alert if none is open.
    trigger_logs is a list of (log_id, ts). New evidence is attached idempotently."""
    cur.execute(
        "INSERT INTO siem.alerts (rule_id, src_ip) VALUES (%s, %s) "
        "ON CONFLICT (rule_id, src_ip) WHERE status = 'open' DO NOTHING "
        "RETURNING alert_id",
        (rule_id, src_ip),
    )
    row = cur.fetchone()
    if row:
        alert_id = row["alert_id"]
    else:  # an open alert already exists
        cur.execute(
            "SELECT alert_id FROM siem.alerts "
            "WHERE rule_id = %s AND src_ip = %s AND status = 'open'",
            (rule_id, src_ip),
        )
        alert_id = cur.fetchone()["alert_id"]

    for log_id, ts in trigger_logs:
        cur.execute(
            "INSERT INTO siem.alert_logs (alert_id, log_id, ts) VALUES (%s, %s, %s) "
            "ON CONFLICT DO NOTHING",
            (alert_id, log_id, ts),
        )
    return alert_id


def run_detection() -> dict:
    raised: list[int] = []
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM siem.alert_rules WHERE enabled = true")
        rules = cur.fetchall()
        for r in rules:
            if r["rule_type"] == "threshold":
                cur.execute(_THRESHOLD_HITS, {
                    "event_type": r["event_type"],
                    "window": r["window_seconds"],
                    "threshold": r["threshold_count"],
                })
                for hit in cur.fetchall():
                    cur.execute(_THRESHOLD_LOGS, {
                        "event_type": r["event_type"],
                        "window": r["window_seconds"],
                        "src_ip": hit["src_ip"],
                    })
                    logs = [(x["log_id"], x["ts"]) for x in cur.fetchall()]
                    raised.append(_raise_or_attach(cur, r["rule_id"], hit["src_ip"], logs))
            else:  # pattern
                cur.execute(_PATTERN_HITS, {
                    "pattern": r["pattern"], "window": r["window_seconds"],
                })
                by_ip: dict = {}
                for x in cur.fetchall():
                    by_ip.setdefault(x["src_ip"], []).append((x["log_id"], x["ts"]))
                for src_ip, logs in by_ip.items():
                    raised.append(_raise_or_attach(cur, r["rule_id"], src_ip, logs))
    return {"alerts_touched": len(raised)}
