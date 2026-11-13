"""Alert management and IP blocking (FR17-FR19).

Closing an alert and blocking its IP are independent actions (business rule):
closing does not unblock, blocking does not close. Evidence (triggering logs) is
looked up in logs first, then logs_archive, because alert_logs has no FK.
"""
from psycopg.errors import UniqueViolation

from app.db import execute, get_conn, query, query_one


def list_alerts(status: str | None = None) -> list[dict]:
    sql = (
        "SELECT a.alert_id, a.src_ip, a.status, a.raised_at, a.closed_at, a.closing_note, "
        "r.rule_name, r.severity, "
        "(SELECT count(*) FROM alert_logs al WHERE al.alert_id = a.alert_id) AS log_count, "
        "EXISTS (SELECT 1 FROM blocked_ips b WHERE b.alert_id = a.alert_id AND b.unblocked_at IS NULL) AS is_blocked "
        "FROM alerts a JOIN alert_rules r ON r.rule_id = a.rule_id"
    )
    if status:
        sql += " WHERE a.status = %s"
        sql += " ORDER BY a.raised_at DESC"
        return query(sql, (status,))
    return query(sql + " ORDER BY a.raised_at DESC")


def get_alert(alert_id: int) -> dict | None:
    return query_one(
        "SELECT a.*, r.rule_name, r.severity, r.rule_type "
        "FROM alerts a JOIN alert_rules r ON r.rule_id = a.rule_id WHERE a.alert_id = %s",
        (alert_id,),
    )


def triggering_logs(alert_id: int, limit: int = 100) -> list[dict]:
    """Resolve alert_logs references against live logs then the archive."""
    return query(
        """
        SELECT al.log_id, al.ts, l.src_ip, l.actor_username, l.event_type, l.status, l.payload
        FROM alert_logs al
        LEFT JOIN siem.logs l ON l.log_id = al.log_id AND l.ts = al.ts
        WHERE al.alert_id = %(aid)s
        UNION ALL
        SELECT al.log_id, al.ts, la.src_ip, la.actor_username, la.event_type, la.status, la.payload
        FROM alert_logs al
        JOIN siem.logs_archive la ON la.log_id = al.log_id AND la.ts = al.ts
        WHERE al.alert_id = %(aid)s
        ORDER BY ts
        LIMIT %(lim)s
        """,
        {"aid": alert_id, "lim": limit},
    )


def close_alert(alert_id: int, operator_id: int, note: str) -> None:
    execute(
        "UPDATE alerts SET status='closed', closed_by=%s, closed_at=now(), closing_note=%s "
        "WHERE alert_id=%s AND status='open'",
        (operator_id, note, alert_id),
    )


def block_ip(alert_id: int, operator_id: int) -> str:
    """Block the alert's src_ip. Idempotent against one_active_block."""
    alert = get_alert(alert_id)
    if not alert:
        return "Alert not found"
    try:
        execute(
            "INSERT INTO blocked_ips (alert_id, ip_address, blocked_by) VALUES (%s, %s, %s)",
            (alert_id, str(alert["src_ip"]), operator_id),
        )
        return "blocked"
    except UniqueViolation:
        return "already blocked"


def unblock_ip(block_id: int) -> None:
    execute(
        "UPDATE blocked_ips SET unblocked_at = now() WHERE block_id = %s AND unblocked_at IS NULL",
        (block_id,),
    )


def list_blocks() -> list[dict]:
    return query(
        "SELECT b.block_id, b.ip_address, b.blocked_at, b.unblocked_at, u.username AS blocked_by, b.alert_id "
        "FROM blocked_ips b JOIN users u ON u.user_id = b.blocked_by ORDER BY b.blocked_at DESC"
    )


def is_blocked(ip: str) -> bool:
    row = query_one(
        "SELECT 1 FROM blocked_ips WHERE ip_address = %s AND unblocked_at IS NULL LIMIT 1",
        (ip,),
    )
    return row is not None
