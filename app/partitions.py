"""Partition lifecycle (FR11, FR21).

create_partitions_ahead(): makes sure the next N monthly partitions of siem.logs
exist (N from system_settings.partitions_ahead).

archive_old_partitions(): for every monthly partition fully older than the
retention cutoff, copy its rows into logs_archive, then detach and drop it.
Rows are moved, never deleted (business rule). A foreign key would block the
detach, which is exactly why alert_logs has none.
"""
from datetime import date, datetime, timezone

from dateutil.relativedelta import relativedelta  # from python-dateutil (psycopg dep)

from app.db import get_conn, query, query_one


def _setting_int(key: str, default: int) -> int:
    row = query_one("SELECT setting_value FROM system_settings WHERE setting_key = %s", (key,))
    return int(row["setting_value"]) if row else default


def _month_floor(d: date) -> date:
    return d.replace(day=1)


def create_partitions_ahead() -> list[str]:
    ahead = _setting_int("partitions_ahead", 3)
    created: list[str] = []
    base = _month_floor(datetime.now(timezone.utc).date())
    with get_conn() as conn, conn.cursor() as cur:
        for i in range(ahead + 1):  # current month + N ahead
            start = base + relativedelta(months=i)
            end = start + relativedelta(months=1)
            name = f"logs_{start:%Y_%m}"
            cur.execute(
                f"CREATE TABLE IF NOT EXISTS siem.{name} "
                f"PARTITION OF siem.logs FOR VALUES FROM (%s) TO (%s)",
                (start, end),
            )
            created.append(name)
    return created


def archive_old_partitions() -> dict:
    retention = _setting_int("retention_months", 6)
    cutoff = _month_floor(datetime.now(timezone.utc).date()) - relativedelta(months=retention)
    moved_partitions, moved_rows = [], 0

    parts = query(
        """
        SELECT c.relname AS name
        FROM pg_inherits i
        JOIN pg_class c ON c.oid = i.inhrelid
        WHERE i.inhparent = 'siem.logs'::regclass
          AND c.relname ~ '^logs_[0-9]{4}_[0-9]{2}$'
        ORDER BY c.relname
        """
    )
    for p in parts:
        name = p["name"]
        y, m = int(name[5:9]), int(name[10:12])
        if date(y, m, 1) >= cutoff:
            continue
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute(f"SELECT count(*) AS n FROM siem.{name}")
            n = cur.fetchone()["n"]
            # copy rows, then detach + drop the now-empty partition
            cur.execute(
                f"INSERT INTO siem.logs_archive "
                f"(log_id, ts, source_id, actor_username, src_ip, event_type, status, user_agent, payload) "
                f"SELECT log_id, ts, source_id, actor_username, src_ip, event_type, status, user_agent, payload "
                f"FROM siem.{name}"
            )
            cur.execute(f"ALTER TABLE siem.logs DETACH PARTITION siem.{name}")
            cur.execute(f"DROP TABLE siem.{name}")
        moved_partitions.append(name)
        moved_rows += n
    return {"partitions": moved_partitions, "rows": moved_rows}
