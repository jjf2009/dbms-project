"""Log search (FR13).

Filter by IP, username, time range, event type and/or payload text; optionally
include archived rows. Returns matching rows, the wall-clock query time, and the
EXPLAIN plan so the demo can show which index was used (NFR2).
"""
import time

from app.db import get_conn


def _where(f: dict) -> tuple[str, dict]:
    clauses, params = [], {}
    if f.get("src_ip"):
        clauses.append("src_ip = %(src_ip)s"); params["src_ip"] = f["src_ip"]
    if f.get("actor_username"):
        clauses.append("actor_username = %(actor_username)s")
        params["actor_username"] = f["actor_username"]
    if f.get("event_type"):
        clauses.append("event_type = %(event_type)s"); params["event_type"] = f["event_type"]
    if f.get("ts_from"):
        clauses.append("ts >= %(ts_from)s"); params["ts_from"] = f["ts_from"]
    if f.get("ts_to"):
        clauses.append("ts <= %(ts_to)s"); params["ts_to"] = f["ts_to"]
    if f.get("text"):
        clauses.append("payload ILIKE %(text)s"); params["text"] = f"%{f['text']}%"
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    return where, params


def _select(table: str, where: str, limit: int) -> str:
    return (
        f"SELECT log_id, ts, src_ip, actor_username, event_type, status, payload "
        f"FROM siem.{table}{where} ORDER BY ts DESC LIMIT {int(limit)}"
    )


def search(f: dict, include_archived: bool = False, limit: int = 200) -> dict:
    where, params = _where(f)
    sql = _select("logs", where, limit)
    if include_archived:
        sql = (
            f"({_select('logs', where, limit)}) UNION ALL "
            f"({_select('logs_archive', where, limit)}) "
            f"ORDER BY ts DESC LIMIT {int(limit)}"
        )
    with get_conn() as conn, conn.cursor() as cur:
        t0 = time.perf_counter()
        cur.execute(sql, params)
        rows = cur.fetchall()
        elapsed_ms = (time.perf_counter() - t0) * 1000
        cur.execute("EXPLAIN " + _select("logs", where, limit), params)
        plan = "\n".join(r["QUERY PLAN"] for r in cur.fetchall())
    return {"rows": rows, "elapsed_ms": round(elapsed_ms, 1), "plan": plan}
