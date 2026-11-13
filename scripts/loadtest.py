#!/usr/bin/env python3
"""Load test for the SIEM (NFR1-NFR4).

Bulk-loads N log rows with COPY, then times the index-backed searches and the
dashboard query. Prints throughput and EXPLAIN ANALYZE execution times so the
numbers can be quoted at the demo.

  POSTGRES_HOST=localhost .venv/bin/python scripts/loadtest.py --rows 1000000
"""
import argparse
import ipaddress
import os
import random
import sys
import time
from datetime import datetime, timedelta, timezone

import psycopg

# allow "import app.*" when run as scripts/loadtest.py
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

DSN = (f"postgresql://{os.environ.get('POSTGRES_USER','siem')}:"
       f"{os.environ.get('POSTGRES_PASSWORD','siem_pw')}@"
       f"{os.environ.get('POSTGRES_HOST','localhost')}:"
       f"{os.environ.get('POSTGRES_PORT','5432')}/{os.environ.get('POSTGRES_DB','siem')}")

EVENTS = ["page_view", "search", "login_success", "login_failed", "register", "request_blocked"]
PAYLOADS = ["/", "/items", "keyboard", "monitor", "user=alice", "user=bob",
            "' OR 1=1 --", "union select * from users", "normal search text", "checkout"]


def rand_ips(n):
    base = int(ipaddress.ip_address("10.0.0.0"))
    return [str(ipaddress.ip_address(base + random.randint(1, 4000))) for _ in range(n)]


def seed(rows, batch=50_000):
    ip_pool = rand_ips(250)          # ~250 distinct sources
    now = datetime.now(timezone.utc)
    span = 25 * 24 * 3600            # spread over last 25 days (within existing partitions)
    cols = "ts, source_id, actor_username, src_ip, event_type, status, user_agent, payload"

    print(f"Seeding {rows:,} rows via COPY ...")
    t0 = time.perf_counter()
    written = 0
    with psycopg.connect(DSN) as conn:
        while written < rows:
            n = min(batch, rows - written)
            with conn.cursor() as cur:
                with cur.copy(f"COPY siem.logs ({cols}) FROM STDIN") as cp:
                    for _ in range(n):
                        ts = now - timedelta(seconds=random.randint(0, span))
                        ev = random.choice(EVENTS)
                        cp.write_row((ts, 1,
                                      random.choice([None, "alice", "bob", "carol"]),
                                      random.choice(ip_pool), ev,
                                      401 if ev == "login_failed" else 200,
                                      "sim/loadtest", random.choice(PAYLOADS)))
            conn.commit()
            written += n
            print(f"  {written:,}/{rows:,}", end="\r")
    dt = time.perf_counter() - t0
    print(f"\nLoaded {rows:,} rows in {dt:.1f}s  ->  {rows/dt:,.0f} rows/s (COPY)   [NFR1 target >= 2,000/s]")
    with psycopg.connect(DSN) as conn:
        conn.execute("ANALYZE siem.logs")
    return ip_pool


def explain_time(conn, sql, params):
    cur = conn.execute("EXPLAIN (ANALYZE, TIMING OFF, SUMMARY ON, FORMAT TEXT) " + sql, params)
    lines = [r[0] for r in cur.fetchall()]
    exec_ms = next((float(l.split(":")[1].strip().split(" ")[0])
                    for l in lines if l.startswith("Execution Time")), None)
    scan = next((l.strip() for l in lines if "Scan" in l), "")
    return exec_ms, scan


def bench(ip_pool):
    ip = random.choice(ip_pool)
    recent = datetime.now(timezone.utc) - timedelta(hours=6)
    queries = [
        ("by src_ip (B-tree)",
         "SELECT log_id,ts FROM siem.logs WHERE src_ip=%s ORDER BY ts DESC LIMIT 50", (ip,)),
        ("by event_type + time (B-tree)",
         "SELECT log_id,ts FROM siem.logs WHERE event_type='login_failed' AND ts>%s "
         "ORDER BY ts DESC LIMIT 50", (recent,)),
        ("payload text (trigram GIN)",
         "SELECT log_id,ts FROM siem.logs WHERE payload ILIKE %s ORDER BY ts DESC LIMIT 50",
         ("%union select%",)),
        ("time range (BRIN)",
         "SELECT count(*) FROM siem.logs WHERE ts > %s", (recent,)),
    ]
    print("\nSearch latency  [NFR2 target < 1000 ms on >= 1M rows]")
    with psycopg.connect(DSN) as conn:
        total = conn.execute("SELECT count(*) FROM siem.logs").fetchone()[0]
        print(f"  (total rows in logs: {total:,})")
        for name, sql, params in queries:
            ms, scan = explain_time(conn, sql, params)
            flag = "OK " if ms is not None and ms < 1000 else "!! "
            print(f"  {flag}{name:34} {ms:8.1f} ms   {scan[:70]}")


def bench_dashboard():
    import app.db as db
    from app.dashboard import dashboard_data
    db.pool.open(); db.pool.wait()
    t = time.perf_counter()
    dashboard_data()
    ms = (time.perf_counter() - t) * 1000
    db.pool.close()
    flag = "OK " if ms < 2000 else "!! "
    print(f"\nDashboard query  [NFR3 target < 2000 ms]\n  {flag}dashboard_data() {ms:8.1f} ms")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--rows", type=int, default=1_000_000)
    ap.add_argument("--no-seed", action="store_true", help="benchmark existing data only")
    a = ap.parse_args()
    pool = rand_ips(250) if a.no_seed else seed(a.rows)
    bench(pool)
    bench_dashboard()
