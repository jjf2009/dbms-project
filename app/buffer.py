"""In-memory event buffer with batch COPY flush (FR10, NFR1, NFR5).

Accepted events accumulate in a thread-safe list and are written to siem.logs
in one psycopg3 COPY per flush. A flush happens when the buffer reaches
batch_max_events, on the scheduler's every-second tick, and on shutdown, so no
accepted event is lost. A failed COPY puts the batch back for retry.
"""
import threading

from app.config import settings
from app.db import pool

_COLUMNS = (
    "ts", "source_id", "actor_username", "src_ip",
    "event_type", "status", "user_agent", "payload",
)

_lock = threading.Lock()
_events: list[tuple] = []

# simple counters for the dashboard / lossless-ingestion proof
accepted = 0
stored = 0


def add_event(ev: dict) -> None:
    """Queue one event. Flushes inline if the buffer is full."""
    global accepted
    row = (
        ev["ts"], ev["source_id"], ev.get("actor_username"), ev["src_ip"],
        ev["event_type"], ev.get("status"), ev.get("user_agent"), ev.get("payload"),
    )
    with _lock:
        _events.append(row)
        accepted += 1
        full = len(_events) >= settings.batch_max_events
    if full:
        flush()


def flush() -> int:
    """Write the current batch with COPY. Returns rows written."""
    global stored
    with _lock:
        if not _events:
            return 0
        batch = _events[:]
        _events.clear()

    cols = ", ".join(_COLUMNS)
    try:
        with pool.connection() as conn:
            with conn.cursor() as cur:
                with cur.copy(f"COPY siem.logs ({cols}) FROM STDIN") as copy:
                    for row in batch:
                        copy.write_row(row)
        with _lock:
            stored += len(batch)
        return len(batch)
    except Exception:
        # retry: put the batch back at the front
        with _lock:
            _events[:0] = batch
        raise


def stats() -> dict:
    with _lock:
        return {"accepted": accepted, "stored": stored, "buffered": len(_events)}
