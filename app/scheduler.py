"""Background scheduled jobs (APScheduler) — FR11, FR15, FR21.

  detect   : evaluate rules every detect_interval seconds.
  flush    : flush the ingestion buffer every batch_max_seconds.
  partition: create partitions ahead periodically.
  archive  : archive partitions past the retention period periodically.
"""
import logging

from apscheduler.schedulers.background import BackgroundScheduler

from app import buffer
from app.config import settings
from app.detection import run_detection
from app.partitions import archive_old_partitions, create_partitions_ahead

log = logging.getLogger("siem.scheduler")
_scheduler: BackgroundScheduler | None = None


def _safe(fn):
    def wrapped():
        try:
            fn()
        except Exception:
            log.exception("scheduled job %s failed", getattr(fn, "__name__", fn))
    wrapped.__name__ = getattr(fn, "__name__", "job")
    return wrapped


def start() -> BackgroundScheduler:
    global _scheduler
    s = BackgroundScheduler(timezone="UTC")
    s.add_job(_safe(buffer.flush), "interval", seconds=settings.batch_max_seconds,
              id="flush", max_instances=1, coalesce=True)
    s.add_job(_safe(run_detection), "interval", seconds=settings.detect_interval,
              id="detect", max_instances=1, coalesce=True)
    s.add_job(_safe(create_partitions_ahead), "interval", seconds=settings.partition_interval,
              id="partition", max_instances=1, coalesce=True, next_run_time=None)
    s.add_job(_safe(archive_old_partitions), "interval", seconds=settings.archive_interval,
              id="archive", max_instances=1, coalesce=True, next_run_time=None)
    s.start()
    _scheduler = s
    return s


def shutdown() -> None:
    if _scheduler:
        _scheduler.shutdown(wait=False)
    buffer.flush()  # NFR5: never lose an accepted event on shutdown
