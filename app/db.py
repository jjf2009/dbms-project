"""PostgreSQL connection pool (psycopg 3) and small query helpers.

A single pooled connection source is shared by the request handlers, the
ingestion COPY path and the scheduler jobs. Rows come back as dicts.
"""
from contextlib import contextmanager

from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from app.config import settings

# Opened in app startup (app.main). search_path defaults to siem for every
# connection so unqualified names resolve to the SIEM schema; demo queries
# qualify their tables explicitly.
pool = ConnectionPool(
    conninfo=settings.dsn,
    min_size=1,
    max_size=10,
    open=False,
    kwargs={"row_factory": dict_row, "options": "-c search_path=siem,public"},
)


@contextmanager
def get_conn():
    with pool.connection() as conn:
        yield conn


def query(sql: str, params: tuple | dict | None = None) -> list[dict]:
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            return cur.fetchall()


def query_one(sql: str, params: tuple | dict | None = None) -> dict | None:
    rows = query(sql, params)
    return rows[0] if rows else None


def execute(sql: str, params: tuple | dict | None = None) -> None:
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
