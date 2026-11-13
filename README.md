# Real-Time SIEM Log Engine

A PostgreSQL-centered SIEM (Security Information and Event Management) for a DBMS
mini project. It ingests log events in batches, stores them in a time-partitioned
table, searches them with indexes, detects attacks with stored rules, raises
alerts, and lets an analyst block the attacking IP — which a bundled demo website
then enforces with HTTP 403.

The **database is the centre of the project**. It demonstrates: normalized schema
design (BCNF), declarative range partitioning, BRIN / B-tree / trigram-GIN
indexing, batch writes via `COPY`, scheduled jobs, and role-based access control.

See the two specification documents in this folder for the full requirements, ER
model, relational schema and functional-dependency / normal-form analysis.

> **New to this code or to Docker?** Read [`GUIDE.md`](GUIDE.md) — a plain-language
> tour of how the code works, Docker explained from scratch, and all demo logins.

## Architecture

One FastAPI process, one PostgreSQL database with two schemas:

- **`siem`** — the SIEM data model (9 tables). The grading surface.
- **`demo`** — the demo website's own users and items. A *source of logs*, never
  part of the SIEM model.

| Part | Path | Responsibility |
|---|---|---|
| Ingestion API | `app/ingest.py`, `app/buffer.py` | API-key auth, batch `COPY` into `logs` |
| Partition/archive jobs | `app/partitions.py` | create months ahead, archive old ones |
| Detection engine | `app/detection.py` | threshold + pattern rules, every 10 s |
| Scheduler | `app/scheduler.py` | detect / flush / partition / archive |
| Search | `app/search.py` | multi-field search + `EXPLAIN` + timing |
| Alerts & blocking | `app/alerts.py` | review, close, block, unblock |
| Dashboard / report | `app/dashboard.py` | live metrics, summary report, retention |
| SIEM UI | `app/routers/siem.py` + `templates/` | role-gated pages (Jinja2 + Chart.js) |
| Demo website | `app/routers/demo.py` | register/login/browse/search, blocklist 403 |
| Attack simulator | `simulator/simulate.py` | brute-force + SQL-injection traffic |

## Quick start

```bash
cp .env.example .env
docker compose up --build        # Postgres + app on http://localhost:8000
```

- SIEM dashboard: http://localhost:8000/siem/
- Demo website:   http://localhost:8000/demo/

The schema in `db/schema/*.sql` is applied in filename order the first time the
database volume is created.

> **No `docker` group?** If `docker` needs sudo on your machine, either run
> `sudo docker compose up --build`, or use the rootless **podman** flow below
> (used to validate this project).

### Rootless podman / local app

```bash
# 1. database
podman run -d --rm --name siem_db -p 5432:5432 \
  -e POSTGRES_USER=siem -e POSTGRES_PASSWORD=siem_pw -e POSTGRES_DB=siem \
  -v "$PWD/db/schema:/docker-entrypoint-initdb.d:ro,Z" docker.io/library/postgres:16

# 2. app (Python 3.12)
python3.12 -m venv .venv && .venv/bin/pip install -r requirements.txt
POSTGRES_HOST=localhost .venv/bin/python -m uvicorn app.main:app --port 8000
```

## Default credentials (seeded)

| Where | User | Password |
|---|---|---|
| SIEM Admin | `admin` | `admin123` |
| SIEM Analyst | `analyst` | `analyst123` |
| SIEM Viewer | `viewer` | `viewer123` |
| Demo visitor | `alice` | `alice123` |
| Demo source API key | — | `demo-key-123` |

## Live demo — a brute-force attack, start to finish

This mirrors §15 of the Requirement Analysis document.

```bash
# 1. send 10 failed logins from one IP to the demo site
.venv/bin/python simulator/simulate.py brute --ip 10.0.0.5 --count 10
# (also try: sqli --ip 10.0.0.9   and   normal --ip 10.0.0.2 --count 50)
```

2. Within ~10 s the scheduler evaluates the rule **"5 failed logins / IP / 60 s"**
   and an **open alert** appears on the dashboard and under **Alerts**.
3. Open the alert (as `analyst` or `admin`) → see the 10 triggering logs.
4. Click **Block 10.0.0.5**, then **Close** with a note.
5. The next demo-site request from `10.0.0.5` returns **HTTP 403**:
   ```bash
   curl -s -o /dev/null -w "%{http_code}\n" -H "X-Forwarded-For: 10.0.0.5" http://localhost:8000/demo/
   # -> 403     (a clean IP still returns 200)
   ```
   The SQL-injection path is identical, except a **pattern rule** matches the
   payload regex instead of a count.

## DBMS concepts — how to see each one

- **Normalization (BCNF):** `db/schema/01_siem_tables.sql`; FD tables and
  normal-form justification are in the ER document §5.
- **Partitioning:** `logs` is `PARTITION BY RANGE (ts)`, monthly, with a DEFAULT
  partition; the scheduler pre-creates months ahead. Inspect with `\d+ siem.logs`.
- **Indexing:** BRIN on `ts`, B-tree on `(src_ip, ts)` and `(event_type, ts)`,
  trigram GIN on `payload`. The **Search** page prints the `EXPLAIN` plan so you
  can see the index chosen (NFR2 — under 1 s on ≥1 M rows).
- **Batch writes:** `app/buffer.py` flushes with `COPY` every 1 s / 1 000 events;
  the dashboard shows `accepted == stored` (lossless, NFR1/NFR5).
- **Scheduled jobs:** APScheduler runs detection, buffer flush, partition
  creation and archiving (`app/scheduler.py`).
- **RBAC:** `app/auth.py` `require_role()` gates every SIEM route. Admin ⊇ Analyst
  ⊇ Viewer; a Viewer is 403'd from log search and raw payloads (FR3, FR23).
- **Archiving:** partitions past the retention period are copied to `logs_archive`,
  detached and dropped — rows moved, never deleted (FR21). `alert_logs` has no FK
  to `logs`, which is what lets a partition detach.

## Measured performance (1,000,000 rows, laptop)

Run it yourself: `POSTGRES_HOST=localhost .venv/bin/python scripts/loadtest.py --rows 1000000`

| NFR | Target | Measured |
|---|---|---|
| NFR1 ingestion (COPY) | ≥ 2,000 events/s | **~72,000 rows/s** |
| NFR2 search by IP (B-tree) | < 1,000 ms on ≥1M | **~0.1 ms** |
| NFR2 search event+time (B-tree) | < 1,000 ms | **~0.1 ms** |
| NFR2 payload text (trigram GIN) | < 1,000 ms | **~49 ms** |
| NFR2 time range (BRIN) | < 1,000 ms | **~21 ms** |
| NFR3 dashboard query | < 2,000 ms | **~118 ms** |
| NFR4 detection latency | < 30 s | **~10 s** |

The script seeds via `COPY` and prints `EXPLAIN ANALYZE` execution times so you can
confirm each index is used.

## Tests

```bash
# with the database running and schema loaded:
POSTGRES_HOST=localhost .venv/bin/python -m pytest tests/ -q
```

Covers: API-key ingestion, lossless ingest→search, threshold detection, viewer
RBAC, and the demo-site blocklist 403. The suite skips itself if no database is
reachable.

## Requirement coverage

All 24 functional requirements are implemented. See the FR→module table in the
project plan; `db/schema/` and `app/` headers name the FRs each file serves.
# dbms-project
