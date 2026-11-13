# Project Guide — How It Works, Docker, and Credentials

A plain-language companion to the README. Read this if you want to understand the
code, or if Docker is new to you.

---

## 1. The big picture

The system is two things sharing one program:

1. A **demo website** (a tiny shop) that normal users and attackers visit.
2. A **SIEM** that watches everything the website does and flags attacks.

Every time anyone touches the website — views a page, searches, logs in, fails a
login — the website writes one **log event** to the SIEM. The SIEM stores those
events in a database, and a background job keeps asking: *"did anything suspicious
just happen?"* If yes, it raises an **alert**. An analyst reviews the alert and
can **block** the attacker's IP address. Once blocked, the website answers that IP
with "403 Forbidden".

That whole loop — **attack → log → alert → block → 403** — is the demo.

### One request, start to finish

```
Attacker ─(10 failed logins)─▶ Demo website (/demo/login)
                                   │  writes a "login_failed" event each time
                                   ▼
                              Buffer (in memory)   ← holds events briefly
                                   │  every 1 second, dumped in one fast batch
                                   ▼
                              PostgreSQL  "logs" table (partitioned by month)
                                   ▲
   every 10 seconds ──────────────┘
   Detection job runs the rule "5 failed logins / IP / 60s"
                                   │  match! → create an Alert
                                   ▼
   Analyst opens the SIEM dashboard, sees the alert, clicks "Block 10.0.0.5"
                                   │  writes a row to "blocked_ips"
                                   ▼
   Next visit from 10.0.0.5 → website checks the blocklist → 403 Forbidden
```

---

## 2. Code tour (what each file does)

Everything lives in two folders: `db/schema/` (the database) and `app/` (the
program). Here is each piece in order of the data flow above.

### The database — `db/schema/*.sql`

These run **once**, in number order, when the database is first created. They
build the tables.

| File | What it makes |
|---|---|
| `00_extensions.sql` | Turns on two Postgres add-ons (`pg_trgm` for text search, `pgcrypto` for hashing) and creates the two schemas (`siem`, `demo`). A *schema* is just a namespace, like a folder for tables. |
| `01_siem_tables.sql` | The 9 SIEM tables: `users`, `log_sources`, `alert_rules`, `alerts`, `alert_logs`, `blocked_ips`, `system_settings` (the `logs` tables are in file 03). |
| `02_demo_tables.sql` | The demo shop's own tables: `demo_users`, `items`. |
| `03_partitions.sql` | The big `logs` table. It is **partitioned by month** — see the box below. |
| `04_indexes.sql` | Indexes = shortcuts that make searching fast. |
| `05_constraints.sql` | Two safety rules the database enforces itself (one open alert per IP, one active block per IP). |
| `06_seed.sql` | Starter data so the app works the moment it boots: the admin user, sample rules, demo items. |

> **What is partitioning?** Instead of one gigantic `logs` table, Postgres keeps a
> separate sub-table for each month (`logs_2026_11`, `logs_2026_12`, …). You still
> read/write `logs` as if it were one table; Postgres sends each row to the right
> month automatically. This keeps searches fast and lets us retire old data by
> simply detaching an old month. That's the headline DBMS concept of the project.

### The program — `app/`

**Setup and plumbing**
- `config.py` — reads settings (database address, passwords, timings) from the
  `.env` file.
- `db.py` — opens a **connection pool** to Postgres (a reusable set of open
  connections, so we don't reconnect on every query) and has helpers like
  `query(...)` and `execute(...)`.
- `main.py` — the starting point. It wires everything together, opens the database,
  creates upcoming partitions, and starts the background scheduler. When you run
  the app, this is what runs.

**Getting logs in (ingestion)**
- `ingest.py` — the `/ingest` endpoint. A log source must send a secret **API key**
  (like a password for machines) or it's rejected. Valid events go into the buffer.
  It also has `emit_demo_event()`, which the website uses to log its own requests.
- `buffer.py` — holds events in memory and writes them to the database in **one
  batch** using Postgres `COPY` (the fastest bulk-insert method). Writing 1 000
  rows at once is far cheaper than 1 000 separate inserts. It also counts
  `accepted` vs `stored` so we can prove no event is lost.

**Background jobs**
- `scheduler.py` — a timer (APScheduler) that runs four jobs on a loop: flush the
  buffer (every 1s), run detection (every 10s), create future partitions, archive
  old ones.
- `detection.py` — the brain. For each enabled rule it asks the database a question:
  *threshold* rules count events ("5 failed logins from one IP in 60s"); *pattern*
  rules match the payload text against a regular expression (used to catch SQL
  injection). A match creates an alert and links the exact logs that caused it.
- `partitions.py` — creates next months' partitions ahead of time, and archives
  (moves + removes) partitions older than the retention period.

**Using the SIEM**
- `search.py` — search logs by IP, user, time, event type or text. It also returns
  the database's `EXPLAIN` output, which shows *which index was used* — handy proof
  for the DBMS demo.
- `alerts.py` — list alerts, see an alert's triggering logs, close an alert, block
  or unblock an IP.
- `rules.py`, `users.py`, `sources.py`, `dashboard.py` — admin management of rules,
  operator accounts, log sources, plus the live dashboard metrics and reports.
- `auth.py` — logs operators in and enforces **roles**: Admin can do everything,
  Analyst can investigate and block, Viewer can only look. Passwords are stored
  hashed (never in plain text).

**The web pages**
- `routers/demo.py` — the demo shop pages. Every page first checks the blocklist
  (returns 403 if the visitor's IP is blocked) and logs the request.
- `routers/siem.py` — the SIEM operator pages, each protected by a role check.
- `templates/*.html` — the actual HTML pages (Jinja2 templates).
- `static/` — the stylesheet and Chart.js (for the dashboard graph).

**Testing it**
- `simulator/simulate.py` — a script that pretends to be an attacker, sending
  brute-force logins or SQL-injection searches from a chosen fake IP.
- `tests/` — automated checks that the whole loop works.

---

## 3. Docker, explained from scratch

### What problem does Docker solve?

To run this project you normally need: PostgreSQL installed, the right version,
Python installed, all the libraries installed, everything configured to talk to
each other. That's fiddly and "works on my machine" problems are common.

**Docker** packages a program together with everything it needs into a
**container** — a lightweight, isolated box that runs the same way on any machine.
You don't install Postgres; you run the official Postgres *image* in a container.

Two words to know:
- **Image** = a frozen template (e.g. "PostgreSQL 16"). You download it once.
- **Container** = a running copy of an image. You can start/stop/throw it away.

### What `docker compose` does

Our project needs **two** containers: the database and the app. Starting and
connecting them by hand is tedious, so **Docker Compose** describes both in one
file (`docker-compose.yml`) and starts them together with one command.

Here is our compose file in plain English:

```yaml
services:
  db:                                   # container #1: the database
    image: postgres:16                  # use the official PostgreSQL 16 image
    environment:                        # set its username/password/db name
      POSTGRES_USER: siem
      POSTGRES_PASSWORD: siem_pw
      POSTGRES_DB: siem
    ports:
      - "5432:5432"                     # expose the DB on your machine's port 5432
    volumes:
      - pgdata:/var/lib/postgresql/data # keep the data even if the container restarts
      - ./db/schema:/docker-entrypoint-initdb.d:ro   # run our .sql files on first boot
    healthcheck: ...                    # wait until the DB is actually ready

  app:                                  # container #2: our FastAPI program
    build: .                            # build it from our Dockerfile
    env_file: .env                      # load settings from .env
    ports:
      - "8000:8000"                     # the website is on your machine's port 8000
    depends_on:
      db: { condition: service_healthy }# don't start until the DB is ready

volumes:
  pgdata:                               # a named, persistent storage area for the DB
```

- A **volume** is storage that survives even when a container is deleted — that's
  where the database keeps its data.
- `"8000:8000"` means "connect port 8000 on *my computer* to port 8000 *inside the
  container*". That's why you open http://localhost:8000.
- `./db/schema:/docker-entrypoint-initdb.d` is a trick the Postgres image supports:
  any `.sql` file placed in that special folder runs automatically the first time
  the database starts. That's how our tables get created.

The `Dockerfile` (one short file) describes how to build the app container:
start from Python 3.12, copy our code in, install the libraries, run the server.

### The only commands you need

```bash
cp .env.example .env     # make your settings file (do this once)
docker compose up --build  # build + start everything (Ctrl-C to stop)
docker compose down        # stop and remove the containers
docker compose down -v     # also delete the database data (fresh start next time)
```

When it's running, open **http://localhost:8000/siem/**.

### "docker: permission denied" on this machine

On your computer, `docker` currently needs admin rights. Two easy options:

1. **Use sudo:** `sudo docker compose up --build`
2. **Fix it once** (so you never need sudo for Docker again):
   ```bash
   sudo usermod -aG docker $USER
   ```
   then log out and back in. This adds you to the `docker` group.

(There's also a third option, **podman**, which runs containers without admin
rights at all — the README shows those commands. We used it to test this project.)

---

## 4. Demo credentials

All of these are **demo-only** passwords, created by `db/schema/06_seed.sql`.
Change them for anything real.

### SIEM operators (log in at `/siem/login`)

| Role | Username | Password | Can do |
|---|---|---|---|
| **Admin** | `admin` | `admin123` | Everything: manage users, sources, rules, retention, reports. |
| **Analyst** | `analyst` | `analyst123` | Search logs, review alerts, block/unblock IPs. |
| **Viewer** | `viewer` | `viewer123` | Read-only dashboard and alert summaries. No raw payloads, no search. |

### Demo website visitor (log in at `/demo/login`)

| Username | Password |
|---|---|
| `alice` | `alice123` |

You can also register a fresh visitor account on the demo site.

### Log source API key

The demo website sends events to the SIEM using this key (header `X-API-Key`):

```
demo-key-123
```

---

## 5. Try the demo in 3 steps

With the app running (`docker compose up`, or the podman/venv flow):

```bash
# 1. attack: 10 failed logins from one fake IP
python simulator/simulate.py brute --ip 10.0.0.5 --count 10

# 2. open the SIEM, log in as analyst/analyst123:
#    http://localhost:8000/siem/alerts
#    -> an alert appears within ~10 seconds. Open it, click "Block 10.0.0.5", close it.

# 3. prove the block works:
curl -s -o /dev/null -w "%{http_code}\n" -H "X-Forwarded-For: 10.0.0.5" http://localhost:8000/demo/
#    -> 403     (a clean IP like 10.0.0.2 still returns 200)
```

Also try `sqli --ip 10.0.0.9` (triggers the pattern rule) and
`normal --ip 10.0.0.2 --count 50` (harmless background traffic for the dashboard).

> **Why `--ip`?** Everything runs on one machine, so every request would normally
> share one IP. The demo and simulator pass a fake client IP in the
> `X-Forwarded-For` header so you can see several distinct "attackers". This is
> explained in the Requirement doc's constraints.
