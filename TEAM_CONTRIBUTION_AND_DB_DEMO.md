# Team Contribution and Database Demonstration Guide

This document divides the Real-Time SIEM Log Engine and AuraMarket project into
three balanced team-member contributions. Each member owns a major subsystem,
and all three contribute to integration, testing, documentation, and the final
presentation.

| Member | Ownership area | Suggested contribution |
|---|---|---:|
| Member 1 | Database architecture, schema, indexing, partitions, archiving | 33.3% |
| Member 2 | SIEM backend, ingestion, detection, alerts, RBAC, reporting | 33.3% |
| Member 3 | AuraMarket frontend, simulator, integration, testing, presentation | 33.3% |

Replace Member 1, Member 2, and Member 3 with the actual names before submitting.

## 1. Member 1 — Database and storage engineer

Member 1 owns the PostgreSQL design and the DBMS concepts demonstrated by the
project.

Responsibilities:

- Maintain the versioned SQL files in db/schema/.
- Maintain the siem and demo schemas.
- Explain the ER model, relational schema, keys, relationships, and normalization.
- Maintain monthly range partitioning for siem.logs.
- Maintain siem.logs_archive and the retention/archive workflow.
- Maintain BRIN, B-tree, trigram-GIN, and supporting indexes.
- Prepare SQL queries for the professor demonstration.
- Run the optional one-million-row load test and record results.

Files to present:

- db/schema/00_extensions.sql through db/schema/06_seed.sql
- app/partitions.py
- scripts/loadtest.py

Questions to prepare for:

- Why is logs partitioned by month?
- Which indexes support IP, event type, time, and payload searches?
- How does archiving move rows without losing them?
- Why are demo users and products outside the SIEM schema?
- How does the database match the ER diagram?

## 2. Member 2 — SIEM backend and security engineer

Member 2 owns the SIEM application services and security workflow.

Responsibilities:

- Maintain ingestion and API-key authentication.
- Maintain the event buffer and PostgreSQL COPY writes.
- Maintain threshold and regex/pattern detection rules.
- Maintain alerts and alert-to-log evidence links.
- Maintain close, block, and unblock workflows.
- Maintain Admin, Analyst, and Viewer role enforcement.
- Maintain operator accounts, source registration, reports, and retention.
- Demonstrate the flow from ingestion to alert to HTTP 403.

Files to present:

- app/ingest.py
- app/buffer.py
- app/detection.py
- app/alerts.py
- app/auth.py
- app/users.py
- app/rules.py
- app/sources.py
- app/search.py
- app/dashboard.py
- app/routers/siem.py
- app/scheduler.py

Questions to prepare for:

- How are invalid API keys rejected?
- Why are events buffered?
- How does brute-force detection work?
- How does the SQL-injection pattern rule work?
- How is duplicate open-alert creation prevented?
- What can each SIEM role access?
- How does an analyst block an IP?

## 3. Member 3 — Storefront, simulator, integration, and QA engineer

Member 3 owns the AuraMarket experience, traffic simulator, integration, and
end-to-end verification.

Responsibilities:

- Maintain the marketplace routes and templates.
- Maintain catalogue, product detail, search, sorting, cart, wishlist, checkout,
  registration, login, and information pages.
- Maintain local product images in app/static/products/.
- Ensure storefront actions emit SIEM events.
- Maintain the blocked HTTP 403 security perimeter page.
- Maintain brute-force, SQL-injection, and normal-traffic simulator modes.
- Run the complete regression suite.
- Verify desktop/mobile presentation and route responses.
- Prepare screenshots or a short demo recording.

Files to present:

- app/routers/demo.py
- app/templates/demo_*.html
- app/static/demo.css
- app/static/products/
- simulator/simulate.py
- tests/test_e2e.py

## 4. Shared contribution

All three members should participate in:

- Docker Compose setup and verification.
- Reading the requirement and ER documents.
- Reviewing another member's changes.
- Running the full database-backed test suite.
- Rehearsing the final professor demonstration.
- Explaining the complete flow:

  attack traffic -> ingestion -> partitioned logs -> detection -> alert ->
  block -> HTTP 403.

## 5. Access the database through Docker

From the project root, start the stack:

~~~bash
docker compose up -d
docker compose ps
~~~

Wait until the db service shows healthy. Open an interactive PostgreSQL console:

~~~bash
docker compose exec db psql -U siem -d siem
~~~

Seeded database values:

- Database: siem
- User: siem
- Password: siem_pw

Exit psql with:

~~~text
\q
~~~

## 6. Display schemas and tables

Run these commands inside psql:

~~~sql
\dn
\dt siem.*
\dt demo.*
~~~

Expected SIEM tables:

- siem.users
- siem.log_sources
- siem.logs
- siem.logs_archive
- siem.alert_rules
- siem.alerts
- siem.alert_logs
- siem.blocked_ips
- siem.system_settings

Expected demo tables:

- demo.demo_users
- demo.items

Display table structures and indexes:

~~~sql
\d+ siem.users
\d+ siem.log_sources
\d+ siem.logs
\d+ siem.logs_archive
\d+ siem.alert_rules
\d+ siem.alerts
\d+ siem.alert_logs
\d+ siem.blocked_ips
\d+ siem.system_settings
\d+ demo.demo_users
\d+ demo.items
~~~

## 7. Useful professor queries

Show operators without exposing password hashes:

~~~sql
SELECT user_id, username, email, role, is_active, created_at
FROM siem.users
ORDER BY user_id;
~~~

Show registered log sources without exposing API-key hashes:

~~~sql
SELECT source_id, source_name, source_type, created_at
FROM siem.log_sources
ORDER BY source_id;
~~~

Show rules:

~~~sql
SELECT rule_id, rule_name, rule_type, event_type, threshold_count,
       window_seconds, severity, enabled, created_by
FROM siem.alert_rules
ORDER BY rule_id;
~~~

Show recent logs:

~~~sql
SELECT log_id, ts, source_id, actor_username, src_ip, event_type,
       status, payload
FROM siem.logs
ORDER BY ts DESC
LIMIT 15;
~~~

Show event totals:

~~~sql
SELECT event_type, count(*) AS total
FROM siem.logs
GROUP BY event_type
ORDER BY total DESC;
~~~

Show alerts and their rules:

~~~sql
SELECT a.alert_id, a.src_ip, a.status, a.raised_at,
       r.rule_name, r.severity
FROM siem.alerts a
JOIN siem.alert_rules r ON r.rule_id = a.rule_id
ORDER BY a.raised_at DESC;
~~~

Show active blocks:

~~~sql
SELECT block_id, alert_id, ip_address, blocked_by,
       blocked_at, unblocked_at
FROM siem.blocked_ips
WHERE unblocked_at IS NULL
ORDER BY blocked_at DESC;
~~~

Show settings:

~~~sql
SELECT setting_key, setting_value
FROM siem.system_settings
ORDER BY setting_key;
~~~

Show archive volume:

~~~sql
SELECT count(*) AS archived_rows,
       min(ts) AS oldest_event,
       max(ts) AS newest_event
FROM siem.logs_archive;
~~~

## 8. Display partitions and indexes

Show all partitions:

~~~sql
SELECT child.relname AS partition_name,
       pg_get_expr(child.relpartbound, child.oid) AS partition_range
FROM pg_inherits
JOIN pg_class parent ON parent.oid = inhparent
JOIN pg_class child ON child.oid = inhrelid
WHERE parent.oid = 'siem.logs'::regclass
ORDER BY child.relname;
~~~

Show approximate rows by partition:

~~~sql
SELECT c.relname AS partition_name,
       c.reltuples::bigint AS approximate_rows
FROM pg_inherits i
JOIN pg_class c ON c.oid = i.inhrelid
WHERE i.inhparent = 'siem.logs'::regclass
ORDER BY c.relname;
~~~

Show indexes:

~~~sql
SELECT schemaname, tablename, indexname, indexdef
FROM pg_indexes
WHERE schemaname = 'siem'
ORDER BY tablename, indexname;
~~~

Show an IP-search query plan:

~~~sql
EXPLAIN
SELECT log_id, ts, src_ip, event_type, payload
FROM siem.logs
WHERE src_ip = '10.0.0.5'
  AND ts >= now() - interval '1 hour'
ORDER BY ts DESC
LIMIT 200;
~~~

The SIEM Search page also displays the live and archive query plans.

## 9. Recommended professor demonstration order

1. Start the services with docker compose up -d.
2. Open the SIEM dashboard and AuraMarket in separate browser tabs.
3. Browse products, search, and add one item to the cart.
4. Open psql and show schemas, tables, rules, and recent logs.
5. Run the brute-force simulator:

~~~bash
.venv/bin/python simulator/simulate.py brute --ip 10.0.0.5 --count 10
~~~

6. Open the generated SIEM alert.
7. Show the linked triggering logs.
8. Block the source IP and close the alert with a note.
9. Request AuraMarket using the same source IP and show HTTP 403.
10. Return to psql and show the new alert and active block.
11. Show partitions, indexes, and an EXPLAIN plan.
12. Run the test suite:

~~~bash
PYTHONPATH=. .venv/bin/pytest -q tests/
~~~

## 10. Host-side and graphical database access

If psql is installed on the host:

~~~bash
PGPASSWORD=siem_pw psql -h localhost -p 5432 -U siem -d siem
~~~

For DBeaver or another database client:

| Setting | Value |
|---|---|
| Host | localhost |
| Port | 5432 |
| Database | siem |
| Username | siem |
| Password | siem_pw |

If host access fails, use docker compose exec db psql -U siem -d siem instead.

## 11. Important safety notes

- Seeded passwords and API keys are for demonstrations only.
- Do not show password hashes or API-key hashes in screenshots.
- Do not run docker compose down -v before the presentation unless resetting data
  is intentional.
- Checkout is a prototype and does not charge real cards.
- X-Forwarded-For is trusted only for this local simulation.
- The project is an academic, one-machine demonstration, not a production SIEM.
