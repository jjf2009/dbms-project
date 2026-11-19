▸ Thought for 10s

  Here is your complete DBMS Demo & Viva Preparation Guide, organized specifically for your 3-member team.

  Dividing the database concepts across 3 members ensures each person can speak with deep authority and confidence when the examiner or
  professor asks questions.
  ──────
   👥 3-Member Team Division of Roles 
    ┌──────────────────────────────────────┬──────────────────────────────────────┬──────────────────────────────────────┐
    │        MEMBER 1: ARCHITECTURE        │     MEMBER 2: PERFORMANCE & DATA     │     MEMBER 3: INTEGRITY & SECURITY   │
    │  Schema, Relations, Normalization    │  Partitioning, Indexes & Storage     │   Constraints, Queries & Live Demo   │
    ├──────────────────────────────────────┼──────────────────────────────────────┼──────────────────────────────────────┤
    │ • 2 Schemas (siem vs demo)           │ • Monthly Range Partitioning         │ • Partial Unique Indexes             │
    │ • ER Design & Table Relationships    │ • BRIN Index on time-series          │ • Check Constraints & Data Types     │
    │ • BCNF Design & 2NF Exception        │ • GIN Trigram Index (pg_trgm)        │ • Ingestion COPY vs Row Insert       │
    │ • Table Structures & Data Dictionary │ • Composite B-Trees & Explain Analyze│ • Live psql Commands & Attack Demo   │
    └──────────────────────────────────────┴──────────────────────────────────────┴──────────────────────────────────────┘
  ──────
   📌 Member 1: Schema Architecture, Relations & Normalization 

  ### 1. Two-Schema Architecture (siem vs demo)
  • Concept: Schema isolation (CREATE SCHEMA siem; CREATE SCHEMA demo;).
  • Why? The demo e-commerce store (demo.items, demo.demo_users) is an untrusted log generator. It is strictly separated from the analytical
  engine (siem.*). The SIEM only receives event streams via API keys and never directly queries or mixes tables with the business app.
  • Table Count:
      • siem: 8 core tables (users, log_sources, alert_rules, alerts, alert_logs, blocked_ips, system_settings, logs_archive) + partitioned
      logs.
      • demo: 2 tables (items, demo_users).
  ### 2. Relational Mapping & Cardinalities

  • users (1) ── (M) alert_rules: An operator creates detection rules (created_by REFERENCES users(user_id)).
  • alert_rules (1) ── (M) alerts: A rule triggers multiple alerts over time.
  • alerts (1) ── (0..1) blocked_ips: An alert leads to at most one block action (alert_id integer UNIQUE REFERENCES alerts(alert_id)).
  • alerts (M) ── (N) logs via alert_logs: Many logs can trigger an alert, and a log could technically trigger multiple rules.

  ### 3. Normalization & Normal Forms (Crucial Viva Point!)
  • BCNF (Boyce-Codd Normal Form): Almost all tables (users, alert_rules, alerts, blocked_ips, log_sources) are in BCNF. Every determinant
  is a candidate key.
  • Deliberate 2NF Exception (alert_logs):
      • Columns: (alert_id, log_id, ts) where PK is composite (alert_id, log_id, ts).
      • Why not 3NF/BCNF? Notice ts (timestamp) is redundant because (log_id, ts) is already in the logs table.
      • DBMS Engineering Justification: In partitioned databases, foreign keys across partitions and detached archive tables are either
      impossible or cause severe performance bottlenecks. By storing ts directly in alert_logs, PostgreSQL can prune partitions immediately
      and fetch the exact log from the correct monthly partition without a slow cross-partition scan.

  ──────
   📌 Member 2: High-Performance Storage, Partitioning & Indexes 
  ### 1. Declarative Range Partitioning (siem.logs)
  • Table: logs is partitioned by range on timestamp: PARTITION BY RANGE (ts).
  • Composite Primary Key Rule: Notice the PK is PRIMARY KEY (log_id, ts).
      • Examiner Question: "Why isn't log_id alone the primary key?"
      • Answer: In PostgreSQL, any unique constraint or primary key on a partitioned table must include the partition key (ts). PostgreSQL
      enforces uniqueness locally within partition shards, so it requires the partition key to know which partition to enforce.
  • Default Partition: CREATE TABLE logs_default PARTITION OF logs DEFAULT;
      • Prevents ingestion failure if a client log arrives with a malformed or out-of-bounds timestamp.
  • Automated Lifecycle & Pruning: Background scheduler creates monthly partitions ahead of time (logs_2026_11, etc.). When querying by date,
  PostgreSQL executes Partition Pruning (scans only the relevant month's table, skipping millions of irrelevant rows).

  ### 2. Advanced Indexing Strategies (Look at db/schema/04_indexes.sql)

  You implemented 3 different index types, each chosen for a specific algorithmic reason:

   Index Name                    │ Type                                 │ Target Column       │ Engineering Reason
  ───────────────────────────────┼──────────────────────────────────────┼─────────────────────┼─────────────────────────────────────────────
   logs_ts_brin                  │ BRIN (Block Range Index)             │ ts                  │ Logs are append-only and strictly ordered
                                 │                                      │                     │ by time. BRIN stores only the min/max
                                 │                                      │                     │ values for groups of pages. It takes 1% of
                                 │                                      │                     │ the space of a B-Tree and gives instant
                                 │                                      │                     │ range filtering.
   logs_payload_trgm             │ GIN (Generalized Inverted Index)     │ payload             │ Standard B-Tree cannot index regex or
                                 │ using pg_trgm                        │                     │ %pattern% searches. GIN with trigrams
                                 │                                      │                     │ breaks text into 3-character sequences,
                                 │                                      │                     │ enabling fast regex and SQL injection
                                 │                                      │                     │ substring searches on millions of rows.
   logs_srcip_ts / logs_event_ts │ B-Tree Composite                     │ (src_ip, ts) /      │ Powers real-time alert aggregation queries
                                 │                                      │ (event_type, ts)    │ (WHERE src_ip = X AND ts >= now() -
                                 │                                      │                     │ interval '60s'). Matches the leftmost
                                 │                                      │                     │ prefix rule.
  ──────
   📌 Member 3: Integrity Constraints, Ingestion & Live Demo 

  ### 1. Advanced Database Constraints
  • Partial Unique Indexes (Conditional Constraints):
    CREATE UNIQUE INDEX one_open_alert ON alerts (rule_id, src_ip) WHERE status = 'open';
    CREATE UNIQUE INDEX one_active_block ON blocked_ips (ip_address) WHERE unblocked_at IS NULL;

      • Prevents alert storms at the database engine level. If an IP triggers an alert 50 times in 10 seconds, only 1 open alert can
      physically exist.
      • An IP can have historical blocks, but at most one active block (unblocked_at IS NULL).
  • Domain-Specific Types (inet):
      • src_ip and ip_address use PostgreSQL's native inet data type rather than varchar(15).
      • Saves storage (4 bytes for IPv4, 16 bytes for IPv6) and allows subnet indexing and IP range calculations (<<=, >>=).
  • Conditional Check Constraints:
    CONSTRAINT rule_shape CHECK (
        (rule_type = 'threshold' AND event_type IS NOT NULL AND threshold_count IS NOT NULL)
        OR (rule_type = 'pattern' AND pattern IS NOT NULL)
    )
  Ensures data validity without needing application-side triggers.
  ### 2. High-Speed Bulk Ingestion

  • Uses PostgreSQL COPY protocol via Python psycopg3 (cur.copy("COPY siem.logs (...) FROM STDIN")).
  • Ingests thousands of rows per second directly in binary/text stream, avoiding the overhead of multiple INSERT INTO roundtrips and
  transaction log bottlenecks.
  ──────
   💻 Live Database Demonstration Cheat Sheet (What to Type in psql) 
  When the examiner says "Show me your database", open terminal and connect:

    docker compose exec postgres psql -U siem_user -d siem_db
    # or if running locally:
    psql -h localhost -U siem_user -d siem_db
  ### 1. Show Schemas and Table Hierarchy
    -- 1. List schemas
    \dn

    -- 2. List tables in the SIEM schema
    \dt siem.*

    -- 3. List tables in the Demo storefront schema
    \dt demo.*
  ### 2. Show Table Partitioning (The most impressive visual)

    -- Inspect the partitioned logs table:
    \d+ siem.logs

    -- View all child partition tables and their date ranges:
    SELECT 
        inhrelid::regclass AS partition_name,
        pg_get_expr(c.relpartbound, c.oid) AS partition_range
    FROM pg_inherits
    JOIN pg_class c ON c.oid = inhrelid
    WHERE inhparent = 'siem.logs'::regclass;

  ### 3. Demonstrate Partition Pruning with EXPLAIN
  Show the professor how PostgreSQL skips untouched months:
    SET search_path TO siem, public;

    EXPLAIN ANALYZE 
    SELECT count(*) FROM logs 
    WHERE ts >= '2026-11-01' AND ts < '2026-11-30';

  (Point out the Seq Scan on logs_2026_11 and note that logs_default and other monthly partitions are excluded / pruned).

  ### 4. Show the Indexes & Partial Constraints

    -- Show indexes on the partitioned table:
    \di+ siem.logs*
    
    -- Show the partial unique indexes on alerts and blocks:
    \d siem.alerts
    \d siem.blocked_ips

  ### 5. Inspect Seed Data & Catalog Items

    -- Show the 20 items with unique SVGs in demo:
    SELECT item_id, slug, category, price, image FROM demo.items LIMIT 5;
    
    -- Show detection rules:
    SELECT rule_id, rule_name, rule_type, pattern, threshold_count FROM siem.alert_rules;
  ──────
   🎯 Top Viva / Oral Exam Questions & Model Answers 

   Question                                                           │ Model Answer
  ────────────────────────────────────────────────────────────────────┼─────────────────────────────────────────────────────────────────────
   "Why PostgreSQL instead of MongoDB or MySQL?"                      │ "SIEM requires strong relational integrity (ACID), native
                                                                      │ declarative range partitioning, time-series indexing (BRIN), full-
                                                                      │ text trigram indexing (pg_trgm), and network-aware data types
                                                                      │ (inet), which PostgreSQL excels at out-of-the-box."
   "Why use BRIN instead of B-Tree for log timestamps?"               │ "A B-Tree index on 10 million rows can take hundreds of megabytes
                                                                      │ in RAM. Because log entries are strictly append-only, the timestamp
                                                                      │ column is naturally sorted on disk. BRIN indexes page ranges
                                                                      │ (storing only min and max timestamps per block), reducing index
                                                                      │ size by ~98% while delivering fast range scans."
   "How does the database prevent duplicate alerts?"                  │ "We enforce it at the database engine level via a partial unique
                                                                      │ index: CREATE UNIQUE INDEX one_open_alert ON siem.alerts (rule_id,
                                                                      │ src_ip) WHERE status = 'open';. Application bugs cannot bypass
                                                                      │ this."
   "What happens if an IP attacks while an analyst is investigating?" │ "Transactions in the alert engine use PostgreSQL row-level locking.
                                                                      │ If an IP triggers an alert and is subsequently blocked, the
                                                                      │ blocked_ips table acts as the authoritative gate, checked with
                                                                      │ cached sub-millisecond lookups."
   "How are old logs archived without slowing down active traffic?"   │ "Because logs are partitioned by month, old partitions can be
                                                                      │ detached (ALTER TABLE logs DETACH PARTITION) instantly with zero
                                                                      │ table-lock downtime, and moved to logs_archive."