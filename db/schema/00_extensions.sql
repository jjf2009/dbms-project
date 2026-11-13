-- 00_extensions.sql
-- Extensions required by the SIEM Log Engine.
-- pg_trgm powers the trigram GIN index on logs.payload (FR12) used for
-- substring/payload text search (FR13).

CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- pgcrypto: lets the seed script hash the admin password (bcrypt) and the demo
-- source's API key (sha256) at init time, so no plaintext secret is stored.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Two schemas: the SIEM data model, and the demo website's own data.
-- The demo site is a *source of logs*, never part of the SIEM model.
CREATE SCHEMA IF NOT EXISTS siem;
CREATE SCHEMA IF NOT EXISTS demo;
