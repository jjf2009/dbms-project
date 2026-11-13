-- 02_demo_tables.sql
-- The demo website's own data. Lives in a separate schema (demo), NOT in the SIEM
-- model. The SIEM only ever sees events the demo site emits to the ingestion API.

SET search_path TO demo, public;

-- Visitors of the demo site. Not SIEM operators.
CREATE TABLE demo_users (
    demo_user_id  serial       PRIMARY KEY,
    username      varchar(50)  NOT NULL UNIQUE,
    password_hash varchar(255) NOT NULL,
    created_at    timestamptz  NOT NULL DEFAULT now()
);

-- Items the visitor can browse/search, so the site produces realistic traffic.
CREATE TABLE items (
    item_id     serial       PRIMARY KEY,
    name        varchar(120) NOT NULL,
    description text,
    price       numeric(10,2) NOT NULL DEFAULT 0
);
