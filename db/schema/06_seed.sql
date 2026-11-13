-- 06_seed.sql
-- Minimal seed so the system is demoable the moment it boots.
-- Passwords are bcrypt (pgcrypto crypt/gen_salt('bf')), verifiable by passlib in app.
-- The demo source API key is sha256 (keys are high-entropy, no need for bcrypt).
--
-- Default credentials (change for anything beyond a demo):
--   SIEM operators: admin/admin123, analyst/analyst123, viewer/viewer123
--   demo visitor  : alice/alice123
--   demo source API key (plaintext, send in X-API-Key): demo-key-123

SET search_path TO siem, public;

-- SIEM operators, one per role (shows RBAC at the demo).
INSERT INTO users (username, email, password_hash, role) VALUES
    ('admin',   'admin@siem.local',   crypt('admin123',   gen_salt('bf')), 'admin'),
    ('analyst', 'analyst@siem.local', crypt('analyst123', gen_salt('bf')), 'analyst'),
    ('viewer',  'viewer@siem.local',  crypt('viewer123',  gen_salt('bf')), 'viewer');

-- The demo website as a registered log source.
INSERT INTO log_sources (source_name, source_type, api_key_hash) VALUES
    ('demo-web-app', 'web', encode(digest('demo-key-123', 'sha256'), 'hex'));

-- Two starter detection rules, created by admin.
INSERT INTO alert_rules
    (rule_name, rule_type, event_type, threshold_count, pattern, window_seconds, severity, enabled, created_by)
VALUES
    ('Brute force: 5 failed logins/IP/60s', 'threshold', 'login_failed', 5, NULL, 60, 'high', true,
        (SELECT user_id FROM users WHERE username = 'admin')),
    ('SQL injection in payload', 'pattern', NULL, NULL,
        '(?i)(union\s+select|or\s+1=1|--|;|/\*|xp_|sleep\s*\(|information_schema)', 60, 'high', true,
        (SELECT user_id FROM users WHERE username = 'admin'));

-- Configuration.
INSERT INTO system_settings (setting_key, setting_value) VALUES
    ('retention_months', '6'),
    ('partitions_ahead', '3');

-- Demo website data (separate schema).
SET search_path TO demo, public;

INSERT INTO demo_users (username, password_hash) VALUES
    ('alice', crypt('alice123', gen_salt('bf')));

INSERT INTO items (name, description, price) VALUES
    ('Mechanical Keyboard', 'Tactile brown switches, hot-swappable', 89.99),
    ('27-inch Monitor',     '1440p 144Hz IPS panel',                 249.00),
    ('USB-C Hub',           '7-in-1 with HDMI and ethernet',          39.50),
    ('Noise-cancel Headset','Over-ear, 30h battery',                 129.00),
    ('Webcam 1080p',        'Auto-focus with privacy shutter',        45.00);
