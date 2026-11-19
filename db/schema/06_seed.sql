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
        '(?i)(union\s+(all\s+)?select|or\s+[''"]?1[''"]?\s*=\s*[''"]?1|--|/\*|xp_|sleep\s*\(|information_schema|;\s*(drop|select|insert|update|delete|create|alter|truncate))', 60, 'high', true,
        (SELECT user_id FROM users WHERE username = 'admin'));

-- Configuration.
INSERT INTO system_settings (setting_key, setting_value) VALUES
    ('retention_months', '6'),
    ('partitions_ahead', '3');

-- Demo website data (separate schema).
SET search_path TO demo, public;

INSERT INTO demo_users (username, password_hash) VALUES
    ('alice', crypt('alice123', gen_salt('bf')));

INSERT INTO items (slug, name, category, description, price, rating, reviews, image, badge) VALUES
    ('acousticpro-anc', 'AcousticPro ANC Wireless Headphones', 'Audio', 'Adaptive noise cancellation, spatial audio, and 65-hour battery life.', 299.99, '4.9', 1248, '/static/products/acousticpro-anc.svg', 'Best seller'),
    ('hyperkey-pro', 'HyperKey Pro Mechanical Keyboard', 'Keyboards', 'Hot-swappable switches, low-latency wireless, and per-key lighting.', 149.00, '4.7', 420, '/static/products/hyperkey-pro.svg', 'Popular'),
    ('aura-view-27', 'AuraView 27-inch 4K HDR Monitor', 'Displays', 'Crisp 4K detail, HDR color, and a clean edge-to-edge workstation view.', 479.00, '4.9', 2105, '/static/products/aura-view-27.svg', 'New'),
    ('connect-7', 'Connect 7-in-1 USB-C Hub', 'Accessories', 'One compact aluminum hub for HDMI, ethernet, storage, and more.', 39.50, '4.8', 834, '/static/products/connect-7.svg', 'Great value'),
    ('studio-master-7', 'Studio Master Series 7 Headphones', 'Audio', 'Planar magnetic detail with a wide, natural soundstage.', 349.00, '4.8', 193, '/static/products/studio-master-7.svg', 'New'),
    ('aurapods-elite', 'AuraPods Elite Earbuds', 'Audio', 'Pocket-sized ANC earbuds with a comfortable all-day fit.', 159.00, '4.7', 266, '/static/products/aurapods-elite.svg', 'Staff pick'),
    ('sonicpulse-go', 'SonicPulse Go Speaker', 'Audio', 'Room-filling sound in a splash-proof portable body.', 129.00, '4.6', 339, '/static/products/sonicpulse-go.svg', 'Popular'),
    ('wavebeam-mini', 'WaveBeam Mini Soundbar', 'Audio', 'A compact desktop soundbar for films, music, and calls.', 89.00, '4.9', 412, '/static/products/wavebeam-mini.svg', 'Great value'),
    ('deskkey-65', 'DeskKey 65 Mechanical Keyboard', 'Keyboards', 'A compact 65% layout with tactile switches and a soft wrist rest.', 129.00, '4.7', 558, '/static/products/deskkey-65.svg', 'Popular'),
    ('typeflow-wireless', 'TypeFlow Wireless Keyboard', 'Keyboards', 'Quiet low-profile keys with multi-device pairing.', 99.00, '4.6', 631, '/static/products/typeflow-wireless.svg', 'New'),
    ('macrodeck-mini', 'MacroDeck Mini Controller', 'Keyboards', 'Nine programmable keys for creative shortcuts and workflows.', 79.00, '4.8', 704, '/static/products/macrodeck-mini.svg', 'Creator pick'),
    ('clicker-pro', 'Clicker Pro Wireless Mouse', 'Keyboards', 'Silent clicks, precise tracking, and a comfortable right-handed shape.', 69.00, '4.7', 850, '/static/products/clicker-pro.svg', 'Bestseller'),
    ('aura-view-24', 'AuraView 24-inch Work Monitor', 'Displays', 'A bright Full HD panel for focused work and everyday browsing.', 229.00, '4.6', 1215, '/static/products/aura-view-24.svg', 'Great value'),
    ('aura-view-ultra', 'AuraView UltraWide 34 Monitor', 'Displays', 'Ultra-wide space for timelines, dashboards, and side-by-side work.', 699.00, '4.8', 1288, '/static/products/aura-view-ultra.svg', 'Studio grade'),
    ('pixelstand-4k', 'PixelStand 4K Monitor', 'Displays', 'Sharp color-accurate detail on a minimal adjustable stand.', 399.00, '4.7', 1361, '/static/products/pixelstand-4k.svg', 'Popular'),
    ('travel-screen', 'TravelScreen 15 Portable Display', 'Displays', 'A lightweight second screen for flexible work anywhere.', 249.00, '4.6', 1434, '/static/products/travel-screen.svg', 'Travel ready'),
    ('connect-pro', 'Connect Pro Thunderbolt Dock', 'Accessories', 'One-cable power, displays, storage, and network for your desk.', 189.00, '4.8', 1580, '/static/products/connect-pro.svg', 'Pro setup'),
    ('chargecube-65', 'ChargeCube 65W GaN Charger', 'Accessories', 'Small, powerful USB-C charging for laptops, tablets, and phones.', 49.00, '4.7', 1653, '/static/products/chargecube-65.svg', 'Great value'),
    ('cablekit', 'CableKit Desk Organizer', 'Accessories', 'A tidy modular kit for routing and labeling every desk cable.', 24.00, '4.6', 1726, '/static/products/cablekit.svg', 'Bestseller'),
    ('webcam-1080', 'ClearView 1080p Webcam', 'Accessories', 'Autofocus video with a privacy shutter for calls and streaming.', 45.00, '4.8', 1945, '/static/products/webcam-1080.svg', 'Work from home')
ON CONFLICT (slug) DO NOTHING;
