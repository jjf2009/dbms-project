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


def sync_db_schema() -> None:
    """Ensure database schema is up to date, fixes SQL injection rule, and ensures demo.items has data."""
    with pool.connection() as conn:
        with conn.cursor() as cur:
            # 1. Fix the SQL injection rule in alert_rules if it has the bare ';' false-positive pattern
            cur.execute("""
                UPDATE siem.alert_rules
                SET pattern = '(?i)(union\\s+(all\\s+)?select|or\\s+[''"]?1[''"]?\\s*=\\s*[''"]?1|--|/\\*|xp_|sleep\\s*\\(|information_schema|;\\s*(drop|select|insert|update|delete|create|alter|truncate))'
                WHERE rule_type = 'pattern'
                  AND pattern ~ '(?<!drop\\|select\\|insert\\|update\\|delete\\|create\\|alter\\|truncate)\\|;\\|'
            """)

            # 2. Add columns to demo.items if missing
            cur.execute("""
                ALTER TABLE demo.items
                ADD COLUMN IF NOT EXISTS slug varchar(80),
                ADD COLUMN IF NOT EXISTS category varchar(80) DEFAULT 'Accessories',
                ADD COLUMN IF NOT EXISTS rating varchar(10) DEFAULT '4.8',
                ADD COLUMN IF NOT EXISTS reviews integer DEFAULT 100,
                ADD COLUMN IF NOT EXISTS image text DEFAULT '/static/products/hub.png',
                ADD COLUMN IF NOT EXISTS badge varchar(40);
            """)

            # 3. Create unique index on slug if not exists
            cur.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS demo_items_slug_idx ON demo.items (slug) WHERE slug IS NOT NULL;
            """)

            # 4. Migrate image paths: update any generic .png paths to per-product .svg
            cur.execute("""
                UPDATE demo.items SET image = '/static/products/' || slug || '.svg'
                WHERE slug IS NOT NULL AND image LIKE '/static/products/%.png'
            """)

            # 5. Check if demo.items has full catalog
            cur.execute("SELECT count(*) AS n FROM demo.items WHERE slug IS NOT NULL")
            if cur.fetchone()["n"] < 10:
                cur.execute("""
                    INSERT INTO demo.items (slug, name, category, description, price, rating, reviews, image, badge) VALUES
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
                """)

