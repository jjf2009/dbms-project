"""End-to-end tests over the real stack (schema + app).

Covered: API-key ingestion, lossless ingest->search, threshold detection,
RBAC (viewer cannot search), and the demo-site blocklist 403.
"""
import uuid


def test_health(client):
    assert client.get("/health").json()["status"] == "ok"


def test_all_pages_render_for_admin(operator):
    # every SIEM page + the demo site renders without a template error
    for path in ["/siem/", "/siem/alerts", "/siem/search", "/siem/blocks",
                 "/siem/rules", "/siem/sources", "/siem/users", "/siem/report",
                 "/siem/settings", "/siem/api/dashboard", "/demo/", "/demo/login"]:
        r = operator.get(path)
        assert r.status_code == 200, f"{path} -> {r.status_code}"


def test_ingest_requires_api_key(client):
    r = client.post("/ingest", json={"events": [{"event_type": "x", "src_ip": "1.2.3.4"}]})
    assert r.status_code == 401  # FR9


def test_ingest_and_search_roundtrip(operator):
    from app import buffer
    marker = f"probe-{uuid.uuid4().hex[:8]}"
    r = operator.post("/ingest", headers={"X-API-Key": "demo-key-123"},
                      json={"events": [{"event_type": "unit_test", "src_ip": "203.0.113.7",
                                        "payload": marker}]})
    assert r.status_code == 200
    buffer.flush()  # force the batch out
    page = operator.get(f"/siem/search?text={marker}")
    assert marker in page.text  # FR13: searchable after batch write


def test_threshold_detection_raises_alert(operator):
    from app import buffer
    from app.detection import run_detection
    ip = "198.51.100.42"
    for i in range(6):  # > threshold of 5 within 60s
        operator.post("/ingest", headers={"X-API-Key": "demo-key-123"},
                      json={"events": [{"event_type": "login_failed", "src_ip": ip,
                                        "actor_username": "admin", "payload": f"try{i}"}]})
    buffer.flush()
    run_detection()  # the scheduler would do this every 10s (FR15/FR16)
    alerts = operator.get("/siem/alerts?status=open").text
    assert ip in alerts


def test_rbac_viewer_cannot_search(client):
    client.post("/siem/login", data={"username": "viewer", "password": "viewer123"})
    r = client.get("/siem/search", follow_redirects=False)
    assert r.status_code == 403  # FR3 / FR23
    client.post("/siem/login", data={"username": "admin", "password": "admin123"})  # restore


def test_pattern_detection_sqli(operator):
    from app import buffer
    from app.detection import run_detection
    ip = "203.0.113.200"
    operator.post("/ingest", headers={"X-API-Key": "demo-key-123"},
                  json={"events": [{"event_type": "search", "src_ip": ip,
                                    "payload": "' UNION SELECT username FROM demo_users --"}]})
    buffer.flush()
    run_detection()
    assert ip in operator.get("/siem/alerts?status=open").text  # FR16 pattern rule


def test_rule_create_and_edit(operator):
    from app.db import query_one
    name = f"unit rule {uuid.uuid4().hex[:8]}"  # unique so reruns don't collide
    operator.post("/siem/rules", data={"rule_name": name, "rule_type": "threshold",
                                        "event_type": "x", "threshold_count": "3",
                                        "window_seconds": "30", "severity": "low"})
    rule = query_one("SELECT * FROM siem.alert_rules WHERE rule_name=%s", (name,))
    assert rule and rule["threshold_count"] == 3
    operator.post(f"/siem/rules/{rule['rule_id']}", data={
        "rule_name": name, "rule_type": "threshold", "event_type": "x",
        "threshold_count": "9", "window_seconds": "30", "severity": "high", "enabled": "off"})
    rule2 = query_one("SELECT * FROM siem.alert_rules WHERE rule_id=%s", (rule["rule_id"],))
    assert rule2["threshold_count"] == 9 and rule2["severity"] == "high" and rule2["enabled"] is False  # FR14


def test_source_registration_and_ingest(operator):
    import re
    from app import buffer
    html = operator.post("/siem/sources", data={"source_name": "unit-src", "source_type": "web"}).text
    key = re.search(r"<pre>([^<]+)</pre>", html).group(1).strip()
    r = operator.post("/ingest", headers={"X-API-Key": key},
                      json={"events": [{"event_type": "unit_src_ev", "src_ip": "1.1.1.1"}]})
    assert r.status_code == 200  # FR8/FR9: a freshly registered source can ingest
    buffer.flush()


def test_archive_moves_rows_losslessly(operator):
    from app.db import execute, query_one
    from app.partitions import archive_old_partitions
    # Create a dedicated partition for a month far in the past (older than any
    # retention cutoff), put a row in it, then archive. Self-contained & repeatable.
    execute("CREATE TABLE IF NOT EXISTS siem.logs_2020_01 PARTITION OF siem.logs "
            "FOR VALUES FROM ('2020-01-01') TO ('2020-02-01')")
    execute("INSERT INTO siem.logs (ts, source_id, src_ip, event_type, payload) "
            "VALUES ('2020-01-15', 1, '10.9.9.9', 'page_view', 'archive probe')")
    before = query_one("SELECT count(*) AS n FROM siem.logs_archive")["n"]
    result = archive_old_partitions()  # default retention 6 months -> 2020 archives
    after = query_one("SELECT count(*) AS n FROM siem.logs_archive")["n"]
    gone = query_one("SELECT count(*) AS n FROM pg_class WHERE relname='logs_2020_01'")["n"]
    assert result["rows"] >= 1 and after == before + result["rows"] and gone == 0  # FR21


def test_unblock(operator):
    import random
    from app.db import execute, query_one
    ip = f"198.51.100.{random.randint(2, 254)}"  # fresh IP so reruns don't collide
    rule = query_one("SELECT rule_id FROM siem.alert_rules LIMIT 1")
    execute("INSERT INTO siem.alerts (rule_id, src_ip) VALUES (%s,%s) ON CONFLICT DO NOTHING",
            (rule["rule_id"], ip))
    alert = query_one("SELECT alert_id FROM siem.alerts WHERE src_ip=%s AND status='open'", (ip,))
    admin = query_one("SELECT user_id FROM siem.users WHERE username='admin'")
    execute("INSERT INTO siem.blocked_ips (alert_id, ip_address, blocked_by) VALUES (%s,%s,%s) "
            "ON CONFLICT DO NOTHING", (alert["alert_id"], ip, admin["user_id"]))
    block = query_one("SELECT block_id FROM siem.blocked_ips WHERE ip_address=%s AND unblocked_at IS NULL", (ip,))
    assert operator.get("/demo/", headers={"X-Forwarded-For": ip}).status_code == 403
    operator.post(f"/siem/blocks/{block['block_id']}/unblock")
    assert operator.get("/demo/", headers={"X-Forwarded-For": ip}).status_code == 200  # FR19


def test_blocklist_returns_403(operator):
    from app.db import execute, query_one
    ip = "192.0.2.55"
    # create an alert + block for this IP directly
    rule = query_one("SELECT rule_id FROM siem.alert_rules LIMIT 1")
    execute("INSERT INTO siem.alerts (rule_id, src_ip) VALUES (%s, %s) "
            "ON CONFLICT DO NOTHING", (rule["rule_id"], ip))
    alert = query_one("SELECT alert_id FROM siem.alerts WHERE src_ip=%s AND status='open' LIMIT 1", (ip,))
    admin = query_one("SELECT user_id FROM siem.users WHERE username='admin'")
    execute("INSERT INTO siem.blocked_ips (alert_id, ip_address, blocked_by) VALUES (%s,%s,%s) "
            "ON CONFLICT DO NOTHING", (alert["alert_id"], ip, admin["user_id"]))
    r = operator.get("/demo/", headers={"X-Forwarded-For": ip})
    assert r.status_code == 403  # FR6
