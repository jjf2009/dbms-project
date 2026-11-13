"""Detection-rule management (FR14). Admin-only (enforced by the route)."""
from app.db import execute, query, query_one


def list_rules() -> list[dict]:
    return query("SELECT * FROM alert_rules ORDER BY rule_id")


def get_rule(rule_id: int) -> dict | None:
    return query_one("SELECT * FROM alert_rules WHERE rule_id = %s", (rule_id,))


def create_rule(d: dict, created_by: int) -> None:
    execute(
        "INSERT INTO alert_rules "
        "(rule_name, rule_type, event_type, threshold_count, pattern, window_seconds, severity, enabled, created_by) "
        "VALUES (%(rule_name)s, %(rule_type)s, %(event_type)s, %(threshold_count)s, %(pattern)s, "
        "%(window_seconds)s, %(severity)s, %(enabled)s, %(created_by)s)",
        {**d, "created_by": created_by},
    )


def update_rule(rule_id: int, d: dict) -> None:
    execute(
        "UPDATE alert_rules SET rule_name=%(rule_name)s, rule_type=%(rule_type)s, "
        "event_type=%(event_type)s, threshold_count=%(threshold_count)s, pattern=%(pattern)s, "
        "window_seconds=%(window_seconds)s, severity=%(severity)s, enabled=%(enabled)s "
        "WHERE rule_id=%(rule_id)s",
        {**d, "rule_id": rule_id},
    )


def set_enabled(rule_id: int, enabled: bool) -> None:
    execute("UPDATE alert_rules SET enabled = %s WHERE rule_id = %s", (enabled, rule_id))
