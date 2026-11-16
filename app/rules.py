"""Detection-rule management (FR14). Admin-only (enforced by the route)."""
from app.db import execute, query, query_one


def _validate(d: dict) -> None:
    if not str(d.get("rule_name") or "").strip():
        raise ValueError("Rule name is required")
    if d.get("rule_type") not in {"threshold", "pattern"}:
        raise ValueError("Rule type must be threshold or pattern")
    if d.get("severity") not in {"low", "medium", "high"}:
        raise ValueError("Invalid severity")
    if int(d.get("window_seconds") or 0) <= 0:
        raise ValueError("Window must be greater than zero")
    if d["rule_type"] == "threshold":
        if not str(d.get("event_type") or "").strip():
            raise ValueError("Threshold rules need an event type")
        if int(d.get("threshold_count") or 0) <= 0:
            raise ValueError("Threshold must be greater than zero")
    elif not str(d.get("pattern") or "").strip():
        raise ValueError("Pattern rules need a regular expression")


def list_rules() -> list[dict]:
    return query("SELECT * FROM alert_rules ORDER BY rule_id")


def get_rule(rule_id: int) -> dict | None:
    return query_one("SELECT * FROM alert_rules WHERE rule_id = %s", (rule_id,))


def create_rule(d: dict, created_by: int) -> None:
    _validate(d)
    execute(
        "INSERT INTO alert_rules "
        "(rule_name, rule_type, event_type, threshold_count, pattern, window_seconds, severity, enabled, created_by) "
        "VALUES (%(rule_name)s, %(rule_type)s, %(event_type)s, %(threshold_count)s, %(pattern)s, "
        "%(window_seconds)s, %(severity)s, %(enabled)s, %(created_by)s)",
        {**d, "created_by": created_by},
    )


def update_rule(rule_id: int, d: dict) -> None:
    _validate(d)
    execute(
        "UPDATE alert_rules SET rule_name=%(rule_name)s, rule_type=%(rule_type)s, "
        "event_type=%(event_type)s, threshold_count=%(threshold_count)s, pattern=%(pattern)s, "
        "window_seconds=%(window_seconds)s, severity=%(severity)s, enabled=%(enabled)s "
        "WHERE rule_id=%(rule_id)s",
        {**d, "rule_id": rule_id},
    )


def set_enabled(rule_id: int, enabled: bool) -> None:
    execute("UPDATE alert_rules SET enabled = %s WHERE rule_id = %s", (enabled, rule_id))
