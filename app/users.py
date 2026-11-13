"""Operator account management (FR2). Admin-only (enforced by the route)."""
from app.auth import hash_password
from app.db import execute, query


def list_users() -> list[dict]:
    return query("SELECT user_id, username, email, role, is_active, created_at FROM users ORDER BY user_id")


def create_user(username: str, email: str, password: str, role: str) -> None:
    execute(
        "INSERT INTO users (username, email, password_hash, role) VALUES (%s, %s, %s, %s)",
        (username, email, hash_password(password), role),
    )


def set_role(user_id: int, role: str) -> None:
    execute("UPDATE users SET role = %s WHERE user_id = %s", (role, user_id))


def set_active(user_id: int, active: bool) -> None:
    execute("UPDATE users SET is_active = %s WHERE user_id = %s", (active, user_id))
