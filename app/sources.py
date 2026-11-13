"""Log-source registration (FR8). Admin-only (enforced by the route).

Registering a source returns a freshly generated API key ONCE (only its hash is
stored). The source then sends that key as X-API-Key to the ingestion endpoint.
"""
import secrets

from app.auth import hash_api_key
from app.db import execute, query


def list_sources() -> list[dict]:
    return query("SELECT source_id, source_name, source_type, created_at FROM log_sources ORDER BY source_id")


def register_source(name: str, source_type: str) -> str:
    api_key = secrets.token_urlsafe(24)
    execute(
        "INSERT INTO log_sources (source_name, source_type, api_key_hash) VALUES (%s, %s, %s)",
        (name, source_type, hash_api_key(api_key)),
    )
    return api_key  # shown once; not recoverable afterwards
