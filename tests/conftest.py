"""Shared pytest fixtures. Tests need a reachable PostgreSQL with the schema
loaded (docker compose up, or the podman steps in the README). If the DB is
unreachable, the whole suite is skipped rather than failing.
"""
import os

import pytest

os.environ.setdefault("POSTGRES_HOST", "localhost")


@pytest.fixture(scope="session")
def client():
    from fastapi.testclient import TestClient

    from app.main import app
    try:
        with TestClient(app) as c:          # runs lifespan: opens pool, starts scheduler
            c.get("/health").raise_for_status()
            yield c
    except Exception as e:                    # DB not up
        pytest.skip(f"stack unavailable: {e}")


@pytest.fixture
def operator(client):
    """A logged-in admin session on the test client."""
    r = client.post("/siem/login", data={"username": "admin", "password": "admin123"},
                    follow_redirects=False)
    assert r.status_code == 303
    return client
