"""Ingestion API (FR8-FR10).

Events are accepted only from a registered source, authenticated by its API key
(sent as X-API-Key and matched against log_sources.api_key_hash). Accepted events
go into the batch buffer; the buffer flushes them to the partitioned logs table.

emit_demo_event() is the in-process path the demo site uses to log every request
without an HTTP round-trip.
"""
from datetime import datetime, timezone

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

from app import buffer
from app.auth import hash_api_key
from app.db import query_one

router = APIRouter(prefix="/ingest", tags=["ingest"])

# cache of demo source id for emit_demo_event
_demo_source_id: int | None = None


def _source_for_key(api_key: str) -> dict | None:
    return query_one(
        "SELECT source_id, source_name FROM log_sources WHERE api_key_hash = %s",
        (hash_api_key(api_key),),
    )


class Event(BaseModel):
    event_type: str
    src_ip: str
    actor_username: str | None = None
    status: int | None = None
    user_agent: str | None = None
    payload: str | None = None
    ts: datetime | None = None


class EventBatch(BaseModel):
    events: list[Event]


@router.post("")
def ingest(body: EventBatch, x_api_key: str = Header(default="")):
    src = _source_for_key(x_api_key)
    if not src:
        raise HTTPException(status_code=401, detail="Unknown or missing API key")  # FR9
    now = datetime.now(timezone.utc)
    for e in body.events:
        buffer.add_event({
            "ts": e.ts or now,
            "source_id": src["source_id"],
            "actor_username": e.actor_username,
            "src_ip": e.src_ip,
            "event_type": e.event_type,
            "status": e.status,
            "user_agent": e.user_agent,
            "payload": e.payload,
        })
    return {"accepted": len(body.events)}


def demo_source_id() -> int:
    global _demo_source_id
    if _demo_source_id is None:
        row = query_one("SELECT source_id FROM log_sources WHERE source_name = 'demo-web-app'")
        _demo_source_id = row["source_id"] if row else 1
    return _demo_source_id


def emit_demo_event(*, event_type: str, src_ip: str, status: int | None = None,
                    actor_username: str | None = None, user_agent: str | None = None,
                    payload: str | None = None) -> None:
    buffer.add_event({
        "ts": datetime.now(timezone.utc),
        "source_id": demo_source_id(),
        "actor_username": actor_username,
        "src_ip": src_ip,
        "event_type": event_type,
        "status": status,
        "user_agent": user_agent,
        "payload": payload,
    })
