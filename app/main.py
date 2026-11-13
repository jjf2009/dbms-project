"""FastAPI application entry point.

Wires the ingestion API, the demo website and the SIEM UI onto one process,
opens the DB pool, pre-creates partitions and starts the background scheduler.
"""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from app import ingest, scheduler
from app.config import settings
from app.db import pool
from app.partitions import create_partitions_ahead
from app.routers import demo, siem

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("siem")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    pool.open()
    pool.wait()
    try:
        create_partitions_ahead()
    except Exception:
        log.exception("initial partition creation failed")
    ingest.demo_source_id()  # warm cache
    scheduler.start()
    log.info("SIEM Log Engine started")
    yield
    scheduler.shutdown()
    pool.close()


app = FastAPI(title="Real-Time SIEM Log Engine", lifespan=lifespan)
app.add_middleware(SessionMiddleware, secret_key=settings.app_secret)
app.mount("/static", StaticFiles(directory="app/static"), name="static")

app.include_router(ingest.router)
app.include_router(demo.router)
app.include_router(siem.router)


@app.get("/")
def root():
    return RedirectResponse("/siem/")


@app.get("/health")
def health():
    return {"status": "ok"}
