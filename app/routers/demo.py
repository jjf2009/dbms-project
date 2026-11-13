"""Demo website (FR4-FR6).

A tiny shop: register, log in, browse and search items. Every request emits one
log event to the SIEM (in-process, via emit_demo_event). Every request first
checks the blocklist and returns HTTP 403 to a blocked IP — the rejection is
itself logged. This is the traffic source the SIEM detects attacks in.
"""
import ipaddress

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from app.alerts import is_blocked
from app.auth import hash_password, verify_password
from app.db import execute, query, query_one
from app.ingest import emit_demo_event

router = APIRouter(prefix="/demo", tags=["demo"])
templates = Jinja2Templates(directory="app/templates")


def client_ip(request: Request) -> str:
    # Everything runs on one machine, so the demo/simulator pass a client IP via
    # X-Forwarded-For to show several distinct sources (spec constraint).
    xff = request.headers.get("x-forwarded-for")
    cand = xff.split(",")[0].strip() if xff else (request.client.host if request.client else "127.0.0.1")
    try:
        ipaddress.ip_address(cand)  # reject non-IP hosts (e.g. test client) before any inet query
        return cand
    except ValueError:
        return "127.0.0.1"


def _guard(request: Request) -> Response | None:
    """Return a 403 response if the caller's IP is blocked, else None (FR6)."""
    ip = client_ip(request)
    if is_blocked(ip):
        emit_demo_event(event_type="request_blocked", src_ip=ip, status=403,
                        user_agent=request.headers.get("user-agent"), payload=str(request.url.path))
        return HTMLResponse("<h1>403 Forbidden</h1><p>Your IP is blocked.</p>", status_code=403)
    return None


@router.get("/", response_class=HTMLResponse)
def home(request: Request, q: str = ""):
    blocked = _guard(request)
    if blocked:
        return blocked
    ip = client_ip(request)
    ua = request.headers.get("user-agent")
    if q:
        # payload carries the raw search term -> pattern rules inspect it (SQLi demo)
        items = query(
            "SELECT * FROM demo.items WHERE name ILIKE %s OR description ILIKE %s ORDER BY item_id",
            (f"%{q}%", f"%{q}%"),
        )
        emit_demo_event(event_type="search", src_ip=ip, status=200, payload=q, user_agent=ua,
                        actor_username=request.session.get("demo_user"))
    else:
        items = query("SELECT * FROM demo.items ORDER BY item_id")
        emit_demo_event(event_type="page_view", src_ip=ip, status=200, payload="/", user_agent=ua,
                        actor_username=request.session.get("demo_user"))
    return templates.TemplateResponse(request, "demo_home.html",
                                      {"items": items, "q": q, "user": request.session.get("demo_user")})


@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    blocked = _guard(request)
    return blocked or templates.TemplateResponse(request, "demo_login.html", {"mode": "login"})


@router.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    blocked = _guard(request)
    if blocked:
        return blocked
    ip = client_ip(request)
    ua = request.headers.get("user-agent")
    user = query_one("SELECT * FROM demo.demo_users WHERE username = %s", (username,))
    ok = bool(user) and verify_password(password, user["password_hash"])
    if ok:
        request.session["demo_user"] = username
        emit_demo_event(event_type="login_success", src_ip=ip, status=200,
                        actor_username=username, user_agent=ua, payload=f"user={username}")
        return RedirectResponse("/demo/", status_code=303)
    # failed login -> the event the brute-force threshold rule counts (FR16 demo)
    emit_demo_event(event_type="login_failed", src_ip=ip, status=401,
                    actor_username=username, user_agent=ua, payload=f"user={username}")
    return templates.TemplateResponse(request, "demo_login.html",
                                      {"mode": "login", "error": "Invalid credentials"}, status_code=401)


@router.get("/register", response_class=HTMLResponse)
def register_form(request: Request):
    blocked = _guard(request)
    return blocked or templates.TemplateResponse(request, "demo_login.html", {"mode": "register"})


@router.post("/register")
def register(request: Request, username: str = Form(...), password: str = Form(...)):
    blocked = _guard(request)
    if blocked:
        return blocked
    ip = client_ip(request)
    try:
        execute("INSERT INTO demo.demo_users (username, password_hash) VALUES (%s, %s)",
                (username, hash_password(password)))
    except Exception:
        return templates.TemplateResponse(request, "demo_login.html",
                                          {"mode": "register", "error": "Username taken"}, status_code=400)
    request.session["demo_user"] = username
    emit_demo_event(event_type="register", src_ip=ip, status=200, actor_username=username,
                    user_agent=request.headers.get("user-agent"), payload=f"user={username}")
    return RedirectResponse("/demo/", status_code=303)


@router.get("/logout")
def logout(request: Request):
    request.session.pop("demo_user", None)
    return RedirectResponse("/demo/", status_code=303)
