"""SIEM operator UI + actions (FR1-3, FR7 trigger, FR13-24).

Role gates (require_role) enforce RBAC on every route (FR3). Admin >= Analyst >=
Viewer. Viewer reaches only the dashboard and alert summaries and never sees raw
payloads (FR23).
"""
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app import alerts as alerts_mod
from app import dashboard as dash
from app import rules as rules_mod
from app import sources as sources_mod
from app import users as users_mod
from app.auth import authenticate, require_role
from app.search import search

router = APIRouter(prefix="/siem", tags=["siem"])
templates = Jinja2Templates(directory="app/templates")


def page(request, name, op, **ctx):
    return templates.TemplateResponse(request, name, {"op": op, **ctx})


# ---- auth ----
@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    return templates.TemplateResponse(request, "login.html", {})


@router.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    user = authenticate(username, password)
    if not user:
        return templates.TemplateResponse(request, "login.html",
                                          {"error": "Invalid credentials"}, status_code=401)
    request.session["operator"] = {"user_id": user["user_id"], "username": user["username"],
                                   "role": user["role"]}
    return RedirectResponse("/siem/", status_code=303)


@router.get("/logout")
def logout(request: Request):
    request.session.pop("operator", None)
    return RedirectResponse("/siem/login", status_code=303)


# ---- dashboard (viewer+) ----
@router.get("/", response_class=HTMLResponse)
def dashboard_page(request: Request, op=Depends(require_role("viewer"))):
    return page(request, "dashboard.html", op)


@router.get("/api/dashboard")
def dashboard_api(op=Depends(require_role("viewer"))):
    return dash.dashboard_data()


# ---- search (analyst+; raw payloads) ----
@router.get("/search", response_class=HTMLResponse)
def search_page(request: Request, op=Depends(require_role("analyst")),
                src_ip: str = "", actor_username: str = "", event_type: str = "",
                text: str = "", ts_from: str = "", ts_to: str = "",
                include_archived: str = ""):
    f = {"src_ip": src_ip or None, "actor_username": actor_username or None,
         "event_type": event_type or None, "text": text or None,
         "ts_from": ts_from or None, "ts_to": ts_to or None}
    result = None
    if any(f.values()) or event_type or text:
        result = search(f, include_archived=bool(include_archived))
    return page(request, "search.html", op, result=result, f=f,
                include_archived=bool(include_archived))


# ---- alerts ----
@router.get("/alerts", response_class=HTMLResponse)
def alerts_list(request: Request, op=Depends(require_role("viewer")), status: str = ""):
    rows = alerts_mod.list_alerts(status or None)
    return page(request, "alerts.html", op, alerts=rows, status=status)


@router.get("/alerts/{alert_id}", response_class=HTMLResponse)
def alert_detail(request: Request, alert_id: int, op=Depends(require_role("analyst"))):
    alert = alerts_mod.get_alert(alert_id)
    logs = alerts_mod.triggering_logs(alert_id)
    return page(request, "alert_detail.html", op, alert=alert, logs=logs)


@router.post("/alerts/{alert_id}/close")
def alert_close(request: Request, alert_id: int, note: str = Form(""),
                op=Depends(require_role("analyst"))):
    alerts_mod.close_alert(alert_id, op["user_id"], note)
    return RedirectResponse(f"/siem/alerts/{alert_id}", status_code=303)


@router.post("/alerts/{alert_id}/block")
def alert_block(request: Request, alert_id: int, op=Depends(require_role("analyst"))):
    alerts_mod.block_ip(alert_id, op["user_id"])
    return RedirectResponse(f"/siem/alerts/{alert_id}", status_code=303)


@router.get("/blocks", response_class=HTMLResponse)
def blocks_list(request: Request, op=Depends(require_role("analyst"))):
    return page(request, "blocks.html", op, blocks=alerts_mod.list_blocks())


@router.post("/blocks/{block_id}/unblock")
def block_unblock(request: Request, block_id: int, op=Depends(require_role("analyst"))):
    alerts_mod.unblock_ip(block_id)
    return RedirectResponse("/siem/blocks", status_code=303)


# ---- rules (admin) ----
@router.get("/rules", response_class=HTMLResponse)
def rules_page(request: Request, op=Depends(require_role("admin"))):
    return page(request, "rules.html", op, rules=rules_mod.list_rules())


@router.post("/rules")
def rules_create(request: Request, op=Depends(require_role("admin")),
                 rule_name: str = Form(...), rule_type: str = Form(...),
                 event_type: str = Form(""), threshold_count: str = Form(""),
                 pattern: str = Form(""), window_seconds: int = Form(60),
                 severity: str = Form("medium")):
    rules_mod.create_rule({
        "rule_name": rule_name, "rule_type": rule_type,
        "event_type": event_type or None,
        "threshold_count": int(threshold_count) if threshold_count else None,
        "pattern": pattern or None, "window_seconds": window_seconds,
        "severity": severity, "enabled": True,
    }, op["user_id"])
    return RedirectResponse("/siem/rules", status_code=303)


@router.post("/rules/{rule_id}/toggle")
def rules_toggle(request: Request, rule_id: int, enabled: str = Form(""),
                 op=Depends(require_role("admin"))):
    rules_mod.set_enabled(rule_id, enabled == "on")
    return RedirectResponse("/siem/rules", status_code=303)


@router.get("/rules/{rule_id}/edit", response_class=HTMLResponse)
def rules_edit_form(request: Request, rule_id: int, op=Depends(require_role("admin"))):
    rule = rules_mod.get_rule(rule_id)
    if not rule:
        return RedirectResponse("/siem/rules", status_code=303)
    return page(request, "rule_edit.html", op, rule=rule)


@router.post("/rules/{rule_id}")
def rules_update(request: Request, rule_id: int, op=Depends(require_role("admin")),
                 rule_name: str = Form(...), rule_type: str = Form(...),
                 event_type: str = Form(""), threshold_count: str = Form(""),
                 pattern: str = Form(""), window_seconds: int = Form(60),
                 severity: str = Form("medium"), enabled: str = Form("on")):
    rules_mod.update_rule(rule_id, {
        "rule_name": rule_name, "rule_type": rule_type,
        "event_type": event_type or None,
        "threshold_count": int(threshold_count) if threshold_count else None,
        "pattern": pattern or None, "window_seconds": window_seconds,
        "severity": severity, "enabled": enabled == "on",
    })
    return RedirectResponse("/siem/rules", status_code=303)


# ---- users (admin) ----
@router.get("/users", response_class=HTMLResponse)
def users_page(request: Request, op=Depends(require_role("admin"))):
    return page(request, "users.html", op, users=users_mod.list_users())


@router.post("/users")
def users_create(request: Request, op=Depends(require_role("admin")),
                 username: str = Form(...), email: str = Form(...),
                 password: str = Form(...), role: str = Form("viewer")):
    try:
        users_mod.create_user(username, email, password, role)
    except Exception:
        pass
    return RedirectResponse("/siem/users", status_code=303)


@router.post("/users/{user_id}/active")
def users_active(request: Request, user_id: int, active: str = Form(""),
                 op=Depends(require_role("admin"))):
    users_mod.set_active(user_id, active == "on")
    return RedirectResponse("/siem/users", status_code=303)


# ---- sources (admin) ----
@router.get("/sources", response_class=HTMLResponse)
def sources_page(request: Request, op=Depends(require_role("admin"))):
    return page(request, "sources.html", op, sources=sources_mod.list_sources(), new_key=None)


@router.post("/sources")
def sources_create(request: Request, op=Depends(require_role("admin")),
                   source_name: str = Form(...), source_type: str = Form("web")):
    key = sources_mod.register_source(source_name, source_type)
    return page(request, "sources.html", op, sources=sources_mod.list_sources(), new_key=key)


# ---- report + settings (admin) ----
@router.get("/report", response_class=HTMLResponse)
def report_page(request: Request, op=Depends(require_role("admin")),
                ts_from: str = "", ts_to: str = ""):
    now = datetime.now(timezone.utc)
    frm = ts_from or (now - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M")
    to = ts_to or now.strftime("%Y-%m-%dT%H:%M")
    report = dash.summary_report(frm, to)
    return page(request, "report.html", op, report=report, ts_from=frm, ts_to=to)


@router.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, op=Depends(require_role("admin"))):
    return page(request, "settings.html", op, retention=dash.get_retention())


@router.post("/settings")
def settings_save(request: Request, retention_months: int = Form(...),
                  op=Depends(require_role("admin"))):
    dash.set_retention(retention_months)
    return RedirectResponse("/siem/settings", status_code=303)
