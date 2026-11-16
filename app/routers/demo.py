"""AuraMarket storefront routes and SIEM event bridge.

The marketplace keeps its own catalog, users, cart and order state, while every
visitor action is emitted to the existing SIEM ingestion buffer. The demo also
checks the SIEM blocklist before serving any route, as required by the project
requirements and end-to-end attack demonstration.
"""
import ipaddress
from decimal import Decimal

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from app.alerts import is_blocked
from app.auth import hash_password, verify_password
from app.db import execute, query_one
from app.ingest import emit_demo_event

router = APIRouter(prefix="/demo", tags=["demo"])
templates = Jinja2Templates(directory="app/templates")

PRODUCTS = [
    {"slug": "acousticpro-anc", "name": "AcousticPro ANC Wireless Headphones", "category": "Audio / Wireless", "description": "Adaptive noise cancellation, spatial audio, and 65-hour battery life.", "price": Decimal("299.99"), "compare_at": Decimal("349.99"), "rating": "4.9", "reviews": 1248, "image": "/static/products/headphones.png", "badge": "Best seller", "features": ["Adaptive active noise cancellation", "Bluetooth 5.3 with LDAC", "65-hour extended battery"]},
    {"slug": "hyperkey-pro", "name": "HyperKey Pro Mechanical Keyboard", "category": "Keyboards / Peripherals", "description": "Hot-swappable switches, low-latency wireless, and per-key lighting.", "price": Decimal("149.00"), "compare_at": None, "rating": "4.7", "reviews": 420, "image": "/static/products/keyboard.png", "badge": "Popular", "features": ["Hot-swappable mechanical switches", "Tri-mode wireless connectivity", "Aluminum top plate"]},
    {"slug": "aura-view-27", "name": "AuraView 27-inch 4K HDR Monitor", "category": "Displays / Workstation", "description": "Crisp 4K detail, HDR color, and a clean edge-to-edge workstation view.", "price": Decimal("479.00"), "compare_at": Decimal("529.00"), "rating": "4.9", "reviews": 2105, "image": "/static/products/monitor.png", "badge": "New", "features": ["27-inch 4K HDR IPS panel", "USB-C power delivery", "Height-adjustable stand"]},
    {"slug": "connect-7", "name": "Connect 7-in-1 USB-C Hub", "category": "Accessories", "description": "One compact aluminum hub for HDMI, ethernet, storage, and more.", "price": Decimal("39.50"), "compare_at": None, "rating": "4.8", "reviews": 834, "image": "/static/products/hub.png", "badge": "Great value", "features": ["4K HDMI output", "100W pass-through charging", "Gigabit ethernet"]},
]
PRODUCT_BY_SLUG = {p["slug"]: p for p in PRODUCTS}


def client_ip(request: Request) -> str:
    """Resolve the simulator's X-Forwarded-For IP, falling back safely."""
    forwarded = request.headers.get("x-forwarded-for")
    candidate = forwarded.split(",")[0].strip() if forwarded else (request.client.host if request.client else "127.0.0.1")
    try:
        ipaddress.ip_address(candidate)
        return candidate
    except ValueError:
        return "127.0.0.1"


def _guard(request: Request) -> Response | None:
    """Return the SIEM-style 403 page for an actively blocked source IP."""
    ip = client_ip(request)
    if is_blocked(ip):
        emit_demo_event(
            event_type="request_blocked", src_ip=ip, status=403,
            user_agent=request.headers.get("user-agent"), payload=str(request.url.path),
        )
        return templates.TemplateResponse(
            request, "demo_forbidden.html", {"blocked_ip": ip}, status_code=403,
        )
    return None


def _log(request: Request, event_type: str, *, status: int = 200,
         actor_username: str | None = None, payload: str | None = None) -> None:
    """Emit one normalized demo event into the SIEM's existing batch buffer."""
    emit_demo_event(
        event_type=event_type,
        src_ip=client_ip(request),
        status=status,
        actor_username=actor_username or request.session.get("demo_user"),
        user_agent=request.headers.get("user-agent"),
        payload=payload,
    )


def _extra_product(slug, name, category, description, price, image, badge, index):
    return {
        "slug": slug, "name": name, "category": category, "description": description,
        "price": Decimal(price), "compare_at": None, "rating": f"{4.6 + (index % 4) / 10:.1f}",
        "reviews": 120 + index * 73, "image": image, "badge": badge,
        "features": ["Designed for everyday setups", "Fast, reliable connectivity", "Two-year AuraMarket warranty"],
    }


_more = [
    ("studio-master-7", "Studio Master Series 7 Headphones", "Audio / Wireless", "Planar magnetic detail with a wide, natural soundstage.", "349.00", "/static/products/headphones.png", "New"),
    ("aurapods-elite", "AuraPods Elite Earbuds", "Audio / Wireless", "Pocket-sized ANC earbuds with a comfortable all-day fit.", "159.00", "/static/products/headphones.png", "Staff pick"),
    ("sonicpulse-go", "SonicPulse Go Speaker", "Audio / Wireless", "Room-filling sound in a splash-proof portable body.", "129.00", "/static/products/headphones.png", "Popular"),
    ("wavebeam-mini", "WaveBeam Mini Soundbar", "Audio / Wireless", "A compact desktop soundbar for films, music, and calls.", "89.00", "/static/products/headphones.png", "Great value"),
    ("quietline-pro", "QuietLine Conference Headset", "Audio / Wireless", "Clear voice pickup and comfortable noise isolation for workdays.", "119.00", "/static/products/headphones.png", "Work from home"),
    ("bassline-max", "Bassline Max Over-Ear Headphones", "Audio / Wireless", "Deep bass, balanced mids, and a soft memory-foam fit.", "199.00", "/static/products/headphones.png", "Popular"),
    ("airloop-sport", "AirLoop Sport Earbuds", "Audio / Wireless", "Secure wireless audio with sweat-resistant sport ear hooks.", "109.00", "/static/products/headphones.png", "Active"),
    ("hush-cans", "Hush Cans Travel Headphones", "Audio / Wireless", "Fold-flat travel headphones with adaptive cabin noise control.", "179.00", "/static/products/headphones.png", "Travel ready"),
    ("roomtone-home", "RoomTone Home Audio Bar", "Audio / Wireless", "Balanced room audio with a warm profile for everyday listening.", "139.00", "/static/products/headphones.png", "Home audio"),
    ("deskkey-65", "DeskKey 65 Mechanical Keyboard", "Keyboards / Peripherals", "A compact 65% layout with tactile switches and a soft wrist rest.", "129.00", "/static/products/keyboard.png", "Popular"),
    ("typeflow-wireless", "TypeFlow Wireless Keyboard", "Keyboards / Peripherals", "Quiet low-profile keys with multi-device pairing.", "99.00", "/static/products/keyboard.png", "New"),
    ("macrodeck-mini", "MacroDeck Mini Controller", "Keyboards / Peripherals", "Nine programmable keys for creative shortcuts and workflows.", "79.00", "/static/products/keyboard.png", "Creator pick"),
    ("glowpad-xl", "GlowPad XL Desk Mat", "Keyboards / Peripherals", "A water-resistant desk mat with a smooth tracking surface.", "35.00", "/static/products/keyboard.png", "Great value"),
    ("clicker-pro", "Clicker Pro Wireless Mouse", "Keyboards / Peripherals", "Silent clicks, precise tracking, and a comfortable right-handed shape.", "69.00", "/static/products/keyboard.png", "Bestseller"),
    ("trackball-one", "Trackball One Ergonomic Mouse", "Keyboards / Peripherals", "Thumb-controlled precision for long, comfortable work sessions.", "89.00", "/static/products/keyboard.png", "Ergonomic"),
    ("keycap-studio", "Keycap Studio Accent Set", "Keyboards / Peripherals", "A 104-key artisan accent set to personalize your keyboard.", "29.00", "/static/products/keyboard.png", "Fresh drop"),
    ("deskpad-wireless", "DeskPad Wireless Charging Mat", "Keyboards / Peripherals", "A clean work surface with a hidden Qi charging zone.", "59.00", "/static/products/keyboard.png", "Smart desk"),
    ("numkey-wireless", "NumKey Wireless Numpad", "Keyboards / Peripherals", "A compact programmable number pad for finance and creative work.", "49.00", "/static/products/keyboard.png", "Add-on"),
    ("aura-view-24", "AuraView 24-inch Work Monitor", "Displays / Workstation", "A bright Full HD panel for focused work and everyday browsing.", "229.00", "/static/products/monitor.png", "Great value"),
    ("aura-view-ultra", "AuraView UltraWide 34 Monitor", "Displays / Workstation", "Ultra-wide space for timelines, dashboards, and side-by-side work.", "699.00", "/static/products/monitor.png", "Studio grade"),
    ("pixelstand-4k", "PixelStand 4K Monitor", "Displays / Workstation", "Sharp color-accurate detail on a minimal adjustable stand.", "399.00", "/static/products/monitor.png", "Popular"),
    ("travel-screen", "TravelScreen 15 Portable Display", "Displays / Workstation", "A lightweight second screen for flexible work anywhere.", "249.00", "/static/products/monitor.png", "Travel ready"),
    ("colorcraft-27", "ColorCraft 27 Creator Display", "Displays / Workstation", "Wide-gamut color and USB-C connectivity for creative work.", "549.00", "/static/products/monitor.png", "Creator pick"),
    ("focusview-22", "FocusView 22 Compact Monitor", "Displays / Workstation", "A compact, crisp monitor for smaller desks and dorm rooms.", "179.00", "/static/products/monitor.png", "Compact"),
    ("standhub", "StandHub Monitor Dock", "Displays / Workstation", "Raise your screen and connect your whole desk through one dock.", "119.00", "/static/products/monitor.png", "Smart desk"),
    ("readmode-27", "ReadMode 27 Eye Comfort Display", "Displays / Workstation", "Flicker-free viewing with warm reading modes for late nights.", "319.00", "/static/products/monitor.png", "Wellness"),
    ("aura-view-vertical", "AuraView Vertical 24 Monitor", "Displays / Workstation", "A portrait-friendly display built for documents, code, and feeds.", "279.00", "/static/products/monitor.png", "Flexible"),
    ("connect-pro", "Connect Pro Thunderbolt Dock", "Accessories", "One-cable power, displays, storage, and network for your desk.", "189.00", "/static/products/hub.png", "Pro setup"),
    ("chargecube-65", "ChargeCube 65W GaN Charger", "Accessories", "Small, powerful USB-C charging for laptops, tablets, and phones.", "49.00", "/static/products/hub.png", "Great value"),
    ("cablekit", "CableKit Desk Organizer", "Accessories", "A tidy modular kit for routing and labeling every desk cable.", "24.00", "/static/products/hub.png", "Bestseller"),
    ("traveldock", "TravelDock Compact Hub", "Accessories", "A pocket-friendly hub with HDMI, USB-A, and SD card access.", "45.00", "/static/products/hub.png", "Travel ready"),
    ("powerstrip-mini", "PowerStrip Mini with USB-C", "Accessories", "A compact surge-protected power strip with two USB-C ports.", "39.00", "/static/products/hub.png", "Smart desk"),
    ("webcam-1080", "ClearView 1080p Webcam", "Accessories", "Autofocus video with a privacy shutter for calls and streaming.", "45.00", "/static/products/hub.png", "Work from home"),
    ("lightbar-pro", "LightBar Pro Monitor Light", "Accessories", "Glare-free adjustable light for comfortable desk sessions.", "59.00", "/static/products/hub.png", "New"),
    ("standfold", "StandFold Laptop Stand", "Accessories", "An adjustable aluminum stand that lifts your screen to eye level.", "69.00", "/static/products/hub.png", "Ergonomic"),
    ("privacycam", "PrivacyCam Slide Cover Pack", "Accessories", "A simple set of camera covers for laptops and external webcams.", "12.00", "/static/products/hub.png", "Essential"),
]
PRODUCTS.extend(_extra_product(*row, index=i) for i, row in enumerate(_more, start=1))
PRODUCT_BY_SLUG = {p["slug"]: p for p in PRODUCTS}

# Keep all catalogue photography local so the demo satisfies the offline-run
# requirement. These four curated product shots are reused by the catalogue's
# product families and are served by FastAPI's static files mount.
LOCAL_IMAGES = {
    "Audio / Wireless": "/static/products/headphones.png",
    "Keyboards / Peripherals": "/static/products/keyboard.png",
    "Displays / Workstation": "/static/products/monitor.png",
    "Accessories": "/static/products/hub.png",
}
for _product in PRODUCTS:
    _product["image"] = LOCAL_IMAGES[_product["category"]]


def cart(request: Request) -> dict[str, int]:
    return request.session.setdefault("demo_cart", {})


def cart_lines(request: Request):
    lines, total, count = [], Decimal("0"), 0
    for slug, quantity in cart(request).items():
        product = PRODUCT_BY_SLUG.get(slug)
        if not product:
            continue
        quantity = max(1, int(quantity))
        subtotal = product["price"] * quantity
        lines.append({"product": product, "quantity": quantity, "subtotal": subtotal})
        total += subtotal
        count += quantity
    return lines, total, count


def context(request: Request, **extra):
    lines, total, count = cart_lines(request)
    return {"user": request.session.get("demo_user"), "cart_count": count, "cart_total": total, **extra}


@router.get("/", response_class=HTMLResponse)
def home(request: Request, q: str = "", sort: str = "featured"):
    blocked = _guard(request)
    if blocked:
        return blocked
    term = q.strip().lower()
    items = [p for p in PRODUCTS if not term or term in (p["name"] + " " + p["description"] + " " + p["category"]).lower()]
    if sort == "price_low":
        items = sorted(items, key=lambda p: p["price"])
    elif sort == "price_high":
        items = sorted(items, key=lambda p: p["price"], reverse=True)
    elif sort == "rating":
        items = sorted(items, key=lambda p: p["rating"], reverse=True)
    _log(request, "search" if q else "page_view", payload=q or "/")
    template = "demo_search.html" if q else "demo_home.html"
    return templates.TemplateResponse(request, template, context(request, items=items, q=q, sort=sort))


@router.get("/product/{slug}", response_class=HTMLResponse)
def product_detail(request: Request, slug: str):
    blocked = _guard(request)
    if blocked:
        return blocked
    product = PRODUCT_BY_SLUG.get(slug)
    if not product:
        _log(request, "product_not_found", status=404, payload=slug)
        return RedirectResponse("/demo/", status_code=303)
    _log(request, "product_view", payload=slug)
    related = [p for p in PRODUCTS if p["slug"] != slug][:3]
    return templates.TemplateResponse(request, "demo_product.html", context(request, product=product, related=related))


@router.post("/cart/add")
def add_to_cart(request: Request, slug: str = Form(...), quantity: int = Form(1)):
    blocked = _guard(request)
    if blocked:
        return blocked
    if slug in PRODUCT_BY_SLUG:
        items = cart(request)
        items[slug] = max(0, int(items.get(slug, 0))) + max(1, min(quantity, 10))
        request.session["demo_cart"] = items
        _log(request, "cart_add", status=303, payload=f"slug={slug};quantity={quantity}")
    else:
        _log(request, "cart_add_invalid", status=400, payload=f"slug={slug}")
    return RedirectResponse(request.headers.get("referer") or "/demo/", status_code=303)


@router.get("/cart", response_class=HTMLResponse)
def cart_page(request: Request):
    blocked = _guard(request)
    if blocked:
        return blocked
    lines, total, _ = cart_lines(request)
    _log(request, "cart_view", payload=f"items={len(lines)}")
    return templates.TemplateResponse(request, "demo_cart.html", context(request, lines=lines, total=total))


@router.post("/cart/update")
def update_cart(request: Request, slug: str = Form(...), quantity: int = Form(...)):
    blocked = _guard(request)
    if blocked:
        return blocked
    items = cart(request)
    if slug in PRODUCT_BY_SLUG:
        if quantity <= 0:
            items.pop(slug, None)
        else:
            items[slug] = min(quantity, 10)
    request.session["demo_cart"] = items
    _log(request, "cart_update", status=303, payload=f"slug={slug};quantity={quantity}")
    return RedirectResponse("/demo/cart", status_code=303)


@router.post("/cart/remove")
def remove_from_cart(request: Request, slug: str = Form(...)):
    blocked = _guard(request)
    if blocked:
        return blocked
    items = cart(request)
    items.pop(slug, None)
    request.session["demo_cart"] = items
    _log(request, "cart_remove", status=303, payload=f"slug={slug}")
    return RedirectResponse("/demo/cart", status_code=303)


@router.get("/wishlist", response_class=HTMLResponse)
def wishlist_page(request: Request):
    blocked = _guard(request)
    if blocked:
        return blocked
    saved = [PRODUCT_BY_SLUG[s] for s in request.session.get("demo_wishlist", []) if s in PRODUCT_BY_SLUG]
    _log(request, "wishlist_view", payload=f"items={len(saved)}")
    return templates.TemplateResponse(request, "demo_wishlist.html", context(request, items=saved))


@router.post("/wishlist/toggle")
def toggle_wishlist(request: Request, slug: str = Form(...)):
    blocked = _guard(request)
    if blocked:
        return blocked
    saved = list(request.session.get("demo_wishlist", []))
    event_type = "wishlist_add"
    if slug in PRODUCT_BY_SLUG:
        if slug in saved:
            saved.remove(slug)
            event_type = "wishlist_remove"
        else:
            saved.append(slug)
    request.session["demo_wishlist"] = saved
    _log(request, event_type, status=303, payload=f"slug={slug}")
    return RedirectResponse(request.headers.get("referer") or "/demo/wishlist", status_code=303)


@router.get("/checkout", response_class=HTMLResponse)
def checkout_page(request: Request):
    blocked = _guard(request)
    if blocked:
        return blocked
    lines, total, count = cart_lines(request)
    if not count:
        _log(request, "checkout_empty", status=303, payload="/demo/checkout")
        return RedirectResponse("/demo/cart", status_code=303)
    _log(request, "checkout_view", payload=f"items={count}")
    return templates.TemplateResponse(request, "demo_checkout.html", context(request, lines=lines, total=total))


@router.post("/checkout")
def checkout(request: Request, full_name: str = Form(...), email: str = Form(...), address: str = Form(...), city: str = Form(...), postal_code: str = Form(...), card_number: str = Form(...)):
    blocked = _guard(request)
    if blocked:
        return blocked
    lines, total, count = cart_lines(request)
    if not count:
        _log(request, "checkout_empty", status=303, payload="/demo/checkout")
        return RedirectResponse("/demo/cart", status_code=303)
    request.session["demo_cart"] = {}
    request.session["demo_order"] = {"number": "AM-" + str(abs(hash((email, full_name))) % 1000000).zfill(6), "total": str(total), "count": count}
    _log(request, "checkout_completed", status=303, actor_username=email, payload=f"order_total={total};items={count}")
    return RedirectResponse("/demo/order-confirmation", status_code=303)


@router.get("/order-confirmation", response_class=HTMLResponse)
def order_confirmation(request: Request):
    blocked = _guard(request)
    if blocked:
        return blocked
    order = request.session.get("demo_order")
    if not order:
        _log(request, "order_not_found", status=303, payload="/demo/order-confirmation")
        return RedirectResponse("/demo/", status_code=303)
    _log(request, "order_confirmation_view", payload=order["number"])
    return templates.TemplateResponse(request, "demo_order.html", context(request, order=order))


@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request, provider: str = "", reset: str = ""):
    blocked = _guard(request)
    if blocked:
        return blocked
    if provider in {"google", "apple"}:
        request.session["demo_user"] = f"{provider}-demo@auramarket.io"
        _log(request, "login_success", status=303, actor_username=request.session["demo_user"], payload=f"provider={provider}")
        return RedirectResponse("/demo/", status_code=303)
    _log(request, "login_view", payload="/demo/login")
    return templates.TemplateResponse(request, "demo_login.html", {"mode": "login", "reset_notice": bool(reset)})


@router.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    blocked = _guard(request)
    if blocked:
        return blocked
    user = query_one("SELECT * FROM demo.demo_users WHERE username = %s", (username,))
    if user and verify_password(password, user["password_hash"]):
        request.session["demo_user"] = username
        _log(request, "login_success", status=303, actor_username=username, payload=f"user={username}")
        return RedirectResponse("/demo/", status_code=303)
    _log(request, "login_failed", status=401, actor_username=username, payload=f"user={username}")
    return templates.TemplateResponse(request, "demo_login.html", {"mode": "login", "error": "Invalid credentials"}, status_code=401)


@router.get("/register", response_class=HTMLResponse)
def register_form(request: Request):
    blocked = _guard(request)
    if blocked:
        return blocked
    _log(request, "register_view", payload="/demo/register")
    return templates.TemplateResponse(request, "demo_login.html", {"mode": "register"})


@router.get("/forgot-password", response_class=HTMLResponse)
def forgot_password_form(request: Request):
    blocked = _guard(request)
    if blocked:
        return blocked
    _log(request, "forgot_password_view", payload="/demo/forgot-password")
    return templates.TemplateResponse(request, "demo_forgot.html", {})


@router.post("/forgot-password", response_class=HTMLResponse)
def forgot_password(request: Request, email: str = Form(...)):
    blocked = _guard(request)
    if blocked:
        return blocked
    _log(request, "forgot_password_request", status=200, actor_username=email, payload=f"email={email}")
    return templates.TemplateResponse(request, "demo_forgot.html", {"sent": True, "email": email})


@router.get("/info/{topic}", response_class=HTMLResponse)
def info_page(request: Request, topic: str):
    blocked = _guard(request)
    if blocked:
        return blocked
    pages = {
        "help": ("Help center", "Find answers about delivery, returns, account access, and demo orders."),
        "shipping": ("Shipping & delivery", "Orders over $50 receive free standard delivery. Demo orders are confirmed instantly."),
        "returns": ("Returns", "Demo purchases include a simple 30-day return promise for this prototype marketplace."),
        "contact": ("Contact AuraMarket", "Email hello@auramarket.io and our demo support team will get back to you."),
        "privacy": ("Privacy policy", "This local demo stores only the session details needed to demonstrate the storefront."),
        "terms": ("Terms of service", "AuraMarket is a demonstration marketplace. Checkout does not charge a real card."),
        "security": ("Security & compliance", "Demo checkout accepts test card data only and never processes a real payment."),
    }
    title, body = pages.get(topic, ("AuraMarket information", "Thanks for exploring the AuraMarket demo."))
    _log(request, "info_view", payload=topic)
    return templates.TemplateResponse(request, "demo_info.html", context(request, title=title, body=body))


@router.post("/register")
def register(request: Request, username: str = Form(...), password: str = Form(...)):
    blocked = _guard(request)
    if blocked:
        return blocked
    try:
        execute("INSERT INTO demo.demo_users (username, password_hash) VALUES (%s, %s)", (username, hash_password(password)))
    except Exception:
        _log(request, "register_failed", status=400, actor_username=username, payload=f"user={username}")
        return templates.TemplateResponse(request, "demo_login.html", {"mode": "register", "error": "That email is already registered"}, status_code=400)
    request.session["demo_user"] = username
    _log(request, "register", status=303, actor_username=username, payload=f"user={username}")
    return RedirectResponse("/demo/", status_code=303)


@router.get("/logout")
def logout(request: Request):
    blocked = _guard(request)
    if blocked:
        return blocked
    _log(request, "logout", status=303)
    request.session.pop("demo_user", None)
    return RedirectResponse("/demo/", status_code=303)
