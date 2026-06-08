"""Vulnerable demo target — one FastAPI app exposing all the vulnerable
endpoints referenced by the seed threat model. Designed to be safely
exploitable by the CAI AI pentest agent inside the sandbox network."""
from __future__ import annotations
import base64
import hashlib
import hmac
import json
import time
import urllib.request
from typing import Any
from fastapi import FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse, HTMLResponse
from pydantic import BaseModel

app = FastAPI(title="payments-platform (vulnerable demo)", version="0.0.1")

# ── shared toy "secrets" ─────────────────────────────────────
JWT_SECRET = "demo-jwt-secret-do-not-use"

# ── fake data ────────────────────────────────────────────────
USERS: dict[str, dict[str, Any]] = {
    "alice@acme.test": {"id": "u-001", "password": "alicepw", "mfa": False,
                        "role": "user", "pan": "4111-1111-1111-1111"},
    "bob@acme.test":   {"id": "u-002", "password": "bobpw",   "mfa": True,
                        "role": "user", "pan": "4222-2222-2222-2222"},
    "admin@acme.test": {"id": "u-999", "password": "admin123", "mfa": True,
                        "role": "admin", "pan": "5555-5555-5555-4444"},
}

TRANSACTIONS = {
    "tx-001": {"user_id": "u-001", "amount": 12.99, "pan_last4": "1111"},
    "tx-002": {"user_id": "u-002", "amount": 99.00, "pan_last4": "2222"},
    "tx-999": {"user_id": "u-999", "amount": 1.00,  "pan_last4": "4444"},
}

ACTIVE_SESSIONS: dict[str, str] = {}  # session_id -> user email


# ── helpers ──────────────────────────────────────────────────
def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def _b64ud(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

def issue_jwt(email: str, aud: str = "demo-aud") -> str:
    header = _b64u(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64u(json.dumps({"sub": email, "aud": aud,
                                "iat": int(time.time())}).encode())
    sig = _b64u(hmac.new(JWT_SECRET.encode(),
                         f"{header}.{payload}".encode(),
                         hashlib.sha256).digest())
    return f"{header}.{payload}.{sig}"


# ── auth-service ─────────────────────────────────────────────
class LoginBody(BaseModel):
    email: str
    password: str

@app.post("/v1/login")
def login(body: LoginBody):
    """Issues JWT but does NOT validate audience on consumption (thr-001)."""
    u = USERS.get(body.email)
    if not u or u["password"] != body.password:
        raise HTTPException(401, "invalid credentials")
    return {"token": issue_jwt(body.email), "mfa_required": u["mfa"]}

@app.post("/v1/password/reset")
def password_reset(email: str = Query(...)):
    """
    THR-002: After a password reset, MFA flag is reset to False so the user
    can 'recover' access. An attacker who can trigger reset can bypass MFA.
    """
    u = USERS.get(email)
    if not u:
        raise HTTPException(404, "no such user")
    u["mfa"] = False
    return {"reset": True, "mfa_required": False}

@app.get("/v1/whoami")
def whoami(authorization: str = Header(...)):
    """THR-001: parses the JWT but skips audience validation entirely."""
    token = authorization.replace("Bearer ", "")
    parts = token.split(".")
    if len(parts) != 3:
        raise HTTPException(401, "malformed token")
    try:
        payload = json.loads(_b64ud(parts[1]))
    except Exception:
        raise HTTPException(401, "bad payload")
    # vulnerable: never checks aud, never checks signature in this code path
    return {"sub": payload.get("sub"), "aud": payload.get("aud")}


# ── payments-api ─────────────────────────────────────────────
@app.get("/v1/transactions/{tx_id}")
def get_transaction(tx_id: str):
    """THR-004: error path returns the full PAN in the error body."""
    tx = TRANSACTIONS.get(tx_id)
    if not tx:
        # NB: dev "helpful" error includes real PAN values from the table.
        leaked = [{"id": k, "pan": USERS_BY_ID(v["user_id"])["pan"]}
                  for k, v in TRANSACTIONS.items()]
        return JSONResponse(
            status_code=404,
            content={"error": f"transaction {tx_id} not found",
                     "debug_known_transactions": leaked},
        )
    return tx


def USERS_BY_ID(uid: str) -> dict:
    for u in USERS.values():
        if u["id"] == uid:
            return u
    return {}


# ── webhook-dispatcher ───────────────────────────────────────
class WebhookBody(BaseModel):
    url: str
    event: str = "ping"

@app.post("/v1/webhooks/inbound")
def webhook_inbound(body: WebhookBody):
    """THR-006: fetches arbitrary URL with no allow-list (SSRF)."""
    try:
        with urllib.request.urlopen(body.url, timeout=3) as r:  # noqa: S310
            data = r.read(2048).decode("utf-8", errors="replace")
        return {"event": body.event, "fetched_preview": data[:500]}
    except Exception as e:
        return {"event": body.event, "error": str(e)}


# ── admin-portal ─────────────────────────────────────────────
@app.get("/admin/users")
def admin_users(user_id: str | None = Query(None)):
    """
    THR-007: IDOR — `user_id` is honored from query string with no authz check
    so any caller can fetch any user's record by id.
    """
    if user_id:
        u = USERS_BY_ID(user_id)
        if not u:
            raise HTTPException(404, "no such user")
        return {"id": user_id, "pan": u["pan"], "role": u["role"]}
    return [{"id": u["id"], "role": u["role"]} for u in USERS.values()]


@app.get("/admin/login", response_class=HTMLResponse)
def admin_login_form(sid: str | None = Query(None), response: Response = None):
    """THR-008: session fixation — accepts caller-supplied session id."""
    if sid:
        ACTIVE_SESSIONS.setdefault(sid, "")
    set_cookie = f"<!-- session id pre-bound to: {sid or 'auto'} -->"
    return f"""<html><body><h3>Admin login</h3>{set_cookie}
<form method='post' action='/admin/login'>
<input name='email'/><input name='password' type='password'/>
<button>Login</button></form></body></html>"""


@app.post("/admin/login")
def admin_login_submit(request: Request, sid: str | None = Query(None)):
    return {"ok": True, "session_id": sid or "newly-generated"}


# ── ops ─────────────────────────────────────────────────────
@app.get("/")
def index():
    return {
        "service": "payments-platform (vulnerable demo)",
        "endpoints": [r.path for r in app.routes],
        "warning": "Intentionally vulnerable. Sandbox network only.",
    }
