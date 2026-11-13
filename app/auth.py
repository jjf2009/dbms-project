"""Operator authentication and role-based access control (FR1-FR3, NFR6).

Passwords are bcrypt. The seed hashes them with pgcrypto; passlib verifies the
same $2 hashes here. Sessions are signed cookies (SessionMiddleware).

Role hierarchy: admin >= analyst >= viewer. require_role(min_role) lets any
operator at or above that rank through, so Admin can do everything an Analyst can.
"""
import hashlib

import bcrypt
from fastapi import HTTPException, Request

from app.db import query_one

RANK = {"viewer": 1, "analyst": 2, "admin": 3}


def hash_password(plain: str) -> str:
    # bcrypt ignores bytes past 72; passwords here are short.
    return bcrypt.hashpw(plain.encode()[:72], bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    # Verifies bcrypt hashes produced either here or by pgcrypto's crypt('..','bf').
    try:
        return bcrypt.checkpw(plain.encode()[:72], hashed.encode())
    except Exception:
        return False


def hash_api_key(key: str) -> str:
    """API keys are high-entropy; a fast sha256 hex digest matches the seed."""
    return hashlib.sha256(key.encode()).hexdigest()


def authenticate(username: str, password: str) -> dict | None:
    user = query_one(
        "SELECT user_id, username, role, password_hash, is_active "
        "FROM users WHERE username = %s",
        (username,),
    )
    if not user or not user["is_active"]:
        return None
    if not verify_password(password, user["password_hash"]):
        return None
    return user


def current_operator(request: Request) -> dict | None:
    return request.session.get("operator")


def require_role(min_role: str):
    """Dependency factory. Redirects to login if signed out, 403 if under-ranked."""
    need = RANK[min_role]

    def dependency(request: Request) -> dict:
        op = request.session.get("operator")
        if not op:
            raise HTTPException(status_code=303, headers={"Location": "/siem/login"})
        if RANK.get(op["role"], 0) < need:
            raise HTTPException(status_code=403, detail="Insufficient role")
        return op

    return dependency
