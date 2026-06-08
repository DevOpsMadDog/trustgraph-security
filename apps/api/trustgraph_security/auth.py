"""JWT auth with bcrypt-hashed users (admin seeded from .env)."""
from __future__ import annotations
from datetime import datetime, timedelta, timezone
from typing import Annotated
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from passlib.context import CryptContext
from pydantic import BaseModel

from .settings import get_settings

pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2 = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


class User(BaseModel):
    email: str
    roles: list[str] = ["admin"]


_USERS: dict[str, dict] = {}


def _bootstrap() -> None:
    s = get_settings()
    if s.admin_email not in _USERS:
        _USERS[s.admin_email] = {
            "email": s.admin_email,
            "password_hash": pwd.hash(s.admin_password),
            "roles": ["admin", "architect", "appsec", "soc", "exec"],
        }


_bootstrap()


def authenticate(email: str, password: str) -> User | None:
    rec = _USERS.get(email)
    if not rec or not pwd.verify(password, rec["password_hash"]):
        return None
    return User(email=email, roles=rec["roles"])


def issue_token(user: User) -> str:
    s = get_settings()
    payload = {
        "sub": user.email,
        "roles": user.roles,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=s.jwt_expires_min),
    }
    return jwt.encode(payload, s.jwt_secret, algorithm=s.jwt_algorithm)


def current_user(token: Annotated[str, Depends(oauth2)]) -> User:
    s = get_settings()
    try:
        payload = jwt.decode(token, s.jwt_secret, algorithms=[s.jwt_algorithm])
    except JWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid token")
    return User(email=payload["sub"], roles=payload.get("roles", []))


def require_role(*roles: str):
    def _dep(user: Annotated[User, Depends(current_user)]) -> User:
        if not any(r in user.roles for r in roles):
            raise HTTPException(403, f"requires one of {roles}")
        return user
    return _dep
