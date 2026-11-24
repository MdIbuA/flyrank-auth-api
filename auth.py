"""Supabase client factory and the reusable "is this request logged in?" guard."""

from fastapi import Depends, Header
from supabase import Client, ClientOptions, create_client
from supabase_auth.errors import AuthError

import config


class AuthFailure(Exception):
    """Raised by the guard; main.py turns it into a 401 JSON response."""

    def __init__(self, message: str):
        self.message = message


def supabase_client() -> Client:
    """A fresh client per call.

    The Python SDK keeps the last signed-in session inside the client object.
    One shared client would mix up sessions when two users log in at once,
    so every request gets its own, with session storage and auto-refresh off.
    """
    return create_client(
        config.SUPABASE_URL,
        config.SUPABASE_KEY,
        options=ClientOptions(auto_refresh_token=False, persist_session=False),
    )


def bearer_token(authorization: str | None = Header(None)) -> str:
    """Pull the token out of `Authorization: Bearer <token>` or fail with 401."""
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise AuthFailure("Access token required")
    return token.strip()


def require_user(token: str = Depends(bearer_token)) -> dict:
    """Ask Supabase whether the token is real, unexpired and belongs to a live session."""
    try:
        response = supabase_client().auth.get_user(token)
    except AuthError:
        response = None
    if response is None or response.user is None:
        raise AuthFailure("Invalid or expired token")
    user = response.user
    return {
        "id": user.id,
        "email": user.email,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "last_sign_in_at": user.last_sign_in_at.isoformat() if user.last_sign_in_at else None,
        "token": token,
    }
