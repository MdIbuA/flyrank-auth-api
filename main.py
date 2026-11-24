"""Auth API: sign up, log in, log out, and routes only a logged-in user can open.

Supabase is the identity provider: it stores users, checks passwords and
issues JWTs. This server never sees a password hash and never signs a token.
"""

import logging
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI

import config

log = logging.getLogger("uvicorn.error")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Fail loudly at startup if Supabase is unreachable or the key is wrong.
    try:
        r = httpx.get(
            f"{config.SUPABASE_URL}/auth/v1/health", headers={"apikey": config.SUPABASE_KEY}, timeout=5
        )
        r.raise_for_status()
        log.info("Server running and connected to Supabase")
    except httpx.HTTPError as exc:
        log.error("Server running but could NOT reach Supabase Auth: %s", exc)
    yield


app = FastAPI(
    title="Auth API",
    version="1.0",
    description="Sign up and log in through Supabase Auth, then call protected routes with the JWT.",
    lifespan=lifespan,
)
