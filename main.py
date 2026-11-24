"""Auth API: sign up, log in, log out, and routes only a logged-in user can open.

Supabase is the identity provider: it stores users, checks passwords and
issues JWTs. This server never sees a password hash and never signs a token.
"""

import logging
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Header, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, StrictStr, field_validator
from supabase_auth.errors import AuthApiError

import config
from auth import supabase_client

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


# ---------- Schemas ----------

class Credentials(BaseModel):
    email: StrictStr
    password: StrictStr

    model_config = {"json_schema_extra": {"examples": [{"email": "test@example.com", "password": "password123"}]}}

    @field_validator("email", "password")
    @classmethod
    def not_blank(cls, value: str, info) -> str:
        if not value.strip():
            raise ValueError(f"{info.field_name} must not be empty")
        return value.strip() if info.field_name == "email" else value


class ErrorMessage(BaseModel):
    error: str


BAD_REQUEST = {400: {"model": ErrorMessage, "description": "Missing or invalid email/password"}}


# ---------- Errors ----------

def error(status: int, message: str) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": message})


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    first = exc.errors()[0]
    field = ".".join(str(part) for part in first["loc"] if part != "body")
    message = first["msg"].removeprefix("Value error, ")
    return error(400, f"{field}: {message}" if field else message)


# ---------- Open routes ----------

@app.post("/auth/signup", status_code=201, responses=BAD_REQUEST, tags=["auth"], summary="Create an account")
def signup(body: Credentials):
    try:
        result = supabase_client().auth.sign_up({"email": body.email, "password": body.password})
    except AuthApiError as exc:  # e.g. weak password, invalid email, rate limit
        return error(400, exc.message)
    user = result.user
    return {
        "user": {"id": user.id, "email": user.email, "created_at": user.created_at.isoformat()},
        # Without a session, the project requires email confirmation before login.
        "email_confirmation_required": result.session is None,
    }


@app.post(
    "/auth/login",
    responses={**BAD_REQUEST, 401: {"model": ErrorMessage, "description": "Wrong email or password"}},
    tags=["auth"],
    summary="Log in and receive a JWT",
)
def login(body: Credentials):
    try:
        result = supabase_client().auth.sign_in_with_password({"email": body.email, "password": body.password})
    except AuthApiError:
        # Same message whether the email exists or not: don't help attackers enumerate accounts.
        return error(401, "Invalid login credentials")
    session = result.session
    return {
        "access_token": session.access_token,
        "refresh_token": session.refresh_token,
        "token_type": "bearer",
        "expires_in": session.expires_in,
        "user": {"id": result.user.id, "email": result.user.email},
    }


@app.get("/public/info", tags=["public"], summary="Anyone can read this")
def public_info():
    return {"message": "Welcome stranger! This info is public."}


@app.get("/protected/profile", tags=["protected"], summary="Your account details")
def profile(authorization: str | None = Header(None)):
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return error(401, "Access token required")
    return {"message": "Token received (not verified yet)"}
