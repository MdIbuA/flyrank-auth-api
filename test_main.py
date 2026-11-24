"""Tests run against a fake Supabase, so they need no network and no account.

The fake mimics the SDK calls this app makes: sign_up, sign_in_with_password,
get_user and admin.sign_out. Run: pytest -q
"""

import os
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

os.environ.setdefault("SUPABASE_URL", "https://example.supabase.co")
os.environ.setdefault("SUPABASE_KEY", "test-anon-key")

import pytest
from fastapi.testclient import TestClient
from supabase_auth.errors import AuthApiError

import auth
import main


class FakeSupabase:
    """In-memory stand-in for Supabase Auth, shared by every client() call."""

    def __init__(self):
        self.users = {}     # email -> (password, user)
        self.sessions = {}  # token -> user
        self.auth = self
        self.admin = self

    def __call__(self):
        return self

    def sign_up(self, creds):
        if len(creds["password"]) < 6:
            raise AuthApiError("Password should be at least 6 characters.", 422, "weak_password")
        user = SimpleNamespace(id=str(uuid.uuid4()), email=creds["email"],
                               created_at=datetime.now(timezone.utc), last_sign_in_at=None)
        self.users[creds["email"]] = (creds["password"], user)
        return SimpleNamespace(user=user, session=None)

    def sign_in_with_password(self, creds):
        stored = self.users.get(creds["email"])
        if not stored or stored[0] != creds["password"]:
            raise AuthApiError("Invalid login credentials", 400, "invalid_credentials")
        token = "tok-" + uuid.uuid4().hex
        self.sessions[token] = stored[1]
        return SimpleNamespace(user=stored[1], session=SimpleNamespace(
            access_token=token, refresh_token="ref-" + token, expires_in=3600))

    def get_user(self, token):
        if token not in self.sessions:
            raise AuthApiError("invalid JWT", 401, "bad_jwt")
        return SimpleNamespace(user=self.sessions[token])

    def sign_out(self, token, scope="global"):
        self.sessions.pop(token, None)


@pytest.fixture()
def client(monkeypatch):
    fake = FakeSupabase()
    monkeypatch.setattr(auth, "supabase_client", fake)
    monkeypatch.setattr(main, "supabase_client", fake)
    return TestClient(main.app)


def login(client, email="test@example.com", password="password123"):
    client.post("/auth/signup", json={"email": email, "password": password})
    return client.post("/auth/login", json={"email": email, "password": password}).json()["access_token"]


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def test_signup_201(client):
    r = client.post("/auth/signup", json={"email": "a@b.com", "password": "password123"})
    assert r.status_code == 201 and r.json()["user"]["email"] == "a@b.com"


@pytest.mark.parametrize("body", [{}, {"email": "a@b.com"}, {"password": "x"}, {"email": " ", "password": "password123"}])
def test_missing_fields_400(client, body):
    assert client.post("/auth/signup", json=body).status_code == 400
    assert client.post("/auth/login", json=body).status_code == 400


def test_supabase_rejection_on_signup_is_400(client):
    r = client.post("/auth/signup", json={"email": "a@b.com", "password": "123"})
    assert r.status_code == 400 and "6 characters" in r.json()["error"]


def test_login_200_and_wrong_password_401(client):
    login(client)
    r = client.post("/auth/login", json={"email": "test@example.com", "password": "wrong"})
    assert r.status_code == 401 and r.json() == {"error": "Invalid login credentials"}
    r = client.post("/auth/login", json={"email": "test@example.com", "password": "password123"})
    assert r.status_code == 200 and r.json()["access_token"] and r.json()["token_type"] == "bearer"


def test_public_needs_no_token(client):
    assert client.get("/public/info").json() == {"message": "Welcome stranger! This info is public."}


@pytest.mark.parametrize("path", ["/protected/profile", "/protected/dashboard"])
@pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer "}, {"Authorization": "Basic abc"}, {"Authorization": "tok"}])
def test_missing_or_malformed_token_401(client, path, headers):
    r = client.get(path, headers=headers)
    assert r.status_code == 401 and r.json() == {"error": "Access token required"}
    assert r.headers["WWW-Authenticate"] == "Bearer"


def test_valid_token_200_tampered_401(client):
    token = login(client)
    r = client.get("/protected/profile", headers=bearer(token))
    assert r.status_code == 200 and r.json()["email"] == "test@example.com" and "token" not in r.json()
    r = client.get("/protected/profile", headers=bearer(token[:-1] + "X"))
    assert r.status_code == 401 and r.json() == {"error": "Invalid or expired token"}


def test_dashboard_uses_same_guard(client):
    token = login(client)
    assert client.get("/protected/dashboard", headers=bearer(token)).status_code == 200
    assert client.get("/protected/dashboard", headers=bearer("nope")).status_code == 401


def test_logout_204_then_token_dead(client):
    token = login(client)
    assert client.post("/auth/logout", headers=bearer(token)).status_code == 204
    assert client.get("/protected/profile", headers=bearer(token)).status_code == 401
    assert client.post("/auth/logout").status_code == 401
