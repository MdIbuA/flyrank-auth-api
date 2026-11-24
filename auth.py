"""Supabase client factory and the reusable "is this request logged in?" guard."""

from supabase import Client, ClientOptions, create_client

import config


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
