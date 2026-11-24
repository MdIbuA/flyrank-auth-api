"""Settings come from environment variables, loaded from .env if present."""

import os

from dotenv import load_dotenv

load_dotenv()  # reads .env in the working directory; real env vars win


def _required(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} is not set. Copy .env.example to .env and fill it in.")
    return value


SUPABASE_URL = _required("SUPABASE_URL")
SUPABASE_KEY = _required("SUPABASE_KEY")  # the public anon key, never the service_role key
PORT = int(os.getenv("PORT", "8000"))
