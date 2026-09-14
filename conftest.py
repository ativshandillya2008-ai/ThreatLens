"""Root conftest: set environment variables required for Settings validation before any test import."""
import os
from cryptography.fernet import Fernet

# These are TEST-ONLY values — never use in production
os.environ.setdefault("GOOGLE_CLIENT_ID", "test-client-id")
os.environ.setdefault("GOOGLE_CLIENT_SECRET", "test-client-secret")
os.environ.setdefault("FERNET_KEY", Fernet.generate_key().decode())
os.environ.setdefault("SESSION_SECRET", "test-session-secret-at-least-32-chars-long!!!")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("GEMINI_API_KEY", "")
os.environ.setdefault("SAFE_BROWSING_API_KEY", "")
os.environ.setdefault("PUBSUB_TOPIC", "")
os.environ.setdefault("PUBSUB_PUSH_AUDIENCE", "")
os.environ.setdefault("DEBUG", "true")
