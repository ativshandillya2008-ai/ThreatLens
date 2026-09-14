"""Pytest configuration and shared fixtures."""
from __future__ import annotations

import email
import pytest
from pathlib import Path


FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def phishing_email_bytes() -> bytes:
    with open(FIXTURES_DIR / "phishing_email.eml", "rb") as f:
        return f.read()


@pytest.fixture
def benign_email_bytes() -> bytes:
    with open(FIXTURES_DIR / "benign_email.eml", "rb") as f:
        return f.read()


@pytest.fixture
def phishing_msg(phishing_email_bytes):
    return email.message_from_bytes(phishing_email_bytes)


@pytest.fixture
def benign_msg(benign_email_bytes):
    return email.message_from_bytes(benign_email_bytes)
