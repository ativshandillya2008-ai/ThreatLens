"""Async Gmail API client with retry logic and automatic token refresh."""
from __future__ import annotations

import asyncio
import base64
import logging
from typing import Any, Optional

import httpx

from ..auth.token_store import get_valid_access_token

logger = logging.getLogger(__name__)

GMAIL_API_BASE = "https://gmail.googleapis.com/gmail/v1"
MAX_RETRIES = 3
BACKOFF_FACTOR = 2.0


class GmailClient:
    """Async Gmail REST API wrapper.

    Automatically refreshes access tokens before each request.
    Retries on 429 (quota) and 5xx errors with exponential backoff.
    """

    def __init__(self, user_email: str) -> None:
        self.user_email = user_email
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self) -> "GmailClient":
        self._client = httpx.AsyncClient(timeout=30.0)
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    async def _get_headers(self) -> dict[str, str]:
        token = await get_valid_access_token(self.user_email)
        return {"Authorization": f"Bearer {token}"}

    async def _request(
        self,
        method: str,
        path: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Make an authenticated request with retry logic."""
        url = f"{GMAIL_API_BASE}/users/me{path}"
        headers = await self._get_headers()
        kwargs.setdefault("headers", {})
        kwargs["headers"].update(headers)

        assert self._client is not None, "GmailClient must be used as async context manager"

        last_exc: Optional[Exception] = None
        for attempt in range(MAX_RETRIES):
            try:
                response = await self._client.request(method, url, **kwargs)

                if response.status_code == 401:
                    # Token might have just expired; force refresh and retry
                    logger.warning("401 on Gmail request, forcing token refresh")
                    from ..auth.token_store import _access_token_cache
                    _access_token_cache.pop(self.user_email, None)
                    headers = await self._get_headers()
                    kwargs["headers"].update(headers)
                    continue

                if response.status_code == 429 or response.status_code >= 500:
                    wait = BACKOFF_FACTOR ** attempt
                    logger.warning(
                        "Gmail API %s on attempt %d, backing off %.1fs",
                        response.status_code, attempt + 1, wait,
                    )
                    await asyncio.sleep(wait)
                    continue

                response.raise_for_status()
                return response.json()

            except httpx.TimeoutException as exc:
                last_exc = exc
                wait = BACKOFF_FACTOR ** attempt
                logger.warning("Gmail request timeout (attempt %d), retry in %.1fs", attempt + 1, wait)
                await asyncio.sleep(wait)

        raise RuntimeError(
            f"Gmail API request failed after {MAX_RETRIES} attempts"
        ) from last_exc

    async def list_messages(
        self,
        query: str = "",
        max_results: int = 50,
        page_token: Optional[str] = None,
        include_spam_trash: bool = False,
    ) -> dict[str, Any]:
        """List messages matching a query."""
        params: dict[str, Any] = {"maxResults": int(max_results)}
        if query:
            params["q"] = query
            if "in:spam" in query.lower() or "is:spam" in query.lower():
                include_spam_trash = True
        if include_spam_trash:
            params["includeSpamTrash"] = "true"
        if page_token:
            params["pageToken"] = page_token
        return await self._request("GET", "/messages", params=params)

    async def get_message(
        self,
        message_id: str,
        format: str = "full",
    ) -> dict[str, Any]:
        """Get a single message in the specified format."""
        return await self._request(
            "GET", f"/messages/{message_id}", params={"format": format}
        )

    async def get_raw_message(self, message_id: str) -> bytes:
        """Fetch raw RFC2822 message bytes (base64url-encoded in API response)."""
        data = await self._request(
            "GET", f"/messages/{message_id}", params={"format": "raw"}
        )
        raw_b64 = data.get("raw", "")
        # Gmail uses base64url encoding
        padded = raw_b64 + "==" * ((-len(raw_b64)) % 4)
        return base64.urlsafe_b64decode(padded)

    async def get_message_history(
        self, start_history_id: str, label_id: Optional[str] = None
    ) -> dict[str, Any]:
        """Fetch history since a given historyId."""
        params: dict[str, Any] = {"startHistoryId": start_history_id}
        if label_id:
            params["labelId"] = label_id
        return await self._request("GET", "/history", params=params)

    async def list_labels(self) -> list[dict[str, Any]]:
        """List all labels in the mailbox."""
        data = await self._request("GET", "/labels")
        return data.get("labels", [])

    async def create_label(
        self,
        name: str,
        background_color: Optional[str] = None,
        text_color: Optional[str] = None,
    ) -> dict[str, Any]:
        """Create a new label, gracefully handling Gmail's strict color palette constraints."""
        body: dict[str, Any] = {
            "name": name,
            "labelListVisibility": "labelShow",
            "messageListVisibility": "show",
        }
        if background_color and text_color:
            body["color"] = {
                "backgroundColor": background_color,
                "textColor": text_color,
            }
        try:
            return await self._request("POST", "/labels", json=body)
        except Exception as exc:
            # If rejected due to custom color palette, retry without color
            if "color" in body:
                body.pop("color", None)
                return await self._request("POST", "/labels", json=body)
            raise exc

    async def modify_message(
        self,
        message_id: str,
        add_label_ids: Optional[list[str]] = None,
        remove_label_ids: Optional[list[str]] = None,
    ) -> dict[str, Any]:
        """Add or remove labels from a message."""
        body: dict[str, Any] = {}
        if add_label_ids:
            body["addLabelIds"] = add_label_ids
        if remove_label_ids:
            body["removeLabelIds"] = remove_label_ids
        return await self._request(
            "POST", f"/messages/{message_id}/modify", json=body
        )

    async def watch(
        self,
        topic_name: str,
        label_ids: Optional[list[str]] = None,
    ) -> dict[str, Any]:
        """Set up Gmail push notifications via Cloud Pub/Sub."""
        body: dict[str, Any] = {"topicName": topic_name}
        if label_ids:
            body["labelIds"] = label_ids
        return await self._request("POST", "/watch", json=body)

    async def create_draft(
        self,
        to: str,
        subject: str,
        body: str,
    ) -> dict[str, Any]:
        """Create an email draft in the user's Gmail mailbox."""
        from email.message import EmailMessage
        msg = EmailMessage()
        msg["To"] = to
        msg["Subject"] = subject
        msg.set_content(body)
        raw_b64 = base64.urlsafe_b64encode(msg.as_bytes()).decode("ascii")
        return await self._request(
            "POST", "/drafts", json={"message": {"raw": raw_b64}}
        )

    async def send_message(
        self,
        to: str,
        subject: str,
        body: str,
    ) -> dict[str, Any]:
        """Send an email from the user's Gmail account."""
        from email.message import EmailMessage
        msg = EmailMessage()
        msg["To"] = to
        msg["Subject"] = subject
        msg.set_content(body)
        raw_b64 = base64.urlsafe_b64encode(msg.as_bytes()).decode("ascii")
        return await self._request(
            "POST", "/messages/send", json={"raw": raw_b64}
        )

    async def stop_watch(self) -> None:
        """Stop Gmail push notifications."""
        try:
            await self._request("POST", "/stop", json={})
        except Exception as exc:
            logger.warning("Failed to stop watch: %s", exc)
