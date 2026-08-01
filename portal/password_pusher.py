from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import requests

_URL_TOKEN = re.compile(r"^[A-Za-z0-9_-]{8,128}$")


class PasswordPusherError(RuntimeError):
    """Erreur d'intégration volontairement dépourvue de secret ou de token."""


class PasswordPusherTransportError(PasswordPusherError):
    pass


class PasswordPusherHTTPError(PasswordPusherError):
    def __init__(self, status: int):
        super().__init__(f"Password Pusher a répondu avec le statut {status}.")
        self.status = status


class PasswordPusherProtocolError(PasswordPusherError):
    pass


@dataclass(frozen=True)
class CredentialPush:
    url: str
    expire_after_days: int
    expire_after_views: int


@dataclass
class PasswordPusherClient:
    base_url: str
    api_token: str
    expire_after_days: int = 1
    expire_after_views: int = 1
    ca_bundle: str | None = None
    timeout_seconds: int = 10

    def __post_init__(self) -> None:
        parsed = urlparse(self.base_url)
        if (
            parsed.scheme != "https"
            or not parsed.netloc
            or parsed.username
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("PORTAL_PWPUSH_URL doit être une URL HTTPS sûre.")
        if not self.api_token:
            raise ValueError("PORTAL_PWPUSH_API_TOKEN est requis.")
        if not 1 <= self.expire_after_days <= 30:
            raise ValueError("PORTAL_PWPUSH_EXPIRE_DAYS est invalide.")
        if not 1 <= self.expire_after_views <= 10:
            raise ValueError("PORTAL_PWPUSH_EXPIRE_VIEWS est invalide.")
        self.base_url = self.base_url.rstrip("/")

    def push(self, secret: str, *, note: str) -> CredentialPush:
        payload = {
            "push": {
                "payload": secret,
                "note": note[:200],
                "expire_after_days": self.expire_after_days,
                "expire_after_views": self.expire_after_views,
            }
        }
        try:
            response = requests.post(
                f"{self.base_url}/api/v2/pushes.json",
                json=payload,
                headers={
                    "Accept": "application/json",
                    "Authorization": f"Bearer {self.api_token}",
                },
                timeout=self.timeout_seconds,
                verify=self.ca_bundle or True,
                allow_redirects=False,
            )
        except requests.RequestException as error:
            raise PasswordPusherTransportError(
                "Password Pusher est temporairement indisponible."
            ) from error
        if not 200 <= response.status_code < 300:
            raise PasswordPusherHTTPError(response.status_code)
        try:
            data: Any = response.json()
        except requests.JSONDecodeError as error:
            raise PasswordPusherProtocolError(
                "La réponse Password Pusher est invalide."
            ) from error
        url = data.get("html_url") if isinstance(data, dict) else None
        token = data.get("url_token") if isinstance(data, dict) else None
        if url is None and isinstance(token, str) and _URL_TOKEN.fullmatch(token):
            url = f"{self.base_url}/p/{token}"
        parsed_url = urlparse(url) if isinstance(url, str) else None
        if parsed_url is None or parsed_url.scheme != "https" or not parsed_url.netloc:
            raise PasswordPusherProtocolError(
                "Le lien Password Pusher est invalide."
            )
        assert isinstance(url, str)
        return CredentialPush(
            url=url,
            expire_after_days=self.expire_after_days,
            expire_after_views=self.expire_after_views,
        )


@dataclass
class FakePasswordPusherClient:
    pushes: list[dict[str, str]]
    expire_after_days: int = 1
    expire_after_views: int = 1

    def push(self, secret: str, *, note: str) -> CredentialPush:
        self.pushes.append({"secret": secret, "note": note})
        return CredentialPush(
            url=f"https://pwpush.example/p/fake-{len(self.pushes)}",
            expire_after_days=self.expire_after_days,
            expire_after_views=self.expire_after_views,
        )
