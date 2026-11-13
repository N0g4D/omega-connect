"""OAuth 2.0 sign-in for delegated access: the device authorization grant
(RFC 8628) and the authorization code grant with PKCE (RFC 7636).

Used for Microsoft 365: a person runs the `connect` action, signs in with their
own account and consents to the scopes the server needs. With the device code
they enter a short code on a sign-in page. With the browser flow they open an
address, sign in, and paste back the address the browser lands on, which
carries the code. Tenants created since July 2026 block the device code while
Microsoft's security defaults are on, so the browser flow is the one that works
there. Tokens never leave the app: they are kept encrypted in the store and
turned into an Authorization header just before a call. With the `openid` and
`profile` scopes the identity provider also sends an id_token; only its
preferred_username is kept, to show who signed in.

Standard library only. The authority defaults to the Microsoft identity
platform; OMEGA_CONNECT_OAUTH_AUTHORITY overrides it (tests use a local fake).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

DEFAULT_AUTHORITY = "https://login.microsoftonline.com"
# Entra's authorization codes last about ten minutes; a browser sign-in waits no longer for its address.
BROWSER_SIGNIN_SECONDS = 600


class OAuthError(RuntimeError):
    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind
        self.message = message


def authority() -> str:
    return os.environ.get("OMEGA_CONNECT_OAUTH_AUTHORITY", DEFAULT_AUTHORITY).rstrip("/")


def _post(url: str, form: dict) -> dict:
    body = urllib.parse.urlencode(form).encode("ascii")
    request = urllib.request.Request(url, data=body, method="POST",
                                     headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            return json.loads(exc.read().decode("utf-8"))
        except Exception:
            raise OAuthError("http", f"identity provider answered HTTP {exc.code}")
    except urllib.error.URLError as exc:
        raise OAuthError("unreachable", f"identity provider unreachable: {exc.reason}")


@dataclass
class DeviceCode:
    device_code: str
    user_code: str
    verification_uri: str
    interval: int
    expires_at: float
    message: str


def start_device_flow(tenant: str, client_id: str, scopes: list[str]) -> DeviceCode:
    data = _post(f"{authority()}/{tenant}/oauth2/v2.0/devicecode",
                 {"client_id": client_id, "scope": " ".join(scopes)})
    if "device_code" not in data:
        raise OAuthError("device_code", data.get("error_description") or data.get("error") or "no device code")
    return DeviceCode(
        device_code=data["device_code"],
        user_code=data["user_code"],
        verification_uri=data.get("verification_uri") or data.get("verification_url", ""),
        interval=int(data.get("interval", 5)),
        expires_at=time.time() + int(data.get("expires_in", 900)),
        message=str(data.get("message", "")),
    )


def poll_device_flow(tenant: str, client_id: str, code: DeviceCode, sleep=time.sleep) -> dict:
    """Blocks until the person signs in, declines, or the code expires."""
    interval = max(code.interval, 1)
    while time.time() < code.expires_at:
        data = _post(f"{authority()}/{tenant}/oauth2/v2.0/token", {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "client_id": client_id,
            "device_code": code.device_code,
        })
        if "access_token" in data:
            return _token_record(data)
        error = data.get("error")
        if error == "authorization_pending":
            sleep(interval)
            continue
        if error == "slow_down":
            interval += 5
            sleep(interval)
            continue
        raise OAuthError(error or "token", data.get("error_description") or "sign-in failed")
    raise OAuthError("expired_token", "the sign-in code expired before it was used")


@dataclass
class BrowserSignIn:
    """A browser sign-in in progress. The address goes to the person who started it; the state and
    the verifier stay in the app's memory and are never shown."""
    url: str
    redirect_uri: str
    state: str
    verifier: str
    expires_at: float


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def native_redirect() -> str:
    """Where the browser lands after the person signs in. Entra offers this address for public
    clients (app registration, Authentication, Mobile and desktop applications): the page stays
    empty and its address carries the code."""
    return f"{authority()}/common/oauth2/nativeclient"


def start_browser_flow(tenant: str, client_id: str, scopes: list[str]) -> BrowserSignIn:
    """Authorization code with PKCE (RFC 7636, S256). Nothing is sent yet: the person opens the
    address, signs in and consents, and the browser lands on the redirect address with the code."""
    verifier = _b64url(secrets.token_bytes(32))
    state = _b64url(secrets.token_bytes(24))
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    redirect_uri = native_redirect()
    query = urllib.parse.urlencode({
        "client_id": client_id, "response_type": "code", "redirect_uri": redirect_uri, "response_mode": "query",
        "scope": " ".join(scopes), "state": state, "code_challenge": challenge, "code_challenge_method": "S256"})
    return BrowserSignIn(url=f"{authority()}/{tenant}/oauth2/v2.0/authorize?{query}", redirect_uri=redirect_uri,
                         state=state, verifier=verifier, expires_at=time.time() + BROWSER_SIGNIN_SECONDS)


def finish_browser_flow(tenant: str, client_id: str, scopes: list[str], signin: BrowserSignIn, landed: str) -> dict:
    """Trades the code in the address the browser landed on for tokens, once the address is the
    redirect address and its state is this sign-in's."""
    parts = urllib.parse.urlsplit(landed.strip())
    expected = urllib.parse.urlsplit(signin.redirect_uri)
    if (parts.scheme, parts.netloc, parts.path) != (expected.scheme, expected.netloc, expected.path):
        raise OAuthError("bad_redirect", f"paste the whole address the browser landed on; it starts with "
                                         f"{signin.redirect_uri}")
    fields = urllib.parse.parse_qs(parts.query)

    def field(name: str) -> str:
        return (fields.get(name) or [""])[0]

    if field("error"):
        described = f": {field('error_description')[:300]}" if field("error_description") else ""
        raise OAuthError(field("error")[:80], f"the sign-in ended with {field('error')[:80]}{described}")
    if not secrets.compare_digest(field("state").encode(), signin.state.encode()):
        raise OAuthError("state_mismatch", "that address belongs to another sign-in; run connect again")
    if not field("code"):
        raise OAuthError("bad_redirect", "the address has no code; paste the whole address the browser landed on")
    data = _post(f"{authority()}/{tenant}/oauth2/v2.0/token", {
        "grant_type": "authorization_code",
        "client_id": client_id,
        "code": field("code"),
        "redirect_uri": signin.redirect_uri,
        "code_verifier": signin.verifier,
        "scope": " ".join(scopes),
    })
    if "access_token" not in data:
        raise OAuthError(data.get("error") or "token", data.get("error_description") or "sign-in failed")
    return _token_record(data)


def refresh(tenant: str, client_id: str, scopes: list[str], record: dict) -> dict:
    if not record.get("refresh_token"):
        raise OAuthError("no_refresh_token", "sign-in expired; a person must run connect again")
    data = _post(f"{authority()}/{tenant}/oauth2/v2.0/token", {
        "grant_type": "refresh_token",
        "client_id": client_id,
        "refresh_token": record["refresh_token"],
        "scope": " ".join(scopes),
    })
    if "access_token" not in data:
        raise OAuthError(data.get("error") or "refresh", "sign-in expired; a person must run connect again")
    new = _token_record(data)
    if not new.get("refresh_token"):
        new["refresh_token"] = record["refresh_token"]
    if not new.get("account") and record.get("account"):
        new["account"] = record["account"]
    return new


def _token_record(data: dict) -> dict:
    record = {
        "access_token": data["access_token"],
        "refresh_token": data.get("refresh_token"),
        "expires_at": time.time() + int(data.get("expires_in", 3600)),
        "scope": data.get("scope", ""),
    }
    account = account_name(data.get("id_token"))
    if account:
        record["account"] = account  # the id_token itself is not kept
    return record


def account_name(id_token: str | None) -> str | None:
    """preferred_username from an id_token, only to show who signed in. The signature is not
    checked, so nothing may be decided on this value."""
    try:
        payload = id_token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        name = claims.get("preferred_username")
    except Exception:
        return None
    return name[:200] if isinstance(name, str) and name.strip() else None


def needs_refresh(record: dict, margin: float = 120.0) -> bool:
    return float(record.get("expires_at", 0)) - margin < time.time()
