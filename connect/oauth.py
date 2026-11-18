"""OAuth 2.0 sign-in for delegated access: the device authorization grant
(RFC 8628) and the authorization code grant with PKCE (RFC 7636), whose code
the browser brings back to a loopback address of this machine (RFC 8252, 7.3).

Used for Microsoft 365: a person runs the `connect` action, signs in with their
own account and consents to the scopes the server needs. With the device code
they enter a short code on a sign-in page. With the browser flow they open an
address and sign in; their browser then goes to `http://localhost:<port>`,
where a listener of the app, open for that sign-in alone and on the loopback
interface only, takes the code. Tenants created since July 2026 block the
device code while Microsoft's security defaults are on, so the browser flow is
the one that works there; it needs the person's browser on the hive's machine.
Tokens never leave the app: they are kept encrypted in the store and turned
into an Authorization header just before a call. With the `openid` and
`profile` scopes the identity provider also sends an id_token; only its
preferred_username is kept, to show who signed in.

Standard library only. The authority defaults to the Microsoft identity
platform; OMEGA_CONNECT_OAUTH_AUTHORITY overrides it (tests use a local fake).
"""

from __future__ import annotations

import base64
import errno
import hashlib
import json
import os
import secrets
import selectors
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Callable

DEFAULT_AUTHORITY = "https://login.microsoftonline.com"
# A browser sign-in is waited for this long; then its listener closes.
BROWSER_SIGNIN_SECONDS = 600
# What that listener takes: this many requests in all, each within this size and this time.
MAX_REQUESTS = 50
MAX_REQUEST_BYTES = 64 * 1024
REQUEST_SECONDS = 5.0


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


def poll_device_flow(tenant: str, client_id: str, code: DeviceCode, sleep=time.sleep,
                     wanted: Callable[[], bool] = lambda: True) -> dict | None:
    """Blocks until the person signs in, declines, or the code expires. `wanted` is asked before each
    request: once it says no, nothing more is sent and the answer is None."""
    interval = max(code.interval, 1)
    while time.time() < code.expires_at:
        if not wanted():
            return None
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


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def start_browser_flow(tenant: str, client_id: str, scopes: list[str], redirect_uri: str) -> BrowserSignIn:
    """Authorization code with PKCE (RFC 7636, S256). Nothing is sent yet: the person opens the
    address, signs in and consents, and the identity platform sends their browser to the redirect
    address with the code. For Entra that address is a LoopbackListener's `http://localhost:<port>`:
    the app registration lists `http://localhost` under Mobile and desktop applications, and Entra
    leaves the port out when it compares the two."""
    verifier = _b64url(secrets.token_bytes(32))
    state = _b64url(secrets.token_bytes(24))
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    query = urllib.parse.urlencode({
        "client_id": client_id, "response_type": "code", "redirect_uri": redirect_uri, "response_mode": "query",
        "scope": " ".join(scopes), "state": state, "code_challenge": challenge, "code_challenge_method": "S256"})
    return BrowserSignIn(url=f"{authority()}/{tenant}/oauth2/v2.0/authorize?{query}", redirect_uri=redirect_uri,
                         state=state, verifier=verifier)


def finish_browser_flow(tenant: str, client_id: str, scopes: list[str], signin: BrowserSignIn, code: str) -> dict:
    """Trades the code the browser came back with for tokens, with this sign-in's verifier and the
    redirect address the code was asked with."""
    data = _post(f"{authority()}/{tenant}/oauth2/v2.0/token", {
        "grant_type": "authorization_code",
        "client_id": client_id,
        "code": code,
        "redirect_uri": signin.redirect_uri,
        "code_verifier": signin.verifier,
        "scope": " ".join(scopes),
    })
    if "access_token" not in data:
        raise OAuthError(data.get("error") or "token", data.get("error_description") or "sign-in failed")
    return _token_record(data)


def _page(status: str, text: str) -> bytes:
    """A whole HTTP answer with a page of one sentence."""
    body = ('<!doctype html>\n<html lang="en"><head><meta charset="utf-8"><title>omega-connect</title></head>'
            f"<body><p>{text}</p></body></html>\n").encode("utf-8")
    head = (f"HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {len(body)}\r\n"
            "Cache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\n"
            "Connection: close\r\n\r\n")
    return head.encode("ascii") + body


# All that a LoopbackListener ever answers: fixed, with nothing of the request in it.
SIGNED_IN_PAGE = _page("200 OK", "You are signed in. You can close this page.")
FAILED_PAGE = _page("400 Bad Request", "The sign-in did not complete. You can close this page; to try again, "
                                       "run connect again.")
REFUSED_PAGE = _page("400 Bad Request", "This address only takes the answer to a sign-in in progress.")


def _listen(family: int, host: str, port: int) -> socket.socket:
    """A listening socket on that address alone. No SO_REUSEADDR: the port must be nobody else's."""
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.bind((host, port))
        sock.listen()
        sock.setblocking(False)  # accept() comes after a select and must never wait
    except OSError:
        sock.close()
        raise
    return sock


def _bind_loopback() -> tuple[int, list[socket.socket]]:
    """Listening sockets on one free port of the loopback interface: 127.0.0.1, and ::1 where this
    machine has it, since a browser may take `localhost` for either. A port that another program
    holds on ::1 is not used: a browser that went there would hand that program the code."""
    for _ in range(8):
        try:
            ipv4 = _listen(socket.AF_INET, "127.0.0.1", 0)
        except OSError as exc:
            raise OAuthError("no_listener", "the app cannot listen on 127.0.0.1 for the browser sign-in "
                                            f"({exc.__class__.__name__})") from None
        port = ipv4.getsockname()[1]
        try:
            return port, [ipv4, _listen(socket.AF_INET6, "::1", port)]
        except OSError as exc:
            if exc.errno != errno.EADDRINUSE:
                return port, [ipv4]  # this machine has no ::1
            ipv4.close()
    raise OAuthError("no_listener", "the app found no port free on both loopback addresses for the browser sign-in")


def _request_line(connection: socket.socket) -> bytes | None:
    """The first line of the HTTP request on `connection`, read up to the end of its headers. b"" for
    a request that does not come whole within REQUEST_SECONDS and MAX_REQUEST_BYTES, None when
    nothing comes at all."""
    deadline, received = time.monotonic() + REQUEST_SECONDS, bytearray()
    while True:
        left = deadline - time.monotonic()
        if left <= 0 or len(received) > MAX_REQUEST_BYTES:
            return b"" if received else None
        connection.settimeout(left)
        try:
            piece = connection.recv(4096)
        except OSError:  # the time is up, or the connection broke
            piece = b""
        if not piece:
            return b"" if received else None
        new = max(len(received) - 3, 0)  # the end of the headers may come in two pieces
        received += piece
        if b"\r\n\r\n" in received[new:] or b"\n\n" in received[new:]:
            return bytes(received.split(b"\n", 1)[0])


def _redirect_query(line: bytes) -> dict[str, str] | None:
    """The query of a request line `GET /?... HTTP/1.1`, as {field: value} for the fields that come
    once; None for any other request line."""
    words = line.split()
    if len(words) != 3 or words[0] != b"GET" or not words[2].startswith(b"HTTP/"):
        return None
    try:
        target = urllib.parse.urlsplit(words[1].decode("ascii"))
        # Blank values count, so that a field is known to come once.
        fields = urllib.parse.parse_qs(target.query, keep_blank_values=True)
    except ValueError:  # not ASCII, or not an address
        return None
    if target.path != "/":
        return None
    return {name: values[0] for name, values in fields.items() if len(values) == 1}


class LoopbackListener:
    """Where the browser comes back after a browser sign-in (RFC 8252, 7.3): an HTTP listener on the
    loopback interface only, on a port the system picks, for one sign-in. `redirect_uri` is its
    address, `http://localhost:<port>`.

    Only a GET for `/` whose `state` is the sign-in's, compared in constant time, ends the wait,
    and only once: `landed(code, failure)` gets the code, or the failure that came in its place, and
    says whether the person is now signed in; the browser gets SIGNED_IN_PAGE or FAILED_PAGE. Every
    other request gets REFUSED_PAGE and leaves the wait as it was. The wait also ends, with
    `ended(failure)`, once `seconds` have passed or more than MAX_REQUESTS requests have come, and
    with nothing said on `close()`. Each connection is served in a thread of its own, so one that
    sends nothing holds up no other. Nothing of a request is ever logged or sent back: its first
    line carries the code."""

    def __init__(self):
        self.port, self._sockets = _bind_loopback()
        self.redirect_uri = f"http://localhost:{self.port}"
        self._wake, self._woken = socket.socketpair()  # how an outcome or close() ends the listening thread's wait
        self._lock = threading.Lock()
        self._over = False  # the wait has ended: by the redirect, by time or requests, or closed
        self._thread: threading.Thread | None = None

    def start(self, state: str, landed: Callable[[str | None, OAuthError | None], bool],
              ended: Callable[[OAuthError], None], seconds: float) -> None:
        with self._lock:
            if self._over:  # closed before it started
                return
            self._state, self._landed, self._ended = state.encode("ascii"), landed, ended
            self._thread = threading.Thread(target=self._wait, args=(time.monotonic() + seconds,),
                                            name="omega-connect-signin-listener", daemon=True)
            self._thread.start()

    def close(self) -> None:
        """Ends the wait with no outcome. Returns once the port is closed, or after a second."""
        self._claim()
        thread = self._thread
        if thread is None:
            self._release()
            return
        self._stop()
        if thread is not threading.current_thread():
            thread.join(1)

    def _claim(self) -> bool:
        """Ends the wait; True for the one caller that ended it."""
        with self._lock:
            if self._over:
                return False
            self._over = True
            return True

    def _stop(self) -> None:
        """Wakes the listening thread, which then closes the port."""
        with self._lock:
            if self._sockets:
                self._wake.send(b"\0")

    def _release(self) -> None:
        with self._lock:
            for sock in (*self._sockets, self._wake, self._woken):
                sock.close()
            self._sockets = []

    def _wait(self, deadline: float) -> None:
        """The listening thread: takes requests until the wait ends, then closes the port."""
        try:
            failure = self._take_requests(deadline)
        except Exception as exc:  # no thread to be had, say: the wait ends here, and `ended` hears why
            failure = OAuthError("listener", f"the listener of the browser sign-in failed ({exc.__class__.__name__})")
        finally:
            self._release()
        if failure is not None and self._claim():
            self._ended(failure)

    def _take_requests(self, deadline: float) -> OAuthError | None:
        """Hands each connection to a thread of its own. Returns why the wait ended, or None when an
        outcome or close() ended it."""
        with selectors.DefaultSelector() as selector:
            for sock in (*self._sockets, self._woken):
                selector.register(sock, selectors.EVENT_READ)
            taken = 0
            while True:
                left = deadline - time.monotonic()
                if left <= 0:
                    return OAuthError("expired", "nobody finished the sign-in in the browser before its address "
                                                 "expired; run connect again")
                ready = [key.fileobj for key, _ in selector.select(left)]
                if self._woken in ready:
                    return None
                for sock in ready:
                    try:
                        connection, _ = sock.accept()
                    except OSError:
                        continue  # gone before it was taken
                    taken += 1
                    if taken > MAX_REQUESTS:
                        connection.close()
                        return OAuthError("too_many_requests", "too many requests came to the address of the "
                                                               "sign-in before the browser did; run connect again")
                    threading.Thread(target=self._serve, args=(connection,), name="omega-connect-signin-request",
                                     daemon=True).start()

    def _serve(self, connection: socket.socket) -> None:
        """One connection: at most one request, and one of the three fixed answers."""
        try:
            with connection:
                line = _request_line(connection)
                if line is None:
                    return
                connection.settimeout(REQUEST_SECONDS)
                connection.sendall(self._answer(line))
                # What is left of the request is read before the connection closes: closing over unread
                # bytes resets it, and the browser could lose the page.
                connection.shutdown(socket.SHUT_WR)
                connection.settimeout(1)
                finished = time.monotonic() + 1
                while time.monotonic() < finished and connection.recv(4096):
                    pass
        except Exception:  # a broken connection; and no error's text may carry a piece of a request anywhere
            pass

    def _answer(self, line: bytes) -> bytes:
        query = _redirect_query(line)
        if query is None or not secrets.compare_digest(query.get("state", "").encode(), self._state) \
                or not self._claim():
            return REFUSED_PAGE
        self._stop()  # the wait is over, whatever comes of this request
        code, error, failure = query.get("code"), query.get("error"), None
        if error:
            described = f": {query['error_description'][:300]}" if query.get("error_description") else ""
            failure = OAuthError(error[:80], f"the sign-in ended with {error[:80]}{described}")
        elif not code:
            failure = OAuthError("bad_redirect", "the browser came back from the sign-in without a code")
        try:
            signed_in = self._landed(None if failure else code, failure)
        except Exception:
            signed_in = False
        return SIGNED_IN_PAGE if signed_in else FAILED_PAGE


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
