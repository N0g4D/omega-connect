import base64
import hashlib
import importlib.util
import json
import os
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "tests" / "fixtures" / "demo_server.py"
sys.path.insert(0, str(ROOT / "tests"))

# Everything stays on this machine.
os.environ["NO_PROXY"] = os.environ["no_proxy"] = "127.0.0.1,localhost"


@pytest.fixture(scope="session")
def program():
    spec = importlib.util.spec_from_file_location("omega_connect_program", ROOT / "program.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    yield module
    module.ENGINE.shutdown()


@pytest.fixture(autouse=True)
def fresh_sessions(program):
    """Each test starts with no MCP sessions, as its store starts empty."""
    yield
    program.ENGINE.shutdown()


@pytest.fixture(autouse=True)
def isolated_store(tmp_path, monkeypatch):
    monkeypatch.setenv("OMEGA_CONNECT_DATA_DIR", str(tmp_path / "store"))
    monkeypatch.setenv("OMEGA_CONNECT_LOG_DIR", str(tmp_path / "logs"))
    from cryptography.fernet import Fernet

    monkeypatch.setenv("OMEGA_CONNECT_SECRET_KEY", Fernet.generate_key().decode())
    monkeypatch.delenv("OMEGA_CONNECT_ALLOW_STDIO", raising=False)
    yield


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _start_demo(env_extra: dict, port: int | None = None) -> tuple[subprocess.Popen, str]:
    port = port or free_port()
    env = {**os.environ, **env_extra}
    proc = subprocess.Popen([sys.executable, str(DEMO), "http", str(port)], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.time() + 20
    while time.time() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
            return proc, f"http://127.0.0.1:{port}/mcp"
        except OSError:
            time.sleep(0.2)
    proc.kill()
    raise RuntimeError("demo server did not start")


@pytest.fixture
def demo_url():
    proc, url = _start_demo({})
    yield url
    proc.terminate()
    proc.wait(timeout=10)


@pytest.fixture
def wide_demo():
    """Demo server with 250 extra read-only tools."""
    proc, url = _start_demo({"DEMO_EXTRA_TOOLS": "250"})
    yield url
    proc.terminate()
    proc.wait(timeout=10)


@pytest.fixture
def restartable_demo():
    """Demo server that a test can restart on the same address, with other settings."""
    proc, url = _start_demo({})
    demo = SimpleNamespace(url=url, proc=proc)

    def restart(**env):
        demo.proc.terminate()
        demo.proc.wait(timeout=10)
        demo.proc, _ = _start_demo(env, port=int(url.rsplit(":", 1)[1].split("/")[0]))

    demo.restart = restart
    yield demo
    demo.proc.terminate()
    demo.proc.wait(timeout=10)


SECRET = "tok-9f2c4b7e51d0a8"
NEW_TOKEN = "tok-3e8a1c6f92b47d"  # what a refresh returns when a test asks for a new token
REFRESH = "rt-55aa66bb"  # the first refresh token; the ones that follow start with it too
ACCOUNT = "ada@contoso.example"
AUTH_CODE = "ac-5d1e8b2f9a"  # what the browser sign-in's redirect address carries


@pytest.fixture
def guarded_url():
    """Demo server that answers only with `Authorization: Bearer SECRET`."""
    proc, url = _start_demo({"DEMO_REQUIRE_TOKEN": SECRET})
    yield url
    proc.terminate()
    proc.wait(timeout=10)


@pytest.fixture
def token_server(tmp_path_factory):
    """Demo server that answers only with the token `accept` last named (SECRET at first). The
    file it reads sits outside the test's tmp_path, which tests search for leaked tokens."""
    path = tmp_path_factory.mktemp("token-server") / "token"
    path.write_text(SECRET)
    proc, url = _start_demo({"DEMO_TOKEN_FILE": str(path)})
    yield SimpleNamespace(url=url, accept=path.write_text)
    proc.terminate()
    proc.wait(timeout=10)


def _id_token(claims: dict) -> str:
    def part(value: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()
    return f"{part({'alg': 'RS256', 'typ': 'JWT'})}.{part(claims)}.c2lnbmF0dXJl"


class _FakeAuthority(BaseHTTPRequestHandler):
    """Microsoft identity platform stand-in: device code, token, refresh. As with Entra, an id_token
    comes when openid is asked for, and each refresh token works once: a refresh rotates it."""
    state = None  # set by the fake_authority fixture

    def log_message(self, *args):
        pass

    def do_POST(self):
        state = type(self).state
        length = int(self.headers.get("Content-Length", 0))
        form = {k: v[0] for k, v in parse_qs(self.rfile.read(length).decode()).items()}
        if self.path.endswith("/devicecode"):
            state.scopes.append(form.get("scope", ""))
            body = {"device_code": "dev-1", "user_code": "ABCD-1234",
                    "verification_uri": "https://microsoft.com/devicelogin",
                    "expires_in": 60, "interval": 1, "message": "sign in"}
        elif form.get("grant_type", "").endswith("device_code"):
            if state.pending_polls > 0:
                state.pending_polls -= 1
                body = {"error": "authorization_pending"}
            else:
                body = state.grant(state.access_token)
        elif form.get("grant_type") == "authorization_code":
            state.redemptions.append(form)
            with state.lock:
                issued = state.codes.pop(form.get("code"), None)  # each code works once
            verifier = form.get("code_verifier", "").encode()
            proof = base64.urlsafe_b64encode(hashlib.sha256(verifier).digest()).rstrip(b"=").decode()
            body = state.grant(state.access_token) if issued == (proof, form.get("redirect_uri")) else \
                {"error": "invalid_grant", "error_description": "AADSTS70008: the code, its verifier or the "
                                                                "redirect address does not match"}
        elif form.get("grant_type") == "refresh_token":
            with state.lock:
                state.refreshes += 1
            time.sleep(state.refresh_delay)
            with state.lock:
                live = form.get("refresh_token") in state.refresh_tokens
                state.refresh_tokens.discard(form.get("refresh_token"))
            body = state.grant(state.refreshed_token) if live else \
                {"error": "invalid_grant", "error_description": "AADSTS70000: the refresh token was already used"}
        else:
            body = {"error": "unsupported"}
        data = json.dumps(body).encode()
        status = 400 if "error" in body else 200
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class _Authority:
    """What the fake identity platform hands out; tests change it and read what it saw."""

    def __init__(self):
        self.lock = threading.Lock()
        self.access_token = SECRET  # from the device code sign-in
        self.refreshed_token = SECRET  # from a refresh
        self.pending_polls = 1  # "authorization_pending" answers before the sign-in completes
        self.refresh_delay = 0.0
        self.refreshes = 0
        self.scopes: list[str] = []  # scope of each device code request
        self.refresh_tokens: set[str] = set()  # the ones that still work
        self.id_tokens: list[str] = []
        # browser sign-in: code -> (PKCE challenge, redirect address) it was issued for; what each redemption sent
        self.codes: dict[str, tuple[str, str]] = {}
        self.redemptions: list[dict] = []

    def authorize(self, address: str, code: str = AUTH_CODE) -> str:
        """The person signs in at the authorization address and consents: the identity platform issues
        a code for its challenge, and the browser lands on the redirect address with that code."""
        query = {k: v[0] for k, v in parse_qs(urlsplit(address).query).items()}
        with self.lock:
            self.codes[code] = (query["code_challenge"], query["redirect_uri"])
        return f"{query['redirect_uri']}?code={code}&state={query['state']}&session_state=s-1"

    def grant(self, access_token: str) -> dict:
        with self.lock:
            refresh_token = REFRESH if not self.id_tokens else f"{REFRESH}-{len(self.id_tokens)}"
            self.refresh_tokens.add(refresh_token)
            self.id_tokens.append(_id_token({"preferred_username": ACCOUNT, "name": "Ada Lovelace"}))
            return {"access_token": access_token, "refresh_token": refresh_token, "expires_in": 3600,
                    "id_token": self.id_tokens[-1], "scope": "Mail.Read openid profile offline_access"}


@pytest.fixture
def fake_authority(monkeypatch):
    _FakeAuthority.state = state = _Authority()
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FakeAuthority)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("OMEGA_CONNECT_OAUTH_AUTHORITY", f"http://127.0.0.1:{server.server_port}")
    yield state
    server.shutdown()
