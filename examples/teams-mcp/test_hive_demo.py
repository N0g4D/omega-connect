"""hive_demo.py as a person runs it, with the hive, Microsoft Graph and the sign-in simulated.

Each test starts hive_demo.py in its own process and answers its prompts through its
standard input. HiveRoutes below stands for the hive: it answers, over the fake hive
of ../../tests, the HTTP routes that hive_demo.py and a person's browser use, with
the checks the Mac test build 0.33 makes on them (as read in its hive/core: the
owner's one-time sign-in link, the Origin a person's session must send, the host's
confirm token for confirm actions, a mind's token on the mind's route). omega-connect
itself runs inside it, unchanged. The person's part on the hive's pages (accept-reads,
the approval) is played by the test with a session of its own, as their browser would.
teams-mcp runs with the simulated Graph of test_server.py, and the sign-in goes to the
fake identity platform of test_demo.py. Nothing leaves this machine.

    python -m pytest -q examples/teams-mcp

Run as a program, this file is a stand-in for teams-mcp that needs no Microsoft
sign-in, to rehearse hive_demo.py --no-signin on a real hive without a tenant:

    python examples/teams-mcp/test_hive_demo.py --port 8791
"""

import asyncio
import hashlib
import importlib.util
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
HIVE_DEMO = HERE / "hive_demo.py"
sys.path.insert(0, str(ROOT / "tests"))
os.environ["NO_PROXY"] = os.environ["no_proxy"] = "127.0.0.1,localhost"  # everything stays on this machine

from fakehive import APP_ID, FakeHive, HostRefusal, _check_request, digest  # noqa: E402


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


demo_tests = _load(HERE / "test_demo.py", "teams_demo_tests")  # the identity platform, Run, FakeGraph's data
TOKEN, REFRESH, ID_TOKEN, AUTH_CODE = demo_tests.TOKEN, demo_tests.REFRESH, demo_tests.ID_TOKEN, demo_tests.AUTH_CODE
TENANT, CLIENT_ID, ACCOUNT = demo_tests.TENANT, demo_tests.CLIENT_ID, demo_tests.ACCOUNT
TEAM, CHANNEL = demo_tests.TEAM, demo_tests.CHANNEL
OWNER = "ada"  # the hive's owner: a named person, user:ada
READS = ["GET /me/joinedTeams", f"GET /teams/{TEAM}/channels", f"GET /teams/{TEAM}/channels/{CHANNEL}/messages"]
POST = f"POST /teams/{TEAM}/channels/{CHANNEL}/messages"


def serve_stand_in(argv: list[str]) -> None:
    """teams-mcp with the simulated Graph, asking for no token: the server for hive_demo.py --no-signin.
    Each Graph request is written to $FAKE_GRAPH_LOG, when that is set, as "METHOD path"."""
    teams = _load(HERE / "server.py", "teams_mcp_server")
    graph = demo_tests.graph_tests.FakeGraph(teams.GRAPH)
    log = os.environ.get("FAKE_GRAPH_LOG")

    def send(method, url, headers, body):
        if log:
            with open(log, "a") as out:
                out.write(f"{method} {url[len(teams.GRAPH):].split('?')[0]}\n")
        return graph.send(method, url, headers, body)

    teams.graph_send = send
    teams._token = lambda ctx: TOKEN  # the simulated Graph's own; no request needs to bring one
    teams.main(argv)


# ------------------------------------------------------------------ the hive, over HTTP

def http(method: str, url: str, body=None, token: str | None = None, origin: str | None = None):
    """One JSON request: (status, answer)."""
    request = urllib.request.Request(url, data=None if body is None else json.dumps(body).encode(), method=method)
    request.add_header("Content-Type", "application/json")
    if origin:
        request.add_header("Origin", origin)
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return response.status, json.loads(response.read() or b"null")
    except urllib.error.HTTPError as exc:
        with exc:
            return exc.code, json.loads(exc.read() or b"null")


class HiveRoutes:
    """The routes of a local-owner hive that the demo uses, answered over FakeHive.

    As on the Mac test build: the owner signs in with a one-time code (here GET /control/signin-url
    gives the link, where the build's launcher asks the hive's control socket); a request with an
    Origin other than the hive's is refused, and a session's request that changes something needs
    the hive's; a confirm action runs only with a confirm token minted for the same session, swarm,
    action and payload digest, once; a mind acts with its own token, under the rules written for it,
    and its body names neither itself nor its swarm. Not modelled: visibility (one person owns
    everything here), expiry of sessions and confirm tokens, and what FakeHive leaves out."""

    def __init__(self, program):
        self.fake = FakeHive(program)
        self.version = json.loads((ROOT / "plugin.json").read_text())["version"]
        self.mounted = True
        self.lose_answer: set[str] = set()  # last parts of paths whose request is carried out, then answered 500
        self.codes: set[str] = set()  # sign-in codes not used yet
        self.sessions: set[str] = set()
        self.issued: set[str] = set()  # every secret the hive ever gave out
        self.swarms: list[dict] = []
        self.minds: dict[str, dict] = {}
        self.rules: dict[str, dict] = {}
        self.confirms: dict[str, dict] = {}
        self.actions: dict[tuple[str, str], str] = {}  # (mind, idempotency key) -> action
        self.requests: list[dict] = []
        self.lock = threading.RLock()
        routes = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _serve(self):
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                status, answer = routes.handle(self.command, self.path, self.headers, raw)
                data = answer if isinstance(answer, bytes) else json.dumps(answer).encode()
                self.send_response(status)
                self.send_header("Content-Type", "text/plain" if isinstance(answer, bytes) else "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = do_DELETE = _serve

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def new_link(self) -> str:
        code = secrets.token_urlsafe(32)
        self.codes.add(code)
        self.issued.add(code)
        return f"{self.base}/local-signin#{code}"

    def live_minds(self) -> list[dict]:
        return [mind for mind in self.minds.values() if not mind["deleted"]]

    # ---------------------------------------------------------------- one request
    def handle(self, method: str, target: str, headers, raw: bytes):
        parts = urlsplit(target)
        path, query = parts.path, {k: v[0] for k, v in parse_qs(parts.query).items()}
        bearer = (headers.get("Authorization") or "").removeprefix("Bearer ").strip() or None
        origin = headers.get("Origin")
        try:
            body = json.loads(raw) if raw else None
        except ValueError:
            return 400, {"error": {"code": "bad_request", "message": "expected a JSON body"}}
        with self.lock:
            self.requests.append({"method": method, "path": path, "query": query, "origin": origin, "bearer": bearer,
                                  "body": body})
            try:
                if path == "/control/signin-url":  # the launcher's way in, not a route of the hive
                    return 200, self.new_link().encode()
                if origin is not None and origin != self.base:
                    raise HostRefusal(403, "origin_refused")
                changes = method in ("POST", "PUT", "PATCH", "DELETE")
                if changes and origin is None and (path == "/api/auth/local/exchange" or bearer in self.sessions):
                    raise HostRefusal(403, "origin_required")
                answer = self.route(method, path, query, bearer, headers, body if isinstance(body, dict) else {})
                if path.rsplit("/", 1)[1] in self.lose_answer:
                    raise RuntimeError("the answer is lost")
                return 200, answer
            except HostRefusal as exc:
                return exc.status, {"error": {"code": exc.code, "message": str(exc)}}
            except Exception as exc:  # as the hive answers an error it did not expect
                return 500, {"error": {"code": "internal_error", "message": exc.__class__.__name__}}

    def route(self, method, path, query, bearer, headers, body):
        if (method, path) == ("POST", "/api/auth/local/exchange"):
            if (headers.get("Content-Type") or "").split(";")[0].strip().lower() != "application/json":
                raise HostRefusal(415, "bad_content_type")
            if body.get("code") not in self.codes:
                raise HostRefusal(401, "code_refused")
            self.codes.discard(body["code"])
            token = secrets.token_urlsafe(32)
            self.sessions.add(token)
            self.issued.add(token)
            return {"token": token, "expires_at": time.time() + 30 * 86400,
                    "user": {"id": OWNER, "email": "owner@local.invalid", "name": "Ada", "role": "admin"}}
        if (method, path) == ("POST", f"/api/agent/programs/{APP_ID}/act"):
            return self.mind_act(bearer, body)
        if bearer not in self.sessions:
            raise HostRefusal(401, "unauthorized")
        if (method, path) == ("POST", "/api/auth/logout"):
            self.sessions.discard(bearer)
            return {"ok": True}
        if path == f"/api/programs/{APP_ID}" and method == "GET":
            return self.program()
        if path.startswith(f"/api/programs/{APP_ID}/") and method == "POST":
            return self.person_route(path.rsplit("/", 1)[1], bearer, body)
        if path == "/api/swarms":
            return self.swarm_route(method, body)
        if path == "/api/agents" or path.startswith("/api/agents/"):
            return self.mind_route(method, path, body)
        if path == "/api/policy" or path.startswith("/api/policy/"):
            return self.policy_route(method, path, body)
        if path == "/api/approvals" and method == "GET":
            return [row for row in map(self.approval_row, self.fake.approvals.values())
                    if not query.get("status") or row["status"] == query["status"]]
        if path.startswith("/api/approvals/") and method == "POST":
            return self.decide(*path.split("/")[3:5])
        if path == "/api/program-activity" and method == "GET":
            return [{"id": record["id"], "program": APP_ID, "swarm_id": self.minds[mind]["swarm_id"],
                     "principal": f"agent:{mind}", "action": self.actions.get((mind, key)), "status": record["status"],
                     "approval_id": (record.get("approval") or {}).get("id")}
                    for (mind, key), record in self.fake.records.items()
                    if self.minds[mind]["swarm_id"] == query.get("swarm_id")]
        raise HostRefusal(404, "not_found")

    # ---------------------------------------------------------------- the app
    def program(self) -> dict:
        if not self.mounted:
            raise HostRefusal(404, "not_found")
        actions = [{**action, "confirm": action.get("confirm") is True} for action in self.fake.descriptor["actions"]]
        return {"id": APP_ID, "name": "Tool connections", "version": self.version, "source": "plugin-dir",
                "enabled": True, "error": None, "describe": {**self.fake.descriptor, "actions": actions}}

    def swarm(self, swarm_id) -> str:
        if swarm_id not in [swarm["id"] for swarm in self.swarms]:
            raise HostRefusal(404, "not_found")
        return swarm_id

    def person_route(self, what: str, session: str, body: dict):
        swarm = self.swarm(body.get("swarm_id"))
        if what == "view":
            if set(body) - {"swarm_id", "focus", "stage", "untrusted_intent"}:
                raise HostRefusal(400, "bad_request")
            return asyncio.run(self.fake.view(swarm, OWNER, body.get("focus"), body.get("stage") or "unfold"))
        if what == "confirm":
            return self.mint_confirm(session, swarm, body)
        if what != "act":
            raise HostRefusal(404, "not_found")
        _check_request({k: v for k, v in body.items() if k not in ("swarm_id", "params", "confirm_token")},
                       body.get("params") or {})
        action, items, params = str(body.get("action") or ""), body.get("items") or [], body.get("params") or {}
        if self.fake.actions.get(action, {}).get("confirm") is True:
            self.take_confirm(session, swarm, action, body.get("confirm_token"),
                              {"items": items, "params": params, "base_revision": body.get("base_revision")})
        return asyncio.run(self.fake.person_act(swarm, OWNER, action, items, params, confirmed=True,
                                                base_revision=body.get("base_revision"),
                                                key=body.get("idempotency_key")))

    def mint_confirm(self, session: str, swarm: str, body: dict) -> dict:
        """The host's confirm token for one act: its payload digest is checked against the payload sent."""
        if set(body) != {"swarm_id", "action", "payload", "payload_digest"}:
            raise HostRefusal(400, "bad_request")
        payload = body["payload"]
        if not isinstance(payload, dict) or set(payload) - {"items", "params", "base_revision", "file"}:
            raise HostRefusal(400, "bad_request")
        payload = {"items": payload.get("items") or [], "params": payload.get("params") or {},
                   "base_revision": payload.get("base_revision")}
        if digest(payload) != body["payload_digest"]:
            raise HostRefusal(400, "confirm_digest_mismatch")
        if self.fake.actions.get(body["action"], {}).get("confirm") is not True:
            raise HostRefusal(400, "confirm_not_needed")
        token = "hct_" + secrets.token_urlsafe(32)
        self.issued.add(token)
        self.confirms[hashlib.sha256(token.encode()).hexdigest()] = {
            "session": session, "swarm": swarm, "action": body["action"], "digest": body["payload_digest"],
            "used": False}
        return {"confirm_token": token, "expires_at": "2026-11-17T00:02:00.000Z", "expires_in": 120}

    def take_confirm(self, session: str, swarm: str, action: str, token, payload: dict) -> None:
        if token is None:
            raise HostRefusal(403, "confirm_required")
        minted = self.confirms.get(hashlib.sha256(str(token).encode()).hexdigest())
        wanted = {"session": session, "swarm": swarm, "action": action, "digest": digest(payload), "used": False}
        if minted != wanted:
            raise HostRefusal(403, "confirm_invalid")
        minted["used"] = True

    def mind_act(self, bearer, body: dict):
        mind = next((mind for mind in self.live_minds() if bearer and mind["token"] == bearer), None)
        if mind is None:
            raise HostRefusal(401, "unauthorized")
        params = body.get("params") or {}
        _check_request({k: v for k, v in body.items() if k != "params"}, params)
        action, key = str(body.get("action") or ""), body.get("idempotency_key")
        self.actions[(mind["id"], key)] = action
        return asyncio.run(self.fake.agent_act(mind["swarm_id"], mind["id"], action, params, key,
                                               body.get("approval_id"), body.get("base_revision"),
                                               body.get("items") or []))

    # ---------------------------------------------------------------- swarms, minds, rules, approvals
    def swarm_route(self, method: str, body: dict):
        if method == "GET":
            return self.swarms
        if method != "POST" or not str(body.get("name") or "").strip():
            raise HostRefusal(400, "bad_request")
        self.swarms.append({"id": "s_" + secrets.token_hex(16), "name": body["name"].strip(),
                            "description": str(body.get("description") or ""), "owner": f"user:{OWNER}",
                            "visibility": body.get("visibility", "private"), "archived_at": None})
        return self.swarms[-1]

    def mind_route(self, method: str, path: str, body: dict):
        shown = lambda mind: {k: v for k, v in mind.items() if k not in ("token", "deleted")}  # noqa: E731
        if (method, path) == ("GET", "/api/agents"):
            return [shown(mind) for mind in self.live_minds()]
        if (method, path) == ("POST", "/api/agents"):
            if not str(body.get("name") or "").strip() or body.get("kind", "omega") not in ("omega", "iter", "module"):
                raise HostRefusal(400, "bad_request")
            token = secrets.token_urlsafe(32)
            self.issued.add(token)
            mind = {"id": "a_" + secrets.token_hex(16), "name": body["name"].strip(), "kind": body.get("kind", "omega"),
                    "swarm_id": self.swarm(body.get("swarm_id")), "persona": str(body.get("persona") or ""),
                    "status": "created", "owner": f"user:{OWNER}", "token": token, "deleted": False}
            self.minds[mind["id"]] = mind
            return {**shown(mind), "token": token}  # the only answer that ever carries it
        mind = self.minds.get(path.rsplit("/", 1)[1])
        if method != "DELETE" or mind is None or mind["deleted"]:
            raise HostRefusal(404, "not_found")
        mind["deleted"] = True
        return {"ok": True}

    def policy_route(self, method: str, path: str, body: dict):
        if (method, path) == ("GET", "/api/policy"):
            return list(self.rules.values())
        if (method, path) == ("POST", "/api/policy"):
            if body.get("mode") not in ("allow", "ask", "deny") or not str(body.get("skill") or "").strip() \
                    or not re.fullmatch(r"hive|(?:swarm|agent):.+", str(body.get("scope") or "")):
                raise HostRefusal(400, "bad_request")
            rule = {"id": "r_" + secrets.token_hex(8), "scope": body["scope"], "skill": body["skill"].strip(),
                    "mode": body["mode"], "note": str(body.get("note") or ""), "granted_by": f"user:{OWNER}"}
            self.rules[rule["id"]] = rule
            self.fake.rules[(rule["scope"].removeprefix("agent:"), rule["skill"])] = rule["mode"]
            return rule
        rule = self.rules.pop(path.rsplit("/", 1)[1], None)
        if method == "DELETE" and rule is not None:
            self.fake.rules.pop((rule["scope"].removeprefix("agent:"), rule["skill"]), None)
        return {"ok": True}

    @staticmethod
    def approval_row(approval: dict) -> dict:
        return {"id": approval["id"], "agent_id": approval["mind"], "skill": f"program:{APP_ID}:{approval['action']}",
                "status": approval["state"], "decided_by": approval["by"], "kind": "ask", "risk": "medium",
                "binding": json.dumps(approval["binding"], sort_keys=True), "may_answer": True}

    def decide(self, approval_id: str, answer: str) -> dict:
        approval = self.fake.approvals.get(approval_id)
        if approval is None or answer not in ("approve", "deny"):
            raise HostRefusal(404, "not_found")
        if approval["state"] != "pending":
            raise HostRefusal(409, "not_pending")
        if answer == "approve":
            self.fake.approve(approval_id, OWNER)
        else:
            approval.update(state="denied", by=f"user:{OWNER}")
        return self.approval_row(approval)


class Page:
    """The person on the hive's pages: a session of their own in the browser, the hive's Origin on
    every request, and the host's confirm before an act that needs one."""

    def __init__(self, hive: HiveRoutes):
        self.hive = hive
        code = hive.new_link().rsplit("#", 1)[1]
        self.token = self.call("POST", "/api/auth/local/exchange", {"code": code})["token"]

    def call(self, method: str, path: str, body=None):
        status, answer = http(method, self.hive.base + path, body, getattr(self, "token", None), self.hive.base)
        assert status == 200, (status, answer)
        return answer

    def view(self, swarm: str) -> dict:
        return self.call("POST", f"/api/programs/{APP_ID}/view", {"swarm_id": swarm})

    def act(self, swarm: str, action: str, items: list, params: dict | None = None, base_revision=None) -> dict:
        payload = {"items": items, "params": params or {}, "base_revision": base_revision}
        minted = self.call("POST", f"/api/programs/{APP_ID}/confirm",
                           {"swarm_id": swarm, "action": action, "payload": payload, "payload_digest": digest(payload)})
        return self.call("POST", f"/api/programs/{APP_ID}/act",
                         {"swarm_id": swarm, "action": action, **payload, "confirm_token": minted["confirm_token"]})

    def accept_reads(self) -> dict:
        """What the app's page sends for Accept read-only tools on the server, after the host's confirm."""
        swarm = self.hive.swarms[0]["id"]
        return self.act(swarm, "accept-reads", ["server:teams"], base_revision=self.view(swarm)["revision"])

    def answer(self, yes: bool) -> dict:
        """Approve or No on the Approvals page, for the one request that waits."""
        [waiting] = self.hive.fake.pending()
        return self.call("POST", f"/api/approvals/{waiting['id']}/{'approve' if yes else 'deny'}", {})


# ------------------------------------------------------------------ fixtures

def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture(scope="module")
def program():
    module = _load(ROOT / "program.py", "omega_connect_program")
    yield module
    module.ENGINE.shutdown()


@pytest.fixture
def platform():
    """The fake identity platform of test_demo.py, for the app's browser sign-in."""
    demo_tests._IdentityPlatform.state = state = SimpleNamespace(pending=0, refuse={}, requests=[], codes={})
    server = ThreadingHTTPServer(("127.0.0.1", 0), demo_tests._IdentityPlatform)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    state.url = f"http://127.0.0.1:{server.server_port}"
    yield state
    server.shutdown()
    server.server_close()


# What stands for ~/OmegaHive/app/install/macos/omegahive.sh: `signin-url` prints a link that works once.
LAUNCHER = """#!{python}
import sys, urllib.request
if sys.argv[1:] != ["signin-url"]:
    sys.exit("usage: omegahive.sh signin-url")
opener = urllib.request.build_opener(urllib.request.ProxyHandler({{}}))
print(opener.open("{base}/control/signin-url", timeout=30).read().decode())
"""


def install_launcher(home: Path, text: str) -> None:
    launcher = home / "app" / "install" / "macos" / "omegahive.sh"
    launcher.parent.mkdir(parents=True, exist_ok=True)
    launcher.write_text(text)
    launcher.chmod(0o755)


@pytest.fixture
def hive(program, platform, tmp_path, monkeypatch):
    """The hive with omega-connect mounted: its own store and key, the sign-in at the fake platform."""
    from cryptography.fernet import Fernet

    monkeypatch.setenv("OMEGA_CONNECT_DATA_DIR", str(tmp_path / "store"))
    monkeypatch.setenv("OMEGA_CONNECT_SECRET_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("OMEGA_CONNECT_OAUTH_AUTHORITY", platform.url)
    monkeypatch.delenv("OMEGA_CONNECT_ALLOW_STDIO", raising=False)
    routes = HiveRoutes(program)
    routes.home = tmp_path / "OmegaHive"
    install_launcher(routes.home, LAUNCHER.format(python=sys.executable, base=routes.base))
    yield routes
    routes.close()
    program.ENGINE.shutdown()
    for pending in list(program._PENDING_SIGNINS.values()):
        if pending.get("listener"):
            pending["listener"].close()  # a browser sign-in that a stopped run left waiting


class Teams:
    """teams-mcp with the simulated Graph, in its own process; the Graph requests it got so far."""

    def __init__(self, tmp_path: Path, script: Path):
        self.log = tmp_path / f"graph-{script.stem}.log"
        port = free_port()
        self.url = f"http://127.0.0.1:{port}/mcp"
        env = {name: value for name, value in os.environ.items() if not name.startswith("OMEGA_CONNECT_")}
        self.proc = subprocess.Popen([sys.executable, str(script), "--port", str(port)],
                                     env={**env, "FAKE_GRAPH_LOG": str(self.log)},
                                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 30
        while True:
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
                return
            except OSError:
                assert self.proc.poll() is None and time.monotonic() < deadline, "teams-mcp did not start"
                time.sleep(0.1)

    def graph(self) -> list[str]:
        lines = self.log.read_text().splitlines() if self.log.exists() else []
        return [line for line in lines if not line.startswith("{")]  # test_demo.py's first line is its settings

    def stop(self) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()


@pytest.fixture
def teams(tmp_path):
    """teams-mcp as test_demo.py serves it: it takes only the token the fake identity platform gives."""
    server = Teams(tmp_path, HERE / "test_demo.py")
    yield server
    server.stop()


@pytest.fixture
def stand_in(tmp_path):
    """This file as a program: teams-mcp that asks for no token."""
    server = Teams(tmp_path, Path(__file__))
    yield server
    server.stop()


# Runs hive_demo.py with a stand-in for the person's browser, which writes the address it gets to
# $FAKE_BROWSER_LOG and opens only if $FAKE_BROWSER is not "none", and with short waits between two
# looks at the hive. argv: hive_demo.py, then its own arguments.
RUNNER = """\
import importlib.util, os, pathlib, sys
spec = importlib.util.spec_from_file_location("teams_hive_demo", sys.argv[1])
demo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(demo)
demo.POLL = 0.1

def open_in_browser(url):
    pathlib.Path(os.environ["FAKE_BROWSER_LOG"]).write_text(url)
    return os.environ["FAKE_BROWSER"] != "none"

demo.open_in_browser = open_in_browser
sys.exit(demo.main(sys.argv[2:]))
"""


class HiveDemoRun(demo_tests.Run):
    """hive_demo.py in its own process, against the hive of the test."""

    def __init__(self, hive: HiveRoutes, tmp_path: Path, *args: str, browser: bool = True, home: Path | None = None):
        self.browser_log = tmp_path / "browser.log"
        env = {name: value for name, value in os.environ.items() if not name.startswith("OMEGA_CONNECT_")}
        env.update(PYTHONUNBUFFERED="1", PYTHONIOENCODING="utf-8", FAKE_BROWSER_LOG=str(self.browser_log),
                   FAKE_BROWSER="yes" if browser else "none")
        super().__init__([sys.executable, "-c", RUNNER, str(HIVE_DEMO), "--hive-home", str(home or hive.home), *args],
                         env, tmp_path)

    def browser_address(self) -> str | None:
        """The address the demo gave the browser, or None if it gave it none."""
        return self.browser_log.read_text() if self.browser_log.exists() else None


@pytest.fixture
def start(hive, tmp_path):
    """Starts hive_demo.py with the given arguments; after the test, stops it if it still runs."""
    runs = []

    def start(*args: str, **options) -> HiveDemoRun:
        runs.append(HiveDemoRun(hive, tmp_path, *args, **options))
        return runs[-1]

    yield start
    for run in runs:
        run.stop()


def sign_in(run: HiveDemoRun, platform) -> None:
    """The person's part of connect: yes at the terminal, then the sign-in in the browser the script
    opened, which comes back to the app's listener on this machine."""
    run.expect("with your Microsoft account? (y/n): ")
    run.send("y")
    run.expect("the demo goes on by itself.")
    status, page = demo_tests.browse(demo_tests.authorize(platform, run.browser_address()))
    assert status == 200 and "You can close this page" in page


def shown_nowhere(run: HiveDemoRun, hive: HiveRoutes, *more: str) -> None:
    """No secret reached the screen: nothing the hive gave out (sign-in codes, sessions, the mind's
    token, confirm tokens), nothing of the Microsoft sign-in."""
    assert len(hive.issued) >= 3
    for hidden in (*hive.issued, TOKEN, REFRESH, ID_TOKEN, AUTH_CODE, *more):
        assert hidden not in run.output, hidden
    assert "hct_" not in run.output and "local-signin" not in run.output


# ------------------------------------------------------------------ the demo

def test_the_mind_reads_and_posts_only_after_the_person_approves_in_the_hive(start, hive, platform, teams):
    run = start("--server-url", teams.url)
    run.expect("Tenant ID (Directory ID): ")
    run.send("organizations")  # a single-tenant app needs its tenant id
    run.expect("does not accept 'organizations'")
    run.send(TENANT, CLIENT_ID)
    run.expect("Add this server as Ada? (y/n): ")
    run.send("y")
    sign_in(run, platform)
    run.expect(f"Sign-in: oauth-device (signed in by user:ada, as {ACCOUNT}; minds use this sign-in)")
    run.expect("Where [1]: ")
    run.send("")  # on the app's page
    run.expect("… waiting for accept-reads on the app's page")
    page = Page(hive)
    assert page.accept_reads()["status"] == "done"
    run.expect("✓ read:  list_channels, list_teams, read_channel_messages")
    run.expect("Which team? [1-2]: ")
    run.send("1")
    run.expect("the only channel: General")
    run.expect("  > ")
    run.send("")  # the default text
    run.expect("Where [1]: ")
    run.send("")  # on the Approvals page
    run.expect("… waiting for your answer on the Approvals page")
    assert teams.graph() == READS  # the mind waits, and nothing is posted
    [waiting] = hive.fake.pending()
    assert waiting["params"]["arguments"]["text"].startswith("Test message from omega-connect")
    assert page.answer(True)["status"] == "approved"
    assert run.finish() == 0
    assert teams.graph() == READS + [POST]

    out = run.output
    swarm, [mind] = hive.swarms[0]["id"], hive.live_minds()
    for shown in ("signed in as its owner Ada (user:ada)",
                  f"App              omega-connect {hive.version} (plugin-dir)",
                  f"mind      connect-scout ({mind['id']}), created",
                  "rules     list-tools allow, read-tool allow, use-tool ask",
                  f"{hive.base}/#/program/omega-connect/{swarm}",
                  "[2] add-server  ·  you, confirmed here, or on the app's page from build 0.38 (Add a server)",
                  "[3] connect  ·  you, confirmed here: the browser sign-in",
                  "sign-in   oauth-device · tenant aaaaaaaa… · client 11111111…",
                  "The sign-in page is open in your browser", "post_channel_message     write",
                  "accepted by person:ada", "write: post_channel_message", "Hi Bob, the demo is at 3pm",
                  f"The hive answers approval_required: request {waiting['id']}",
                  "No use-tool call in the app's trace: nothing has gone to Teams.",
                  f"{hive.base}/#/approvals?id={waiting['id']}",
                  "✓ Approved by user:ada. The mind sends the request again, with the same key and approval_id "
                  f"{waiting['id']}",
                  f"✓ Posted in Teams as {ACCOUNT}: message", "approved by user:ada",
                  "The hive's own activity log has 5 act(s) of this mind in the app: use-tool rec-",
                  "none carries a value shaped like an access token", "Demo complete.",
                  "Signed out of the hive: this run's session is ended."):
        assert shown in out, shown
    assert "no form" not in out  # build 0.38's page asks for add-server's inputs: the step no longer says it cannot
    shown_nowhere(run, hive, TENANT, CLIENT_ID, run.browser_address())

    # The mind's calls: its own token, no Origin, a body that names neither the mind nor its swarm.
    acts = [r for r in hive.requests if r["path"] == f"/api/agent/programs/{APP_ID}/act"]
    assert [r["body"]["action"] for r in acts] == ["list-tools", "read-tool", "read-tool", "read-tool", "use-tool",
                                                   "use-tool"]
    assert {r["bearer"] for r in acts} == {mind["token"]} and {r["origin"] for r in acts} == {None}
    assert all(set(r["body"]) <= {"action", "params", "idempotency_key", "approval_id"} for r in acts)
    first, again = acts[-2]["body"], acts[-1]["body"]
    assert "approval_id" not in first and again == {**first, "approval_id": waiting["id"]}
    # The person's requests: the hive's Origin on each, and no token in any address.
    assert all(r["origin"] == hive.base for r in hive.requests if r["bearer"] in hive.issued - {mind["token"]})
    assert not any(secret in json.dumps([r["path"], r["query"]]) for r in hive.requests for secret in hive.issued)
    # connect went through the host's confirm, like add-server; accept-reads and the approval came from the page.
    script = [r for r in hive.requests if r["bearer"] != page.token]
    confirmed = [r["body"]["action"] for r in script if r["path"].endswith("/confirm")]
    assert confirmed == ["add-server", "connect"]
    connects = [r["body"]["params"] for r in script if r["path"].endswith("/act") and r["body"]["action"] == "connect"]
    assert connects == [{"flow": "browser"}]  # one act: the app finished the sign-in by itself
    assert not [r for r in script if r["path"].startswith("/api/approvals/")]
    assert hive.sessions == {page.token}  # the script's session is ended; the page's is the person's own


def test_a_no_on_the_approvals_page_posts_nothing(start, hive, platform, teams):
    run = start("--server-url", teams.url)
    run.send(TENANT, CLIENT_ID, "y")
    sign_in(run, platform)
    run.expect("Where [1]: ")
    run.send("1")
    run.expect("… waiting for accept-reads on the app's page")
    page = Page(hive)
    page.accept_reads()
    run.expect("Which team? [1-2]: ")
    run.send("1", "Hello", "1")
    run.expect("… waiting for your answer on the Approvals page")
    assert page.answer(False)["status"] == "denied"
    assert run.finish() == 0
    assert "✗ Not approved (denied by user:ada): nothing is posted." in run.output
    assert "Posted in Teams" not in run.output and "Demo complete." in run.output
    assert teams.graph() == READS
    shown_nowhere(run, hive)


def test_here_the_script_sends_the_persons_steps_and_a_second_run_finds_them_done(start, hive, platform, teams):
    """With 2, accept-reads and the approval go out from the script, each after the person's answer at
    the terminal. A second run finds the server, the sign-in and the review there: it asks for no
    ID, and replaces the mind of the first, whose token nobody holds any more."""
    run = start("--server-url", teams.url)
    run.send(TENANT, CLIENT_ID, "y")
    sign_in(run, platform)
    run.expect("Where [1]: ")
    run.send("2", "1", "First", "2", "maybe", "y")  # anything but y or n asks again
    assert run.finish() == 0
    out = run.output
    assert "→ accept-reads server:teams" in out and "✓ Posted in Teams" in out
    assert "waiting for" not in out.replace("… waiting for the sign-in in your browser", "")
    assert teams.graph() == READS + [POST]
    [first_mind] = hive.live_minds()
    confirmed = [r["body"]["action"] for r in hive.requests if r["path"].endswith("/confirm")]
    assert confirmed == ["add-server", "connect", "accept-reads"]
    shown_nowhere(run, hive, TENANT, CLIENT_ID)

    again = start("--server-url", teams.url)
    again.expect("Which team? [1-2]: ")
    again.send("1", "Second", "2", "n")
    assert again.finish() == 0
    out = again.output
    for shown in ("from an earlier run", f"A demo mind of an earlier run is still there ({first_mind['id']})",
                  f"✓ Already there: teams → {teams.url}",
                  "✓ Already signed in. Sign-in: oauth-device (signed in by",
                  "✓ Already accepted as read: list_channels, list_teams, read_channel_messages",
                  "✗ Not approved (denied by user:ada): nothing is posted."):
        assert shown in out, shown
    assert "Tenant ID" not in out and "Microsoft account? (y/n)" not in out
    [second_mind] = hive.live_minds()
    assert second_mind["id"] != first_mind["id"] and len(hive.swarms) == 1
    assert {rule["scope"] for rule in hive.rules.values()} == {f"agent:{second_mind['id']}"} and len(hive.rules) == 3
    assert teams.graph() == READS + [POST] + READS  # the second post was refused: one message in all
    shown_nowhere(again, hive)


def test_an_answer_the_hive_took_but_did_not_acknowledge_still_counts(start, hive, stand_in):
    """The hive records the person's answer, then fails: the script says so and goes by what the hive holds."""
    hive.lose_answer.add("approve")
    run = start("--no-signin", "--server-url", stand_in.url)
    run.send("y", "2", "", "2", "y")
    assert run.finish() == 0
    assert "✗ The hive answered 500 internal_error." in run.output and "✓ Approved by user:ada." in run.output
    assert stand_in.graph() == READS + [POST]


def test_with_device_code_the_code_is_shown_and_the_demo_waits_for_the_sign_in(start, hive, platform, teams):
    """--device-code: connect without a flow. The address and the user code are for the person, so they
    are shown; the device code itself, the tokens and the IDs are not."""
    platform.pending = 2  # the identity platform answers "authorization_pending" twice, then signs in
    run = start("--device-code", "--server-url", teams.url)
    run.send(TENANT, CLIENT_ID, "y", "y")
    run.expect("Open    https://microsoft.com/devicelogin")
    run.expect("Code    ABCD-1234")
    run.expect("… waiting for the sign-in with the code")
    run.expect(f"✓ In the view: Sign-in: oauth-device (signed in by user:ada, as {ACCOUNT}; minds use this sign-in)")
    run.expect("Where [1]: ")
    run.send("2", "1", "", "2", "y")
    assert run.finish() == 0
    out = run.output
    assert "you, confirmed here: the device code" in out and "✓ Posted in Teams" in out and "Demo complete." in out
    assert "The sign-in page is open" not in out and run.browser_address() is None
    assert teams.graph() == READS + [POST]
    connects = [r["body"] for r in hive.requests if r["path"].endswith("/act") and r["body"].get("action") == "connect"]
    assert [body["params"] for body in connects] == [{}]
    assert [path for path, _ in platform.requests][0].endswith("/devicecode")
    shown_nowhere(run, hive, TENANT, CLIENT_ID, demo_tests.DEVICE_CODE)


def test_a_declined_device_code_stops_the_demo(start, hive, platform, teams):
    platform.refuse = {"token": {"error": "authorization_declined", "error_description": "The end user declined."}}
    run = start("--device-code", "--server-url", teams.url)
    run.send(TENANT, CLIENT_ID, "y", "y")
    assert run.finish() == 1
    assert "Code    ABCD-1234" in run.output and "✗ The sign-in failed" in run.output
    assert "list-tools" not in run.output.split("[3] connect")[1] and teams.graph() == [] and hive.sessions == set()


def test_a_no_at_the_terminal_sends_nothing(start, hive, teams):
    run = start("--server-url", teams.url)
    run.send(TENANT, CLIENT_ID, "n")
    assert run.finish() == 1
    assert "✗ Not confirmed: nothing was sent." in run.output and run.output.rstrip().endswith("session is ended.")
    assert not [r for r in hive.requests if r["path"].endswith(("/confirm", "/act"))] and hive.sessions == set()
    assert Page(hive).view(hive.swarms[0]["id"])["items"] == []


def test_without_a_browser_the_address_is_printed_with_a_warning(start, hive, platform, teams):
    run = start("--server-url", teams.url, browser=False)
    run.send(TENANT, CLIENT_ID, "y", "y")
    run.expect("the demo goes on by itself.")
    address = run.browser_address()
    assert "pause a recording first" in run.output and address in run.output
    assert demo_tests.browse(demo_tests.authorize(platform, address))[0] == 200  # opened by hand, it signs in
    run.expect("✓ In the view: Sign-in: oauth-device (signed in by user:ada")
    assert run.finish() == 1  # the input ends at the next question
    assert run.output.rstrip().endswith("Signed out of the hive: this run's session is ended.")
    assert hive.sessions == set()


def test_a_sign_in_declined_in_the_browser_stops_the_demo(start, hive, platform, teams):
    run = start("--server-url", teams.url)
    run.send(TENANT, CLIENT_ID, "y", "y")
    run.expect("the demo goes on by itself.")
    query = {k: v[0] for k, v in parse_qs(urlsplit(run.browser_address()).query).items()}
    status, page = demo_tests.browse(f"{query['redirect_uri']}/?error=access_denied&state={query['state']}")
    assert status == 400 and "did not complete" in page
    assert run.finish() == 1
    assert "✗ The sign-in failed" in run.output and "If something fails" in run.output
    assert "list-tools" not in run.output.split("[3] connect")[1]
    assert platform.requests == [] and teams.graph() == [] and hive.sessions == set()


def test_an_earlier_app_that_answers_connect_its_own_way_is_told_apart(start, hive, teams, monkeypatch):
    """A hive started before the checkout changed still runs the app it loaded. 0.2 answered connect with flow
    browser by asking for the landing address to be pasted back: the script says what to do, and shows nothing
    of that answer, whose message carries a sign-in link."""
    act = hive.fake.program.act

    async def as_0_2(ctx, action, items, params):
        if action != "connect":
            return await act(ctx, action, items, params)
        return {"status": "needs_input", "needs": {"address": "the address your browser lands on"},
                "message": "Open https://login.example/authorize?state=st-4f1e9a7c and sign in."}

    monkeypatch.setattr(hive.fake.program, "act", as_0_2)
    run = start("--server-url", teams.url)
    run.send(TENANT, CLIENT_ID, "y", "y")
    assert run.finish() == 1
    assert "✗ connect did not start a browser sign-in that finishes by itself" in run.output
    assert "restart" in run.output and "st-4f1e9a7c" not in run.output and run.browser_address() is None
    assert hive.sessions == set()


def test_a_stand_in_server_needs_no_sign_in_and_is_not_taken_for_teams(start, hive, stand_in, teams):
    """--no-signin, for a rehearsal: the same steps without connect, against a server that asks for no
    token. A run with the Microsoft sign-in then refuses the server the rehearsal left in the swarm."""
    run = start("--no-signin", "--server-url", stand_in.url)
    run.send("y", "2", "", "2", "y")  # add the server; accept here; the default text; answer here: yes
    assert run.finish() == 0
    out = run.output
    assert "(a stand-in: no Microsoft sign-in)" in out and "→ the only team: Omega demo" in out
    assert "Tenant ID" not in out and "connect" not in out.replace("omega-connect", "").replace("connect-scout", "")
    assert "✓ Posted in Teams: message 2004" in out and "Demo complete." in out
    assert stand_in.graph() == READS + [POST]

    real = start("--server-url", teams.url)
    assert real.finish() == 1
    assert "✗ A server named 'teams' is already in this swarm, with another address or sign-in" in real.output
    assert teams.graph() == []


def test_cleanup_deletes_the_mind_an_interrupted_run_left_and_denies_its_request(start, hive, platform, teams):
    run = start("--server-url", teams.url)
    run.send(TENANT, CLIENT_ID, "y")
    sign_in(run, platform)
    run.expect("Where [1]: ")
    run.send("2", "1", "", "1")
    run.expect("… waiting for your answer on the Approvals page")
    run.stop()  # Ctrl-C
    assert run.proc.returncode == 130 and "Interrupted." in run.output and hive.sessions == set()
    assert len(hive.live_minds()) == 1 and len(hive.fake.pending()) == 1 and len(hive.rules) == 3

    cleanup = start("--cleanup")
    assert cleanup.finish() == 0
    assert "✓ 1 demo mind(s) deleted, with their rules." in cleanup.output
    assert hive.live_minds() == [] and hive.fake.pending() == [] and hive.rules == {} and hive.sessions == set()
    assert teams.graph() == READS  # nothing was posted
    nothing_left = start("--cleanup")
    assert nothing_left.finish() == 0 and "No demo mind to delete." in nothing_left.output


@pytest.mark.parametrize("break_it, says", [
    (lambda hive, tmp: setattr(hive, "mounted", False),
     "✗ This hive has no app 'omega-connect' (404 not_found). Mount it"),
    (lambda hive, tmp: install_launcher(hive.home, "#!/bin/sh\necho 'OmegaHive: not running' >&2\nexit 1\n"),
     "✗ The hive gave no sign-in link."),
    (lambda hive, tmp: install_launcher(hive.home, f"#!/bin/sh\necho {hive.base}/local-signin#{'x' * 43}\n"),
     "✗ The hive did not take its own sign-in link (401 code_refused)"),
    (lambda hive, tmp: hive.home.rename(tmp / "moved"), "✗ No hive at"),
], ids=["app-not-mounted", "hive-not-running", "link-already-used", "no-hive-folder"])
def test_what_is_missing_is_said_before_anything_is_made(start, hive, teams, tmp_path, break_it, says):
    break_it(hive, tmp_path)
    run = start("--server-url", teams.url)
    assert run.finish() == 1
    assert says in run.output and run.output.rstrip().splitlines()[-1] in (
        "Demo stopped.", "Signed out of the hive: this run's session is ended.")
    assert hive.swarms == [] and hive.minds == {} and hive.sessions == set()
    assert "x" * 43 not in run.output


def test_teams_mcp_must_answer_before_anything_is_made(start, hive):
    run = start("--server-url", f"http://127.0.0.1:{free_port()}/mcp")
    assert run.finish() == 1
    assert "✗ teams-mcp does not answer at" in run.output
    assert "python examples/teams-mcp/server.py --port 8765" in run.output
    assert hive.swarms == [] and hive.minds == {} and hive.sessions == set()


# ------------------------------------------------------------------ parts

@pytest.fixture(scope="module")
def hive_demo():
    return _load(HIVE_DEMO, "teams_hive_demo")


def test_the_confirm_digest_is_the_hives(hive_demo):
    """hive/PROGRAMS.md 9d: sha256 of canonical JSON, keys sorted at every level, no spaces, non-ASCII as
    it is. When the test build is installed, also its shared vectors (read there, never copied here)."""
    payload = {"params": {"z": [1, True, None], "à": "è\n\"x\"", "a": {"b": "/"}}, "items": ["server:teams"],
               "base_revision": None}
    canonical = ('{"base_revision":null,"items":["server:teams"],'
                 '"params":{"a":{"b":"/"},"z":[1,true,null],"à":"è\\n\\"x\\""}}')
    assert hive_demo.payload_digest(payload) == "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()
    assert hive_demo.payload_digest(payload) == digest(payload)  # the fake hive's own
    vectors = Path.home() / "OmegaHive" / "app" / "hive" / "tests" / "fixtures" / "confirm_digest_vectors.json"
    if not vectors.is_file():
        pytest.skip(f"no installed hive with {vectors.name}")
    for vector in json.loads(vectors.read_text())["vectors"]:
        assert hive_demo.payload_digest(vector["payload"]) == vector["digest"], vector["name"]


def test_a_token_in_what_the_app_returned_stops_the_demo(hive_demo, capsys):
    demo = hive_demo.HiveDemo("http://127.0.0.1:1", "session-token", {"principal": "user:ada", "name": "Ada",
                                                                     "code": "c" * 43}, "http://127.0.0.1:2/mcp")
    demo.outputs = [{"status": "done", "detail": {"result": {"text": "plain text, eyJhbGciOi is no token"}}}]
    demo.check_tokens()
    for leaked in (TOKEN, "session-token"):
        demo.outputs.append({"status": "done", "detail": {"result": {"text": f"it says {leaked}"}}})
        with pytest.raises(hive_demo.Stop):
            demo.check_tokens()
        demo.outputs.pop()
    assert "session-token" not in capsys.readouterr().out


if __name__ == "__main__":  # the stand-in server for a rehearsal (see the top of this file)
    serve_stand_in(sys.argv[1:])
