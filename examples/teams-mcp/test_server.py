"""teams-mcp with a simulated Microsoft Graph: no request leaves this machine.

FakeGraph answers in memory in place of Graph (it replaces server.graph_send).
The MCP server runs on 127.0.0.1 in a thread of this process and is reached
with omega-connect's own MCP client. The last test walks the README demo
through omega-connect's actions in the fake hive of ../../tests.

    python -m pytest -q examples/teams-mcp
"""

import asyncio
import base64
import http.client
import importlib.util
import json
import logging
import os
import re
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

import pytest
import uvicorn

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "tests"))
os.environ["NO_PROXY"] = os.environ["no_proxy"] = "127.0.0.1,localhost"  # everything stays on this machine

from fakehive import FakeHive, run  # noqa: E402

TOKEN = "eyJ0eXAiOiJKV1Qi.graph-token-of-ada.Zk9mX3"
OTHER = "eyJ0eXAiOiJKV1Qi.graph-token-of-bob.Qm2vR8"
REFRESH = "rt-0aa1bb2cc3dd"
TEAM = "6f0d2c3e-5a1b-4c2d-9e3f-0123456789ab"
CHANNEL = "19:4b1c0d9e2f6a4e8b9c7d1e2f3a4b5c6d@thread.tacv2"
TENANT = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
CLIENT_ID = "11111111-2222-3333-4444-555555555555"
SCOPES = [f"https://graph.microsoft.com/{name}" for name in
          ("Team.ReadBasic.All", "Channel.ReadBasic.All", "ChannelMessage.Read.All", "ChannelMessage.Send")]
SWARM, PERSON, MIND = "demo", "ada", "scout"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _thread() -> list[dict]:
    return [
        {"id": "1003", "messageType": "message", "createdDateTime": "2026-11-12T09:30:00Z",
         "from": {"user": {"displayName": "Ada Lovelace"}},
         "body": {"contentType": "html", "content": '<p>Hi <at id="0">Bob</at>, the demo is at <b>3pm</b>&nbsp;'
                                                    '<emoji id="smile" alt="🙂" title="Smile"></emoji></p>'
                                                    "<p>Agenda below.</p>"}},
        {"id": "1002", "messageType": "systemEventMessage", "createdDateTime": "2026-11-12T09:10:00Z", "from": None,
         "body": {"contentType": "html", "content": "<systemEventMessage/>"}},
        {"id": "1001", "messageType": "message", "createdDateTime": "2026-11-12T09:00:00Z",
         "deletedDateTime": "2026-11-12T09:05:00Z", "from": {"user": {"displayName": "Bob"}},
         "body": {"contentType": "text", "content": ""}},
        {"id": "1000", "messageType": "message", "createdDateTime": "2026-11-12T08:00:00Z", "subject": "Weekly plan",
         "from": {"application": {"displayName": "Planner"}},
         "body": {"contentType": "text", "content": "Plan: ship the demo.\r\nThen rest."}},
    ]


class FakeGraph:
    """Microsoft Graph in memory: the calls the server makes, answered in Graph's shapes, each one recorded."""

    def __init__(self, base: str):
        self.base = base  # the server's Graph address; nothing is ever sent there
        self.tokens = {TOKEN}
        self.requests: list[dict] = []
        self.failure: tuple[int, dict, dict] | None = None  # (status, body, headers) for every request
        self.teams = [{"id": TEAM, "displayName": "Omega demo", "description": "Scratch team for the demo"}]
        self.channels = {TEAM: [{"id": CHANNEL, "displayName": "General", "description": "",
                                 "membershipType": "standard"}]}
        self.messages = {(TEAM, CHANNEL): _thread()}

    def send(self, method: str, url: str, headers: dict, body: bytes | None):
        assert url.startswith(self.base + "/"), url
        parts = urlsplit(url)
        path = parts.path[len(urlsplit(self.base).path):]
        query = {key: values[0] for key, values in parse_qs(parts.query).items()}
        self.requests.append({"method": method, "path": path, "query": query,
                              "authorization": headers.get("Authorization"),
                              "body": json.loads(body) if body else None})
        if self.failure:
            return self._reply(*self.failure)
        if headers.get("Authorization") not in {f"Bearer {token}" for token in self.tokens}:
            return self._error(401, "InvalidAuthenticationToken", "Access token validation failure.")
        if method == "GET" and path == "/me/joinedTeams":
            return self._reply(200, {"value": self.teams})
        match = re.fullmatch(r"/teams/([^/]+)/channels(?:/([^/]+)/messages)?", path)
        team, channel = match.groups() if match else (None, None)
        if team not in self.channels:
            return self._error(404, "NotFound", "No team found with that id.")
        if channel is None:
            return self._reply(200, {"value": self.channels[team]})
        thread = self.messages.get((team, unquote(channel)))
        if thread is None:
            return self._error(404, "NotFound", "No channel found with that id.")
        if method == "POST":
            message = {"id": str(2000 + len(thread)), "createdDateTime": "2026-11-12T10:00:00Z",
                       "messageType": "message", "from": {"user": {"displayName": "Ada Lovelace"}},
                       "body": json.loads(body)["body"], "webUrl": "https://teams.microsoft.com/l/message/demo"}
            thread.insert(0, message)
            return self._reply(201, message)
        top = int(query.get("$top", 20))
        if top > 50:
            return self._error(400, "BadRequest", "$top can be at most 50.")
        page = {"value": thread[:top]}
        if len(thread) > top:
            page["@odata.nextLink"] = f"{self.base}{path}?$skiptoken=next"
        return self._reply(200, page)

    @staticmethod
    def _reply(status: int, payload: dict, headers: dict | None = None):
        return status, {"Content-Type": "application/json", **(headers or {})}, json.dumps(payload).encode()

    def _error(self, status: int, code: str, message: str):
        return self._reply(status, {"error": {"code": code, "message": message}})


class Client:
    """omega-connect's MCP client, as the hive uses it: one session per token."""

    def __init__(self, engine_mod, url: str):
        self.engine_mod, self.url = engine_mod, url
        self.engine = engine_mod.McpEngine()
        self.names: dict = {}

    def spec(self, token):
        name = self.names.setdefault(token, f"teams-{len(self.names)}")  # never the token: names reach logs
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return self.engine_mod.ServerSpec(name=name, url=self.url, auth_headers=headers)

    def tools(self, token=TOKEN):
        return asyncio.run(self.engine.connect("tests", self.spec(token))).tools

    def call(self, tool, token=TOKEN, **arguments):
        return asyncio.run(self.engine.call("tests", self.spec(token), tool, arguments, retry_on_drop=False))


@pytest.fixture(scope="module")
def teams():
    return _load(HERE / "server.py", "teams_mcp_server")


@pytest.fixture(scope="module")
def program():
    module = _load(ROOT / "program.py", "omega_connect_program")
    yield module
    module.ENGINE.shutdown()


@pytest.fixture(scope="module")
def url(teams):
    """The server on 127.0.0.1, in a thread of this process so that the tests can swap its Graph."""
    sock = socket.socket()
    sock.bind((teams.HOST, 0))
    server = uvicorn.Server(uvicorn.Config(teams.http_app(), log_config=None, log_level="warning"))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    deadline = time.monotonic() + 20
    while not server.started:
        assert time.monotonic() < deadline, "the server did not start"
        time.sleep(0.05)
    yield f"http://{teams.HOST}:{sock.getsockname()[1]}/mcp"
    server.should_exit = True
    thread.join(timeout=10)


@pytest.fixture(autouse=True)
def graph(teams, monkeypatch):
    fake = FakeGraph(teams.GRAPH)
    monkeypatch.setattr(teams, "graph_send", fake.send)
    return fake


@pytest.fixture
def client(program, url):
    c = Client(program.engine_mod, url)
    yield c
    c.engine.shutdown()


# ------------------------------------------------------------------ tools

def test_three_tools_say_read_only_and_the_post_does_not(client):
    tools = client.tools()
    assert {name: tool.read_only_hint for name, tool in tools.items()} == {
        "list_teams": True, "list_channels": True, "read_channel_messages": True, "post_channel_message": False}
    schema = tools["read_channel_messages"].input_schema
    assert set(schema["required"]) == {"team_id", "channel_id"} and schema["properties"]["top"]["default"] == 20


def test_lists_teams_and_channels(client, graph):
    assert json.loads(client.call("list_teams").text) == {
        "teams": [{"id": TEAM, "name": "Omega demo", "description": "Scratch team for the demo"}]}
    assert json.loads(client.call("list_channels", team_id=TEAM).text) == {
        "channels": [{"id": CHANNEL, "name": "General", "membership": "standard"}]}
    assert [(r["method"], r["path"]) for r in graph.requests] == [("GET", "/me/joinedTeams"),
                                                                  ("GET", f"/teams/{TEAM}/channels")]
    assert graph.requests[1]["query"] == {"$select": "id,displayName,description,membershipType"}


def test_reads_a_channel_as_plain_text(client, graph):
    read = json.loads(client.call("read_channel_messages", team_id=TEAM, channel_id=CHANNEL, top=10).text)
    assert read == {"messages": [
        {"id": "1003", "at": "2026-11-12T09:30:00Z", "from": "Ada Lovelace",
         "text": "Hi Bob, the demo is at 3pm 🙂\nAgenda below."},
        {"id": "1000", "at": "2026-11-12T08:00:00Z", "from": "Planner", "subject": "Weekly plan",
         "text": "Plan: ship the demo.\nThen rest."},
    ]}  # the system event and the deleted message are left out
    assert graph.requests[-1]["path"] == f"/teams/{TEAM}/channels/{CHANNEL}/messages"
    assert graph.requests[-1]["query"] == {"$top": "10"}


def test_posts_plain_text_and_checks_it_first(client, graph):
    posted = json.loads(client.call("post_channel_message", team_id=TEAM, channel_id=CHANNEL,
                                    text="<b>Ship it</b> today").text)
    assert posted == {"posted": {"id": "2004", "at": "2026-11-12T10:00:00Z",
                                 "url": "https://teams.microsoft.com/l/message/demo"}}
    assert graph.requests[-1]["method"] == "POST"
    assert graph.requests[-1]["body"] == {"body": {"contentType": "text", "content": "<b>Ship it</b> today"}}
    for text in ("   ", "x" * 4001):
        refused = client.call("post_channel_message", team_id=TEAM, channel_id=CHANNEL, text=text)
        assert not refused.ok
    assert len(graph.requests) == 1


@pytest.mark.parametrize("team_id, channel_id", [
    ("../../me/messages", CHANNEL),
    (TEAM + "/members", CHANNEL),
    (TEAM, "19:abc@thread.tacv2/../../members"),
    (TEAM, "19:abc@thread.tacv2?$top=50"),
    (TEAM, "general"),
])
def test_ids_are_checked_before_graph_is_called(client, graph, team_id, channel_id):
    assert not client.call("read_channel_messages", team_id=team_id, channel_id=channel_id).ok
    assert not client.call("post_channel_message", team_id=team_id, channel_id=channel_id, text="hi").ok
    assert graph.requests == []


# ------------------------------------------------------------------ sizes

def test_results_are_capped_and_stay_whole_json(client, graph, teams):
    graph.teams = [{"id": f"00000000-0000-4000-8000-{n:012d}", "displayName": f"Team {n}", "description": "d" * 5000}
                   for n in range(500)]
    out = client.call("list_teams")
    listed = json.loads(out.text)
    assert listed["more"] is True and len(listed["teams"]) < teams.MAX_TEAMS
    assert len(out.text) <= teams.RESULT_CHARS and not out.truncated
    assert all(len(team["description"]) <= teams.DESCRIPTION_CHARS for team in listed["teams"])

    graph.messages[(TEAM, CHANNEL)] = [
        {"id": str(n), "messageType": "message", "createdDateTime": "2026-11-12T08:00:00Z",
         "from": {"user": {"displayName": "Ada"}}, "body": {"contentType": "html", "content": "<p>word </p>" * 3000}}
        for n in range(80)]
    out = client.call("read_channel_messages", team_id=TEAM, channel_id=CHANNEL, top=500)
    assert graph.requests[-1]["query"] == {"$top": "50"}  # Graph's own page limit
    read = json.loads(out.text)
    assert read["more"] is True and read["messages"]
    assert len(out.text) <= teams.RESULT_CHARS and not out.truncated
    assert all(len(message["text"]) <= teams.MESSAGE_CHARS for message in read["messages"])
    client.call("read_channel_messages", team_id=TEAM, channel_id=CHANNEL, top=0)
    assert graph.requests[-1]["query"] == {"$top": "1"}


# ------------------------------------------------------------------ the token

def test_each_call_uses_the_token_of_its_own_request(client, graph):
    graph.tokens.add(OTHER)
    for token in (TOKEN, OTHER, TOKEN):
        assert client.call("list_teams", token=token).ok
    assert [r["authorization"] for r in graph.requests] == [f"Bearer {TOKEN}", f"Bearer {OTHER}", f"Bearer {TOKEN}"]


@pytest.mark.parametrize("token", [None, "two words"])
def test_without_a_bearer_token_nothing_reaches_graph(client, graph, token):
    out = client.call("list_teams", token=token)
    assert not out.ok and "Authorization: Bearer" in out.text
    assert graph.requests == []


@pytest.mark.parametrize("status, code, says", [
    (401, "InvalidAuthenticationToken", "sign in again"),
    (403, "Forbidden", "delegated permissions"),
    (404, "NotFound", "no such team or channel"),
    (429, "TooManyRequests", "try again in 7 s"),
    (503, "ServiceUnavailable", "HTTP 503"),
])
def test_graph_errors_are_explained_without_the_token(client, graph, status, code, says):
    graph.failure = (status, {"error": {"code": code, "message": f"refused Bearer {TOKEN}"}}, {"Retry-After": "7"})
    out = client.call("list_teams")
    assert not out.ok and says in out.text and code in out.text
    assert TOKEN not in out.text


def test_the_token_is_never_logged(client, graph, caplog):
    caplog.set_level(logging.DEBUG)
    client.call("list_teams")
    client.call("read_channel_messages", team_id=TEAM, channel_id=CHANNEL)
    client.call("post_channel_message", team_id=TEAM, channel_id=CHANNEL, text="hello")
    client.call("list_channels", team_id="not-a-team")
    graph.failure = (401, {"error": {"code": "InvalidAuthenticationToken", "message": f"bad {TOKEN}"}}, {})
    client.call("list_teams")
    assert caplog.text and TOKEN not in caplog.text


# ------------------------------------------------------------------ this machine only

def test_listens_on_127_0_0_1_only(teams, monkeypatch):
    seen = {}
    monkeypatch.setattr(uvicorn, "run", lambda app, **options: seen.update(options))
    teams.main(["--port", "9999"])
    assert seen["host"] == "127.0.0.1" and seen["port"] == 9999
    with pytest.raises(SystemExit):
        teams.main(["--host", "0.0.0.0"])


@pytest.mark.parametrize("headers, status", [({"Host": "evil.example"}, 421),
                                             ({"Origin": "http://evil.example"}, 403)])
def test_requests_from_another_site_are_refused(url, graph, headers, status):
    """DNS rebinding: a web page elsewhere cannot drive the server through a browser on this machine."""
    parts = urlsplit(url)
    connection = http.client.HTTPConnection(parts.hostname, parts.port, timeout=10)
    call = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "list_teams", "arguments": {}}}
    connection.request("POST", parts.path, json.dumps(call), headers={
        "Content-Type": "application/json", "Accept": "application/json, text/event-stream",
        "Authorization": f"Bearer {TOKEN}", **headers})
    assert connection.getresponse().status == status
    connection.close()
    assert graph.requests == []


def test_the_real_transport_follows_no_redirect(teams):
    """urllib_send, used outside the tests: a redirect comes back as it is instead of carrying the token
    elsewhere, an error comes back with its body, and an unreachable address names no header."""
    seen = []

    class Stub(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            seen.append((self.path, self.headers.get("Authorization")))
            if self.path == "/moved":
                self.send_response(302)
                self.send_header("Location", "/elsewhere")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = json.dumps({"error": {"code": "Nope"}} if self.path == "/broken" else {"value": []}).encode()
            self.send_response(500 if self.path == "/broken" else 200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    stub = ThreadingHTTPServer(("127.0.0.1", 0), Stub)
    threading.Thread(target=stub.serve_forever, daemon=True).start()
    base, auth = f"http://127.0.0.1:{stub.server_port}", {"Authorization": f"Bearer {TOKEN}"}
    try:
        assert teams.urllib_send("GET", base + "/fine", auth, None)[::2] == (200, b'{"value": []}')
        assert teams.urllib_send("GET", base + "/moved", auth, None)[0] == 302
        assert teams.urllib_send("GET", base + "/broken", auth, None)[::2] == (500, b'{"error": {"code": "Nope"}}')
        assert seen == [(path, f"Bearer {TOKEN}") for path in ("/fine", "/moved", "/broken")]  # never /elsewhere
    finally:
        stub.shutdown()
        stub.server_close()
    with pytest.raises(teams.ToolError) as unreachable:
        teams.urllib_send("GET", base + "/fine", auth, None)
    assert "unreachable" in str(unreachable.value) and TOKEN not in str(unreachable.value)


# ------------------------------------------------------------------ the README demo

def test_the_demo_through_omega_connect(program, url, graph, tmp_path, monkeypatch, caplog):
    """add-server with an oauth-device sign-in, connect, list-tools, accept-reads, read-tool on the channel,
    then use-tool waiting for a person and posting once approved. The token stays between omega-connect and
    Graph."""
    caplog.set_level(logging.DEBUG)
    from cryptography.fernet import Fernet

    monkeypatch.setenv("OMEGA_CONNECT_DATA_DIR", str(tmp_path / "store"))
    monkeypatch.setenv("OMEGA_CONNECT_SECRET_KEY", Fernet.generate_key().decode())
    asked = []
    claims = base64.urlsafe_b64encode(json.dumps({"preferred_username": "ada@omegademo.example"}).encode())
    id_token = f"eyJhbGciOiJSUzI1NiJ9.{claims.decode().rstrip('=')}.c2ln"

    def identity_platform(address, form):  # the Microsoft identity platform, in memory
        asked.append((address, form.get("scope")))
        if address.endswith("/devicecode"):
            return {"device_code": "dev-1", "user_code": "ABCD-1234", "expires_in": 60, "interval": 1,
                    "verification_uri": "https://microsoft.com/devicelogin"}
        return {"access_token": TOKEN, "refresh_token": REFRESH, "expires_in": 3600, "scope": " ".join(SCOPES),
                "id_token": id_token}

    monkeypatch.setattr(program.oauth_mod, "_post", identity_platform)
    hive = FakeHive(program)
    hive.attach(MIND, "list-tools", "allow")
    hive.attach(MIND, "read-tool", "allow")
    hive.attach(MIND, "use-tool", "ask")

    def person(action, items, params):
        outputs.append(run(hive.person_act(SWARM, PERSON, action, items, params, confirmed=True)))
        return outputs[-1]

    def mind(action, key, approval_id=None, **params):
        outputs.append(run(hive.agent_act(SWARM, MIND, action, params, key, approval_id)))
        return outputs[-1]

    outputs = []
    signin = {"kind": "oauth-device", "tenant": TENANT, "client_id": CLIENT_ID, "scopes": SCOPES}
    assert person("add-server", [], {"name": "teams", "url": url, "signin": signin})["status"] == "done"

    assert person("connect", ["server:teams"], {})["detail"]["user_code"] == "ABCD-1234"
    store = program.store_mod.SwarmStore(SWARM)
    for _ in range(100):
        if store.has_credentials("teams"):
            break
        time.sleep(0.1)
    assert asked[0] == (f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/devicecode",
                        " ".join(SCOPES + ["openid", "profile", "offline_access"]))
    server_item = next(i for i in run(hive.view(SWARM, PERSON))["items"] if i["id"] == "server:teams")
    assert "signed in as ada@omegademo.example" in server_item["text"] and "ABCD-1234" not in server_item["text"]

    tools = mind("list-tools", "k1", server="teams")["detail"]["tools"]["teams"]
    assert {tool["name"]: tool["class"] for tool in tools} == dict.fromkeys(
        ("list_teams", "list_channels", "read_channel_messages", "post_channel_message"), "write")
    accepted = person("accept-reads", ["server:teams"], {})  # a person looks at the tools and accepts the reads
    assert accepted["detail"] == {"accepted": ["list_channels", "list_teams", "read_channel_messages"],
                                  "still_write": ["post_channel_message"]}
    tools = mind("list-tools", "k1", server="teams")["detail"]["tools"]["teams"]
    assert {tool["name"]: tool["class"] for tool in tools} == {
        "list_teams": "read", "list_channels": "read", "read_channel_messages": "read",
        "post_channel_message": "write"}

    where = {"team_id": TEAM, "channel_id": CHANNEL}
    read = mind("read-tool", "k2", server="teams", tool="read_channel_messages", arguments={**where, "top": 10})
    assert read["status"] == "done" and read["detail"]["result"]["untrusted"] is True
    assert json.loads(read["detail"]["result"]["text"])["messages"][0]["from"] == "Ada Lovelace"
    assert mind("read-tool", "k3", server="teams", tool="post_channel_message",
                arguments={**where, "text": "hi"})["status"] == "refused"

    post = {**where, "text": "Summary: the demo is at 3pm, agenda in the channel."}
    waiting = mind("use-tool", "w1", server="teams", tool="post_channel_message", arguments=post)
    assert waiting["status"] == "approval_required"
    assert [r for r in graph.requests if r["method"] == "POST"] == []  # nothing posted before a person says yes
    hive.approve(waiting["approval_id"], PERSON)
    done = mind("use-tool", "w1", waiting["approval_id"], server="teams", tool="post_channel_message", arguments=post)
    assert done["status"] == "done" and json.loads(done["detail"]["result"]["text"])["posted"]["id"]
    posts = [r for r in graph.requests if r["method"] == "POST"]
    assert len(posts) == 1 and posts[0]["body"]["body"]["content"] == post["text"]
    assert {r["authorization"] for r in graph.requests} == {f"Bearer {TOKEN}"}  # the person who signed in

    outputs.append(run(hive.view(SWARM, PERSON)))
    stored = "".join(p.read_text("utf-8", errors="ignore") for p in (tmp_path / "store").rglob("*") if p.is_file())
    blob = json.dumps(outputs) + caplog.text + stored
    assert TOKEN not in blob and REFRESH not in blob and id_token not in blob
    program.ENGINE.forget(SWARM, "teams")
