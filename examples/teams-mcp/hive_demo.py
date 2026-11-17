"""The Teams demo on a real hive (the Mac test build), with the mind's calls made by hand.

For a scratch hive in ~/OmegaHive with omega-connect mounted (README, "On a scratch
hive (Mac test build)") and teams-mcp running. On that build a mind cannot call an
app's actions by itself yet, so this script makes the mind's calls in its place, at
POST /api/agent/programs/omega-connect/act with the mind's own token: list-tools,
read-tool on list_teams, list_channels and read_channel_messages, then use-tool
posting a message. The hive answers approval_required; once you have approved, the
script sends the same request again with the approval_id.

    python examples/teams-mcp/hive_demo.py

You are the hive's owner, a named person. What the hive's pages can do, you do
there, and the script waits and goes on by itself: accept-reads on the app's page,
the approval on the Approvals page (it can send either with your sign-in if you
choose so). What the pages cannot do yet, the script does with your sign-in, after
a yes at the terminal: add-server, whose parameters the page has no form for, and
connect with the browser sign-in. It also makes the demo mind and its three rules,
since the mind's token is returned only by the request that creates it.

Your session comes from a one-time link (omegahive.sh signin-url) and is ended when
the script stops. That link, your session's token, the mind's token, the hive's
confirm tokens and the address your browser lands on after the Microsoft sign-in
stay in this process's memory: they are never printed or written anywhere, and the
address is not shown as you paste it. The tenant ID and the client ID are asked
only when the server is not in the hive yet, and shown by their first characters.
Standard library only, with terminal_input.py beside it, so any Python 3.10+ runs it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.request
import uuid
import webbrowser
from pathlib import Path
from urllib.parse import parse_qs, quote, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))

from terminal_input import UNSAFE, Stop, ask, ask_hidden, ask_id  # noqa: E402

APP_ID = "omega-connect"
SERVER_NAME = "teams"
DEFAULT_SERVER_URL = "http://127.0.0.1:8765/mcp"
SWARM_NAME = "omega-connect demo"
MIND_NAME = "connect-scout"
# How a later run knows the mind an earlier one left behind; its token ended with that run.
MIND_PERSONA = ("Demo mind of omega-connect. Its calls to the app are made by examples/teams-mcp/hive_demo.py; "
                "the hive never starts it.")
RULES = (("list-tools", "allow"), ("read-tool", "allow"), ("use-tool", "ask"))
POST_TOOL = "post_channel_message"
SCOPES = [f"https://graph.microsoft.com/{name}" for name in
          ("Team.ReadBasic.All", "Channel.ReadBasic.All", "ChannelMessage.Read.All", "ChannelMessage.Send")]
GUID = re.compile(r"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}")
DOMAIN = re.compile(r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
# What omegahive.sh signin-url prints: the hive's own address on this machine, and a code that works once.
SIGNIN_LINK = re.compile(r"(http://(?:127\.0\.0\.1|localhost):[0-9]{1,5})/local-signin#([A-Za-z0-9_-]{43})")
JWT = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}")  # the shape of an access token
HINT = "See 'If something fails' in examples/teams-mcp/README.md."
DEFAULT_POST = ("Test message from omega-connect: a mind read this channel and asked to post here, "
                "and a person approved.")
POLL = 2.0  # seconds between two looks at what the person did in the hive's pages
ACCEPT_WAIT = 600  # seconds the script waits for accept-reads there
APPROVAL_WAIT = 900  # and for the approval
ACT_TIMEOUT = 240  # an act may connect, sign in again and try a write that did not arrive a few times


class Refusal(Exception):
    """An error answer of the hive: its HTTP status, and the code and message it gives."""

    def __init__(self, status: int, code: str, message: str):
        super().__init__(f"{status} {code}: {message}")
        self.status, self.code, self.message = status, code, message


def ask_choice(prompt: str, choices: tuple[str, ...], default: str | None = None) -> str:
    while True:
        answer = ask(prompt).lower() or (default or "")
        if answer in choices:
            return answer


def _mask(value: str) -> str:
    """Enough of an id to recognise it on screen, or in a recording."""
    return value if len(value) <= 12 else value[:8] + "…"


def _short(text: str, limit: int) -> str:
    text = " ".join(str(text or "").split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _key(action: str) -> str:
    return f"{action}-{uuid.uuid4().hex[:12]}"


def open_in_browser(url: str) -> bool:
    """Opens the address in the person's own browser without printing it. False where there is no
    graphical browser: a text one would take over this terminal."""
    if sys.platform not in ("darwin", "win32") and not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        return False
    try:
        return webbrowser.open(url)
    except webbrowser.Error:
        return False


def payload_digest(payload: dict) -> str:
    """The digest a host confirm token is minted for (hive/PROGRAMS.md, 9d): sha256 of the payload's
    canonical JSON, keys sorted, no spaces, non-ASCII as it is."""
    text = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


# ------------------------------------------------------------------ HTTP

class _NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # a redirect would carry a token to another address; it fails instead


# Straight to the hive on this machine: no proxy, no redirect.
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirects)


def send(method: str, url: str, body: dict | None = None, token: str | None = None, origin: str | None = None,
         timeout: float = 60):
    """One JSON request to the hive. A person's session needs the hive's own Origin on every request
    that changes something; a mind's token needs none. An error answer raises Refusal."""
    request = urllib.request.Request(url, data=None if body is None else json.dumps(body).encode("utf-8"),
                                     method=method)
    request.add_header("Content-Type", "application/json")
    if origin:
        request.add_header("Origin", origin)
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with _OPENER.open(request, timeout=timeout) as response:
            return json.loads(response.read() or b"null")
    except urllib.error.HTTPError as exc:
        with exc:
            raw = exc.read()
        try:
            error = json.loads(raw or b"null")
        except ValueError:
            error = None
        error = error.get("error", error) if isinstance(error, dict) else {}
        error = error if isinstance(error, dict) else {}
        raise Refusal(exc.code, str(error.get("code") or "error"),
                      str(error.get("message") or error.get("detail") or exc.reason)) from None
    except (urllib.error.URLError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        print(f"\n✗ The hive does not answer at {urlsplit(url).netloc} ({reason.__class__.__name__}).")
        raise Stop from None


def owner_signin(home: Path) -> tuple[str, str, dict]:
    """A session of the hive's owner: (the hive's address, the session's token, who signed in).
    omegahive.sh signin-url prints a link that works once, within a minute; the code after its # goes
    to POST /api/auth/local/exchange with the hive's own Origin. Neither is printed."""
    launcher = home / "app" / "install" / "macos" / "omegahive.sh"
    if not launcher.is_file():
        print(f"✗ No hive at {home}: {launcher} is not there. Give its folder with --hive-home.")
        raise Stop
    try:
        done = subprocess.run([str(launcher), "signin-url"], capture_output=True, text=True, timeout=240,
                              stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        print("✗ omegahive.sh signin-url did not answer; is the hive running?")
        raise Stop from None
    link = SIGNIN_LINK.search(done.stdout or "")
    if done.returncode != 0 or not link:
        print("✗ The hive gave no sign-in link. Start it with omegahive.sh start, or open Omega Hive.")
        said = SIGNIN_LINK.sub("[link removed]", UNSAFE.sub("", (done.stderr or "").strip()))
        if said:
            print("  " + said[-600:])
        raise Stop
    base, code = link.groups()
    try:
        session = send("POST", base + "/api/auth/local/exchange", {"code": code}, origin=base)
    except Refusal as exc:
        print(f"✗ The hive did not take its own sign-in link ({exc.status} {exc.code}); run the demo again.")
        raise Stop from None
    user = session.get("user") or {}
    if not session.get("token") or not user.get("id"):
        print("✗ The sign-in link did not give the session of the hive's owner.")
        raise Stop
    return base, session["token"], {"principal": f"user:{user['id']}", "name": user.get("name") or "the owner",
                                    "code": code}


class HiveDemo:
    def __init__(self, base: str, session: str, owner: dict, server_url: str, signin: bool = True,
                 swarm_name: str = SWARM_NAME):
        self.base, self.session, self.server_url, self.signin = base, session, server_url, signin
        self.swarm_name = swarm_name
        self.me, self.my_name = owner["principal"], owner["name"]
        self.secrets = {session, owner["code"]}  # every secret value this run holds, to keep off the screen
        self.outputs: list = []  # every result and view the app gave, for the check at the end
        self.confirm_actions: set[str] = set()
        self.swarm = self.mind = self.mind_token = None
        self.tools: list[dict] = []  # the server's tools as the mind's list-tools gave them
        self.started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self.steps = 0

    # ---------------------------------------------------------------- output
    def redact(self, text: str) -> str:
        """Terminal controls dropped, and the secret values of this run replaced."""
        text = UNSAFE.sub("", str(text))
        for secret in self.secrets:
            text = text.replace(secret, "[removed]")
        return text

    def say(self, text: str = "", indent: int = 0) -> None:
        pad = " " * indent
        print("\n".join(pad + line if line else line for line in self.redact(text).split("\n")), flush=True)

    def step(self, title: str, who: str) -> None:
        self.steps += 1
        self.say(f"\n[{self.steps}] {title}  ·  {who}")

    def call_line(self, action: str, params: dict, items: list | None = None) -> None:
        target = f" {' '.join(items)}" if items else ""
        self.say(f"→ {action}{target} {json.dumps(params, ensure_ascii=False)}", 2)

    def yes(self, question: str) -> bool:
        return ask_choice(f"  {question} (y/n): ", ("y", "yes", "n", "no")).startswith("y")

    # ---------------------------------------------------------------- the hive
    def person(self, method: str, path: str, body: dict | None = None, timeout: float = 60):
        """A request in the owner's session, with the hive's own Origin."""
        return send(method, self.base + path, body, token=self.session, origin=self.base, timeout=timeout)

    def person_act(self, action: str, items: list, params: dict, base_revision: str | None = None) -> dict:
        """POST /api/programs/omega-connect/act as the owner. An action that declares confirm needs
        the hive's confirm token first: POST .../confirm with the act's payload and its digest gives
        one, good for this act alone, once, for two minutes."""
        body = {"swarm_id": self.swarm["id"], "action": action, "items": items, "params": params,
                "base_revision": base_revision}
        if action in self.confirm_actions:
            payload = {"items": items, "params": params, "base_revision": base_revision}
            minted = self.person("POST", f"/api/programs/{APP_ID}/confirm",
                                 {"swarm_id": self.swarm["id"], "action": action, "payload": payload,
                                  "payload_digest": payload_digest(payload)})
            self.secrets.add(minted["confirm_token"])
            body["confirm_token"] = minted["confirm_token"]
        result = self.person("POST", f"/api/programs/{APP_ID}/act", body, timeout=ACT_TIMEOUT)
        self.outputs.append(result)
        return result

    def mind_act(self, action: str, params: dict, key: str | None = None, approval_id: str | None = None) -> dict:
        """POST /api/agent/programs/omega-connect/act with the mind's token. The hive takes who acts
        and in which swarm from the token: a body that names them is refused."""
        body = {"action": action, "params": params, "idempotency_key": key or _key(action)}
        if approval_id:
            body["approval_id"] = approval_id
        result = send("POST", f"{self.base}/api/agent/programs/{APP_ID}/act", body, token=self.mind_token,
                      timeout=ACT_TIMEOUT)
        self.outputs.append(result)
        return result

    def view(self) -> dict:
        graph = self.person("POST", f"/api/programs/{APP_ID}/view", {"swarm_id": self.swarm["id"]})
        self.outputs.append(graph)
        return graph

    def server_item(self, graph: dict | None = None) -> dict | None:
        return next((item for item in (graph or self.view())["items"] if item["id"] == f"server:{SERVER_NAME}"), None)

    def tool_classes(self, graph: dict) -> dict[str, str]:
        """Each tool of the server in the view, with the first line of its text: "Class: read (...)"."""
        prefix = f"tool:{SERVER_NAME}/"
        return {item["id"][len(prefix):]: item["text"].split("\n", 1)[0]
                for item in graph["items"] if item["id"].startswith(prefix)}

    def need(self, result: dict, what: str, hint: str = "") -> dict:
        if result.get("status") == "done":
            return result
        self.say(f"✗ {what}: {result.get('status')}. {result.get('message', '')}", 2)
        text = ((result.get("detail") or {}).get("result") or {}).get("text")
        if text:
            self.say(text, 4)
        if hint:
            self.say(hint, 2)
        raise Stop

    def data(self, result: dict) -> dict:
        try:
            return json.loads(result["detail"]["result"]["text"])
        except (KeyError, TypeError, ValueError):
            self.say("✗ The server answered with text that is not JSON.", 2)
            raise Stop from None

    def read(self, tool: str, arguments: dict) -> tuple[dict, dict]:
        params = {"server": SERVER_NAME, "tool": tool, "arguments": arguments}
        self.call_line("read-tool", params)
        result = self.need(self.mind_act("read-tool", params), f"read-tool {tool}", HINT)
        return result, self.data(result)

    def page(self, fragment: str) -> str:
        """An address of the hive's own page, for the person to open where they are signed in."""
        return f"{self.base}/#/{fragment}"

    # ---------------------------------------------------------------- steps
    def run(self) -> None:
        self.check_app()
        self.check_server()
        self.prepare()
        self.add_server()
        if self.signin:
            self.connect()
        self.list_tools()
        self.accept_reads()
        team = self.pick_team()
        channel = self.pick_channel(team)
        self.read_messages(team, channel)
        self.post(team, channel)
        self.show_trace()
        self.check_tokens()
        self.say("\nThe demo mind stays in the hive, so you can show it there; its token ended with this run.\n"
                 "The next run replaces it, and `hive_demo.py --cleanup` deletes it.")
        if self.signin:
            self.say(f"Your Microsoft sign-in stays in the app's store, encrypted. To delete it: on the app's "
                     f"page select the server '{SERVER_NAME}', then Revoke sign-in.")

    def check_app(self) -> None:
        """The app as the hive loaded it; its describe says which actions need the hive's confirm."""
        try:
            app = self.person("GET", f"/api/programs/{APP_ID}")
        except Refusal as exc:
            if exc.status != 404:
                raise
            self.say(f"✗ This hive has no app '{APP_ID}' ({exc.status} {exc.code}). Mount it first: "
                     "examples/teams-mcp/README.md, 'On a scratch hive (Mac test build)'.")
            raise Stop from None
        if app.get("error") or app.get("enabled") is False:
            self.say(f"✗ The hive did not load '{APP_ID}': {app.get('error') or 'it is disabled'}")
            raise Stop
        actions = (app.get("describe") or {}).get("actions") or []
        self.confirm_actions = {action["id"] for action in actions if action.get("confirm") is True}
        self.say(f"Hive             {self.base}, signed in as its owner {self.my_name} (user:{_mask(self.me[5:])})")
        self.say(f"App              {APP_ID} {app.get('version', '')} ({app.get('source', 'loaded')})")

    def check_server(self) -> None:
        parts = urlsplit(self.server_url)
        try:
            socket.create_connection((parts.hostname, parts.port or 80), timeout=3).close()
        except (OSError, ValueError):
            self.say(f"✗ teams-mcp does not answer at {self.server_url}. Start it on this machine, in another "
                     "terminal:\n    python examples/teams-mcp/server.py --port 8765")
            raise Stop from None
        self.say(f"teams-mcp        {self.server_url}"
                 + ("" if self.signin else "  (a stand-in: no Microsoft sign-in)"))

    def prepare(self) -> None:
        """The swarm of the demo, a new mind in it and the mind's three rules. The mind's token comes
        back only from the request that creates the mind, so the script makes that request and keeps the
        token in memory; the rules name the new mind, so it writes them too."""
        self.step("swarm, mind and rules", "you, through the hive's API with your sign-in")
        self.find_swarm()
        for old in self.leftover_minds():
            self.say(f"A demo mind of an earlier run is still there ({old['id']}); its token ended with that "
                     "run, so it is deleted.", 2)
            self.delete_mind(old["id"])
        try:
            mind = self.person("POST", "/api/agents", {"name": MIND_NAME, "kind": "omega",
                                                       "swarm_id": self.swarm["id"], "persona": MIND_PERSONA})
        except Refusal as exc:
            self.say(f"✗ The hive did not create the mind: {exc.status} {exc.code}. {exc.message}", 2)
            raise Stop from None
        self.mind, self.mind_token = mind, mind.pop("token")
        self.secrets.add(self.mind_token)
        self.say(f"mind      {MIND_NAME} ({mind['id']}), {mind.get('status', 'created')}: the hive never starts "
                 "it, and its token stays in this process's memory", 2)
        for action, mode in RULES:
            self.person("POST", "/api/policy", {"scope": f"agent:{mind['id']}", "skill": f"program:{APP_ID}:{action}",
                                                "mode": mode, "note": "omega-connect demo"})
        self.say("rules     " + ", ".join(f"{action} {mode}" for action, mode in RULES), 2)
        self.say(f"The app's page for this swarm: {self.page(f'program/{APP_ID}/{self.swarm_id_quoted()}')}", 2)

    def swarm_id_quoted(self) -> str:
        return quote(self.swarm["id"], safe="")

    def find_swarm(self) -> None:
        mine = [swarm for swarm in self.person("GET", "/api/swarms")
                if swarm.get("name") == self.swarm_name and swarm.get("owner") == self.me
                and not swarm.get("archived_at")]
        if mine:
            self.swarm = mine[0]
            self.say(f"swarm     {self.swarm_name} ({self.swarm['id']}), from an earlier run", 2)
            return
        self.swarm = self.person("POST", "/api/swarms", {
            "name": self.swarm_name, "description": "A mind uses Microsoft Teams through omega-connect; a person "
                                                    "approves what it posts."})
        self.say(f"swarm     {self.swarm_name} ({self.swarm['id']}), new and private to you", 2)

    def leftover_minds(self) -> list[dict]:
        return [mind for mind in self.person("GET", "/api/agents")
                if mind.get("swarm_id") == self.swarm["id"] and mind.get("name") == MIND_NAME
                and mind.get("persona") == MIND_PERSONA]

    def delete_mind(self, mind_id: str) -> None:
        """A demo mind of this script, with what was written for it: its rules, and a request of its
        that still waits for a person (nobody holds the token to send it again)."""
        for approval in self.person("GET", "/api/approvals?status=pending"):
            if approval.get("agent_id") == mind_id:
                self.person("POST", f"/api/approvals/{quote(approval['id'], safe='')}/deny", {})
        for rule in self.person("GET", "/api/policy"):
            if rule.get("scope") == f"agent:{mind_id}":
                self.person("DELETE", f"/api/policy/{quote(rule['id'], safe='')}")
        self.person("DELETE", f"/api/agents/{quote(mind_id, safe='')}")

    def cleanup(self) -> None:
        """--cleanup: only delete the demo minds earlier runs left."""
        self.check_app()
        deleted = 0
        for swarm in self.person("GET", "/api/swarms"):
            if swarm.get("name") == self.swarm_name and swarm.get("owner") == self.me:
                self.swarm = swarm
                for old in self.leftover_minds():
                    self.delete_mind(old["id"])
                    deleted += 1
        self.say(f"\n✓ {deleted} demo mind(s) deleted, with their rules." if deleted else "\nNo demo mind to delete.")
        self.say(f"The swarm '{self.swarm_name}', its server and your sign-in are yours to remove, on the app's page "
                 "(Revoke sign-in, Remove server) and the swarm's.")

    def add_server(self) -> None:
        self.step("add-server", "you, confirmed here: the app's page has no form for its parameters")
        there = self.server_item()
        if there is not None:
            lines = there["text"].splitlines()
            address = next((line[len("Address: "):] for line in lines if line.startswith("Address: ")), "")
            kind = next((line for line in lines if line.startswith("Sign-in: ")), "")
            wanted = "Sign-in: oauth-device" if self.signin else "Sign-in: none"
            if address != self.server_url or not kind.startswith(wanted):
                self.say(f"✗ A server named '{SERVER_NAME}' is already in this swarm, with another address or "
                         f"sign-in ({address}; {kind}).", 2)
                self.say("Remove it on the app's page (select it, then Remove server) and run the demo again.", 2)
                raise Stop
            self.say(f"✓ Already there: {SERVER_NAME} → {address}", 2)
            return
        signin = {"kind": "none"}
        if self.signin:
            self.say("The server is not in the hive yet: it needs the tenant ID and the client ID of the app "
                     "registration (README, 'Before the demo').", 2)
            tenant = ask_id("  Tenant ID (Directory ID): ",
                            lambda v: len(v) <= 100 and bool(GUID.fullmatch(v) or DOMAIN.fullmatch(v)),
                            "Give the tenant ID (a GUID) or its domain: a single-tenant app does not accept "
                            "'organizations'.")
            client_id = ask_id("  Client ID (Application ID): ", lambda v: bool(GUID.fullmatch(v)),
                               "Give the Application (client) ID: a GUID.")
            signin = {"kind": "oauth-device", "tenant": tenant, "client_id": client_id, "scopes": SCOPES}
            self.say(f"sign-in   oauth-device · tenant {_mask(tenant)} · client {_mask(client_id)}", 2)
            self.say(f"scope     {', '.join(scope.rsplit('/', 1)[1] for scope in SCOPES)}", 2)
            self.say("          (+ openid, profile, offline_access, added by the app)", 2)
        self.say(f"server    {SERVER_NAME} → {self.server_url}", 2)
        if not self.yes(f"Add this server as {self.my_name}?"):
            self.say("✗ Not confirmed: nothing was sent.", 2)
            raise Stop
        result = self.need(self.person_act("add-server", [], {"name": SERVER_NAME, "url": self.server_url,
                                                              "signin": signin}), "add-server")
        self.say(f"✓ {result['message']}", 2)

    def connect(self) -> None:
        """connect with the browser sign-in (authorization code with PKCE). The app's page can only
        send connect without parameters, which is the device code; a tenant whose security defaults
        block that code needs {"flow": "browser"}, so the script sends it."""
        self.step("connect", "you, confirmed here: the browser sign-in")
        state = self.signin_line()
        if "signed in by" in state:
            self.say(f"✓ Already signed in. {state}", 2)
            return
        if not self.yes(f"Sign in to '{SERVER_NAME}' as {self.my_name}, with your Microsoft account?"):
            self.say("✗ Not confirmed: nothing was sent.", 2)
            raise Stop
        self.call_line("connect", {"flow": "browser"}, [f"server:{SERVER_NAME}"])
        started = self.person_act("connect", [f"server:{SERVER_NAME}"], {"flow": "browser"})
        if started.get("status") == "done":  # the answer of another sign-in, whose message is not for this screen
            self.say("✗ connect did not start a browser sign-in.", 2)
            raise Stop
        if started.get("status") != "needs_input":
            self.need(started, "connect", HINT)  # says why, then stops
        detail = started["detail"]
        if open_in_browser(detail["authorization_url"]):
            self.say("The sign-in page is open in your browser (its address carries the tenant and client IDs, "
                     "so it is not printed here).", 2)
        else:
            self.say("No browser opens from here. Open this address in one; it carries the tenant and client "
                     "IDs in full, so pause a recording first:", 2)
            self.say(detail["authorization_url"], 4)
        self.say("Sign in with an account of the tenant and accept the permissions. The browser then lands on an "
                 f"empty page whose address starts with {detail['redirect_uri']}: copy that whole address.", 2)
        while True:
            landed = ask_hidden("  Paste the address the browser landed on (it is not shown; Enter alone stops): ")
            if not landed:
                raise Stop
            # The code in it works once, with the app's PKCE verifier; still, it never reaches the screen.
            self.secrets.update(code for code in parse_qs(urlsplit(landed).query).get("code", []) if len(code) >= 16)
            self.say(f"({len(landed):,} characters received)", 2)
            self.call_line("connect", {"redirect_url": "<the address you pasted>"}, [f"server:{SERVER_NAME}"])
            finished = self.person_act("connect", [f"server:{SERVER_NAME}"], {"redirect_url": landed})
            if finished.get("status") == "done":
                break
            self.say(f"✗ {finished.get('message', '')}", 2)
            if finished.get("status") != "error":  # refused: no sign-in is waiting any more (expired)
                self.say(HINT, 2)
                raise Stop
            self.say("The sign-in is still open: paste the address again, or sign in again from the same page.", 2)
        self.say(f"✓ In the view: {self.signin_line()}", 2)
        self.say("The token stays encrypted in the app's store; the view shows neither the token nor the code.", 2)

    def signin_line(self) -> str:
        server = self.server_item() or {"text": ""}
        return next((line for line in server["text"].splitlines() if line.startswith("Sign-in")), "")

    def list_tools(self) -> None:
        self.step("list-tools", f"mind {MIND_NAME}, rule allow")
        params = {"server": SERVER_NAME}
        self.call_line("list-tools", params)
        tools = self.need(self.mind_act("list-tools", params), "list-tools")["detail"]["tools"].get(SERVER_NAME)
        if not isinstance(tools, list):
            self.say(f"✗ {(tools or {}).get('error', 'the app listed no tools for this server')}", 2)
            self.say(HINT, 2)
            raise Stop
        for tool in tools:
            self.say(f"{tool['name']:<24} {tool['class']:<6} {tool.get('review', '')}", 4)
            self.say(_short(tool["description"], 90), 6)
        self.tools = tools

    def accept_reads(self) -> None:
        self.step("accept-reads", "you, a person")
        waiting = sorted(tool["name"] for tool in self.tools if tool.get("review") in ("not reviewed",
                                                                                       "changed since review"))
        if not waiting:
            reads = sorted(tool["name"] for tool in self.tools if tool["class"] == "read")
            self.say(f"✓ Already accepted as read: {', '.join(reads) or 'none'}", 2)
            return
        self.say(f"The server marks {', '.join(waiting)} read-only. Its hint counts only once a person has "
                 "accepted it; until then every tool is write.", 2)
        self.say("Where do you accept them?", 2)
        self.say(f"1. on the app's page: select the server '{SERVER_NAME}', then Accept read-only tools, and confirm",
                 4)
        self.say(self.page(f"program/{APP_ID}/{self.swarm_id_quoted()}"), 7)
        self.say("2. here: the script sends accept-reads with your sign-in", 4)
        if ask_choice("  Where [1]: ", ("1", "2"), "1") == "2":
            graph = self.view()
            for _ in range(2):  # once more if the page changed in between
                params = {"base_revision": graph["revision"]}
                self.call_line("accept-reads", params, [f"server:{SERVER_NAME}"])
                result = self.person_act("accept-reads", [f"server:{SERVER_NAME}"], {}, graph["revision"])
                if result.get("status") != "stale":
                    break
                graph = result.get("graph") or self.view()
            self.need(result, "accept-reads")
            graph = self.view()
        else:
            def accepted():
                graph = self.view()
                classes = self.tool_classes(graph)
                return graph if all(classes.get(name, "").startswith("Class: read") for name in waiting) else None

            graph = self.wait_for("accept-reads on the app's page", ACCEPT_WAIT, accepted)
        classes = self.tool_classes(graph)
        reads = sorted(name for name, line in classes.items() if line.startswith("Class: read"))
        self.say(f"✓ read:  {', '.join(reads)}", 2)
        by = re.search(r"accepted by ([^;)]+)", classes.get(reads[0], "")) if reads else None
        if by:
            self.say(f"  accepted by {by.group(1)}", 2)
        writes = sorted(name for name, line in classes.items() if line.startswith("Class: write"))
        if writes:
            self.say(f"  write: {', '.join(writes)} (the server does not mark it read-only)", 2)

    def wait_for(self, what: str, seconds: float, look):
        """Looks every POLL seconds until `look` returns something, which it then returns."""
        found = look()
        if found is not None:
            return found
        self.say(f"… waiting for {what} (Ctrl-C stops the demo)", 2)
        deadline = time.monotonic() + seconds
        reminder = time.monotonic() + 30
        while True:
            time.sleep(POLL)
            found = look()
            if found is not None:
                return found
            now = time.monotonic()
            if now > deadline:
                self.say(f"✗ Still waiting for {what} after {int(seconds // 60)} minutes: the demo stops here.", 2)
                raise Stop
            if now > reminder:
                self.say(f"… still waiting for {what}", 2)
                reminder = now + 30

    def pick_team(self) -> dict:
        self.step("read-tool list_teams", f"mind {MIND_NAME}, rule allow")
        _, data = self.read("list_teams", {})
        teams = data.get("teams") or []
        if not teams:
            self.say("✗ The account is not a member of any team.", 2)
            raise Stop
        return self.choose(teams, "team", data.get("more"))

    def pick_channel(self, team: dict) -> dict:
        self.step("read-tool list_channels", f"mind {MIND_NAME}, rule allow")
        _, data = self.read("list_channels", {"team_id": team["id"]})
        channels = data.get("channels") or []
        if not channels:
            self.say("✗ The account sees no channel in this team.", 2)
            raise Stop
        return self.choose(channels, "channel", data.get("more"))

    def choose(self, entries: list[dict], what: str, more: bool) -> dict:
        for number, entry in enumerate(entries, 1):
            notes = [entry["membership"]] if entry.get("membership") not in (None, "standard") else []
            notes += [_short(entry["description"], 60)] if entry.get("description") else []
            name = entry.get("name") or entry["id"]
            self.say(f"{number:>3}. {name}" + (f"  ({' · '.join(notes)})" if notes else ""), 2)
        if more:
            self.say("(partial list)", 2)
        if len(entries) == 1:
            self.say(f"→ the only {what}: {entries[0].get('name') or entries[0]['id']}", 2)
            return entries[0]
        while True:
            answer = ask(f"  Which {what}? [1-{len(entries)}]: ")
            if answer.isdigit() and 1 <= int(answer) <= len(entries):
                return entries[int(answer) - 1]

    def read_messages(self, team: dict, channel: dict) -> None:
        self.step("read-tool read_channel_messages", f"mind {MIND_NAME}, rule allow")
        where = {"team_id": team["id"], "channel_id": channel["id"]}
        result, data = self.read("read_channel_messages", {**where, "top": 10})
        if result["detail"]["result"].get("untrusted"):
            self.say("The result comes labelled untrusted: data for the mind, not instructions.", 2)
        messages = data.get("messages") or []
        for message in messages:
            head = f"{message.get('at', '')}  {message.get('from', '')}"
            self.say(head + (f" · {message['subject']}" if message.get("subject") else ""), 4)
            self.say(message.get("text") or "(no text)", 6)
        if not messages:
            self.say("(no messages)", 4)
        if data.get("more"):
            self.say("(the channel has more)", 4)

    def post(self, team: dict, channel: dict) -> None:
        self.step(f"use-tool {POST_TOOL}", f"mind {MIND_NAME}, rule ask")
        text = ask(f"  Text the mind will ask to post\n  (Enter for: {DEFAULT_POST})\n  > ") or DEFAULT_POST
        params = {"server": SERVER_NAME, "tool": POST_TOOL,
                  "arguments": {"team_id": team["id"], "channel_id": channel["id"], "text": text}}
        key = _key("use-tool")
        self.call_line("use-tool", params)
        waiting = self.mind_act("use-tool", params, key)
        if waiting.get("status") != "approval_required":
            self.say(f"✗ Expected the request to wait for a person, got: {waiting.get('status')}. "
                     f"{waiting.get('message', '')}", 2)
            raise Stop
        approval_id = waiting["approval_id"]
        self.say(f"⏸ The hive answers approval_required: request {approval_id}, bound to these exact arguments "
                 "and this key. The mind waits.", 2)
        self.say(f"mind     {MIND_NAME} ({self.mind['id']})", 4)
        self.say(f"action   use-tool → {SERVER_NAME} / {POST_TOOL} (write)", 4)
        self.say(f"team     {team.get('name') or team['id']}", 4)
        self.say(f"channel  {channel.get('name') or channel['id']}", 4)
        self.say(f"text     {text}", 4)
        if not self.calls("use-tool"):
            self.say("No use-tool call in the app's trace: nothing has gone to Teams.", 2)

        self.step("approval", "you, a person")
        self.say("Where do you answer?", 2)
        self.say("1. on the hive's Approvals page: Approve, or No", 4)
        self.say(self.page(f"approvals?id={quote(approval_id, safe='')}"), 7)
        self.say("2. here: the script sends your answer with your sign-in", 4)
        path = f"/api/approvals/{quote(approval_id, safe='')}"
        if ask_choice("  Where [1]: ", ("1", "2"), "1") == "2":
            approve = self.yes("Approve the post?")
            try:
                self.person("POST", path + ("/approve" if approve else "/deny"), {})
            except Refusal as exc:  # what the hive holds decides, below: it may have taken the answer all the same
                self.say(f"✗ The hive answered {exc.status} {exc.code}. {exc.message}", 2)
        decided = self.wait_for("your answer on the Approvals page", APPROVAL_WAIT,
                                lambda: next((row for row in self.person("GET", "/api/approvals")
                                              if row.get("id") == approval_id and row.get("status") != "pending"),
                                             None))
        if decided["status"] != "approved":
            self.say(f"✗ Not approved ({decided['status']} by {decided.get('decided_by')}): nothing is posted.", 2)
            return
        self.say(f"✓ Approved by {decided.get('decided_by')}. The mind sends the request again, with the same key "
                 f"and approval_id {approval_id}.", 2)

        self.step(f"use-tool {POST_TOOL}, again", f"mind {MIND_NAME}, with the approval")
        self.call_line("use-tool", params)
        posted = self.data(self.need(self.mind_act("use-tool", params, key, approval_id), "use-tool",
                                     HINT)).get("posted") or {}
        account = re.search(r", as ([^;)]+)", self.signin_line())  # the view's "signed in by ..., as <account>"
        self.say(f"✓ Posted in Teams{f' as {account.group(1)}' if account else ''}: "
                 f"message {posted.get('id')}, {posted.get('at')}", 2)
        if posted.get("url"):
            self.say(posted["url"], 4)

    def calls(self, action: str | None = None) -> list[dict]:
        """The calls of this run in the app's trace, as its view shows them (digests, never content)."""
        found = []
        for item in self.view()["items"]:
            if item.get("kind") != "call":
                continue
            fields = dict(line.split(": ", 1) for line in item["text"].splitlines() if ": " in line)
            if fields.get("at", "") >= self.started and (action is None or item["label"].startswith(action + " ")):
                found.append({"label": item["label"], **fields})
        return found

    def show_trace(self) -> None:
        self.step("trace", "app and hive")
        for call in self.calls():
            line = (f"{call.get('at', '')[11:19]}  {call['label']:<38} {call.get('status', ''):<8} "
                    f"{call.get('actor', '')}")
            if call.get("record_id"):
                line += f"  {call['record_id']}"
            if call.get("approved_by"):  # the approver the hive passed with the approval it redeemed
                line += f", approved by {call['approved_by']}"
            self.say(line, 2)
        self.say("The app's trace keeps who approved each write and sha256 digests of arguments and results, "
                 "never their content.", 2)
        records = [row for row in self.person("GET", f"/api/program-activity?program={APP_ID}"
                                                     f"&swarm_id={self.swarm_id_quoted()}&limit=50")
                   if row.get("principal") == f"agent:{self.mind['id']}"]
        writes = [row for row in records if row.get("action") == "use-tool"]
        self.say(f"The hive's own activity log has {len(records)} act(s) of this mind in the app"
                 + (": use-tool " + ", ".join(f"{row['id']} ({row['status']}, approval {row.get('approval_id')})"
                                              for row in writes) if writes else "") + ".", 2)

    def check_tokens(self) -> None:
        """What this script can check from outside the hive: its own secrets, and anything shaped
        like an access token, in what the app gave back. The Microsoft tokens themselves stay with the
        app, inside the hive, and never reach this script, so it cannot look for their values."""
        self.step("token check", "what the app returned in this run")
        text = json.dumps(self.outputs, ensure_ascii=False)
        if any(secret in text for secret in self.secrets) or JWT.search(text):
            self.say("✗ A token appears in a result or a view of the app.", 2)
            raise Stop
        self.say(f"✓ {len(self.outputs)} results and views: none carries a value shaped like an access token, "
                 "or any token or code of this run.", 2)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="The omega-connect Teams demo on a scratch hive (the Mac test "
                                                 "build): makes the mind's calls with the mind's token.")
    parser.add_argument("--hive-home", default=os.environ.get("OMEGAHIVE_HOME") or str(Path.home() / "OmegaHive"),
                        help="the hive's folder (default: $OMEGAHIVE_HOME or ~/OmegaHive)")
    parser.add_argument("--server-url", default=DEFAULT_SERVER_URL,
                        help=f"where teams-mcp listens on this machine (default: {DEFAULT_SERVER_URL})")
    parser.add_argument("--swarm", default=SWARM_NAME, metavar="NAME",
                        help=f"the swarm of the demo, made if you have none of that name (default: {SWARM_NAME!r})")
    parser.add_argument("--no-signin", action="store_true",
                        help="for a stand-in server that needs no Microsoft sign-in (rehearsals and tests): "
                             "add-server without one, and no connect")
    parser.add_argument("--cleanup", action="store_true",
                        help="delete the demo mind an earlier run left, with its rules, and stop")
    args = parser.parse_args(argv)
    print("omega-connect · the Teams demo on a real hive\n"
          "A mind reads a Teams channel and asks to post; you approve in the hive.\n"
          "This script makes the mind's calls with the mind's token; no token, code or sign-in link is printed.\n")
    demo = base = session = None
    try:
        base, session, owner = owner_signin(Path(args.hive_home).expanduser())
        demo = HiveDemo(base, session, owner, args.server_url, signin=not args.no_signin, swarm_name=args.swarm)
        if args.cleanup:
            demo.cleanup()
            return 0
        demo.run()
        demo.say("\nDemo complete.")
        return 0
    except Stop:
        print("\nDemo stopped.")
        return 1
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130
    except Refusal as exc:
        text = f"\n✗ The hive refused a request: {exc.status} {exc.code}. {exc.message}"
        print(demo.redact(text) if demo else UNSAFE.sub("", text))
        return 1
    except Exception:
        text = "\n✗ Unexpected error:\n" + traceback.format_exc()
        print(demo.redact(text) if demo else UNSAFE.sub("", text))
        return 1
    finally:
        if session:
            try:  # the session was for this run alone
                send("POST", base + "/api/auth/logout", {}, token=session, origin=base, timeout=15)
                print("Signed out of the hive: this run's session is ended.")
            except (Refusal, Stop):
                print("The hive did not confirm the sign-out; the session ends by itself in 30 days.")


if __name__ == "__main__":
    sys.exit(main())
