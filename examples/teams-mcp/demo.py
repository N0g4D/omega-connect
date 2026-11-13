"""Live demo of omega-connect with Microsoft 365, step by step in the terminal.

Starts teams-mcp on 127.0.0.1, mounts omega-connect in the repository's fake hive
(tests/fakehive.py) with a temporary store and a Fernet key made for this run, and
walks the README demo on a real tenant: add-server with an oauth-device sign-in,
connect (a device code, or the browser for tenants whose security defaults block
the device code), list-tools, accept-reads, list_teams, list_channels,
read_channel_messages on the channel you pick, then use-tool posting a message.
The mind's rule for use-tool is "ask": the request waits until you approve it here.

    python examples/teams-mcp/demo.py

It asks for the tenant ID and the client ID of the app registration (README,
"Before the demo"). They stay in memory and in the temporary store, which is
deleted at the end with the token and the key. Tokens are never printed: every
line goes through a filter that removes the token values of the sign-in, and the
last step checks the app's results and views, the store's plain files and the
logs for them.
"""

from __future__ import annotations

import importlib.util
import json
import logging
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import traceback
import uuid
import webbrowser
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from cryptography.fernet import Fernet

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SERVER = HERE / "server.py"
sys.path.insert(0, str(ROOT / "tests"))

from fakehive import FakeHive, HostRefusal, run  # noqa: E402

SWARM, PERSON, MIND = "demo", "operator", "scout"
SERVER_NAME = "teams"
SCOPES = [f"https://graph.microsoft.com/{name}" for name in
          ("Team.ReadBasic.All", "Channel.ReadBasic.All", "ChannelMessage.Read.All", "ChannelMessage.Send")]
GUID = re.compile(r"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}")
DOMAIN = re.compile(r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
UNSAFE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]")  # terminal controls, bidi overrides
HINT = "See 'If something fails' in examples/teams-mcp/README.md."
DEFAULT_POST = ("Test message from omega-connect: a mind read this channel and asked to post here, "
                "and a person approved.")


class Stop(Exception):
    """The demo cannot go on; the reason has been printed."""


def ask(prompt: str) -> str:
    try:
        return input(UNSAFE.sub("", prompt)).strip()
    except EOFError:
        print()
        raise Stop from None


def ask_id(prompt: str, valid, why: str) -> str:
    while True:
        value = ask(prompt)
        if valid(value):
            return value
        print(f"  {why}")


def _mask(value: str) -> str:
    """Enough of an id to recognise it on screen, or in a recording."""
    return value if len(value) <= 12 else value[:8] + "…"


def _short(text: str, limit: int) -> str:
    text = " ".join(str(text or "").split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _key(action: str) -> str:
    return f"{action}-{uuid.uuid4().hex[:12]}"


def start_server(log_path: Path) -> tuple[subprocess.Popen, str]:
    """teams-mcp on a free port of 127.0.0.1, without the app's settings (the Fernet key above all)."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    env = {k: v for k, v in os.environ.items() if not k.startswith("OMEGA_CONNECT_")}
    with log_path.open("wb") as log:
        proc = subprocess.Popen([sys.executable, str(SERVER), "--port", str(port)], env=env,
                                stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline and proc.poll() is None:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
            return proc, f"http://127.0.0.1:{port}/mcp"
        except OSError:
            time.sleep(0.2)
    proc.kill()
    proc.wait()
    print("✗ teams-mcp did not start:")
    print(UNSAFE.sub("", log_path.read_text("utf-8", errors="replace")[-2000:]))
    raise Stop


def open_in_browser(url: str) -> bool:
    """Opens the address in the person's own browser without printing it. False where there is no
    graphical browser: a text one would take over this terminal."""
    if sys.platform not in ("darwin", "win32") and not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        return False
    try:
        return webbrowser.open(url)
    except webbrowser.Error:
        return False


def load_program():
    spec = importlib.util.spec_from_file_location("omega_connect_program", ROOT / "program.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Demo:
    def __init__(self, program, url: str, store_dir: Path, logs: Path, fernet_key: str):
        self.program, self.url, self.store_dir, self.logs = program, url, store_dir, logs
        self.hive = FakeHive(program)
        self.store = program.store_mod.SwarmStore(SWARM)
        self.secrets = {fernet_key}  # every secret value of this run, tokens included once they exist
        self.outputs: list = []  # every result and view, for the check at the end
        self.steps = 0

    # ---------------------------------------------------------------- output
    def redact(self, text: str) -> str:
        """Terminal controls dropped, and the token values of the sign-in (the current ones and any
        seen before) replaced."""
        try:
            tokens = self.store.signins(SERVER_NAME)["people"].values()
        except self.program.store_mod.StoreError:
            tokens = ()
        for token in tokens:
            self.secrets.update(value for value in (token.get("access_token"), token.get("refresh_token")) if value)
        text = UNSAFE.sub("", str(text))
        for secret in self.secrets:
            text = text.replace(secret, "[token removed]")
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

    # ---------------------------------------------------------------- the hive
    def person(self, action: str, items: list, params: dict) -> dict:
        result = run(self.hive.person_act(SWARM, PERSON, action, items, params, confirmed=True))
        self.outputs.append(result)
        return result

    def mind(self, action: str, params: dict, key: str | None = None, approval_id: str | None = None) -> dict:
        result = run(self.hive.agent_act(SWARM, MIND, action, params, key or _key(action), approval_id))
        self.outputs.append(result)
        return result

    def view(self) -> dict:
        graph = run(self.hive.view(SWARM, PERSON))
        self.outputs.append(graph)
        return graph

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
        result = self.need(self.mind("read-tool", params), f"read-tool {tool}", HINT)
        return result, self.data(result)

    # ---------------------------------------------------------------- steps
    def run(self, tenant: str, client_id: str) -> None:
        for action, mode in (("list-tools", "allow"), ("read-tool", "allow"), ("use-tool", "ask")):
            self.hive.attach(MIND, action, mode)
        self.say(f"Mind '{MIND}': list-tools allow, read-tool allow, use-tool ask")
        self.add_server(tenant, client_id)
        self.connect()
        self.list_tools()
        self.accept_reads()
        team = self.pick_team()
        channel = self.pick_channel(team)
        self.read_messages(team, channel)
        self.post(team, channel)
        self.show_trace()
        self.revoke_and_check()

    def add_server(self, tenant: str, client_id: str) -> None:
        self.step("add-server", "person, confirmed")
        signin = {"kind": "oauth-device", "tenant": tenant, "client_id": client_id, "scopes": SCOPES}
        self.say(f"server    {SERVER_NAME} → {self.url}", 2)
        self.say(f"sign-in   oauth-device · tenant {_mask(tenant)} · client {_mask(client_id)}", 2)
        self.say(f"scope     {', '.join(scope.rsplit('/', 1)[1] for scope in SCOPES)}", 2)
        self.say("          (+ openid, profile, offline_access, added by the app)", 2)
        result = self.need(self.person("add-server", [], {"name": SERVER_NAME, "url": self.url, "signin": signin}),
                           "add-server")
        self.say(f"✓ {result['message']}", 2)

    def connect(self) -> None:
        self.step("connect", "person, confirmed")
        self.say("How do you sign in?", 2)
        self.say("1. device code: a code to enter at microsoft.com/devicelogin", 4)
        self.say("2. browser: for tenants whose security defaults block the device code, as on every tenant "
                 "created since July 2026", 4)
        while True:
            choice = ask("  Sign-in [1]: ") or "1"
            if choice in ("1", "2"):
                break
        if choice == "1":
            self.device_code()
        else:
            self.browser()
        server = next(item for item in self.view()["items"] if item["id"] == f"server:{SERVER_NAME}")
        signin = next(line for line in server["text"].splitlines() if line.startswith("Sign-in"))
        self.say(f"✓ In the view: {signin}", 2)
        self.say("The token stays encrypted in the store; the view shows neither the token nor the code.", 2)

    def browser(self) -> None:
        """Authorization code with PKCE: the person signs in in a browser and pastes back the address it lands
        on. The sign-in address carries the tenant and client IDs in full, so it is opened, not printed,
        where a browser can be opened."""
        self.call_line("connect", {"flow": "browser", "for_minds": True}, [f"server:{SERVER_NAME}"])
        started = self.person("connect", [f"server:{SERVER_NAME}"], {"flow": "browser", "for_minds": True})
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
            landed = ask("  Address the browser landed on (Enter to stop): ")
            if not landed:
                raise Stop
            # The code in it works once, with this run's PKCE verifier; still, it is never shown or kept.
            self.secrets.update(code for code in parse_qs(urlsplit(landed).query).get("code", []) if len(code) >= 16)
            self.call_line("connect", {"redirect_url": "<the address you pasted>"}, [f"server:{SERVER_NAME}"])
            finished = self.person("connect", [f"server:{SERVER_NAME}"], {"redirect_url": landed})
            if finished.get("status") == "done":
                return
            self.say(f"✗ {finished.get('message', '')}", 2)
            if finished.get("status") != "error":  # refused: no sign-in is waiting any more (expired)
                self.say(HINT, 2)
                raise Stop
            self.say("The sign-in is still open: paste the address again, or sign in again from the same page.", 2)

    def device_code(self) -> None:
        self.call_line("connect", {"for_minds": True}, [f"server:{SERVER_NAME}"])
        detail = self.need(self.person("connect", [f"server:{SERVER_NAME}"], {"for_minds": True}), "connect",
                           HINT)["detail"]
        self.say(f"Open    {detail['verification_uri']}", 2)
        self.say(f"Code    {detail['user_code']}", 2)
        self.say("Sign in with an account of the tenant and accept the permissions; the demo goes on by itself.", 2)
        deadline = time.monotonic() + detail["expires_in"] + 5
        reminder = time.monotonic() + 30
        while not self.store.has_credentials(SERVER_NAME):
            failed = [entry for entry in self.store.traces(20)
                      if entry.get("action") == "connect" and entry.get("status") == "error"]
            if failed:
                self.say(f"✗ Sign-in failed: {failed[-1].get('reason', '')}", 2)
                self.say(HINT, 2)
                raise Stop
            now = time.monotonic()
            if now > deadline:
                self.say("✗ The code expired before anyone signed in.", 2)
                raise Stop
            if now > reminder:
                self.say(f"… waiting for the sign-in ({int(deadline - now)} s left)", 2)
                reminder = now + 30
            time.sleep(1)

    def list_tools(self) -> None:
        self.step("list-tools", f"mind {MIND}, rule allow")
        params = {"server": SERVER_NAME}
        self.call_line("list-tools", params)
        tools = self.need(self.mind("list-tools", params), "list-tools")["detail"]["tools"][SERVER_NAME]
        if isinstance(tools, dict):
            self.say(f"✗ {tools.get('error')}", 2)
            self.say(HINT, 2)
            raise Stop
        for tool in tools:
            self.say(f"{tool['name']:<24} {tool['class']:<6} {tool.get('review', '')}", 4)
            self.say(_short(tool["description"], 90), 6)
        self.say("All write for now: a server's read-only hint counts only once a person has accepted it.", 2)

    def accept_reads(self) -> None:
        self.step("accept-reads", "person, confirmed, on the definitions listed above")
        params = {"base_revision": self.view()["revision"]}
        self.call_line("accept-reads", params, [f"server:{SERVER_NAME}"])
        detail = self.need(self.person("accept-reads", [f"server:{SERVER_NAME}"], params), "accept-reads")["detail"]
        self.say(f"✓ read:  {', '.join(detail['accepted'])}", 2)
        if detail["still_write"]:
            self.say(f"  write: {', '.join(detail['still_write'])} (the server does not mark it read-only)", 2)

    def pick_team(self) -> dict:
        self.step("read-tool list_teams", f"mind {MIND}, rule allow")
        _, data = self.read("list_teams", {})
        teams = data.get("teams") or []
        if not teams:
            self.say("✗ The account is not a member of any team.", 2)
            raise Stop
        return self.choose(teams, "team", data.get("more"))

    def pick_channel(self, team: dict) -> dict:
        self.step("read-tool list_channels", f"mind {MIND}, rule allow")
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
        self.step("read-tool read_channel_messages", f"mind {MIND}, rule allow")
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
        self.step("use-tool post_channel_message", f"mind {MIND}, rule ask")
        text = ask(f"  Text the mind will ask to post\n  (Enter for: {DEFAULT_POST})\n  > ") or DEFAULT_POST
        params = {"server": SERVER_NAME, "tool": "post_channel_message",
                  "arguments": {"team_id": team["id"], "channel_id": channel["id"], "text": text}}
        key = _key("use-tool")
        self.call_line("use-tool", params)
        waiting = self.mind("use-tool", params, key)
        if waiting.get("status") != "approval_required":
            self.say(f"✗ Expected the request to wait for a person, got: {waiting.get('status')}", 2)
            raise Stop
        approval = self.hive.approvals[waiting["approval_id"]]
        self.say(f"⏸ The host answers approval_required: request {approval['id']}, bound to these exact arguments "
                 "and this key. The mind waits.", 2)
        self.say(f"mind     {approval['mind']}", 4)
        self.say(f"action   {approval['action']} → {SERVER_NAME} / {params['tool']} (write)", 4)
        self.say(f"team     {team.get('name') or team['id']}", 4)
        self.say(f"channel  {channel.get('name') or channel['id']}", 4)
        self.say(f"text     {text}", 4)
        if not any(entry.get("action") == "use-tool" for entry in self.store.traces(100)):
            self.say("No use-tool call in the trace: nothing has gone to Teams.", 2)

        self.step("approval", "person")
        while True:
            answer = ask("  Approve the post? (y/n): ").lower()
            if answer in ("y", "yes", "n", "no"):
                break
        if answer.startswith("n"):
            self.say("✗ Not approved: the request stays pending, and nothing is posted.", 2)
            return
        self.hive.approve(approval["id"], PERSON)
        self.say(f"✓ Approved by {PERSON}. The mind sends the request again, with the same key and "
                 f"approval_id {approval['id']}.", 2)
        self.call_line("use-tool", params)
        posted = self.data(self.need(self.mind("use-tool", params, key, approval["id"]), "use-tool",
                                     HINT)).get("posted") or {}
        signins = self.store.signins(SERVER_NAME)
        account = (signins["people"].get(signins["minds"]) or {}).get("account") or "the account that signed in"
        self.say(f"✓ Posted in Teams as {account}: message {posted.get('id')}, {posted.get('at')}", 2)
        if posted.get("url"):
            self.say(posted["url"], 4)

    def show_trace(self) -> None:
        self.step("trace", "app and host")
        for entry in self.store.traces(100):
            what = f"{entry.get('action')} {entry.get('tool') or ''}".strip()
            line = f"{entry.get('at', '')[11:19]}  {what:<36} {entry.get('status', ''):<8} {entry.get('actor', '')}"
            if entry.get("record_id"):
                line += f"  {entry['record_id']}"
            if entry.get("approved_by"):  # the approver the hive passed with the approval it redeemed
                line += f", approved by {entry['approved_by']}"
            self.say(line, 2)
        self.say("The trace keeps who approved each write and sha256 digests of arguments and results, "
                 "never their content.", 2)

    def revoke_and_check(self) -> None:
        self.step("revoke and token check", "person, confirmed")
        self.redact("")  # learn the current token values before they are deleted
        self.call_line("revoke", {}, [f"server:{SERVER_NAME}"])
        self.need(self.person("revoke", [f"server:{SERVER_NAME}"], {}), "revoke")
        self.view()
        self.say("✓ Token deleted from the store.", 2)
        texts = [json.dumps(self.outputs, ensure_ascii=False)]
        texts += [path.read_text("utf-8", errors="ignore") for folder in (self.store_dir, self.logs)
                  for path in folder.rglob("*") if path.is_file()]
        if any(secret in text for secret in self.secrets for text in texts):
            self.say("✗ A token appears in the results, the views, the store or the logs.", 2)
            raise Stop
        self.say("✓ No token in the app's results and views, in the store's plain files, "
                 "or in the app's and the server's logs.", 2)


def main() -> int:
    print("omega-connect · demo with Microsoft 365\n"
          "A mind reads a Teams channel and asks to post; you approve.\n"
          "It needs the tenant ID and the client ID of the app registration (README, 'Before the demo').\n"
          "They stay in memory and in the temporary store of this run, deleted at the end.\n")
    tmp = demo = program = server = None
    try:
        tenant = ask_id("Tenant ID (Directory ID): ",
                        lambda v: len(v) <= 100 and bool(GUID.fullmatch(v) or DOMAIN.fullmatch(v)),
                        "Give the tenant ID (a GUID) or its domain: a single-tenant app does not accept "
                        "'organizations'.")
        client_id = ask_id("Client ID (Application ID): ", lambda v: bool(GUID.fullmatch(v)),
                           "Give the Application (client) ID: a GUID.")
        tmp = Path(tempfile.mkdtemp(prefix="omega-connect-demo-"))
        store_dir, logs = tmp / "store", tmp / "logs"
        logs.mkdir()
        # Logs go to a file that the last step checks, never to the terminal unfiltered.
        logging.basicConfig(filename=logs / "demo.log", level=logging.DEBUG, force=True)
        server, url = start_server(logs / "server.log")
        fernet_key = Fernet.generate_key().decode()
        os.environ.update({"OMEGA_CONNECT_DATA_DIR": str(store_dir), "OMEGA_CONNECT_LOG_DIR": str(logs),
                           "OMEGA_CONNECT_SECRET_KEY": fernet_key})
        os.environ.pop("OMEGA_CONNECT_ALLOW_STDIO", None)
        for name in ("NO_PROXY", "no_proxy"):  # the app reaches teams-mcp directly
            os.environ[name] = ",".join(v for v in (os.environ.get(name), "127.0.0.1,localhost") if v)
        program = load_program()
        demo = Demo(program, url, store_dir, logs, fernet_key)
        demo.say(f"\nteams-mcp        {url} (process {server.pid}), to Microsoft Graph")
        demo.say(f"Identity         {program.oauth_mod.authority()}")
        demo.say(f"Temporary store  {tmp}")
        demo.say("Fernet key       made for this run, in memory only")
        demo.run(tenant, client_id)
        demo.say("\nDemo complete.")
        return 0
    except Stop:
        print("\nDemo stopped.")
        return 1
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130
    except HostRefusal as exc:
        cause = f" ({exc.__cause__.__class__.__name__}: {exc.__cause__})" if exc.__cause__ else ""
        text = f"\n✗ The host refused the request: {exc}{cause}"
        print(demo.redact(text) if demo else text)
        return 1
    except Exception:
        text = "\n✗ Unexpected error:\n" + traceback.format_exc()
        print(demo.redact(text) if demo else UNSAFE.sub("", text))
        return 1
    finally:
        if program is not None:
            program.ENGINE.shutdown()
        if server is not None:
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()
        for handler in logging.root.handlers[:]:  # nothing may reopen the log, or reach the terminal
            logging.root.removeHandler(handler)
            handler.close()
        logging.root.addHandler(logging.NullHandler())
        if tmp is not None:
            shutil.rmtree(tmp, ignore_errors=True)
            print("Server stopped; temporary store, token and key deleted.")


if __name__ == "__main__":
    sys.exit(main())
