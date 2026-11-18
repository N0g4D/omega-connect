# teams-mcp: Microsoft Teams for the omega-connect demo

A small MCP server (streamable HTTP, `127.0.0.1` only) with four tools backed by
Microsoft Graph. It is the server for the brief's live demo: a mind reads a
Teams channel, asks to post, and a person approves. `demo.py` runs that demo
from a terminal against a real tenant ([Run it with demo.py](#run-it-with-demopy)).

| Tool | Graph call | Delegated permission | Hint |
|---|---|---|---|
| `list_teams()` | `GET /me/joinedTeams` | `Team.ReadBasic.All` | `readOnlyHint` |
| `list_channels(team_id)` | `GET /teams/{id}/channels` | `Channel.ReadBasic.All` | `readOnlyHint` |
| `read_channel_messages(team_id, channel_id, top)` | `GET /teams/{id}/channels/{id}/messages` | `ChannelMessage.Read.All` (admin consent) | `readOnlyHint` |
| `post_channel_message(team_id, channel_id, text)` | `POST /teams/{id}/channels/{id}/messages` | `ChannelMessage.Send` | none, so omega-connect classes it `write` |

What the server guarantees:

- **No credentials of its own.** Each call uses the Graph token in the
  `Authorization: Bearer` header of its own HTTP request, hands it to Graph and
  drops it. The token is never stored, logged, or put in a result or an error
  (Graph error texts are scrubbed of it). Redirects are not followed, so the
  token cannot be carried to another address. Without a bearer token, nothing
  reaches Graph.
- **This machine only.** It listens on `127.0.0.1` (there is no host option),
  checks `Host` and `Origin` against DNS rebinding, and keeps no state between
  requests.
- **Bounded results.** Compact JSON: at most 50 teams and 100 channels, `top`
  clamped to 1–50 (Graph's page limit), HTML message bodies turned into plain
  text, names, descriptions and messages trimmed, and every answer under 7,000
  characters with `"more": true` when something was left out. omega-connect's
  8,000-character cap therefore never cuts the JSON. Posts are plain text
  (`contentType: text`), at most 4,000 characters. Team and channel ids are
  checked before any call.

Passing the client's token on to Graph is *token passthrough*, which the MCP
security guidance warns against for shared servers. It fits here because only
this machine can reach the server and omega-connect, next to it, holds the
person's token. A shared server should accept only tokens issued to itself and
get its own Graph token (on-behalf-of flow).

## Before the demo

1. **Tenant.** A Microsoft 365 developer tenant with a team and a channel, and an
   account that is a member of it.
2. **App registration** (Entra admin center, App registrations, New):
   - single tenant; note the *Application (client) ID* and *Directory (tenant) ID*;
   - Authentication: *Allow public client flows* = Yes (needed for the device code),
     and, for the browser sign-in, *Add a platform*, *Mobile and desktop
     applications*, with `http://localhost` added as a redirect URI. It takes
     no port: the app listens on a port the system picks, and Entra leaves the
     port out when it compares a `localhost` redirect URI. Not under *Web*: a
     redirect URI of that type makes Entra ask for a client secret;
   - API permissions, Microsoft Graph, delegated: `Team.ReadBasic.All`,
     `Channel.ReadBasic.All`, `ChannelMessage.Read.All`, `ChannelMessage.Send`.
     `ChannelMessage.Read.All` needs admin consent: *Grant admin consent* on the
     same page. The other three need only the person's consent at sign-in.
3. **Server**, on the hive's machine (`mcp` is already in omega-connect's requirements):
   ```sh
   python examples/teams-mcp/server.py --port 8765   # -> http://127.0.0.1:8765/mcp
   ```
4. **Hive**: omega-connect mounted (see the main README) with
   `OMEGA_CONNECT_SECRET_KEY` set, and a mind attached with `list-tools` and
   `read-tool` on *allow* and `use-tool` on *ask*. Do the person's steps as a
   named person signed in to the hive, not with the local operator password:
   `connect` and `use-tool` declare `approver: "person"`, so with the operator
   password nobody can sign in, or run or approve a write.

## Demo steps

The parameters below are what each action receives. People's actions go
through the host's confirmation; a mind's actions go through its rules.

**1. add-server** (person, confirmed). Use the tenant ID: a single-tenant app
does not accept `organizations`.

```json
{"name": "teams", "url": "http://127.0.0.1:8765/mcp",
 "signin": {"kind": "oauth-device",
            "tenant": "<Directory (tenant) ID>",
            "client_id": "<Application (client) ID>",
            "scopes": ["https://graph.microsoft.com/Team.ReadBasic.All",
                       "https://graph.microsoft.com/Channel.ReadBasic.All",
                       "https://graph.microsoft.com/ChannelMessage.Read.All",
                       "https://graph.microsoft.com/ChannelMessage.Send"]}}
```

omega-connect adds `openid` and `profile` (to show who signed in) and
`offline_access` (so the token can be renewed).

**2. connect** (person, confirmed), on `server:teams`. The sign-in is the
person's own. The result shows a code and `https://microsoft.com/devicelogin`,
to this person only: the app's view never shows the code. Sign in there with
the tenant account and accept the permissions. The app finishes the sign-in by
itself; the view then shows
`Sign-in: oauth-device (signed in by <principal>, as <the account>; minds use this sign-in)`.
A mind uses the sign-in of the person it belongs to; until the hive names that
person (omegahive #332), it uses a sign-in only while one person alone is
signed in to the swarm's servers, so do the demo in a swarm where nobody else
has signed in to a server.

On a tenant whose security defaults block the device code (the sign-in is
then refused with `AADSTS530035`), run connect with
`{"flow": "browser"}` instead. Open the address in the result in a browser on
the hive's machine, sign in and accept. The browser then goes to
`http://localhost:<port>`, where the app listens for it, and says "You are
signed in. You can close this page."; the app finishes the sign-in by itself,
and the view names who signed in, as above. The address stays good for ten
minutes, and a new connect of yours on the server replaces it.

The browser sign-in works when your browser is on the hive's machine. On a
hive shared over a network, a person on another machine cannot use it yet:
their browser would look for `localhost` on their own machine. That takes a
callback address of the hive itself, which is still to do; until then they
sign in with the device code, where the tenant allows it.

**3. list-tools** (mind) with `{"server": "teams"}`. Every tool is `write` for
now: the three Graph reads carry `"review": "not reviewed"`, because a
server's read-only hint counts only once a person has accepted it.

**4. accept-reads** (person, confirmed), on `server:teams`, after looking at
the tools in the view. `list_teams`, `list_channels` and
`read_channel_messages` become `read`; `post_channel_message` stays `write`,
since the server does not mark it read-only. If the server later changes one
of the accepted definitions, that tool is `write` again and the view says
*changed since review*.

**5. Find the channel** (mind, read-tool): `{"server": "teams", "tool": "list_teams"}`,
then `{"server": "teams", "tool": "list_channels", "arguments": {"team_id": "<team id>"}}`.

**6. read-tool reads the channel** (mind, runs on *allow*):

```json
{"server": "teams", "tool": "read_channel_messages",
 "arguments": {"team_id": "<team id>", "channel_id": "19:...@thread.tacv2", "top": 10}}
```

The result is `{"untrusted": true, "text": "{\"messages\": [...]}"}`: id, time,
sender, subject and plain text of each message, labelled as data, not
instructions. Asking read-tool for `post_channel_message` is refused: it is
classed `write`.

**7. use-tool posts, and waits for a person** (mind, *ask*):

```json
{"server": "teams", "tool": "post_channel_message",
 "arguments": {"team_id": "<team id>", "channel_id": "19:...@thread.tacv2",
               "text": "Summary of today's thread: ..."}}
```

The host files an approval bound to these exact arguments and the mind waits;
nothing is posted yet. The post would go out as the person who signed in, so
only that person can approve it. Once they do, the app runs the tool once, the
message appears in the channel as them, and the trace keeps digests, who
approved and the hive's record id. A retry with the same idempotency key
returns the recorded result instead of posting again.

To finish, **revoke** (person, confirmed) on `server:teams` deletes the token.

## Run it with demo.py

`demo.py` walks the steps above against your tenant from a terminal, without a
hive. It mounts omega-connect in the repository's stand-in for the host
(`tests/fakehive.py`) and plays both parts: the mind `scout` (`list-tools` and
`read-tool` on *allow*, `use-tool` on *ask*), and you, the person who signs in,
confirms and approves, whom the fake host calls `ada`: a named person, as
`use-tool` requires. It starts the server itself on a free port of `127.0.0.1`, and
keeps the store in a temporary folder with a Fernet key made for the run;
both are deleted at the end, and the token with them.

From a checkout of this repository, once steps 1 and 2 of *Before the demo* are done:

```sh
pip install -r requirements-dev.txt    # mcp, cryptography, uvicorn
python examples/teams-mcp/demo.py
```

1. It asks for the *Directory (tenant) ID* and the *Application (client) ID*.
   They are kept in memory and in the temporary folder only, and shown by their
   first eight characters, so that a recording does not carry them.
2. **add-server** with the four delegated scopes, then **connect**, which asks
   how you sign in. With **1**, the device code (Enter), it prints
   `https://microsoft.com/devicelogin` and a code. Sign in there with an account
   of the tenant and accept the permissions; the demo goes on by itself once you
   have. With **2**, the browser, for tenants whose security defaults block the
   device code (every tenant created since July 2026), it opens the sign-in page
   in your browser without printing its address, which carries the tenant and
   client IDs (where no browser opens, it prints the address and says so). Sign
   in and accept: the browser goes back to the app, which listens for it on
   this machine, and says "You are signed in. You can close this page." The
   demo asks for nothing more and goes on by itself once the view names who
   signed in; a sign-in that is declined, or not finished within ten minutes,
   stops it. The app registration needs the redirect URI of *Before the demo*.
   Either way the demo then shows the account that the view names.
3. **list-tools**, where every tool is `write`, then **accept-reads** on the
   definitions just listed: the three reads become `read`, and
   `post_channel_message` stays `write`.
4. **read-tool** `list_teams` and `list_channels`: choose a team and a channel by
   number (when there is only one, it is chosen for you). Then
   `read_channel_messages` prints the last 10 messages, labelled untrusted.
5. **use-tool** `post_channel_message`: type the text the mind asks to post, or
   press Enter for a default one. The request waits for a person: the demo shows
   it (mind, tool, team, channel, text) and asks *Approve the post? (y/n)*.
   Only `y` posts, once, as the account that signed in; `n` posts nothing.
6. It prints the trace (actor, the hive's record id, who approved), runs
   **revoke**, and checks that no token appears in the app's results and views,
   in the store's plain files or in the logs.

Then it stops the server and deletes the temporary folder; Ctrl-C at any step
does the same. Tokens are never printed: every line goes through a filter that
removes the token values of the sign-in, and the terminal control characters
that a message could carry. Nothing is kept between runs, so each run signs in
again.

## On a scratch hive (Mac test build)

`hive_demo.py` runs the demo on a real hive: the one the Mac test build
installs in `~/OmegaHive`, where you enter as its owner, a named person. The
app was mounted and checked there on build 0.33, and what follows about the
hive's routes and pages was read in that build. The demo recorded on 17 Nov
2026 ran on build 0.34; on 18 Nov 2026 it ran on build 0.37 with the browser
sign-in, Microsoft's security defaults on. Both runs were on a real tenant.
As read on 0.33, a mind cannot call an app's actions by itself yet, so the
script makes the mind's calls in its place, with the mind's own token. The
person's steps are yours: on the hive's pages where a page can do them,
otherwise from the script, with your sign-in, after a yes at the terminal.

**Mount the app**, from a checkout of this repository:

```sh
~/OmegaHive/venv/bin/python -m pip install -r requirements.txt
printf 'HIVE_PLUGIN_DIRS=%s\n' "$PWD" >> ~/OmegaHive/hive.env
printf 'OMEGA_CONNECT_SECRET_KEY=%s\n' "$(~/OmegaHive/venv/bin/python -c \
  'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')" >> ~/OmegaHive/hive.env
~/OmegaHive/app/install/macos/omegahive.sh stop
~/OmegaHive/app/install/macos/omegahive.sh start
```

The key goes from the command into the file without reaching the screen.
`omegahive.sh` reads `hive.env` at each start (a shell reads it: a folder with
spaces in its path needs quotes) and keeps your folder beside the Tools app's
in `HIVE_PLUGIN_DIRS`. The app is not among the hive's pins, so it loads
unpinned, from your checkout as it is when the hive starts: after a change in
the checkout, stop and start the hive again. Its store is `~/.omega-connect`. To
check: *Tool connections* is among the hive's apps, and the hive's own checker
passes:

```sh
cd ~/OmegaHive/app && ~/OmegaHive/venv/bin/python -m hive.programs_check /path/to/omega-connect
```

**Who does what.** The routes are the build's own.

| Step | Who | Where |
|---|---|---|
| swarm, mind, rules | you | the script: `POST /api/swarms`, `POST /api/agents` (the only answer that carries the mind's token) and `POST /api/policy` with `{"scope": "agent:<mind id>", "skill": "program:omega-connect:<action>", "mode": ...}`, three times |
| add-server | you | the script, after a yes: the app's page offers an action only on an item you selected and sends it without parameters, so it cannot add the first server |
| connect | you | the script, after a yes, with `{"flow": "browser"}`; the sign-in itself in your browser, which then goes back to the app inside the hive. The page's own *Sign in to this server* sends no parameters, which is the device code |
| list-tools, read-tool | the mind | the script: `POST /api/agent/programs/omega-connect/act` with `{"action", "params", "idempotency_key"}` and the mind's token. The hive takes the mind and its swarm from the token; a body that names them is refused |
| accept-reads | you | the app's page: select the server `teams`, *Accept read-only tools*, confirm |
| use-tool | the mind | the script, same route. The hive answers `{"status": "approval_required", "approval_id": ...}` |
| approval | you | the hive's Approvals page: *Approve*, or *No* |
| use-tool, again | the mind | the script: the same body with the `approval_id` |

That table is the page of the builds the demo ran on: up to 0.37 it offers
an action only on a selected item and sends it without inputs, hence the
script for add-server and connect. From build 0.38 the page asks for the
inputs an action declares, and lists the actions on the app itself under *In
this app* when nothing is selected (omegahive #403). There add-server and
connect can be done on the page, since both declare their inputs (the main
README, "Actions"): *Add a server* with nothing selected, then *Sign in to
this server* on the server, where the *browser* choice is this same sign-in,
in a browser on the hive's machine. That is still to try on this hive. The
script sends these two steps itself, whichever page the hive has; on 0.38 it
has not been run yet (the routes it uses are all there).

A person's act that declares `confirm` needs the host's confirm first:
`POST /api/programs/omega-connect/confirm` with `{"swarm_id", "action",
"payload": {"items", "params", "base_revision"}, "payload_digest"}` gives a
`confirm_token` for that act alone, once, for two minutes; the act then goes
to `POST /api/programs/omega-connect/act` with it. Every request of a person's
session that changes something carries the hive's own `Origin`.

The mind is made with `POST /api/agents` and never started: the hive's note
about the approval is queued for it and does not wake it. It is attached with
the three rules alone. The *Access* panel of the app's page is not the way:
activating an app there needs attachment hooks that omega-connect does not
have (as read in the build's code, the hive answers 409 `hooks_missing`).

**Run it**, once *Before the demo* is done (the browser sign-in needs the
redirect URI of step 2):

```sh
python examples/teams-mcp/server.py --port 8765    # in one terminal, left running
python examples/teams-mcp/hive_demo.py             # in another; standard library only
```

1. It signs in as the hive's owner through a one-time link
   (`omegahive.sh signin-url`), finds or makes the swarm *omega-connect demo*,
   makes the mind `connect-scout` in it and writes its rules. It prints the
   address of the app's page for that swarm.
2. **add-server**: it asks for the *Directory (tenant) ID* and the
   *Application (client) ID*, shows their first eight characters, and sends
   add-server after your yes. A later run finds the server and asks for neither.
3. **connect**: after your yes it opens the sign-in page in your browser, without
   printing its address. Sign in and accept: the browser goes back to the app,
   which listens for it on this machine inside the hive, and says "You are
   signed in. You can close this page." The script waits for the app's view to
   name who signed in, and goes on by itself.
4. **list-tools** as the mind, then **accept-reads**: press Enter and accept
   the reads on the app's page; the script waits and goes on by itself.
5. **read-tool** `list_teams`, `list_channels`, `read_channel_messages`: choose
   the team and the channel by number.
6. **use-tool** `post_channel_message`: type the text, or press Enter for the
   default one. The hive answers `approval_required` and the script shows the
   request. Press Enter and answer on the Approvals page; once you approve,
   the script sends the same request again with the `approval_id`, and the
   message is posted once, as your Microsoft account. *No* posts nothing.
7. It prints the app's trace and the hive's activity log for the mind, checks
   that nothing the app returned is shaped like an access token, and ends its
   session in the hive.

With `--device-code`, step 3 is connect without a flow: the script shows the
address and the user code of the device code, which are for you, and goes on
by itself once you have entered the code and signed in. The browser sign-in
is the default: it is the one that works on a tenant whose security defaults
block the device code (`AADSTS530035`), as it did on 18 Nov 2026.

At steps 4 and 6 the answer **2** makes the script send your accept-reads or
your approval itself. The steps on the hive's pages are described from the
build's page source: if a page does not offer one, stop with Ctrl-C and run
again answering 2; the new run finds the server and the sign-in in place.

No token or sign-in link is printed or written, and no code but the device
code you enter yourself: the one-time link, your
session's token, the mind's token and the hive's confirm tokens stay in the
script's memory. The code of the browser sign-in goes from your browser to
the app, and the Microsoft tokens stay with the app, inside the hive: neither
reaches the script.

**Afterwards.** The mind stays in the hive, so you can show it there; its token
ended with the run, the next run replaces it, and `hive_demo.py --cleanup`
deletes it with its rules. Your Microsoft sign-in stays in the app's store,
encrypted: *Revoke sign-in* on the server deletes it, *Remove server* the
server. To unmount the app, take the two lines out of `hive.env`, restart the
hive and delete `~/.omega-connect`.

**A rehearsal without a tenant.** `test_hive_demo.py`, run as a program, is a
stand-in for teams-mcp with a simulated Graph that needs no sign-in:

```sh
python examples/teams-mcp/test_hive_demo.py --port 8791
python examples/teams-mcp/hive_demo.py --no-signin --swarm "omega-connect rehearsal" \
    --server-url http://127.0.0.1:8791/mcp
```

It walks the same steps without connect, in a swarm of its own, and posts
only to the stand-in's memory.

## If something fails

| Symptom | Cause |
|---|---|
| `AADSTS7000218` at connect | *Allow public client flows* is off |
| `AADSTS50194` at connect | `organizations` with a single-tenant app: use the tenant ID |
| `AADSTS700016` at connect | wrong client ID, or the app is registered in another tenant |
| `AADSTS90002` at connect | wrong tenant ID |
| `403` from read_channel_messages | no admin consent for `ChannelMessage.Read.All`, or the person is not in the team |
| `401` from any tool | Graph refused the token: run `connect` again |
| `connection refused` | the server is not running, or not on the hive's machine |
| demo.py asks for the tenant ID again | `organizations` or `common`: give the Directory (tenant) ID, or the tenant's domain |
| demo.py: `teams-mcp did not start` | `mcp` or `uvicorn` missing (`pip install -r requirements-dev.txt`); the demo prints the server's log |
| demo.py: `The code expired before anyone signed in`, or `Sign-in failed` naming an expired code | the code lasts about 15 minutes: run the demo again |
| demo.py: `Sign-in failed` | the sign-in was cancelled or the permissions declined; the identity platform's own text follows |
| device code: `AADSTS530035` (*Access has been blocked by security defaults*) | the tenant's security defaults block the device code, as on every tenant created since July 2026: sign in with the browser. demo.py: run it again and choose **2**; hive_demo.py: run it without `--device-code` |
| browser sign-in: `AADSTS530035` in the browser | the browser's Microsoft session was opened before the tenant's security defaults were on. Sign out of Microsoft and in again, or use a private window; with the security defaults on, the browser sign-in then goes through |
| browser sign-in: `AADSTS50011` in the browser | the redirect URI `http://localhost` is missing under *Mobile and desktop applications* (*Before the demo*, step 2); the port in the address does not matter |
| browser sign-in: after the sign-in the browser cannot open `localhost:<port>` | the browser is not on the hive's machine, where the app listens (on a hive shared over a network this sign-in does not work yet: use the device code). Or the app no longer waits: ten minutes have passed, a newer connect of yours replaced the sign-in, or the hive was restarted. Run connect again |
| browser sign-in: the page says *The sign-in did not complete* | the sign-in was cancelled or the permissions declined, or Microsoft refused the code. demo.py prints the reason; on a hive it is the `reason` of the last `connect` line in the app's trace (`trace.jsonl` in the swarm's folder under `~/.omega-connect`). `AADSTS7000218` there: `http://localhost` is registered under *Web*, not under *Mobile and desktop applications* |
| demo.py: `Sign-in failed: nobody finished the sign-in in the browser` | the sign-in address lasts ten minutes: run the demo again |
| demo.py: the *Identity* line is not `https://login.microsoftonline.com` | `OMEGA_CONNECT_OAUTH_AUTHORITY` is set in the shell (the tests use it): unset it |
| hive_demo.py: `connect did not start a browser sign-in that finishes by itself` | the hive still runs the app as it loaded it before the checkout changed (0.2 asked for an address to paste back): stop and start the hive |
| hive_demo.py: `This hive has no app 'omega-connect'` | the app is not mounted, or the hive was not restarted after `hive.env` changed |
| hive_demo.py: `The hive gave no sign-in link` | the hive is not running: `omegahive.sh start`, or open Omega Hive |
| hive_demo.py: `teams-mcp does not answer` | start `server.py` first, on the port of `--server-url` |
| hive_demo.py: `A server named 'teams' is already in this swarm, with another address or sign-in` | a rehearsal or a run on another port left it: remove it on the app's page, or give another `--swarm` |
| hive_demo.py keeps waiting for accept-reads or for your answer | the page did not send it: Ctrl-C, run again and answer **2** |
| hive_demo.py: `The sign-in failed` | declined, or not finished in time; the reason is in the app's trace, as above |

## Tests

```sh
python -m pytest -q examples/teams-mcp      # 54 tests, ~60 s
```

Graph is simulated in memory (`FakeGraph` replaces `server.graph_send`), so no
request reaches Microsoft or any other outside address.

`test_server.py` runs the server on `127.0.0.1` in a thread and calls it with
omega-connect's own MCP client. Its tests cover the tool hints, listing,
plain-text messages, posting, id checks before any call, the size caps, the
token of each request forwarded as it is, no call without a token, Graph errors
explained without the token, nothing logged with the token, the `127.0.0.1`
binding, Host and Origin checks, and the real transport not following
redirects. The last test runs the demo above through omega-connect's actions in
the repository's fake hive (sign-in and the review of the reads included,
identity platform in memory) and checks that the token never appears in
results, views, the store or the logs.

`test_demo.py` runs `demo.py` in its own process and answers its prompts as a
person would. The demo starts the server with the simulated Graph, and the
sign-in goes to a fake identity platform. The tests check that nothing is
posted before the `y`, and exactly once after it; that `n` posts nothing; that
message text cannot drive the terminal; that the device code, the tokens and
the full tenant and client IDs never appear on screen; that the browser sign-in
gives its address to the browser, not to the screen (printing it, with a
warning, only where no browser opens), then asks for nothing: the test plays
the browser, which comes back to the app's listener, and the demo goes on once
the view names who signed in, the code redeemed once with its PKCE verifier
and the same redirect address; that a sign-in declined in the browser stops
the demo; that the
demo uses its own store and key and passes none of the shell's
`OMEGA_CONNECT_` settings to the server; that a failed sign-in, Ctrl-C or a
closed input stop the demo, with the server stopped and the temporary folder
deleted; that Ctrl-C reaches a script also when pytest itself runs with
SIGINT ignored, as a shell's background job does (the tests of both demos
start their scripts with SIGINT at its default); and that no `.py` file of
the whole repository, nor any of its documents (`.md`, `.json`, `.txt`),
holds an invisible control or bidirectional character.

`terminal_input.py` is what the two demos ask at the terminal with.

`test_hive_demo.py` runs `hive_demo.py` in its own process against the hive's
HTTP routes, simulated over the repository's fake hive with the checks the Mac
test build makes on them: the one-time sign-in link, the `Origin` of a person's
session, the confirm token of each confirm act (minted for the same session,
swarm, action and payload digest, spent once), the mind's token on the mind's
route. The test plays the person on the hive's pages with a session of its own.
The tests check that nothing is posted before the approval and exactly once
after it, whether the answer comes from the Approvals page or from the script;
that *No* posts nothing; that the mind's calls carry the mind's token, no
`Origin` and a body that names neither the mind nor its swarm; that no sign-in
link, session, mind token, confirm token, Microsoft token or sign-in code
reaches the screen, and no token any address; that a second run asks for no ID
and replaces the first run's mind; that the browser sign-in takes one connect
and nothing pasted, and a declined one stops the demo; that a hive still
running the earlier app, which answers connect another way, is told apart
without showing its answer; that `--cleanup` deletes the mind an
interrupted run left and denies its waiting request; that a missing hive, app
or server is said before anything is made; and that the confirm digest is the
hive's (also against the build's shared vectors, when it is installed).

All three files pass with MCP SDK 1.x and 2.x.
