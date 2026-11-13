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
     applications*, with `https://login.microsoftonline.com/common/oauth2/nativeclient`
     ticked as a redirect URI;
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
   `read-tool` on *allow* and `use-tool` on *ask*.

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

**2. connect** (person, confirmed), on `server:teams`, with
`{"for_minds": true}`: the sign-in is the person's own, and this lends it to
the swarm's minds, which use no other. The result shows a code and
`https://microsoft.com/devicelogin`, to this person only: the app's view never
shows the code. Sign in there with the tenant account and accept the
permissions. The app finishes the sign-in by itself; the view then shows
`Sign-in: oauth-device (1 person signed in; lent to minds by <principal>, as <the account>)`.

On a tenant whose security defaults block the device code, run connect with
`{"flow": "browser", "for_minds": true}` instead. Open the address in the
result, sign in and accept, then copy the address of the empty page the
browser lands on and run connect again with `{"redirect_url": "<that address>"}`.

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
nothing is posted yet. When a person approves, the app runs the tool once, the
message appears in the channel as the person who signed in, and the trace keeps
digests and the hive's record id. A retry with the same idempotency key returns
the recorded result instead of posting again.

To finish, **revoke** (person, confirmed) on `server:teams` deletes the token.

## Run it with demo.py

`demo.py` walks the steps above against your tenant from a terminal, without a
hive. It mounts omega-connect in the repository's stand-in for the host
(`tests/fakehive.py`) and plays both parts: the mind `scout` (`list-tools` and
`read-tool` on *allow*, `use-tool` on *ask*), and you, the person who confirms
and approves. It starts the server itself on a free port of `127.0.0.1`, and
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
   in and accept, then paste the whole address of the empty page the browser
   lands on; a wrong or declined one is asked again, and Enter alone stops the
   demo. The app registration needs the redirect URI of *Before the demo*.
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
| demo.py: the device code sign-in fails on a tenant created since July 2026 | its security defaults block the device code: run the demo again and choose **2**, the browser |
| demo.py, browser: `AADSTS50011` in the browser | the redirect URI `https://login.microsoftonline.com/common/oauth2/nativeclient` is missing under *Mobile and desktop applications* |
| demo.py: the *Identity* line is not `https://login.microsoftonline.com` | `OMEGA_CONNECT_OAUTH_AUTHORITY` is set in the shell (the tests use it): unset it |

## Tests

```sh
python -m pytest -q examples/teams-mcp      # 32 tests, ~17 s
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
warning, only where no browser opens), asks again after a wrong or declined
address, and redeems the code once with its PKCE verifier; that the demo uses its
own store and key and passes none of the shell's `OMEGA_CONNECT_` settings to
the server; and that a failed sign-in, Ctrl-C or a closed input stop the demo,
with the server stopped and the temporary folder deleted.

Both files pass with MCP SDK 1.x and 2.x.
