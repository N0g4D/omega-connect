# omega-connect: tool connections for OmegaHive

An OmegaHive app that lets the minds in a hive use outside tools through MCP
servers (Microsoft 365, Dataverse, GitHub, Slack, Notion...). Reads run under
the owner's choice of permission, once a person has accepted the tools as
reads; every write goes through `use-tool`, which the owner keeps on "ask", so
a person approves each one. The app refuses a mind's `use-tool` that no person
approved, even under an "allow" rule.

Built against the "Omega tool connections: starter brief" (12 Nov 2026) and
program contract 0.2 as described in
[omegahive-schematics](https://github.com/omega-flagship/omegahive-schematics)
(`06-apps/`). Apache-2.0.

**Status: 0.3.0.** All actions work against real MCP servers over streamable
HTTP and stdio, and the offline tests pass. 0.2.0 was the first working
version with the changes from the first review
([Changes in 0.2.0](#changes-in-020)); 0.3.0 changes the browser sign-in,
which the app now finishes by itself on a loopback listener
([Changes in 0.3.0](#changes-in-030)).
`hive.programs_check` from a pre-release copy of omegahive (04fc3f2) reports it
compatible. The contract fixture is not in that copy; the omegahive repository
opens around 19–20 November. How the hive runs a mind's action is checked
against `hive/core/program_actions.py` from omegahive main (832b36e).

## Actions

| Action | Minds | Effect | What it does |
|---|---|---|---|
| `list-servers` | yes | read | Servers in this swarm, their transport and status |
| `list-tools` | yes | read | Tools per server, each classed `read` or `write` |
| `inspect-tool` | yes | read | One tool's description and full input schema |
| `read-tool` | yes | read | Runs a tool only if it is classed `read` |
| `use-tool` | yes | (write) | Runs any visible tool; a mind's call needs a named person's approval ("ask"), on a person's sign-in that person's |
| `add-server`, `remove-server` | no | confirm | People only |
| `accept-reads` | no | confirm | Accept the tools a server marks read-only as reads: a whole server, or one tool |
| `reclass-tool` | no | confirm | Make a tool `write` or `hidden`, or back to `default` (never `read`) |
| `connect`, `revoke` | no | confirm | OAuth sign-in inside the app (device code, or browser with PKCE and a loopback redirect), for a named person only, and its removal |

Parameters for the tool actions: `server`, `tool`, `arguments` (a JSON object,
or a string holding one). They are also `binding_params`, so an approval binds
to the exact server, tool and arguments.

A tool is `read` only when the server marks it `readOnlyHint`, **a person has
accepted it** with `accept-reads`, its definition is **still the one they
accepted**, and the owner has not reclassed it. Everything else is `write`.
`list-tools` says why with a `review` field: `accepted`, `not reviewed` or
`changed since review`.

## Reads are reviewed by a person

MCP annotations are hints from the server, not guarantees: an untrusted or
compromised server can label a delete as read-only. So every tool of a newly
added server is `write`, whatever it claims, until a person accepts its reads:

1. Someone runs `list-tools` on the server, which loads its tools into the view.
2. A person looks at them and runs `accept-reads` on the server (all the tools
   it marks read-only) or on one tool. Only tools marked `readOnlyHint` can be
   accepted; the others stay `write`.
3. After that the owner can only make a tool stricter: `reclass-tool` sets
   `write` or `hidden`, and `default` goes back to what the review says.

For each accepted tool the store keeps a **digest of its definition** as the
server sent it (sha256 of the name, the full description, the input schema
and the annotations), with who accepted it and when. A tool whose definition
no longer matches drops back to `write`, and the view marks it *changed since
review* until a person accepts it again. The app loads the tool list again
when the server sends `notifications/tools/list_changed` and whenever it opens
a session (also after a server restart: the server answers the old session
with 404, and the app opens a new one). A call goes out only while the
session still has the definition it was classed by.

`accept-reads` applies to the definitions loaded in the app, the ones the view
shows, without connecting again. The view's revision covers their digests, so
if the server changed them after the person looked, the act comes back
`stale`.

**What the digest does not catch.** It detects changes in a tool's
definition, not in its behaviour. A server can keep a definition unchanged and
make the tool do something else, behave differently for some arguments or some
callers, or put a different service behind the same name. Accepting reads
means trusting the server's word for those definitions; for a server you do
not trust, accept nothing, and every call goes through `use-tool` and a person.

## What the app guarantees

- **Credentials stay inside the app.** Bearer tokens come from operator
  variables named `OMEGA_CONNECT_CRED_<NAME>` (a server can never be pointed
  at the hive's own secrets), and each goes only to the addresses the operator
  lists in `OMEGA_CONNECT_ORIGINS_<NAME>`, checked when a person adds a server
  and before every call. OAuth tokens are encrypted at rest with Fernet
  and the key in `OMEGA_CONNECT_SECRET_KEY`; without that key the app refuses
  to store them. Tokens never appear in results, `view()`, traces, logs or
  errors: every outgoing text is scrubbed of the values tied to the server.
- **Token renewal without races.** An OAuth token is renewed shortly before
  it expires, one renewal at a time per server and swarm (Entra rotates
  refresh tokens, so two renewals at once would spend the same one), after
  checking again that it is still due, and in a thread, so the hive's event
  loop keeps running. The renewed token opens a new MCP session, since headers
  are fixed when a session opens; a call already running finishes on the old
  one. A renewal that ends after a `revoke` never brings the token back.
- **The browser sign-in's listener takes one answer.** While a person signs
  in with the browser flow, the app listens on a port of the loopback
  interface, for ten minutes at most. Only a GET that carries the sign-in's
  `state` completes it, once, for the person who ran `connect`. Its pages are
  fixed text, and nothing of a request is logged or sent back: the request
  line carries the code ("Add a server", below).
- **Tool output is untrusted data.** Results are capped at 8,000 characters,
  returned as `{"untrusted": true, "text": ...}` and labelled as data, not
  instructions. Server-provided descriptions are cleaned and capped too.
- **Every call is traced**: server, tool, digest of the arguments, digest of
  the result, status, actor, who approved it and the approval's id
  (`ctx.actor.approval`), and the hive's record id for the act
  (`ctx.command.record_id`). Traces never hold content.
- **Streamable HTTP by default.** `https://` only (plain `http` for localhost),
  no credentials in URLs. stdio servers start processes on the hive's machine
  and are refused unless the operator sets `OMEGA_CONNECT_ALLOW_STDIO=1`.
- **One swarm per call.** Server lists, tokens and traces are kept per swarm.
- **Idempotency twice.** The hive records every act of a mind under its
  idempotency key, and answers an identical retry of an act it recorded as
  done from that record, without calling the app (open point 3). The app
  also keeps its own record for `use-tool`, so a retried write returns its
  recorded result there too. `use-tool` declares no `revalidate`, which
  would have the hive deliver such a retry to the app as a recovery; should
  one come (`ctx.actor.recovery`), `use-tool` answers from its own record,
  or without it from the hive's (`ctx.command.recorded_result`), and with
  neither it refuses (`detail.type: "recovery"`): the tool never runs a
  second time. Just before a `use-tool` call goes out, the app records it
  without an answer. When `act()` raises, the hive marks the act failed, and
  the mind's identical retry comes back after a new approval, with the same
  `record_id` and no `ctx.command.prior_failed`. If the app's record of it
  still has no answer, that attempt may have reached the server, so
  `use-tool` does not send it again and answers `outcome_unknown` (next
  point). Those records keep each answer whole, what the tool sent back
  included, so they are encrypted with the tokens' key (`intents.bin`),
  never kept in clear, and cut to the newest half once they pass 1 MiB, as
  the trace is. Without the key a mind's `use-tool` fails before anything
  goes out.
- **A write goes out again only if it certainly did not run** (open point
  6). When a `use-tool` call certainly did not run (the connection was
  refused or the server could not be reached, the session ended while the
  call was waiting to go out, or the server answered HTTP 404 for a session
  it no longer has, as after a restart, and so ran nothing), the app tries
  again in the same act, on a new session where the old one is gone, as the
  MCP specification asks of a client after that 404: at most 5 attempts,
  waiting 0.5, 1, 2 and 4 s between them, none started later than 30 s after
  the first; the trace counts the attempts.
  When the call may have reached the server and no answer came back (none
  within the server's timeout, or the connection lost while the call was
  out), `use-tool` does not send it again. It answers `refused` with
  `detail.type: "outcome_unknown"`, and tells the mind to check whether the
  write took effect, for example with `read-tool`, and if it did not, to
  make a new request (a new idempotency key), which a person approves again.

## Mount it in a hive

```sh
pip install -r requirements.txt              # into the hive's Python environment
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
export OMEGA_CONNECT_SECRET_KEY=<that key>    # for OAuth sign-in and minds' use-tool
export HIVE_PLUGIN_DIRS=/path/to/omega-connect
```

Optional settings: `OMEGA_CONNECT_DATA_DIR` (store, default `~/.omega-connect`),
`OMEGA_CONNECT_LOG_DIR` (stderr of stdio servers), `OMEGA_CONNECT_ALLOW_STDIO=1`,
`OMEGA_CONNECT_CRED_<NAME>` (bearer tokens) with `OMEGA_CONNECT_ORIGINS_<NAME>`
(the addresses each may go to, such as `https://api.githubcopilot.com`,
space- or comma-separated), `OMEGA_CONNECT_OAUTH_AUTHORITY` (default
`https://login.microsoftonline.com`).

Then attach a mind, for example `read-tool` on allow and `use-tool` on ask,
and add a server (below). `read-tool` runs only the tools a person has
accepted as reads.

`use-tool` declares `approver: "person"`: only a named person signed in to
the hive runs a write or approves a mind's, and the hive refuses the local
operator password for both (403 `person_required` when it runs `use-tool`,
409 `person_approval_required` when it approves). With only the operator
password, nobody can run or approve a write, so the demo on a scratch hive
is done as a named person. `connect` declares `approver: "person"` too: a
sign-in always belongs to a named person, so the hive refuses `connect` to
the local operator password (403 `person_required`).

## Add a server (person, confirmed)

A GitHub-style server with a token the operator provides, in
`OMEGA_CONNECT_CRED_GITHUB`, for the address they list in
`OMEGA_CONNECT_ORIGINS_GITHUB=https://api.githubcopilot.com`:

```json
{"name": "github", "url": "https://api.githubcopilot.com/mcp/",
 "signin": {"kind": "bearer-env", "variable": "OMEGA_CONNECT_CRED_GITHUB"}}
```

A Microsoft 365 server with delegated sign-in (Entra app registration,
least-privilege scopes, consent by the person who runs `connect`):

```json
{"name": "m365", "url": "https://<your Microsoft 365 MCP endpoint>",
 "signin": {"kind": "oauth-device", "tenant": "organizations",
            "client_id": "<application id>", "scopes": ["ChannelMessage.Read.All"]}}
```

omega-connect adds `openid` and `profile` (so the identity provider says who
signed in) and `offline_access` (so the token can be renewed) to the scopes.

`connect` returns a code and a sign-in address to the person who ran it, and
only to them: the view never shows the code, so nobody else in the swarm can
finish that sign-in with their own account. The app finishes the sign-in on
its own once the person has signed in.

Tenants created since July 2026 block the device code while Microsoft's
security defaults are on. There, run `connect` with `{"flow": "browser"}`
(authorization code with PKCE, the browser coming back to a loopback
address: RFC 8252, section 7.3). The app opens a listener on a free port of
the loopback interface of the hive's machine and uses
`http://localhost:<port>` as the redirect address. The result gives the
address to open to the person who ran `connect`, and only to them: the view
never shows it. They sign in, their browser comes back to the listener with
a code, and the app trades the code for tokens, with its PKCE verifier and
the same redirect address, and keeps them under that person. As with the
device code, the sign-in completes on its own.

The listener:

- listens on `127.0.0.1` and, where the machine has it, on `::1` on the same
  port, since a browser may take `localhost` for either; never on an address
  that another machine can reach. A port that another program holds on `::1`
  is not used.
- completes only on a GET that carries the sign-in's `state`, compared in
  constant time, and only once. Any other request (the browser asking for an
  icon, a wrong or missing state, another method) gets an error page and
  neither closes the listener nor uses up the wait; past 50 requests the
  listener gives up. Each connection is served on its own, so one that sends
  nothing holds up no other.
- with the state and a code, trades the code, keeps the sign-in and answers
  "You are signed in. You can close this page." With the state and an error
  from Microsoft (the person declined, say), or when Microsoft refuses the
  code, it puts the failure in the trace and answers with an error page.
- answers with fixed pages that carry nothing of the request, and logs
  nothing of a request: its first line carries the code.
- closes with the outcome, or after ten minutes; a sign-in nobody finishes
  then leaves the view, with the reason in the trace. A new `connect` by the
  same person on the same server closes the earlier listener, and so does
  removing the server.

The app registration needs the redirect URI `http://localhost` under
*Mobile and desktop applications*. Entra leaves the port out when it
compares a `localhost` redirect URI, so that one entry covers whatever port
the listener gets
([Microsoft's reference](https://learn.microsoft.com/en-us/entra/identity-platform/reply-url#localhost-exceptions)).
RFC 8252 prefers the literal `127.0.0.1` to `localhost`; Entra's portal
takes a plain-`http` loopback address only as `http://localhost`
(`http://127.0.0.1` needs an edit of the app manifest, and `[::1]` is not
supported), hence `localhost` and a listener on both loopback addresses.

**Limit.** The browser sign-in works when the person's browser runs on the
hive's machine: `localhost` in the redirect address is the machine of the
browser. On a hive shared over a network, a person's browser is on another
machine and cannot come back to the app. That takes a callback address of
the hive itself, which is still to do; until then, a person on another
machine signs in with the device code, where the tenant allows it.

Each person signs in for themselves: the app keeps every person's sign-in
under their principal (`ctx.actor.principal`, such as `user:ada`), encrypted,
and a person's own calls to the server use their own. One who has not signed
in is told to run `connect`. A mind uses the sign-in of the person it belongs
to, never anyone else's (open point 4). The hive does not say who that is yet
(asked for in omegahive #332; `_mind_owner` in `program.py` is the one place
that will read it), so until it does, a mind uses a sign-in only while one
person alone is signed in to the swarm's servers, all its `oauth-device`
servers counted together. With ada signed in only to `notes` and bob only to
`notes2`, the mind could be either's, so its acts are refused on both
(`detail.type` `owner_unknown`), as they are when several people are signed
in to one server; on a server nobody has signed in to, they are refused with
`not_signed_in`. Once the hive names owners, a mind whose owner has not
signed in is refused (`owner_not_signed_in`) rather than given someone
else's token. A mind's write runs as that person's account, so only they can
approve it: the approver the hive names (`approved_by`) must be them. The
view lists who signed in to each server, with the account
(`preferred_username` from the id_token, kept only to show it; the id_token
itself is not stored), and says whether minds use that sign-in. `revoke`
deletes only your own sign-in. A sign-in kept
by an earlier version (one per server, naming no principal) counts as none:
its person signs in again.

The parameter is `signin` rather than `auth` because the host refuses request
bodies with credential-like keys.

Then accept the server's reads. Until a person does, every tool of the new
server is `write`, so `read-tool` runs none of them:

1. `list-tools` on the server (by a person, or a mind allowed to) loads its
   tools into the view. For an `oauth-device` server, run `connect` first.
2. A person looks at the tools in the view and runs `accept-reads`
   (confirmed) on `server:<name>`, which accepts every tool the server marks
   read-only, or on one `tool:<name>/<tool>`.

If an accepted tool's definition changes later, the view says *changed since
review* and the tool is `write` until a person accepts it again (see "Reads
are reviewed by a person").

## Changes in 0.3.0

One change, not compatible with 0.2.0: **the browser sign-in finishes on a
loopback listener** (RFC 8252, section 7.3; asked for by MesTTo on #2). In
0.2.0 `connect` with `{"flow": "browser"}` answered `needs_input`, and a
second `connect` took the address the browser landed on, as `redirect_url`.
On a real tenant there was no such address to give: after the sign-in
Microsoft moves an ordinary browser from the `nativeclient` page to
`/common/wrongplace` and takes the code out of the address. For a hive that
ran 0.2.0:

- **`connect` with `{"flow": "browser"}` answers `done`** with the address
  to open, and the app completes the sign-in by itself when the person's
  browser comes back to `http://localhost:<port>` ("Add a server", above).
  `connect` no longer takes `redirect_url` and never answers `needs_input`.
- **The app registration needs another redirect URI:** `http://localhost`
  under *Mobile and desktop applications*, in place of
  `https://login.microsoftonline.com/common/oauth2/nativeclient`, which is
  no longer used.
- **The browser runs on the hive's machine.** During a browser sign-in the
  app listens on a port of that machine's loopback interface, for ten
  minutes at most; from another machine, use the device code.
- **Every `connect` needs the page the person saw:** from a page that has
  changed it is `stale`, like any other act. 0.2.0 let the second `connect`
  of a browser sign-in through.
- **Removing a server closes its browser sign-ins in progress.**
- **`demo.py` and `hive_demo.py`** open the sign-in page and wait for the
  view to name who signed in; no address is pasted back.

## Changes in 0.2.0

Behaviour that changes for a hive that ran 0.1.0:

- **Reads need a person.** A tool runs through `read-tool` only once a person
  has accepted it with `accept-reads`, a new people-only action. Servers added
  under 0.1.0 are no exception: after the upgrade their tools are `write`
  until someone accepts their reads.
- **`reclass-tool` only makes a tool stricter:** it takes `write`, `hidden` or
  `default` and refuses `read`. A `read` reclass stored by 0.1.0 is ignored.
- **A changed definition loses its review:** the tool is `write` again, with
  *changed since review* in the view. The tool list is loaded again on
  `notifications/tools/list_changed` and on every new session.
- **A restarted server gets a new session.** 0.1.0 stayed on the dead session
  and every call failed with "Session not found" (or "Session terminated").
- **`list-tools` and `inspect-tool`** give each tool a `review` field
  (`accepted`, `not reviewed`, `changed since review`); a `read-tool` refusal
  carries it in `detail.review`.
- **Sign-in:** the device code is only in the `connect` result, no longer in
  the view, which shows who signed in and the account instead. New
  `oauth-device` servers also ask for `openid` and `profile`; a server added
  under 0.1.0 keeps its scopes, so its view names who signed in but not the
  account until it is removed and added again.
- **Sign-ins are per person:** each person signs in for themselves, and the
  one sign-in per server that 0.1.0 kept counts as none, so a person runs
  `connect` again. A mind uses its owner's sign-in; until the hive names
  owners, the sign-in of the only person signed in to the swarm's servers,
  and none while several people are (open point 4). Only a named person
  signs in: the hive refuses `connect` to the local operator password.
- **`bearer-env` tokens go only where the operator says:** the token in
  `OMEGA_CONNECT_CRED_<NAME>` is sent only to the origins listed in
  `OMEGA_CONNECT_ORIGINS_<NAME>` (space- or comma-separated, such as
  `https://api.githubcopilot.com`), checked when a server is added and before
  every call. With nothing listed the token goes nowhere: for a `bearer-env`
  server added under 0.1.0 the operator sets that list, or its calls fail
  with an error naming the variable to set.
- **Token renewal** runs in a thread, one at a time per server, and the
  renewed token opens a new MCP session; a call already running finishes on
  the old one.
- **Requirements:** `mcp>=1.30,<3` (was `mcp>=1.10`). 1.30 is the lowest
  version the tests have run with; 1.10 does not even import with pydantic
  2.12 or later.
- **`use-tool`'s records are encrypted:** `intents.json` becomes
  `intents.bin`, encrypted with `OMEGA_CONNECT_SECRET_KEY`, which a mind's
  `use-tool` now needs as OAuth sign-in does. A plain `intents.json` left by
  0.1.0 is moved into it and deleted the first time `use-tool` runs.
- **Failed writes:** a `use-tool` call that certainly did not run (it never
  reached the server, or met a 404 for a session the server no longer has)
  is tried again, up to five times in the same act; one that may have reached
  the server with no answer back is not sent again, and `use-tool` answers
  `refused` with `detail.type: "outcome_unknown"` where 0.1.0 answered with
  an error.

## Tests

```sh
pip install -r requirements-dev.txt
python -m pytest -q tests        # 91 tests, mock MCP servers on localhost, no outside network
```

Both suites (this one and `examples/teams-mcp`) pass with MCP SDK 2.3 and
1.30.

`tests/fakehive.py` is a small stand-in for the host that follows the public
contract notes and `hive/PROGRAMS.md`, and runs actions as
`hive/core/program_actions.py` from omegahive main (832b36e) does: request
keys checked as the hive checks them (no identity or credential-like key at
the top level), the agent flag, no default allow, `approval_required` with an
`approval_id` that the mind sends back once a person approves, approvals
bound to the exact request and its key and redeemed once, `approver:
"person"` refusing the local operator password both as approver and on the
person route, the approval in `ctx.actor.approval`, the hive's record id in
`ctx.command`, an identical retry of a done act answered from the hive's
record (delivered as a recovery, with `recorded_result`, only for an action
that declares `revalidate: true`), failed acts delivered again after a new
approval with the same record id and no `prior_failed`, `base_revision`
added to params, read actions stored as digests only, confirm for people's
actions. `tests/test_fakehive.py` checks the fake host itself, with a stub
app that declares what omega-connect does not.

`tests/test_contract.py` runs the app through the same fake host with the
hive's own `validate_graph` and `validate_result` (`hive/core/programs.py`)
when the contract copy `../omegahive-app-contract-04fc3f2` sits next to this
repository; otherwise it is skipped.

Coverage against the brief's definition of done:

| Done item | Tests |
|---|---|
| Listing servers and tools | `test_lists_servers_and_tools` |
| A read-classed tool through `read-tool` | `test_read_tool_runs_a_read_classed_tool` |
| A write-classed tool refused through `read-tool` | `test_read_tool_refuses_a_write_classed_tool` |
| `use-tool` waiting for approval | `test_use_tool_waits_for_a_person` |
| An identical retry returning the recorded result | `test_identical_retry_returns_the_recorded_result`, `test_app_level_idempotency_also_holds`, `test_a_recovery_answers_from_the_apps_record_or_the_hives` |
| Tokens never in results, views or logs | `test_tokens_never_appear_in_results_views_traces_or_logs`, `test_device_code_sign_in_and_revoke`, `test_browser_sign_in_finishes_on_a_loopback_listener` |
| `programs_check` passes | COMPATIBLE with the pre-release copy: `cd ../omegahive-app-contract-04fc3f2 && python -m hive.programs_check ../omega-connect`, and with the checker of the Mac test build 0.33, which loads the app from `HIVE_PLUGIN_DIRS` (17 Nov 2026). It sees only an empty view, so `test_contract.py` checks fuller views and every result with the hive's validators |
| Live demo: read a Teams channel, then a write a person approves | run on a real tenant with `examples/teams-mcp/demo.py`, in the repository's fake hive (13 Nov 2026: the channel read, a message posted once approved); on a scratch hive still to do, as a named person: `examples/teams-mcp/hive_demo.py` is the script for it on the Mac test build, where it makes the mind's calls with the mind's token (the example's README, *On a scratch hive*). `test_demo.py`, `test_hive_demo.py` and the last test of `test_server.py` rehearse it offline |

Coverage of the first review's changes:

| Change | Tests |
|---|---|
| Every tool of a new server is `write` until a person accepts its reads (people only, confirmed; whole server or one tool; only `readOnlyHint` tools) | `test_a_new_servers_tools_stay_write_until_a_person_accepts_its_reads`, `test_accept_reads_for_one_tool` |
| The owner can only make a tool stricter | `test_the_owner_can_only_make_a_tool_stricter` |
| A changed definition drops back to `write`, the view says *changed since review*; `tools/list_changed` reloads the list; the digest covers the full description | `test_a_changed_tool_definition_drops_back_to_write`, `test_a_tool_relabelled_read_only_after_the_review_stays_write` |
| The list is loaded again on every new session, also after a server restart (HTTP 404 for the old session) | `test_a_restarted_server_gets_a_new_session_with_its_tools_loaded_again` |
| `accept-reads` applies to the definitions the person saw | `test_accepting_reads_needs_the_page_the_person_saw` |
| A call goes out only on the definition it was classed by | `test_a_call_goes_out_only_on_the_definition_it_was_checked_against` (engine) |
| The device code only in the `connect` result; the view shows the account that signed in | `test_device_code_sign_in_and_revoke` |
| Token renewal: off the event loop, once at a time per server, never over a revoke | `test_a_token_renewal_does_not_block_the_event_loop`, `test_calls_on_several_loops_renew_the_token_once`, `test_a_renewal_that_ends_after_a_revoke_does_not_bring_the_token_back` |
| A renewed token opens a new session; the call running on the old one finishes | `test_a_renewed_token_opens_a_new_session`, `test_a_call_running_when_the_token_is_renewed_finishes_on_its_session` |

Coverage of issue #8, which person a mind acts for:

| Change | Tests |
|---|---|
| Each person signs in for themselves: their own calls use their own sign-in, revoke deletes only theirs | `test_each_person_signs_in_for_themselves` |
| A mind uses its owner's sign-in, never another person's; until the hive names owners, the sign-in of the only person signed in to the swarm's servers, or none, saying why | `test_a_mind_uses_its_owners_sign_in_or_the_only_one` |
| That only person is counted over the whole swarm: with one person signed in only to one server and another only to a second, a mind is refused on both (`owner_unknown`) | `test_a_mind_uses_no_sign_in_while_different_people_are_signed_in_to_the_swarms_servers` |
| A mind's write needs the approval of the person whose sign-in it uses; `use-tool` declares `approver: "person"`, so the operator password neither approves nor runs a write | `test_a_minds_write_needs_the_approval_of_the_person_whose_sign_in_it_uses`, `test_describe_matches_the_brief` |
| `connect` declares `approver: "person"`: the operator password starts no sign-in (403 `person_required`) | `test_only_a_named_person_signs_in`, `test_describe_matches_the_brief` |

Coverage of the browser sign-in on a loopback listener (0.3.0):

| Behaviour | Tests |
|---|---|
| The sign-in completes on the listener: redirect address `http://localhost:<port>`, PKCE and state, the same redirect address when the code is traded, the sign-in kept under the person who ran `connect`, a fixed page for the browser; the address only in the `connect` result; no code or token in results, views, traces or logs | `test_browser_sign_in_finishes_on_a_loopback_listener` |
| Only a GET with the sign-in's state completes it: an icon request, a wrong, missing or repeated state, another path, another method or bytes that are no request get one fixed error page, which carries nothing of the request, and leave the sign-in waiting | `test_only_the_redirect_with_its_state_completes_a_browser_sign_in` |
| A connection that sends nothing, or half a request, holds up no sign-in | `test_a_connection_that_sends_no_request_holds_up_no_sign_in` |
| An error from Microsoft, in the redirect or when the code is traded: in the trace, a fixed page that repeats none of it, the listener closed | `test_a_browser_sign_in_that_ends_with_an_error_is_traced_and_closed` |
| A sign-in nobody finishes expires: the listener closes, the view stops showing it, the trace says so | `test_a_browser_sign_in_nobody_finishes_expires` |
| A new `connect` by the same person on the same server closes the earlier listener, with either flow; a stale one closes nothing; another person's sign-in goes on and is kept under them | `test_a_new_connect_closes_the_persons_earlier_browser_sign_in`, `test_a_device_code_connect_closes_the_persons_browser_sign_in_too` |
| Removing a server closes its browser sign-ins; one that is finishing just then is not kept | `test_removing_a_server_closes_its_browser_sign_ins`, `test_a_sign_in_whose_server_is_removed_while_it_finishes_is_not_kept` |
| The listener gives up past its limit of requests | `test_the_listener_gives_up_after_too_many_requests` |
| Loopback only: `127.0.0.1` and, where the machine has it, `::1` on the same port; never a port that another program holds on `::1` | `test_the_listener_is_on_the_loopback_interface_only`, `test_the_listener_takes_no_port_held_on_the_other_loopback_address` |

Coverage of failed writes (open point 6):

| Behaviour | Tests |
|---|---|
| A write that certainly did not run is tried again in the same act, at most 5 times, none started later than 30 s after the first: a refused connection, or a 404 for a session the server no longer has, after which it goes out on a new session and runs once | `test_a_write_that_never_reached_the_server_is_sent_again`, `test_a_write_the_server_has_no_session_for_goes_out_again_on_a_new_one`, `test_a_write_that_cannot_reach_the_server_stops_after_five_attempts`, `test_a_call_that_finds_no_server_is_not_sent` and `test_a_call_the_server_has_no_session_for_did_not_run` (engine) |
| A write whose outcome is unknown is not sent again: `refused`, `outcome_unknown`; also when a failed act comes back after a new approval | `test_a_write_whose_outcome_is_unknown_is_not_sent_again`, `test_a_write_delivered_again_after_a_failure_is_not_sent_again`, `test_a_call_cut_once_it_was_out_has_an_unknown_outcome` (engine) |

## Open points for the flagship team

Checked against `hive/PROGRAMS.md` in the pre-release copy of omegahive
(04fc3f2): sections 1–5, "Read actions" and 9d, and against
`hive/core/program_actions.py` and `hive/ci-constraints.txt` from omegahive
main at 832b36e, which Jon Grove sent (unchanged since 04fc3f2, by his note;
the repository is private until it opens, and neither file is copied here).
The first review (Dot, for Jon Grove, on 8051f30) answered each point; what
MesTTo described of the minds' route (pull requests #3–#11, and on issue #2
that a recovery comes only for `revalidate: true`) matches that file; Jon
settled points 4 and 6 on issue #1.

1. **Settled: `use-tool` declares no effect.** The contract defines only
   `"effect": "read"`, for actions that change nothing and are safe to repeat;
   anything else keeps the ordinary contract, which is what a write needs.
   `USE_TOOL_EFFECT` in `program.py` stays `None`. The review confirmed this
   reading of the contract.
2. **Settled: `applies_to` for actions that do not target an item**
   (`list-servers`, `add-server`) stays `["server"]`. The contract shows
   `applies_to` only as a list of kinds and says nothing about actions without
   an item; the review found this choice fine.
3. **Verified: `act()` is told who approved.** PROGRAMS.md does not say so;
   `hive/core/program_actions.py` (832b36e) does. On the minds' route under
   "ask", the hive answers `approval_required` with an `approval_id`; when the
   mind repeats the request with that `approval_id`, the hive redeems it once
   and `act()` gets `ctx.actor.approval = {id, binding_digest, approved_by}`,
   `approved_by` being the approver's principal. Under "allow" the approval is
   `None`. `ctx.command` carries the request identity: `idempotency_key` and
   `record_id`. An identical retry of an act recorded as done gets the
   recorded answer from the hive, without reaching the app, unless the action
   declares `revalidate: true`: only then is it a recovery, with the original
   approval, `recovery: true` and `ctx.command.recorded_result` (as MesTTo
   said on #2). `use-tool` declares no `revalidate`. So traces keep the
   approver, the approval's id and `record_id`; a mind's `use-tool` with no
   approval is refused; and an identical retry never runs a tool twice.
4. **Settled: which person a mind acts for** (Jon Grove on #1; issue #8, on
   this branch). A mind uses the sign-in of the person it belongs to; if that
   person has not signed in, the app refuses with a clear message instead of
   using someone else's token. The hive does not put a mind's owner in
   `ctx.actor` yet (asked for in omegahive #332), so until it does, a mind
   uses a sign-in only while one person alone is signed in to the swarm's
   servers, all its `oauth-device` servers counted together (MesTTo, in the
   review of #12): it is refused when nobody has signed in to the server,
   and when several people are signed in to the swarm's servers, even each
   to a server of their own. Each person signs in for themselves, under
   their principal, and a mind's write needs the approval of the person
   whose sign-in it uses (`ctx.actor.approval.approved_by`, point 3).
   `use-tool` declares `approver: "person"`, which the hive applies both to
   approvals and to the person route (verified with point 3); `connect`
   declares it too, so a sign-in always belongs to a named person.
5. **Settled: the mind skill for native Omega minds is the flagship team's**
   (MesTTo on #2). The brief called it "a second, smaller piece"; theirs
   covers the actions of every app, not only this one, and takes a request
   up again after an approval, so it is not a piece of this repository.
6. **Settled: failed writes** (Jon Grove on #1). When `act()` raises, the
   hive marks the act failed, and the mind's identical retry comes back only
   after a new approval, with the same `record_id` and no `prior_failed`,
   which the hive sets only for actions that declare `person_activity`
   (verified in `hive/core/program_actions.py`). A failed write is sent again
   automatically only when it certainly did not arrive (a refused
   connection, for one), at most five times in five minutes; after that a
   person approves again. When the outcome is uncertain (a timeout after the
   call went out), nothing is repeated blindly: the mind checks, or goes back
   to a person. `use-tool` tries again within one act, at most 5 attempts
   and none started later than 30 s after the first. A 404 for a session the
   server no longer has (after a restart, for one) counts as not arrived: the
   server ran nothing, and the MCP specification has the client open a new
   session, so `use-tool` does and tries again there. Otherwise it answers
   `outcome_unknown`, also when a failed act comes back and the app's record
   shows that a call went out and no answer came ("What the app guarantees").
7. **Verified: dependencies.** `requirements.txt` resolved on top of the
   exact set the hive's CI installs (`hive/ci-constraints.txt`, 832b36e), as
   Linux x86_64 CPython 3.12: `pip install --dry-run` of every pinned package
   and `requirements.txt`, with `-c hive/ci-constraints.txt`. Nothing clashes
   and no pinned version moves, as MesTTo found. It picks MCP SDK 2.3, which
   adds 13 packages the hive does not pin (`mcp`, `mcp-types`, `httpx2`,
   `httpcore2`, `jsonschema`, `jsonschema-specifications`, `referencing`,
   `rpds-py`, `attrs`, `pyjwt`, `python-multipart`, `sse-starlette`,
   `truststore`); 1.30 would add 11. The ranges stay as they are.

## Layout

| Path | What |
|---|---|
| `plugin.json`, `program.py` | App identity and the host program (`describe` / `view` / `act`) |
| `connect/engine.py` | MCP sessions: one long-lived task per server on a private event loop; tool lists and their definition digests; whether a failed call went out |
| `connect/store.py` | Per-swarm servers (with the reads a person accepted), encrypted credentials and `use-tool` records, traces |
| `connect/oauth.py` | OAuth 2.0 sign-in: the device authorization grant, and the authorization code grant with PKCE on a loopback listener (standard library only) |
| `tests/` | Fake host, mock MCP server, fake identity provider, tests |
| `examples/teams-mcp/` | Microsoft Teams MCP server over Graph for the live demo (127.0.0.1 only), its tests, the demo steps, `demo.py`, which runs them on a real tenant in the fake hive, and `hive_demo.py`, which runs them on a scratch hive (the Mac test build) |
