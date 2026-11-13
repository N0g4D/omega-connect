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

**Status: 0.2.0**, the first working version with the changes from the first
review ([Changes in 0.2.0](#changes-in-020)). All actions work against real MCP
servers over streamable HTTP and stdio, and the offline tests pass.
`hive.programs_check` from a pre-release copy of omegahive (04fc3f2) reports it
compatible. The contract fixture is not in that copy; the omegahive repository
opens around 19–20 November.

## Actions

| Action | Minds | Effect | What it does |
|---|---|---|---|
| `list-servers` | yes | read | Servers in this swarm, their transport and status |
| `list-tools` | yes | read | Tools per server, each classed `read` or `write` |
| `inspect-tool` | yes | read | One tool's description and full input schema |
| `read-tool` | yes | read | Runs a tool only if it is classed `read` |
| `use-tool` | yes | (write) | Runs any visible tool; a mind's call needs a person's approval ("ask"), and on a sign-in lent to minds the lender's |
| `add-server`, `remove-server` | no | confirm | People only |
| `accept-reads` | no | confirm | Accept the tools a server marks read-only as reads: a whole server, or one tool |
| `reclass-tool` | no | confirm | Make a tool `write` or `hidden`, or back to `default` (never `read`) |
| `connect`, `revoke` | no | confirm | OAuth sign-in inside the app (device code, or browser with PKCE), and its removal |

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
- **Idempotency twice.** The hive records intents; the app also keeps its own
  record for `use-tool`, so a retried write returns its recorded result. The
  hive promises at most one delivery per confirm, not exactly-once effects
  (PROGRAMS.md 9d). Just before a `use-tool` call goes out, the app records
  it without a result. When the hive delivers again an attempt that failed
  with an unknown effect and that record has no result yet, `use-tool` runs
  the tool again and the result says the first attempt may already have taken
  effect (`detail.prior_failed: true`). The app needs its own record for this
  if, as MesTTo reads flagship main, the hive's agent route delivers a mind's
  failed attempt again with the same `record_id` and no
  `ctx.command.prior_failed` (open point 6). An identical retry of a write the
  hive recorded as done comes back as a recovery (`ctx.actor.recovery`, with
  the approval it first ran under; open point 3): `use-tool` answers from its own
  record, and if that record is gone it refuses (`detail.type: "recovery"`)
  instead of running the tool a second time. Those records keep each answer
  whole, what the tool sent back included, so they are encrypted with the
  tokens' key (`intents.bin`), never kept in clear, and cut to the newest half
  once they pass 1 MiB, as the trace is. Without the key a mind's `use-tool`
  fails before anything goes out.

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
security defaults are on. There, run `connect` with `{"flow": "browser"}`:
the result gives the person an address to open (authorization code with
PKCE). After they sign in, the browser lands on
`https://login.microsoftonline.com/common/oauth2/nativeclient?code=...`, an
empty page. They run `connect` again with that whole address as
`redirect_url`, within ten minutes, and only they can finish it; that
second `connect` needs no current `base_revision`, since the first one
changed the page. A sign-in nobody finishes leaves the view when it
expires. The app registration needs that address as a redirect URI under
*Mobile and desktop applications*.

Each person signs in for themselves: the app keeps every person's sign-in
under their principal (`ctx.actor.principal`, such as `user:ada`), encrypted,
and a person's own calls to the server use their own. One who has not signed
in is told to run `connect`. A sign-in reaches the swarm's minds only when its
person lends it on purpose: `connect` with `{"for_minds": true}`, confirmed
like any `connect`, lends the person's sign-in, or, if they have none yet, the
one it starts. One sign-in per server is lent at a time; lending another
replaces it. A mind's call uses the lent sign-in, and with none lent it is
refused. A mind's write on it runs as the lender's account, so only the
lender can approve it: the approver the hive names (`approved_by`) must be
the lender. `use-tool` also declares `approver: "person"` (PROGRAMS.md 9d),
so that a named person approves, never the local operator password; whether
the hive applies it to minds' approvals is to verify on a scratch hive. The view says how many people signed in and whose sign-in is lent,
with its account (`preferred_username` from the id_token, kept only to show
it; the id_token itself is not stored). `revoke` deletes only your own
sign-in; if it was the lent one, minds have none until a person lends one
again. A sign-in kept by an earlier version (one per server, naming no
principal) counts as none: its person signs in again, and lends it.

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
  the view, which shows the account that signed in instead. New
  `oauth-device` servers also ask for `openid` and `profile`; a server added
  under 0.1.0 keeps its scopes, so its view says only "signed in" until it is
  removed and added again.
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

## Tests

```sh
pip install -r requirements-dev.txt
python -m pytest -q tests        # 67 tests, mock MCP servers on localhost, no outside network
```

Both suites (this one and `examples/teams-mcp`) pass with MCP SDK 2.3 and
1.30.

`tests/fakehive.py` is a small stand-in for the host that follows the public
contract notes and `hive/PROGRAMS.md`, and on the minds' route answers as
`hive/core/program_actions.py` on flagship main does (open points 3 and 6:
confirmed by MesTTo, or MesTTo's reading; to verify on a scratch hive): agent
flag, no default allow,
`approval_required` with an `approval_id` that the mind sends back once a
person approves, approvals bound to the exact request and its key and
redeemed once, the approval in `ctx.actor.approval`, the hive's record id in
`ctx.command`, an identical retry of a done act delivered again as a recovery
with its original approval, failed attempts delivered again with the same
record id and no `prior_failed`, `base_revision` added to params, read actions stored as
digests only, confirm for people's actions, refusal of identity and
credential keys.

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
| An identical retry returning the recorded result | `test_identical_retry_returns_the_recorded_result`, `test_app_level_idempotency_also_holds`, `test_an_identical_retry_is_a_recovery_that_runs_nothing_again` |
| Tokens never in results, views or logs | `test_tokens_never_appear_in_results_views_traces_or_logs`, `test_device_code_sign_in_and_revoke`, `test_browser_sign_in_with_pkce` |
| `programs_check` passes | COMPATIBLE with the pre-release copy: `cd ../omegahive-app-contract-04fc3f2 && python -m hive.programs_check ../omega-connect`. It sees only an empty view, so `test_contract.py` checks fuller views and every result with the hive's validators |
| Live demo: read a Teams channel, then a write a person approves | run on a real tenant with `examples/teams-mcp/demo.py`, in the repository's fake hive (13 Nov 2026: the channel read, a message posted once approved); on a scratch hive still to do. `test_demo.py` and the last test of `test_server.py` rehearse it offline |

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
| Browser sign-in with PKCE for tenants that block the device code; only its own address and person finish it; it leaves the view when it expires, and finishing it is never stale | `test_browser_sign_in_with_pkce`, `test_a_browser_sign_in_finishes_only_with_its_own_address_for_its_own_person`, `test_an_unfinished_browser_sign_in_stops_showing_once_it_expires`, `test_finishing_a_browser_sign_in_is_not_stale` |
| Token renewal: off the event loop, once at a time per server, never over a revoke | `test_a_token_renewal_does_not_block_the_event_loop`, `test_calls_on_several_loops_renew_the_token_once`, `test_a_renewal_that_ends_after_a_revoke_does_not_bring_the_token_back` |
| A renewed token opens a new session; the call running on the old one finishes | `test_a_renewed_token_opens_a_new_session`, `test_a_call_running_when_the_token_is_renewed_finishes_on_its_session` |

Coverage of issue #8, which person a mind acts for:

| Change | Tests |
|---|---|
| Each person signs in for themselves: their own calls use their own sign-in, revoke deletes only theirs | `test_each_person_signs_in_for_themselves` |
| Minds use only a sign-in lent to them on purpose, one per server at a time | `test_minds_use_only_a_sign_in_lent_to_them` |
| A mind's write on a lent sign-in needs the lender's approval; `use-tool` declares `approver: "person"` | `test_a_minds_write_on_a_lent_sign_in_needs_the_lenders_approval`, `test_describe_matches_the_brief` |

## Open points for the flagship team

Checked against `hive/PROGRAMS.md` in the pre-release copy of omegahive
(04fc3f2): sections 1–5, "Read actions" and 9d. The first review (Dot, for Jon
Grove, on 8051f30) answered each of them. MesTTo's pull requests (#3–#11) added
what the minds' route does in `hive/core/program_actions.py` on flagship main,
a private repository: that file, like `hive/requirements.txt` and
`hive/ci-constraints.txt`, is not in the 04fc3f2 copy, so points 3, 6 and 7
rest on MesTTo's word and are to verify on a scratch hive.

1. **Settled: `use-tool` declares no effect.** The contract defines only
   `"effect": "read"`, for actions that change nothing and are safe to repeat;
   anything else keeps the ordinary contract, which is what a write needs.
   `USE_TOOL_EFFECT` in `program.py` stays `None`. The review confirmed this
   reading of the contract.
2. **Settled: `applies_to` for actions that do not target an item**
   (`list-servers`, `add-server`) stays `["server"]`. The contract shows
   `applies_to` only as a list of kinds and says nothing about actions without
   an item; the review found this choice fine.
3. **`act()` is told who approved: confirmed by MesTTo against flagship
   main, to verify on a scratch hive.** PROGRAMS.md does not say so. On the
   minds' route under "ask", the hive answers `approval_required` with an
   `approval_id`; when the mind repeats the request with that `approval_id`,
   `act()` gets `ctx.actor.approval = {id, binding_digest, approved_by}`,
   `approved_by` being the approver's principal. Under "allow" the approval is
   `None`. An identical retry of an act already recorded gets the original
   approval again, with `recovery: true` (`hive/core/program_actions.py`,
   `agent_act` and `_approval`). `ctx.command` carries the request identity:
   `idempotency_key` and `record_id`. So traces keep the approver, the
   approval's id and `record_id`; a mind's `use-tool` with no approval is
   refused; and a recovery never runs a tool twice.
4. **Which person a mind acts for: issue #8, on this branch.** Each person
   signs in for themselves, under their principal (`ctx.actor.principal`),
   and their own calls use their own sign-in. A sign-in reaches the swarm's
   minds only when its person lends it with `connect` and `for_minds`, one
   per server at a time; a mind's write on it needs the lender's approval
   (`ctx.actor.approval.approved_by`, open point 3). `use-tool` declares
   `approver: "person"` (PROGRAMS.md 9d); whether the hive applies it to
   minds' approvals, and the principal on the person route, are to verify on
   a scratch hive with the rest of point 3.
5. **Agreed, as a separate small piece:** the mind skill for native Omega
   minds (brief, "a second, smaller piece").
6. **Failed writes delivered again after "ask": MesTTo's reading of flagship
   main, to confirm.** Section 9d describes `prior_failed` for acts a person
   confirms in the host. For a mind, MesTTo reads `hive/core/program_actions.py`
   (`agent_act`) as delivering a failed attempt again only after a new
   approval, with the same `record_id` and no `prior_failed`. The app does not
   depend on it: it records each call just before it goes out, so it knows
   such an attempt either way.
7. **Dependencies: no conflict, by MesTTo's check, to confirm.** MesTTo
   resolved `requirements.txt` with the hive's `hive/requirements.txt` under
   the pins of its CI (`pip install --dry-run -c hive/ci-constraints.txt`,
   Python 3.12): nothing clashes and no pinned version moves. MCP SDK 2.3 adds
   13 packages the hive does not pin (`mcp`, `mcp-types`, `httpx2`,
   `httpcore2`, `jsonschema`, `jsonschema-specifications`, `referencing`,
   `rpds-py`, `attrs`, `pyjwt`, `python-multipart`, `sse-starlette`,
   `truststore`), so the ranges stay as they are. Those two files are not in
   the 04fc3f2 copy, so this was not repeated here.

## Layout

| Path | What |
|---|---|
| `plugin.json`, `program.py` | App identity and the host program (`describe` / `view` / `act`) |
| `connect/engine.py` | MCP sessions: one long-lived task per server on a private event loop; tool lists and their definition digests |
| `connect/store.py` | Per-swarm servers (with the reads a person accepted), encrypted credentials and `use-tool` records, traces |
| `connect/oauth.py` | OAuth 2.0 device authorization grant (standard library only) |
| `tests/` | Fake host, mock MCP server, fake identity provider, tests |
| `examples/teams-mcp/` | Microsoft Teams MCP server over Graph for the live demo (127.0.0.1 only), its tests, the demo steps and `demo.py`, which runs them on a real tenant |
