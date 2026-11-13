# CLAUDE.md: working on omega-connect

## What this is

An OmegaHive app (program contract 0.2) that lets minds use outside tools via
MCP. Requested by Jon Grove (SingularityNET / Omega flagship) in the "Omega
tool connections: starter brief", 12 Nov 2026. Kabir and the flagship team
decide what ships. Apache-2.0. Share the repository early.

The brief, in short:
- App in its own repo, mounted through `HIVE_PLUGIN_DIRS`. Never edit the hive.
- Actions: list-servers, list-tools, read-tool (read), use-tool (write, owner
  keeps it on "ask"), and people-only confirm actions: add-server,
  remove-server, connect (OAuth inside the app).
- Streamable HTTP first; stdio off by default. One swarm per call.
  Credentials encrypted at rest, never in results / view() / logs / errors.
  Tool results are untrusted data, capped. Trace every call with digests and
  the approver. Microsoft 365: delegated OAuth, least privilege, consent per
  person, a revoke action.
- Done = programs_check passes; offline tests with a mock MCP server covering
  listing, read-tool on read, read-tool refusing write, use-tool waiting for
  approval, idempotent retry, no token leaks; live demo on a scratch hive
  (mind reads a Teams channel, asks to post, a person approves).

## Contract facts to respect

- `describe()` must be synchronous; `view()` and `act()` may be async.
- `view()` returns a full WorkGraph: `revision` (change it whenever content
  changes), items with stable unique ids, links inside the graph, at most 400
  items and 1,200 links. Stages: unfold, map, compare, detail.
- `act()` returns `{status: done|started|needs_input|stale|refused|error,
  message, detail?, graph?, task?}`. `started` needs `task.id`.
- Return `stale` (with the current graph) when `params.base_revision` is old.
- The host refuses bodies with `principal`, `actor`, `swarm_id`, `agent_id`,
  `member_id` or credential-like keys. That is why add-server takes `signin`,
  not `auth`.
- Confirm payloads are canonical JSON, integers only: no floats in params of
  confirm actions.
- Raise `PermissionError` in `view()` to refuse a swarm.
- Capabilities are not a sandbox; the app runs in the hive process.
- The minds' route, from `hive/core/program_actions.py` on flagship main
  (private; not in the 04fc3f2 copy), confirmed by MesTTo, to verify on a
  scratch hive: "ask" answers `approval_required` with an `approval_id`; the
  repeated request reaches `act()` with `ctx.actor.approval = {id,
  binding_digest, approved_by}` (`None` under "allow"); an identical retry of
  a done act comes back with the original approval and `recovery: true`.
  By MesTTo's reading, to confirm: a mind's failed attempt comes back after a
  new approval with the same `record_id` and no `prior_failed`.

Reference: https://github.com/omega-flagship/omegahive-schematics (06-apps),
https://github.com/omega-flagship/omega-tools (template app). The omegahive
repo (with `hive/PROGRAMS.md` and `hive.programs_check`) opens ~19–20 Nov.

## Layout and design

- `program.py`: describe / view / act. Loads `connect/*.py` by file path
  (`importlib`), because the host imports program.py by path, not as a package.
- `connect/engine.py`: MCP client. One private asyncio loop in a daemon
  thread; one long-lived task per (swarm, server) owns transport and
  ClientSession (anyio cancel scopes must stay in one task). Callers submit
  work through a queue. Dropped connections, and sessions the server forgot
  (HTTP 404 after a restart), reconnect on the next call; only read-classed
  calls are retried. Each session loads the tool list when it opens and on
  `notifications/tools/list_changed` (the reload runs in the worker's task:
  SDK 1.x calls the message handler inside its receive loop). Every tool keeps
  a digest of its definition; `call(expect=digest)` sends nothing if the
  definition changed. New auth headers mean a new session; the old one
  finishes its calls (grace = call timeout). Supports MCP SDK 1.x and 2.x:
  `mcp>=1.30,<3`, 1.30 being the lowest version tested.
- `connect/store.py`: per-swarm folder under `OMEGA_CONNECT_DATA_DIR`:
  servers.json (no secrets; the tools a person accepted as read, with the
  digest of each definition), secrets.bin (Fernet), trace.jsonl (digests),
  intents.bin (app-level idempotency for use-tool, each answer included:
  Fernet, newest half kept past 1 MiB; a plain intents.json is moved in).
  Files mode 0600.
- `connect/oauth.py`: RFC 8628 device flow, and authorization code with PKCE
  (RFC 7636) finished by the address the browser lands on, for tenants that
  block the device code; standard library only; authority
  overridable with `OMEGA_CONNECT_OAUTH_AUTHORITY` (tests use a fake). Keeps
  only `preferred_username` from the id_token, to show who signed in.
  Renewal runs in a thread under a lock per (swarm, server), in program.py.
- `examples/teams-mcp/`: MCP server over Microsoft Graph for the Teams demo,
  separate from the app. 127.0.0.1 only; each call uses the token in its own
  request's Authorization header, never stored or logged. README = demo steps.
  `demo.py` runs them on a real tenant in FakeHive (temporary store, Fernet key
  per run, device code or browser sign-in, the approval asked in the terminal,
  output filtered of tokens);
  `test_demo.py` drives it as a person would, with Graph and sign-in simulated.

Classification rule: read only if the server says `readOnlyHint`, a person
accepted that tool with `accept-reads` (people only, confirm), and its
definition digest still matches the accepted one; every tool of a new server
is write until then. The owner can demote (write, hidden, back to default),
never promote. The digest catches definition changes, not behaviour changes.
The device code and the browser sign-in address go only into the `connect`
result, never into `view()`; only the person who started a browser sign-in
can finish it.

## Commands

```sh
pip install -r requirements-dev.txt
python -m pytest -q tests            # 64 tests, ~70 s, localhost only
python -m pytest -q examples/teams-mcp   # 32 tests, ~17 s, Graph simulated in memory
```

Contract checker, from the pre-release copy next to this repo (until omegahive
is public); `tests/test_contract.py` also uses its validators when it is there:
```sh
cd ../omegahive-app-contract-04fc3f2 && python -m hive.programs_check ../omega-connect
```

## Rules for changes

- Never put a credential in a result, view, trace, log line or error. New
  outputs that can carry server text go through `_scrub` / `engine.redact`.
- Never store tool content in clear: traces hold digests only, and
  use-tool's records (its answers, for retries) are encrypted.
- Keep `describe()` sync and cheap. Keep `view()` deterministic: no network,
  no connecting (the checker compares two views).
- New behaviour needs a test in `tests/test_app.py` through `FakeHive`.
- Keep the brief's action names; open points are listed in README.md.

## Next steps

1. Done (12 Nov 2026): `PROGRAMS.md` and `programs_check` came as a pre-release
   copy (`../omegahive-app-contract-04fc3f2`); the checker reports COMPATIBLE.
   First review (Dot for Jon, on 8051f30) handled on branch `review-1` as
   0.2.0 (13 Nov 2026): reads reviewed by a person, definition digests,
   device code only in the connect result, locked token renewal, new session
   on a new token, `mcp>=1.30,<3`. It settled README open points 1, 2 and 5.
   MesTTo's PRs #3–#7 and #9–#11 merged into `review-1` (13 Nov 2026): the
   fake host as the hive's minds' route, the approver in the trace, a mind's
   write only with a person's approval, bearer tokens only to listed origins,
   the 400-item view, input checks, durable store, browser sign-in with PKCE.
   Then: recoveries never run a tool twice, use-tool's records encrypted.
   Open points 3 (confirmed by MesTTo), 6 and 7 (dependencies, MesTTo's
   check) are to verify on a scratch hive; 4 is issue #8, on the branch
   `per-person-signin`.
2. Microsoft 365 showcase on a dev tenant (Microsoft 365 Developer Program):
   Entra app registration (public client, device code enabled), delegated
   scopes for reading a Teams channel, then one write (post a message) behind
   use-tool on "ask". Pick the MCP endpoint (Work IQ / Agent 365 tooling
   servers, or a Graph-based server over streamable HTTP). A Graph-based one
   is in `examples/teams-mcp/`; `demo.py` ran it on a real tenant on 13 Nov
   2026 (the channel read, a message posted once approved).
3. Scratch hive demo, recorded.
4. Optional: the mind skill for native Omega minds wrapping
   `POST /api/agent/programs/omega-connect/act` (confirm with the team first).
   A standalone MeTTa plugin that calls MCP directly from Omega core already
   exists in the separate `omega-mcp` folder and was tested end to end in Omega.
