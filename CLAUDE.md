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
- A `done` result's `graph` replaces the page's view (PROGRAMS.md 3), and the
  host sends `params.focus` and `params.stage` with every act (6b.2). The done
  results of the people's actions carry `view()` at that focus (MesTTo's #14).
- An action's `params` in `describe()` names its inputs. PROGRAMS.md 2 of
  04fc3f2 has only words for each; since omegahive #403 (read in the Mac test
  build 0.38, the first with it; #14 calls it #416) an input is words or one
  form field in the shape of a property of MCP's elicitation forms (spec
  2025-11-25): a string, number, integer or boolean, one choice (`enum`, or
  `oneOf` of `const` with `title`) or several (an array of them), with
  `title`, `description`, `default`, and `minimum`/`maximum` for a number. The
  page asks for declared inputs before it sends the action, fills in the
  defaults, sends each in its type, flat, and leaves a blank field out: the
  app checks what it gets. `applies_to: []` is an action on the app itself,
  listed when nothing is selected; no `applies_to` means any kind, or none.
  The checker and the host's description check (04fc3f2, and 0.38's) look at
  neither. add-server (on `applies_to: []`) and connect declare theirs.
- The host refuses bodies with `principal`, `actor`, `swarm_id`, `agent_id`,
  `member_id` or credential-like keys (token, secret, password, api key, any
  `*_key` but its own retry keys such as `idempotency_key`) at the top level of
  the body or params: 400 identity_in_request / credential_in_request; nested
  keys pass. That is why add-server takes `signin`, not `auth`.
- Confirm payloads are canonical JSON, integers only: no floats in params of
  confirm actions.
- Raise `PermissionError` in `view()` to refuse a swarm.
- Capabilities are not a sandbox; the app runs in the hive process.
- How the hive runs an action, verified in `hive/core/program_actions.py` at
  omegahive main 832b36e (in `../omegahive-files-for-alessio-832b36e/`, sent
  by Jon; the repository is private: read it, never copy or quote its code
  here): "ask" answers `approval_required` with an `approval_id`; the repeated
  request reaches `act()` with `ctx.actor.approval = {id, binding_digest,
  approved_by}` (`None` under "allow"). For `approver: "person"`, an approval
  by `user:operator` is refused (409 person_approval_required), and so is the
  operator password on the person route (403 person_required). Every act of a
  mind is recorded under its idempotency key, whatever status `act()` gives;
  an identical retry of a done act gets the recorded result without reaching
  `act()`, unless the action declares `revalidate: true`: then it is a
  recovery (`recovery: true`, the original approval,
  `ctx.command.recorded_result`). use-tool declares no revalidate. An act that
  raised is failed: its identical retry comes back after a new approval with
  the same `record_id` and no `prior_failed` (only `person_activity` actions,
  on the person route, get that). The person route records nothing for our
  actions: `record_id` None.
- The Mac test build in `~/OmegaHive` (read it, never copy or quote its code
  here). The app was mounted and checked on 0.33 (f6b4b1c), and what follows
  was read in that build's `hive/core` and page source on 17 Nov 2026. The
  demo recorded that day ran on 0.34 (116bc87), and on 18 Nov it ran with the
  browser sign-in on 0.37 (58b6406), both on a real tenant; since 10:37 that
  day the hive is 0.38 (d5485da), on which nothing was run from here. The
  build updates itself when its owner accepts: `~/OmegaHive/logs/update.log`
  says when, `app/RELEASE_VERSION` which one is installed; look before
  naming a build. A person's confirm act needs a token from
  `POST /api/programs/{id}/confirm` (`{swarm_id, action, payload,
  payload_digest}`, PROGRAMS.md 9d), bound to session, swarm, action and
  digest, single use, 120 s. A local-owner session (kind `sso`, principal
  `user:u_...`, a named person) needs the hive's own `Origin` on every
  request that changes something. The generic app page offers an action only
  on a selected item and sends it without params (then a form for the `needs`
  of a `needs_input` answer): it cannot run add-server on an empty view, nor
  connect with `flow: browser`. A mind acts under `program:omega-connect:<action>`
  rules (`POST /api/policy`) alone, while the app has no activation: an
  activation makes a reviewed attachment mandatory for every mind, and
  activating needs `offer`/`bind`/`unbind` hooks, which the app lacks
  (409 hooks_missing). The approval's note wakes only an `asleep` mind, not a
  `created` one. Its `hive/core/program_actions.py` is byte for byte the
  832b36e copy that the fake host follows, on 0.34, 0.37 and 0.38 too; on
  0.37 and 0.38 `programs_check.py` is the 04fc3f2 copy's. Read on 18 Nov: up
  to 0.37 the
  page is as above; 0.38 has the page of omegahive #403, which asks for the
  inputs an action declares and lists the actions on the app itself (add-server,
  since #14) when nothing is selected, and its PROGRAMS.md 2 has the rules.
  The routes `hive_demo.py` uses are all in 0.38; it sends add-server and
  connect itself on any of these builds.
- Failed writes (Jon on #1): repeat automatically only when the attempt
  certainly did not arrive (a refused connection; for use-tool also a 404
  for a session the server no longer has, which ran nothing, and after which
  MCP has the client open a new session), at most 5 times in 5 minutes,
  then a new approval; when the outcome is uncertain, no blind
  repeat: check, or go back to a person.
- Whose sign-in a mind uses (Jon on #1): its owner's, or a clear refusal,
  never another person's token. The hive's actor for a mind does not carry
  its owner yet (omegahive #332): `_mind_owner(ctx)` is the one place that
  reads it, None until then; meanwhile a mind uses a sign-in only while one
  person alone is signed in to the swarm's servers, all its oauth-device
  servers counted together (MesTTo on #12): with ada signed in only to one
  server and bob only to another, a mind is refused on both
  (`owner_unknown`). use-tool declares approver "person": the scratch hive
  demo is done as a named person, not with the operator password. connect
  declares it too (MesTTo on #12): a sign-in always belongs to a named
  person.

Reference: https://github.com/omega-flagship/omegahive-schematics (06-apps),
https://github.com/omega-flagship/omega-tools (template app). The omegahive
repo (with `hive/PROGRAMS.md` and `hive.programs_check`) opens ~19–20 Nov.

## Layout and design

- `program.py`: describe / view / act. Loads `connect/*.py` by file path
  (`importlib`), because the host imports program.py by path, not as a package.
  What a page asks for add-server is `ADD_SERVER_INPUTS`; `_flat_signin` makes
  the `signin` object from a page's flat fields, and an object sent directly
  wins. `act()` adds `view()` to the done results of the people's actions.
- `connect/engine.py`: MCP client. One private asyncio loop in a daemon
  thread; one long-lived task per (swarm, server) owns transport and
  ClientSession (anyio cancel scopes must stay in one task). Callers submit
  work through a queue. Dropped connections, and sessions the server forgot
  (HTTP 404 after a restart), reconnect on the next call; the engine itself
  retries only read-classed calls. Each session loads the tool list when it
  opens and on
  `notifications/tools/list_changed` (the reload runs in the worker's task:
  SDK 1.x calls the message handler inside its receive loop). Every tool keeps
  a digest of its definition; `call(expect=digest)` sends nothing if the
  definition changed. New auth headers mean a new session; the old one
  finishes its calls (grace = call timeout). A failed call raises NotSent
  (certainly did not run: no connection could be made, the session ended
  while it waited its turn, or the server answered 404 for a session it no
  longer has) or OutcomeUnknown (may have reached it, no
  answer); when the transport fails under a call, both SDKs cancel the
  session's task, and the transport's own error (httpx ConnectError or not)
  decides, in `_run`. use-tool tries a NotSent write again (5 attempts, none
  after 30 s) and answers OutcomeUnknown with `refused`, `outcome_unknown`.
  Supports MCP SDK 1.x and 2.x: `mcp>=1.30,<3`, 1.30 being the lowest
  version tested.
- `connect/store.py`: per-swarm folder under `OMEGA_CONNECT_DATA_DIR`:
  servers.json (no secrets; the tools a person accepted as read, with the
  digest of each definition), secrets.bin (Fernet: each person's sign-in under
  their principal), trace.jsonl (digests),
  intents.bin (app-level idempotency for use-tool, each answer included:
  Fernet, newest half kept past 1 MiB; a plain intents.json is moved in).
  Files mode 0600.
- `connect/oauth.py`: RFC 8628 device flow, and authorization code with PKCE
  (RFC 7636) on a loopback redirect (RFC 8252 7.3), for tenants that block
  the device code. `LoopbackListener` listens for one sign-in on 127.0.0.1
  and, where the machine has it, ::1, on one port the system picks; the
  redirect URI is `http://localhost:<port>` (the Entra registration lists
  `http://localhost` under Mobile and desktop applications; Entra ignores the
  port). One thread waits, 10 minutes and 50 requests at most, and each
  connection gets a thread of its own. Only a GET for `/` with the sign-in's
  state (constant-time comparison) ends the wait, once; every answer is one
  of three fixed pages, and nothing of a request is logged or sent back (the
  request line carries the code). `_browser_signin` in program.py trades the
  code in the listener's thread, keeps the sign-in under the person who ran
  connect and traces the outcome. One sign-in is in progress per person and
  server (`_PENDING_SIGNINS`): a later connect of theirs on that server, or
  remove-server, takes it away, which closes the listener and ends the wait
  for a device code (`poll_device_flow` asks `wanted` before each request);
  `_keep_signin` keeps the tokens of either flow only while the sign-in is
  still the one in progress, check and write under `_SIGNIN_LOCK`.
  Standard library only; authority
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
  `terminal_input.py` holds what both demos ask at the terminal with. With
  the browser sign-in both demos open the sign-in page and wait for the view
  to name who signed in: the browser goes back to the app, not to the demo.
  `hive_demo.py` is the demo on a real hive (the Mac test build): it makes the
  mind's calls with the mind's token, and the person's steps that the hive's
  pages cannot send (add-server, connect with the browser sign-in) with the
  owner's session, after a yes at the terminal; accept-reads and the approval
  are done on the hive's pages while it waits. Standard library only; no token,
  code or sign-in link printed or written. `test_hive_demo.py` runs it against
  the hive's HTTP routes simulated over `tests/fakehive.py`; as a program, it
  is a stand-in server for a rehearsal (`hive_demo.py --no-signin`).

Classification rule: read only if the server says `readOnlyHint`, a person
accepted that tool with `accept-reads` (people only, confirm), and its
definition digest still matches the accepted one; every tool of a new server
is write until then. The owner can demote (write, hidden, back to default),
never promote. The digest catches definition changes, not behaviour changes.
The device code and the browser sign-in address go only into the message and
the detail of the `connect` result, never into `view()`, so not into the view
that this result carries either. The app finishes a browser sign-in by itself,
when the browser comes back to its listener with the sign-in's state, and
keeps it under the person who ran connect. That works with the person's
browser on the hive's machine; a hive shared over a network needs a callback
address of the hive, not done yet.

## Commands

```sh
pip install -r requirements-dev.txt
python -m pytest -q tests            # 99 tests, ~2 min, localhost only
python -m pytest -q examples/teams-mcp   # 54 tests, ~1 min, Graph and the hive's routes simulated
```

Contract checker, from the pre-release copy next to this repo (until omegahive
is public); `tests/test_contract.py` also uses its validators when it is there:
```sh
cd ../omegahive-app-contract-04fc3f2 && python -m hive.programs_check ../omega-connect
```

## Rules for changes

- Never put a credential in a result, view, trace, log line or error. New
  outputs that can carry server text go through `_scrub` / `engine.redact`.
- The sign-in listener answers with its fixed pages only, and nothing of a
  request reaches a log, a trace or an error: the request line carries the
  code. It never listens beyond the loopback interface.
- Never store tool content in clear: traces hold digests only, and
  use-tool's records (its answers, for retries) are encrypted.
- Keep `describe()` sync and cheap. Keep `view()` deterministic: no network,
  no connecting (the checker compares two views).
- New behaviour needs a test in `tests/test_app.py` through `FakeHive`.
- Tests start Python with `sys.executable`, never a `python3` from the PATH.
  A script that is to get Ctrl-C starts through `Run`
  (`examples/teams-mcp/test_demo.py`), with SIGINT at its default: pytest
  runs with it ignored when a shell starts it as a background job.
- No literal control or bidirectional character in a `.py` file, nor in a
  document (`.md`, `.json`, `.txt`): write the escape (`\u202e`).
  `test_the_sources_hold_no_invisible_characters` looks at all of them. An
  agent's edit tools turn a typed escape into the character itself: put one
  in with a script, then run that test.
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
   16 Nov 2026: the fake host runs actions as program_actions.py 832b36e
   does (`tests/test_fakehive.py` checks it); open points 3, 6 and 7 verified
   against that file and `hive/ci-constraints.txt`, 6 settled by Jon on #1
   (failed writes: NotSent tried again, otherwise `outcome_unknown`). 4,
   settled by Jon on #1, is issue #8 on the branch `per-person-signin`
   (review-1 merged in, 16 Nov 2026): a sign-in per person; a mind uses its
   owner's, and until omegahive #332 the only one signed in to the server,
   else it is refused; a mind's write is approved by the person whose sign-in
   it uses; demo.py acts as the named person `ada`. MesTTo approved #12
   (221500d) with two changes, made on that branch the same day: the only
   person signed in is counted over the whole swarm, not per server, and
   connect declares approver "person".
2. Microsoft 365 showcase on a dev tenant (Microsoft 365 Developer Program):
   Entra app registration (public client, device code enabled), delegated
   scopes for reading a Teams channel, then one write (post a message) behind
   use-tool on "ask". Pick the MCP endpoint (Work IQ / Agent 365 tooling
   servers, or a Graph-based server over streamable HTTP). A Graph-based one
   is in `examples/teams-mcp/`; `demo.py` ran it on a real tenant on 13 Nov
   2026 (the channel read, a message posted once approved).
3. Scratch hive demo, recorded, as a named person (use-tool declares approver
   "person": with the operator password nobody runs or approves a write).
   17 Nov 2026, branch `scratch-hive-demo`: the app is mounted on the Mac test
   build in `~/OmegaHive` (MesTTo on #2: its owner is a named person), then
   0.33, which loads it and whose `programs_check` passes;
   `examples/teams-mcp/hive_demo.py` plays the mind's part there (README of
   the example, "On a scratch hive"). The demo was recorded that day, on
   build 0.34 and a real tenant.
   Same day, branch `loopback-signin`, 0.3.0 (asked for by MesTTo on #2, who
   reviews it): on the real tenant the browser sign-in never got its code,
   since Microsoft took it out of the address the browser landed on
   (`/common/wrongplace`), so the app now finishes that sign-in on a loopback
   listener, and the app registration needs the redirect URI
   `http://localhost` under Mobile and desktop applications. The hive loads
   the app when it starts: restart it after a change in the checkout.
   18 Nov 2026: Alessio ran it on the real tenant, on build 0.37: the browser
   sign-in went through, the app got the code on its listener and the demo
   ran to its end, with the tenant's security defaults on, where the device
   code is refused (AADSTS530035; the browser sign-in gets the same error
   from a Microsoft session opened in the browser before the security
   defaults were on: sign out and in again, or use a private window). Same
   day on that branch: MesTTo's #14 merged (add-server on `applies_to: []`,
   declared inputs, the view in done results; for the page of omegahive
   #403, which the hive has had since it took build 0.38 at 10:37, after
   that run: MesTTo tried adding a server and signing in from that page on a
   hive built with it; on this one it is still to try), a sign-in in
   progress ends with its server or the person's next
   connect also when it waits for a device code, and the two tests that
   failed on MesTTo's machine no longer need a `python3` with mcp on the
   PATH (`sys.executable`), nor pytest to run with SIGINT not ignored (the
   scripts the tests start get it at its default).

Not a step here: the mind skill for native Omega minds is the flagship team's
(MesTTo on #2: it covers the actions of every app and takes a request up again
after an approval). A standalone MeTTa plugin that calls MCP directly from
Omega core exists in the separate `omega-mcp` folder and was tested end to end
in Omega.
