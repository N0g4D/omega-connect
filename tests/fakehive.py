"""A small stand-in for the OmegaHive host, for offline tests.

It follows program contract 0.2 as described publicly (omegahive-schematics,
06-apps/01-programs-contract.md) and in hive/PROGRAMS.md (omegahive 04fc3f2).
The agent route answers as hive/core/program_actions.py on flagship main does
(a private repository; the file is not in the 04fc3f2 copy): the approvals and
the recovery below as MesTTo confirmed them against that file, prior_failed
by MesTTo's reading of it. All of it is to verify on a scratch hive.

- describe() is called synchronously; view() and act() may be async.
- Minds act only through actions marked "agents": true, and only under an
  explicit rule for program:<id>:<action>. No rule means deny.
- On "ask" the host files an approval bound to the exact request, its
  idempotency key included, and answers approval_required with its
  approval_id. Once a person approves, the mind sends the same request again
  with that approval_id. The host redeems it once, just before calling act(),
  and passes it as ctx.actor.approval = {id, binding_digest, approved_by},
  approved_by being the approver's principal.
- A mind sends an idempotency key. An identical retry of an act already done
  is delivered again as a recovery: act() gets the approval the act first ran
  under (None under "allow") and ctx.actor.recovery = True, and is to deliver
  nothing again. A different request under the same key is refused (409).
- If act() raises, the effect is unknown. A retry under the same key is
  delivered again, after a new approval on "ask", with the same record_id and
  no ctx.command.prior_failed (the hive sets that on the person route only).
- "effect": "read" actions store only a digest, never the content, and re-run
  on a repeat.
- People's "confirm": true actions need a host confirmation. A person's
  ctx.command carries their idempotency key, if any, and no record_id.
- ctx.actor has the hive's shape (mind_actor, person_actor); view() gets none.
- act() gets params with base_revision added, as the host sends it at the top
  level of the request (None when the caller sends none).
- Bodies naming an identity or carrying credential-like keys are refused.

Views and results are checked with validate_graph and validate_result below;
test_contract.py passes the hive's own (hive/core/programs.py) instead when the
contract copy sits next to this repository.
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import re
from dataclasses import dataclass, field
from typing import Any

APP_ID = "omega-connect"
FORBIDDEN_KEYS = {"principal", "actor", "swarm_id", "agent_id", "member_id"}
CREDENTIAL_LIKE = re.compile(r"(token|secret|password|api[_-]?key|credential|authorization)", re.I)


def canonical(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@dataclass
class Ctx:
    swarm_id: str
    actor: dict | None = None
    command: dict = field(default_factory=dict)
    read_only: bool = False


def mind_actor(swarm: str, mind: str, approval: dict | None = None) -> dict:
    """ctx.actor for a mind, as the hive's ProgramActions.mind_actor builds it."""
    return {"principal": f"agent:{mind}", "kind": "mind", "id": mind, "name": mind, "role": None,
            "local_operator": False, "member_id": mind, "swarm_id": swarm, "route": "agent", "approval": approval}


def person_actor(swarm: str, person: str) -> dict:
    """ctx.actor for a signed-in person, as the hive's ProgramActions.person_actor builds it."""
    return {"principal": f"user:{person}", "kind": "person", "id": person, "name": person, "role": "owner",
            "local_operator": False, "member_id": None, "swarm_id": swarm, "route": "operator", "approval": None}


class HostRefusal(Exception):
    def __init__(self, status: int, code: str):
        super().__init__(f"{status} {code}")
        self.status = status
        self.code = code


async def _maybe_await(value):
    return await value if inspect.isawaitable(value) else value


def _check_body(params: dict) -> None:
    def walk(value, top=True):
        if isinstance(value, dict):
            for key, inner in value.items():
                if top and key in FORBIDDEN_KEYS:
                    raise HostRefusal(400, "identity_in_body")
                if CREDENTIAL_LIKE.search(str(key)):
                    raise HostRefusal(400, "credential_in_body")
                walk(inner, False)
        elif isinstance(value, list):
            for inner in value:
                walk(inner, False)
    walk(params)


class FakeHive:
    def __init__(self, program, checks=None):
        self.program = program
        self.descriptor = program.describe()
        assert not inspect.iscoroutine(self.descriptor), "describe() must be synchronous"
        self.actions = {a["id"]: a for a in self.descriptor["actions"]}
        # (graph check, result check): this file's own unless a test passes the hive's
        self.check_graph, self.check_result = checks or (validate_graph, validate_result)
        self.rules: dict[tuple[str, str], str] = {}
        self.approvals: dict[str, dict] = {}
        self.records: dict[tuple[str, str], dict] = {}
        self._approval_seq = 0

    # ---------------------------------------------------------------- policy
    def attach(self, mind: str, action: str, mode: str) -> None:
        assert mode in ("allow", "ask", "deny")
        self.rules[(mind, f"program:{APP_ID}:{action}")] = mode

    def approve(self, approval_id: str, person: str) -> None:
        """A person approves; the hive keeps their principal as the approver (decided_by)."""
        self.approvals[approval_id]["state"] = "approved"
        self.approvals[approval_id]["by"] = f"user:{person}"

    def pending(self) -> list[dict]:
        return [a for a in self.approvals.values() if a["state"] == "pending"]

    def record(self, record_id: str) -> dict:
        """The host's own record of a mind's act, including who approved it."""
        return next(r for r in self.records.values() if r["id"] == record_id)

    # ---------------------------------------------------------------- routes
    async def view(self, swarm: str, person: str, focus=None, stage="unfold") -> dict:
        ctx = Ctx(swarm_id=swarm)
        graph = await _maybe_await(self.program.view(ctx, focus, stage))
        self.check_graph(graph)
        return graph

    async def agent_act(self, swarm: str, mind: str, action: str, params: dict, key: str,
                        approval_id: str | None = None, base_revision: str | None = None) -> dict:
        _check_body(params)
        spec = self.actions.get(action)
        if spec is None or not spec.get("agents"):
            raise HostRefusal(403, "not_for_agents")
        mode = self.rules.get((mind, f"program:{APP_ID}:{action}"))
        if mode in (None, "deny"):
            raise HostRefusal(403, "policy_denied")
        request = canonical({"action": action, "params": params, "base_revision": base_revision})
        record = self.records.get((mind, key))
        if record is not None:
            if record["request"] != request:
                raise HostRefusal(409, "idempotency_conflict")
            if record["status"] == "done" and record["effect"] != "read":
                # A recovery: act() gets the request again with the approval it first ran under and
                # ctx.actor.recovery, and is to deliver nothing again. No new approval is asked for.
                ctx = Ctx(swarm_id=swarm, actor={**mind_actor(swarm, mind, record["approval"]), "recovery": True},
                          command={"idempotency_key": key, "record_id": record["id"], "route": "agent"})
                try:
                    result = await _maybe_await(self.program.act(ctx, action, [],
                                                                 {**params, "base_revision": base_revision}))
                except Exception as exc:
                    raise HostRefusal(500, "program_error") from exc
                self.check_result(result)
                return result
        approval = None
        if mode == "ask":
            binding = canonical({"mind": mind, "action": action, "request": request, "idempotency_key": key})
            if approval_id is None:
                filed = next((a for a in self.approvals.values()
                              if a["binding"] == binding and a["state"] in ("pending", "approved")), None)
                if filed is None:
                    self._approval_seq += 1
                    filed = {"id": f"apr-{self._approval_seq}", "mind": mind, "action": action, "params": params,
                             "binding": binding, "state": "pending"}
                    self.approvals[filed["id"]] = filed
                return {"status": "approval_required", "approval_id": filed["id"],
                        "message": f"a person must approve program:{APP_ID}:{action}; "
                                   "repeat the same request with this approval_id"}
            found = self.approvals.get(approval_id)
            if found is None or found["mind"] != mind or found["action"] != action or found["binding"] != binding:
                raise HostRefusal(409, "binding_mismatch")
            if found["state"] != "approved":
                raise HostRefusal(409, "not_approved")
            found["state"] = "used"  # once
            approval = {"id": found["id"], "binding_digest": "sha256:" + binding, "approved_by": found["by"]}
        if record is None:
            record = self.records[(mind, key)] = {"id": f"rec-{len(self.records) + 1}", "request": request,
                                                   "effect": spec.get("effect"), "status": None}
        command = {"idempotency_key": key, "record_id": record["id"], "route": "agent"}
        record["approval"] = approval  # what a recovery of this act gets again
        record["approved_by"] = approval and approval["approved_by"]
        ctx = Ctx(swarm_id=swarm, actor=mind_actor(swarm, mind, approval), command=command,
                  read_only=spec.get("effect") == "read")
        try:
            result = await _maybe_await(self.program.act(ctx, action, [], {**params, "base_revision": base_revision}))
        except Exception as exc:
            record["status"] = "failed"  # the effect is unknown
            raise HostRefusal(500, "program_error") from exc
        self.check_result(result)
        record["status"] = "done"
        record["result"] = {"redacted": True, "digest": canonical(result), "status": result["status"]} \
            if spec.get("effect") == "read" else result
        return result

    async def person_act(self, swarm: str, person: str, action: str, items: list, params: dict,
                         confirmed: bool = False, base_revision: str | None = None, key: str | None = None) -> dict:
        _check_body(params)
        spec = self.actions.get(action)
        if spec is None:
            raise HostRefusal(404, "unknown_action")
        if spec.get("confirm") and not confirmed:
            raise HostRefusal(403, "confirm_required")
        ctx = Ctx(swarm_id=swarm, actor=person_actor(swarm, person),
                  command={"idempotency_key": key, "record_id": None, "route": "operator"})
        result = await _maybe_await(self.program.act(ctx, action, items, {**params, "base_revision": base_revision}))
        self.check_result(result)
        return result


STATUSES = {"done", "started", "needs_input", "stale", "refused", "error"}


def validate_result(result: dict) -> None:
    assert isinstance(result, dict), result
    assert result.get("status") in STATUSES, result
    if result["status"] == "started":
        assert result.get("task", {}).get("id"), result
    if "graph" in result:
        validate_graph(result["graph"])
    json.dumps(result)  # must be plain JSON


def validate_graph(graph: dict) -> None:
    assert graph.get("revision"), "revision is required"
    items = graph.get("items", [])
    assert len(items) <= 400, "at most 400 items"
    ids = [item["id"] for item in items]
    assert len(ids) == len(set(ids)), "item ids must be unique"
    known = set(ids)
    assert len(graph.get("links", [])) <= 1200
    for link in graph.get("links", []):
        assert link["from"] in known and link["to"] in known, link
    for group in graph.get("groups", []):
        assert set(group["items"]) <= known, group
    focus = graph.get("focus")
    assert focus is None or focus in known
    json.dumps(graph)


def run(coro):
    return asyncio.run(coro)
