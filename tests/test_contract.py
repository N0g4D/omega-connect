"""FakeHive with the hive's own checks, when the contract copy is at hand.

The pre-release omegahive copy next to this repository
(../omegahive-app-contract-04fc3f2) ships hive/core/programs.py, the host's
loader and validators. When it is there, this test runs the app through
FakeHive with that file's validate_graph and validate_result in place of the
ones in fakehive.py; when it is not, the test is skipped.
"""

import importlib.util

import pytest

from conftest import ROOT
from fakehive import APP_ID, FakeHive, run

CONTRACT_DIR = ROOT.parent / "omegahive-app-contract-04fc3f2"
SWARM = "contract"  # its own swarm: the shared engine still holds other tests' "s1" servers
PERSON = "ada"
MIND = "scout"
STAGES = ("unfold", "map", "compare", "detail")


def hive_checks(program):
    """(graph check, result check) from the hive's programs.py, failing with AssertionError."""
    path = CONTRACT_DIR / "hive" / "core" / "programs.py"
    if not path.is_file():
        pytest.skip(f"no contract copy at {CONTRACT_DIR}")
    spec = importlib.util.spec_from_file_location("omegahive_contract_programs", path)
    host = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(host)
    describe = host.Programs._check_description(program.describe())  # as the hive loads it
    # the stage only labels the hive's normalized copy; it changes no check
    return (lambda graph: host.validate_graph(APP_ID, describe, graph, "unfold", AssertionError),
            lambda result: host.validate_result(APP_ID, describe, result, AssertionError))


def test_views_and_results_pass_the_hives_own_checks(program, demo_url):
    hive = FakeHive(program, checks=hive_checks(program))
    with pytest.raises(AssertionError, match="unknown kind"):  # stricter than fakehive.py's own
        hive.check_graph({"revision": "r1", "items": [{"id": "x", "kind": "nope"}]})
    for action in ("list-servers", "list-tools", "inspect-tool", "read-tool"):
        hive.attach(MIND, action, "allow")
    hive.attach(MIND, "use-tool", "ask")

    def mind(action, key, approval_id=None, **params):
        return run(hive.agent_act(SWARM, MIND, action, params, key, approval_id))

    def person(action, items=(), base_revision=None, **params):
        return run(hive.person_act(SWARM, PERSON, action, list(items), params, confirmed=True,
                                   base_revision=base_revision))

    def views():
        """Every stage, with no focus, a missing focus, and one item of each kind in focus."""
        kinds = {}
        for item in run(hive.view(SWARM, PERSON))["items"]:
            kinds.setdefault(item["kind"], item["id"])
        for focus in (None, "server:gone", *kinds.values()):
            for stage in STAGES:
                run(hive.view(SWARM, PERSON, focus=focus, stage=stage))
        return set(kinds)

    assert views() == set()
    assert person("add-server", name="bad", url="http://example.com/mcp")["status"] == "refused"
    assert person("add-server", name="demo", url=demo_url)["status"] == "done"
    assert views() == {"server"}
    assert person("list-tools", ["server:demo"])["status"] == "done"
    stale = person("accept-reads", ["server:demo"], base_revision="r-old")
    assert stale["status"] == "stale" and stale["graph"]["items"]
    assert person("accept-reads", ["server:demo"])["status"] == "done"
    statuses = [
        mind("list-servers", "k1")["status"],
        mind("list-tools", "k2", server="demo")["status"],
        mind("inspect-tool", "k3", server="demo", tool="add")["status"],
        mind("read-tool", "k4", server="demo", tool="add", arguments={"a": 1, "b": 2})["status"],
        mind("read-tool", "k5", server="demo", tool="create_note", arguments={"title": "a", "text": "b"})["status"],
        mind("read-tool", "k6", server="demo", tool="fail")["status"],
        mind("read-tool", "k7", server="demo", tool="nope")["status"],
        mind("read-tool", "k8", server="ghost", tool="add")["status"],
        mind("read-tool", "k9", server="demo", tool="add", arguments="not json")["status"],
    ]
    assert statuses == ["done", "done", "done", "done", "refused", "error", "refused", "error", "refused"]
    write = {"server": "demo", "tool": "create_note", "arguments": {"title": "plan", "text": "x"}}
    waiting = mind("use-tool", "w1", **write)
    hive.approve(waiting["approval_id"], PERSON)
    assert mind("use-tool", "w1", waiting["approval_id"], **write)["status"] == "done"
    assert views() == {"server", "tool", "call"}
    stale = person("remove-server", ["server:demo"], base_revision="r-old")
    assert stale["status"] == "stale" and stale["graph"]["items"]
    assert person("remove-server", ["server:demo"])["status"] == "done"
    assert views() == {"call"}
