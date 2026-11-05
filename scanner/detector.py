"""
THE CORE: BOLA detector.

For every object-level endpoint found in the spec, we run one test with a fresh
VICTIM (owns an object) and a fresh ATTACKER (tries to touch the victim's object).

A finding is CONFIRMED only with real evidence, not just a 2xx status code:

  GET     -> attacker's response must contain the victim's secret marker
             (+ control: asking for a non-existent id must NOT return that marker)
  PUT/PATCH -> after the attacker's update, the VICTIM reads the object again
             and the attacker's new value must really be there (resource-state check)
  DELETE  -> after the attacker's delete, the VICTIM reads the object again
             and it must really be gone (resource-state check)

Before the attack, a BASELINE check makes sure the victim can read their own object,
otherwise our state check would be meaningless and the test is skipped.

We also record what a naive "status code only" scanner would have said, so we can
compare both in the evaluation. The LLM is NOT used here: detection is deterministic.
"""
from dataclasses import dataclass
import httpx
from .utils import fill, rand, with_id, dig


@dataclass
class Result:
    resource: str
    method: str
    path: str
    vulnerable: bool | None     # our verified verdict (None = could not test)
    naive: bool | None          # what a status-code-only scanner would say
    status: int | None          # HTTP status of the attacker's request
    evidence: str
    skipped: bool = False

    @property
    def key(self):
        return f"{self.method} {self.path}"


def is_2xx(response):
    return 200 <= response.status_code < 300


class Detector:
    def __init__(self, target, spec_ops, config):
        self.t = target
        self.ops = spec_ops
        self.cfg = config

    # ------------------------------------------------------------------ main loop
    def run(self):
        results, tested = [], set()
        for res in self.cfg["resources"]:
            allowed = [m.upper() for m in res.get("methods", [])]
            for endpoint in res["endpoints"]:
                ops = [o for o in self.ops if o["path"] == endpoint]
                if not ops:
                    results.append(Result(res["name"], "-", endpoint, None, None, None,
                                          "endpoint not found in API spec", True))
                    continue
                for op in ops:
                    if allowed and op["method"] not in allowed:
                        continue
                    tested.add((op["method"], op["path"]))
                    try:
                        results.append(self.test_operation(res, op))
                    except httpx.HTTPError as e:
                        results.append(Result(res["name"], op["method"], op["path"], None, None, None,
                                              f"network error: {e}", True))
        uncovered = [o for o in self.ops if (o["method"], o["path"]) not in tested]
        return results, uncovered

    # ------------------------------------------------------------------ one test
    def test_operation(self, res, op):
        method, path, name = op["method"], op["path"], res["name"]

        def skip(msg):
            return Result(name, method, path, None, None, None, msg, True)

        victim = self.t.new_user("victim")
        attacker = self.t.new_user("attacker")
        if not victim.token or not attacker.token:
            return skip("could not log in the test users")

        marker = "MARK" + rand(8)
        obj_id, err = self.create_object(res, victim, marker)
        if err:
            return skip(err)

        read_path = res.get("read_path") or (path if method == "GET" else None)
        if read_path is None:
            return skip("no read_path configured, cannot verify state")

        # BASELINE: the owner must be able to see their own object
        base = self.t.call("GET", with_id(read_path, obj_id), victim.token)
        if not is_2xx(base):
            return skip(f"baseline failed: owner could not read own object (HTTP {base.status_code})")
        if res.get("create") and marker not in base.text:
            return skip("baseline failed: marker not found in owner's own response")

        if method == "GET":
            return self.test_read(res, path, obj_id, marker, attacker)
        if method in ("PUT", "PATCH"):
            return self.test_update(res, method, path, read_path, obj_id, victim, attacker)
        if method == "DELETE":
            return self.test_delete(res, path, read_path, obj_id, victim, attacker)
        return skip("unsupported method")

    # ------------------------------------------------------------------ helpers
    def create_object(self, res, victim, marker):
        """Victim creates an object that contains a unique marker. Returns (object_id, error)."""
        create = res.get("create")
        if not create:                       # e.g. users: the object IS the victim account
            src, _, key = res["id_from"].partition(".")
            return getattr(victim, key), None
        body = fill(create["body"], marker=marker, rand=rand(8))
        r = self.t.call(create.get("method", "POST"), create["path"], victim.token, body)
        if not is_2xx(r):
            return None, f"could not create test object (HTTP {r.status_code})"
        src, _, key = create["id_from"].partition(".")
        if src == "request":
            return body.get(key), None
        try:
            return dig(r.json(), key), None
        except ValueError:
            return None, "create response was not JSON"

    def test_read(self, res, path, obj_id, marker, attacker):
        if not res.get("create"):
            return Result(res["name"], "GET", path, None, None, None,
                          "GET test needs an object with a marker (no create step configured)", True)
        r = self.t.call("GET", with_id(path, obj_id), attacker.token)
        leaked = is_2xx(r) and marker in r.text
        # CONTROL: a non-existent id must not return the marker
        ctl = self.t.call("GET", with_id(path, res.get("nonexistent_id", "nonexistent-999")), attacker.token)
        control_clean = marker not in ctl.text
        vulnerable = leaked and control_clean
        if vulnerable:
            ev = f"HTTP {r.status_code}: attacker's response contained the victim's secret marker"
        elif is_2xx(r):
            ev = f"HTTP {r.status_code} but victim's marker NOT in response (no leak)"
        else:
            ev = f"HTTP {r.status_code}: access denied / hidden"
        return Result(res["name"], "GET", path, vulnerable, is_2xx(r), r.status_code, ev)

    def test_update(self, res, method, path, read_path, obj_id, victim, attacker):
        if "update_body" not in res:
            return Result(res["name"], method, path, None, None, None, "no update_body configured", True)
        new = "HACKED" + rand(8)
        body = fill(res["update_body"], new=new, rand=rand(8))
        r = self.t.call(method, with_id(path, obj_id), attacker.token, body)
        # RESOURCE-STATE CHECK: did the victim's object really change?
        changed = self.state_changed(res, read_path, obj_id, victim, new)
        if changed:
            ev = f"HTTP {r.status_code}: victim's data really changed to the attacker's value"
        elif is_2xx(r):
            ev = f"HTTP {r.status_code} returned, but victim's data is UNCHANGED (decoy / silently ignored)"
        else:
            ev = f"HTTP {r.status_code}: update rejected"
        return Result(res["name"], method, path, changed, is_2xx(r), r.status_code, ev)

    def state_changed(self, res, read_path, obj_id, victim, new):
        verify = res.get("verify", {"type": "read"})
        if verify["type"] == "login":        # e.g. password change: can the victim log in with the NEW password?
            return self.t.login(victim.username, new) is not None
        after = self.t.call("GET", with_id(read_path, obj_id), victim.token)
        return is_2xx(after) and new in after.text

    def test_delete(self, res, path, read_path, obj_id, victim, attacker):
        r = self.t.call("DELETE", with_id(path, obj_id), attacker.token)
        after = self.t.call("GET", with_id(read_path, obj_id), victim.token)
        gone = after.status_code in (404, 410)
        if gone:
            ev = f"HTTP {r.status_code}: victim's object is really gone"
        elif is_2xx(r):
            ev = f"HTTP {r.status_code} returned, but victim's object STILL EXISTS (decoy / silently ignored)"
        else:
            ev = f"HTTP {r.status_code}: delete rejected"
        return Result(res["name"], "DELETE", path, gone, is_2xx(r), r.status_code, ev)
