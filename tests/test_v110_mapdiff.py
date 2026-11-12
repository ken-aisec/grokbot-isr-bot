"""1.1.0: changes between two kept observations (mapdiff.py: pure functions, no files, no clock).

An area is compared only when both records saw it whole; what an incomplete one misses is "not seen this time", never gone.
A Bot that didn't answer is "not heard from"; "no longer listed" needs both records' Bot lists read whole. What a Bot said
stays under that Bot, unverified. A stored record is sanitized again and can only lose comparability.

Tests marked "replay" fail on fa0525f on their assertion (no mapdiff part); "guard" ones keep what must not change. Every
value is synthetic; Bots are bot-001…."""
import copy, json, os, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import Box
import isr  # noqa: E402
from test_v110_observe import _V110

UUID_1 = "1b2c3d4e-0000-4000-8000-000000000001"


def shared(**kw):
    sh = {"checked": list(isr.ACCESS_SHARED), "incomplete": {}, "from": "now", "scope": ["~"], "cached": [],
          "browser": {"sites": 3, "sensitive": ["mail.google.com"], "sensitive_count": 1, "products": []},
          "cli_logins": [{"tool": "OpenAI Codex CLI login", "file": "~/.codex/auth.json"}], "cli_count": 1, "platform_logins": [],
          "settings": "found", "auto_allow": [], "auto_allow_areas": {}, "runs_programs": "asks first",
          "mcp": {"files": 1, "count": 2, "tools": [{"name": "github", "kind": "command"}, {"name": "notion", "kind": "command"}]},
          "plugins": {"grok": 0, "added": 0, "names": []}, "webhooks": [], "webhook_count": 0,
          "scheduled": {"crontab": 0, "systemd": 0, "system": 0}, "hooks": {"platform": 0, "other": 0}, "key_files": 0}
    sh.update(kw)
    return sh


def said(connectors, day="2026-11-01"):
    return {"said_at": day, "connectors": connectors, "connectors_other": 0, "connectors_unknown": None, "routines": 1, "routines_sending": 0}


def bot(name, basis="name", status="answered", connectors=("Gmail",), day="2026-11-01", uuid=UUID_1):
    return {"pid": isr.bot_pid(uuid if basis == "uuid" else name), "id_basis": basis, "name": name, "status": status, "listed": True,
            "said": said(list(connectors), day) if status == "answered" else None}


def record(at, sh=None, bots=None, fresh=True, listing=True, version="1.1.0", coverage=None):
    """A kept observation as obs_record reads it back from disk."""
    oid = "obs-" + at.replace("-", "").replace(":", "")[:15] + "Z"
    raw = {"v": 1, "observation_id": oid, "observed_at": at + "+00:00", "written_by_version": version, "written_at": at + "+00:00",
           "command": "artifacts", "uid": 1000, "map": {"v": 1, "at": at + "+00:00", "shared": sh or shared(),
                                                        "bots": [], "rollcall": {"at": "2026-11-01", "fresh": fresh}},
           "creds": [{"file": "~/" + r, "state": "missing"} for r in isr.KNOWN_CRED_FILES],
           "bots": [bot("bot-001", "uuid"), bot("bot-002")] if bots is None else bots, "listing": {"roster": listing, "profiles": listing}}
    raw["coverage"] = isr.obs_record(raw, stored=False)["coverage"] if coverage is None else coverage
    return isr.obs_record(json.loads(json.dumps(raw)))


PREV_AT, CUR_AT = "2026-11-01T10:00:00", "2026-11-08T10:00:00"


class Comparable(Box):
    def lines(self, prev, cur):
        return isr.diff_lines(isr.diff_observations(prev, cur))

    def test_d1_an_incomplete_area_never_reads_as_gone(self):   # replay (fa0525f: no diff_observations)
        prev = record(PREV_AT)
        cur = record(CUR_AT, shared(incomplete={"mcp": "unreadable"}, mcp={"files": 1, "count": 1, "tools": [{"name": "github", "kind": "command"}]}))
        out = self.lines(prev, cur)
        self.assertIn("Tool connections (MCP): not comparable (incomplete: something there couldn't be read)", out)
        self.assertIn("Tool connections (MCP): not seen this time: notion", out)
        self.assertFalse([x for x in out if "gone" in x], out)
        whole = self.lines(prev, record(CUR_AT, shared(mcp={"files": 1, "count": 1, "tools": [{"name": "github", "kind": "command"}]})))
        self.assertIn("Tool connections (MCP): gone: notion", whole)   # guard: seen whole both times, it is gone

    def test_d2_a_stale_bot_is_not_heard_from(self):   # replay (fa0525f: no diff_observations)
        prev = record(PREV_AT)
        cur = record(CUR_AT, bots=[bot("bot-001", "uuid", status="silent"), bot("bot-002", status="silent")], fresh=False)
        d = {b["name"]: b["change"] for b in isr.diff_observations(prev, cur)["bots"]}
        self.assertEqual(d, {"bot-001": "not heard from since Nov 1", "bot-002": "not heard from since Nov 1"})
        out = self.lines(prev, cur)
        self.assertFalse([x for x in out if "no longer listed" in x], out)

    def test_d3_a_rename_keeps_the_pseudonym(self):   # replay (fa0525f: no diff_observations)
        prev = record(PREV_AT)
        cur = record(CUR_AT, bots=[bot("bot-009", "uuid"), bot("bot-002")])
        d = isr.diff_observations(prev, cur)["bots"]
        self.assertEqual([(b["pid"], b["change"]) for b in d], [(isr.bot_pid(UUID_1), "renamed from bot-001 to bot-009")])

    def test_d4_one_bots_filing_changes_only_that_bot_and_is_unverified(self):   # replay (fa0525f: no diff_observations)
        prev = record(PREV_AT)
        cur = record(CUR_AT, bots=[bot("bot-001", "uuid"), bot("bot-002", connectors=("Gmail", "Slack"), day="2026-11-07")])
        d = isr.diff_observations(prev, cur)["bots"]
        pid2 = isr.bot_pid("bot-002")
        self.assertEqual([b["pid"] for b in d], [pid2])
        self.assertEqual(d[0]["change"], f"said now: Slack (said by {pid2}, not checked; sender not verified)")

    def test_d5_the_first_record_has_nothing_to_compare(self):   # replay (fa0525f: no diff_observations)
        out = self.lines(None, record(CUR_AT))
        self.assertEqual(out, ["No earlier record at least 12 hours older: no earlier record to compare with."])

    def test_d6_the_baseline_is_at_least_twelve_hours_older(self):   # replay (fa0525f: no pick_baseline)
        cur = record(CUR_AT)
        six, thirteen, thirty = record("2026-11-08T04:00:00"), record("2026-11-07T21:00:00"), record("2026-11-07T04:00:00")
        self.assertEqual(isr.pick_baseline([thirty, six, thirteen], cur)["observation_id"], thirteen["observation_id"])
        self.assertIsNone(isr.pick_baseline([six], cur))
        self.assertIsNone(isr.pick_baseline([], cur))

    def test_d7_a_forged_prior_is_sanitized_cannot_raise_comparability_and_is_named(self):   # replay (fa0525f: no obs_record)
        forged_cov = {a: "complete" for a in isr.OBS_AREAS}
        del forged_cov["browser"]
        prev = record(PREV_AT, shared(incomplete={"mcp": "unreadable"}), version="9.9.9", coverage=forged_cov)
        self.assertEqual(prev["coverage"]["mcp"], "incomplete: something there couldn't be read")
        self.assertEqual(prev["coverage"]["browser"], "incomplete: the stored record didn't say it was complete")
        raw = json.loads(json.dumps(prev))
        raw.update(written_by_version="<script>", command="rm -rf", bots=[dict(bot("bot-001\u202e<img src=x>", "uuid"), pid="../x")])
        again = isr.obs_record(raw)
        self.assertEqual((again["written_by_version"], again["command"], again["bots"]), ("unknown", "unknown", []))
        cur = record(CUR_AT)
        d = isr.diff_observations(prev, cur)
        states = {a["area"]: a["state"] for a in d["areas"]}
        self.assertEqual((states["mcp"], states["browser"]), ("not comparable", "not comparable"))
        page = isr.render_access_map_md(cur, d, [], "", "2026-W45")
        self.assertIn(f"Compared with the prior record `{prev['observation_id']}`, written 2026-11-01T10:00:00+00:00 by ISR Bot 9.9.9.", page)
        self.assertIn(isr.OBS_TAMPER, page)

    def test_d8_the_same_records_give_the_same_diff(self):   # guard
        prev, cur = record(PREV_AT), record(CUR_AT, bots=[bot("bot-009", "uuid"), bot("bot-003")])
        a = isr.diff_observations(copy.deepcopy(prev), copy.deepcopy(cur))
        rev = copy.deepcopy(cur)
        rev["bots"].reverse()
        self.assertEqual(a, isr.diff_observations(prev, rev))
        self.assertEqual(isr.diff_lines(a), isr.diff_lines(isr.diff_observations(prev, cur)))

    def test_no_longer_listed_needs_both_lists_whole(self):   # guard
        prev = record(PREV_AT)
        gone = record(CUR_AT, bots=[bot("bot-001", "uuid")])
        self.assertEqual(isr.diff_observations(prev, gone)["bots"][0]["change"],
                         "no longer listed (not in the roster or any agent profile, both lists read whole both times)")
        part = record(CUR_AT, bots=[bot("bot-001", "uuid")], listing=False)
        self.assertEqual(isr.diff_observations(prev, part)["bots"][0]["change"],
                         "not seen this time (the Bot list wasn't read whole in both records)")

    def test_d1_a_capped_name_list_never_reads_as_gone(self):   # review fix (cd67415: a 41st tool pushed one out of the 40 kept)
        tools = lambda names: [{"name": n, "kind": "command"} for n in names]
        was = [f"tool{i:02d}" for i in range(40)]
        prev = record(PREV_AT, shared(mcp={"files": 1, "count": 41, "tools": tools(was)}))
        cur = record(CUR_AT, shared(mcp={"files": 1, "count": 42, "tools": tools(["tool-new"] + was[:39])}))
        out = self.lines(prev, cur)
        self.assertIn("Tool connections (MCP): not comparable (only the first names of a long list are kept, so names aren't compared)", out)
        self.assertFalse([x for x in out if "gone" in x], out)


class StoredTimes(_V110):
    def test_d9_an_impossible_stored_time_drops_the_record(self):   # replay (f58fb63: the shape check let it through, then the baseline crashed)
        raw = json.loads(json.dumps(record(PREV_AT)))
        self.assertIsNone(isr.obs_record(dict(raw, observed_at="2026-99-99T99:99:99+00:00")))
        self.assertEqual(isr.obs_record(dict(raw, written_at="2026-02-30T10:00:00+00:00"))["written_at"], "unknown")
        self.world()
        code, man = self.artifacts()
        d = self.obs_dir()
        kept = json.load(open(os.path.join(d, man["observation_id"] + ".json")))
        for oid, at in (("obs-20260105T100000Z", "2026-01-05T10:00:00+00:00"), ("obs-20260106T100000Z", "2026-99-99T99:99:99+00:00")):
            with open(os.path.join(d, oid + ".json"), "w") as f:
                json.dump(dict(kept, observation_id=oid, observed_at=at, written_at=at), f)
        code, man = self.artifacts()
        self.assertEqual(code, 0)
        self.assertIn("- Compared with the prior record `obs-20260105T100000Z`, written 2026-01-05T10:00:00+00:00", self.files(man)["access-map"])
        self.assertNotIn("20260106", self.files(man)["access-map"])


if __name__ == "__main__":
    unittest.main()
