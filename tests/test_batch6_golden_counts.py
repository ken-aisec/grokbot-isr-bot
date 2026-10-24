"""Batch 6 fix round 1 (Codex 6): a golden entry that expects severity counts to move pins each signed difference.

6cd1ab4's b9 entry in tests/golden_expect/batch6a.json took any "critical"/"high"/.../"info" count line, so a run that dropped a
critical or a high count (with the intended info change, or without it) had no unexpected line. A `json_counts` entry
({at, delta}) expects an output only when the counts object at `at` moved by exactly `delta` (0 for every severity it doesn't
name) and nothing else changed (golden_split.json_counts_change).

Tests marked "replay" fail on 6cd1ab4 on their assertion (its tests/golden_split.py has no json_counts, its batch6a.json pins
nothing); "guard" ones keep what must not change. No sandbox runs: the harness gets each scenario's items in memory."""
import json, os, re, sys, unittest
from unittest import mock
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import golden_split as gs  # noqa: E402  (the module, never its TestCase)

SHIPPED = os.path.join(os.path.dirname(os.path.abspath(__file__)), "golden_expect", "batch6a.json")
SID = "box-busy_clean_box-cli"
KEY = "012 doctor :stdout"
SEVERITIES = ("critical", "high", "medium", "low", "info")


def doctor(**counts):
    """A doctor output's text with these open_by_severity counts (0 for the others)."""
    sev = {s: counts.get(s, 0) for s in SEVERITIES}
    return json.dumps({"version": "x", "last_run": {"score": 90, "open_by_severity": sev}, "run_in_progress": False}, indent=1) + "\n"


def counts_entry(delta, scenario_rx=f"^({SID})$", item="b9"):
    return {"item": item, "scenario_rx": scenario_rx, "key_rx": r"^\d{3} doctor( \[driver\])? :stdout$",
            "json_counts": {"at": ["last_run", "open_by_severity"], "delta": delta}, "must_see": True, "why": "B9: doctor's info count"}


def harness(entries, items, items_on=("b9",)):
    """The golden check over the scenarios in `items` ({sid: (pre items, post items)}) in expect mode: (outcome, report)."""
    class Harness(gs.GoldenSplit):
        report, failed, MODE, pre, post = [], False, "full", "<pre tree>", "<post tree>"
        ITEMS = list(items_on)
    Harness.sandbox = True
    Harness.expect = gs.parse_expect({"entries": entries}, list(items_on))
    h = Harness("test_1_tiers")
    h.place = lambda tree: None
    h.run_sandboxed = lambda sid, plan, tag: {"items": dict(items[sid][1] if tag == "post" else items[sid][0])}
    h.timing = lambda: None
    with mock.patch.dict(os.environ, {"ISR_GOLDEN_ONLY": "^(" + "|".join(items) + ")$"}):
        try:
            h.test_1_tiers()
        except AssertionError as e:
            return "failed: " + str(e), "\n".join(type(h).report)
    return "passed", "\n".join(type(h).report)


def one(pre, post):
    status = {"001 status :stdout": "ok\n"}
    return {SID: (dict(status, **{KEY: pre}), dict(status, **{KEY: post}))}


class SignedCounts(unittest.TestCase):
    def test_the_pinned_change_is_expected(self):   # guard
        out, rep = harness([counts_entry({"info": -3})], one(doctor(medium=1, info=5), doctor(medium=1, info=2)))
        self.assertEqual(out, "passed", rep)

    def test_a_probe_that_also_drops_a_critical_and_a_high_is_unexpected(self):   # replay (6cd1ab4: no json_counts)
        self.assertIn("json_counts", gs.ALT_FIELDS)
        out, rep = harness([counts_entry({"info": -3})], one(doctor(critical=1, high=2, info=5), doctor(critical=0, high=1, info=2)))
        self.assertTrue(out.startswith("failed:"), rep)
        self.assertIn("no enabled entry expects", rep)
        self.assertRegex(rep, r'\| -\s*"critical": 1,')
        self.assertRegex(rep, r'\| \+\s*"high": 1,')

    def test_a_probe_without_the_intended_change_is_unexpected_and_unmet(self):   # replay (6cd1ab4: no json_counts)
        self.assertIn("json_counts", gs.ALT_FIELDS)
        out, rep = harness([counts_entry({"info": -3})], one(doctor(critical=1, high=1, info=5), doctor(info=5)))
        self.assertTrue(out.startswith("failed:"), rep)
        self.assertIn("no enabled entry expects", rep)
        self.assertIn("must_see entry 0 matched nothing in " + SID, rep)

    def test_another_size_of_the_same_change_is_unexpected(self):   # replay (6cd1ab4: no json_counts)
        self.assertIn("json_counts", gs.ALT_FIELDS)
        out, rep = harness([counts_entry({"info": -3})], one(doctor(info=5), doctor(info=1)))
        self.assertTrue(out.startswith("failed:"), rep)

    def test_a_normalized_output_is_still_read(self):   # guard: N4 leaves "seconds_per_stage": {"x": <DUR>} in doctor's JSON
        norm = lambda t: t.replace('"run_in_progress": false', '"run_in_progress": false,\n "took_seconds": <DUR>')
        out, rep = harness([counts_entry({"info": -3})], one(norm(doctor(info=5)), norm(doctor(info=2))))
        self.assertEqual(out, "passed", rep)
        out, rep = harness([counts_entry({"info": -3})], one(norm(doctor(high=1, info=5)), norm(doctor(info=2))))
        self.assertTrue(out.startswith("failed:"), rep)

    def test_any_other_change_in_the_output_is_unexpected(self):   # guard: only the counts may move
        post = doctor(medium=1, info=2).replace('"score": 90', '"score": 80')
        out, rep = harness([counts_entry({"info": -3})], one(doctor(medium=1, info=5), post))
        self.assertTrue(out.startswith("failed:"), rep)

    def test_malformed_entries_are_refused(self):   # guard
        for bad in ({"info": 0}, {}, {"info": True}, {"info": "-3"}):
            with self.assertRaises(ValueError, msg=bad):
                gs.parse_expect({"entries": [counts_entry(bad)]}, ["b9"])
        e = counts_entry({"info": -3})
        e["json_counts"]["at"] = []
        with self.assertRaises(ValueError):
            gs.parse_expect({"entries": [e]}, ["b9"])


class TheShippedB9Entries(unittest.TestCase):
    def entries(self):
        with open(SHIPPED) as f:
            doc = json.load(f)
        return [e for e in doc["entries"] if e["item"] == "b9"]

    def scenarios(self):
        """{scenario id: its b9 entry's delta}, from the entries' literal scenario lists."""
        out = {}
        for e in self.entries():
            m = gs.EXACT_SCENARIOS.fullmatch(e["scenario_rx"])
            self.assertTrue(m, e["scenario_rx"])
            for sid in re.sub(r"^\^\(?|\)?\$$", "", e["scenario_rx"]).split("|"):
                out[sid] = e["json_counts"]["delta"]
        return out

    def test_each_entry_pins_signed_counts(self):   # replay (6cd1ab4: one lines_rx entry taking any count line)
        es = self.entries()
        self.assertTrue(es)
        for e in es:
            self.assertNotIn("lines_rx", e)
            self.assertEqual(e["json_counts"]["at"], ["last_run", "open_by_severity"])
            self.assertTrue(e["must_see"])

    def run_shipped(self, post_of):
        items = {}
        for sid, delta in self.scenarios().items():
            pre = dict(critical=1, high=1, medium=2, low=3, info=40)
            items[sid] = ({KEY: doctor(**pre)}, {KEY: doctor(**post_of(pre, delta))})
        return harness(self.entries(), items)

    def test_the_shipped_entries_take_their_own_change(self):   # guard
        out, rep = self.run_shipped(lambda pre, d: {s: pre[s] + d.get(s, 0) for s in SEVERITIES})
        self.assertEqual(out, "passed", rep)

    def test_a_probe_that_drops_a_critical_or_high_count_is_unexpected(self):   # replay (6cd1ab4: passed, no unexpected line)
        for drop in ("critical", "high"):
            out, rep = self.run_shipped(lambda pre, d: {s: pre[s] + d.get(s, 0) - (s == drop) for s in SEVERITIES})
            self.assertTrue(out.startswith("failed:"), rep)
            self.assertIn("no enabled entry expects", rep)
            self.assertRegex(rep, r'\| -\s*"' + drop + r'": 1,')
            out, rep = self.run_shipped(lambda pre, d: {s: pre[s] - (s == drop) for s in SEVERITIES})   # and the info change left out
            self.assertTrue(out.startswith("failed:"), rep)
            self.assertIn("no enabled entry expects", rep)


if __name__ == "__main__":
    unittest.main()
