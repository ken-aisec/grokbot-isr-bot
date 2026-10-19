"""Batch 6 PR1, KL7 (#16 high 3): a golden must_see entry that names its scenarios exactly is met in every output of each
scenario its key_rx names, those equal to the baseline included.

Tests marked "replay" fail on 5dcd0a2 on their assertion (measured with 5dcd0a2's tests/golden_split.py, this file in place);
"guard" ones keep what must not change. No sandbox runs: the harness gets each scenario's items in memory."""
import os, sys, unittest
from unittest import mock
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import golden_split as gs  # noqa: E402  (the module, never its TestCase)

SIDS = ("box-empty_account-cli", "box-odd_layout-cli")
BEFORE = "{\n}\n"
WITH_ACCESS = '{\n "access": "x",\n}\n'


def entry(scenario_rx="^(box-empty_account-cli|box-odd_layout-cli)$", key_rx=r"^\d{3} audit :stdout$"):
    return {"item": "kl7", "scenario_rx": scenario_rx, "key_rx": key_rx, "block": ['+ "access": "x",'], "must_see": True,
            "why": "the access line in every audit"}


def harness(entries, items):
    """The golden check over SIDS in expect mode, each scenario's (pre, post) items from `items`: (outcome, report)."""
    class Harness(gs.GoldenSplit):
        report, failed, MODE, pre, post = [], False, "full", "<pre tree>", "<post tree>"
        ITEMS = ["kl7"]
    Harness.sandbox = True
    Harness.expect = gs.parse_expect({"entries": entries}, ["kl7"])
    h = Harness("test_1_tiers")
    h.place = lambda tree: None
    h.run_sandboxed = lambda sid, plan, tag: {"items": dict(items[sid][1] if tag == "post" else items[sid][0])}
    h.timing = lambda: None
    with mock.patch.dict(os.environ, {"WT_GOLDEN_ONLY": "^(" + "|".join(SIDS) + ")$"}):
        try:
            h.test_1_tiers()
        except AssertionError as e:
            return "failed: " + str(e), "\n".join(type(h).report)
    return "passed", "\n".join(type(h).report)


def two_audits(second):
    pre = {"001 status :stdout": "ok\n", "003 audit :stdout": BEFORE, "007 audit :stdout": BEFORE}
    return pre, dict(pre, **{"003 audit :stdout": WITH_ACCESS, "007 audit :stdout": second})


class EveryOutputOfAScenario(unittest.TestCase):
    def test_a_second_audit_without_the_access_line_is_unmet(self):   # replay (5dcd0a2: passed, 0 unmet)
        bad = two_audits(BEFORE)   # Codex's case: the second audit left out the lines, so its output equals the baseline's
        out, rep = harness([entry()], {SIDS[0]: two_audits(WITH_ACCESS), SIDS[1]: bad})
        self.assertTrue(out.startswith("failed: 1 problems"), rep)
        self.assertIn("must_see entry 0 matched nothing in box-odd_layout-cli (in 1 output it names: 007 audit :stdout)", rep)
        self.assertNotIn("matched nothing in box-empty_account-cli", rep)

    def test_missing_outputs_names_each_one(self):   # replay (5dcd0a2: no missing_outputs, unmet takes no keys)
        self.assertTrue(hasattr(gs, "missing_outputs"))
        e =gs.parse_expect({"entries": [entry()]}, ["kl7"])[0]
        hits_by = {SIDS[0]: {0: 1, (0, "003 audit :stdout"): 1}}
        keys_by = {SIDS[0]: {"001 status :stdout", "003 audit :stdout", "007 audit :stdout"}}
        self.assertEqual(gs.missing_outputs(e, SIDS[0], hits_by, keys_by), ["007 audit :stdout"])
        self.assertEqual(gs.unmet([e], hits_by, [SIDS[0]], keys_by), [(e, SIDS[0])])

    def test_every_audit_with_the_line_passes(self):   # guard
        self.assertEqual(harness([entry()], {s: two_audits(WITH_ACCESS) for s in SIDS})[0], "passed")

    def test_outputs_the_key_rx_does_not_name_are_not_required(self):   # guard: the status output never shows the access line
        out, rep = harness([entry(key_rx=r"^003 audit :stdout$")], {s: two_audits(BEFORE) for s in SIDS})
        self.assertEqual(out, "passed", rep)

    def test_a_scenario_with_no_such_output_is_still_unmet(self):   # guard (as since batch 5 PR B round 3)
        pre = {"001 status :stdout": "ok\n"}
        out, rep = harness([entry()], {SIDS[0]: two_audits(WITH_ACCESS), SIDS[1]: (pre, pre)})
        self.assertTrue(out.startswith("failed: 1 problems"), rep)
        self.assertIn("must_see entry 0 matched nothing in box-odd_layout-cli (the intended", rep)

    def test_a_pattern_entry_is_still_met_in_any_one_scenario(self):   # guard: ^box- entries keep "any one scenario"
        out, rep = harness([entry(scenario_rx="^box-")], {SIDS[0]: two_audits(WITH_ACCESS), SIDS[1]: two_audits(BEFORE)})
        self.assertEqual(out, "passed", rep)
        e = gs.parse_expect({"entries": [entry(scenario_rx="^box-")]}, ["kl7"])[0]
        self.assertEqual(gs.unmet([e], {SIDS[0]: {0: 1}}, list(SIDS)), [])


if __name__ == "__main__":
    unittest.main()
