"""Batch 6 PR1, B3 (decision 8): "Ask every time" for running commands on this computer is a safe setting, so WT-C002 is a
Tip (no severity, never scored, never new), not a counted low. "Always allow" stays the critical WT-C001.

Tests marked "replay" fail on 5dcd0a2 on their assertion (measured with 5dcd0a2's watchtower/ sources, this file in place);
"guard" ones keep what must not change. The settings file is written into a temp box."""
import json, os, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import Box, wt

TITLE = "Running commands on this computer asks you first each time"
FIX = "That's a safe setting; if you never use it, Never allow is safer still."


class AskEveryTime(Box):
    def settings(self, value):
        p = os.path.join(self.home, "agent-data", "settings.json")
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            json.dump({"localToolPermission": value}, f)
        os.environ["WATCHTOWER_SETTINGS"] = p
        self.addCleanup(os.environ.pop, "WATCHTOWER_SETTINGS", None)
        return p

    def test_it_is_a_tip(self):   # replay (5dcd0a2: [LOW] Confirmed)
        f = wt.label_findings(wt.lint_settings({"local_execution": "ask"}, "settings"))
        self.assertEqual([(x["rule"], x["class"], x["label"], x["severity"]) for x in f], [("WT-C002", "tip", wt.TIP, "info")])
        self.assertEqual((f[0]["title"], f[0]["fix"]), (TITLE, FIX))
        self.assertEqual(wt.score(f), (100, "A"))
        self.assertEqual(wt.status_of(f), wt.ALL_GOOD)

    def test_the_audit_lists_it_as_a_tip_and_counts_nothing(self):   # replay (5dcd0a2: low 1 in open_by_severity)
        self.settings("ask")
        r = self.audit()
        self.assertEqual(r["open_by_severity"]["low"], 0, r)
        self.assertIn(TITLE, [t["title"] for t in r.get("tips", [])])
        self.assertEqual(r["status"], wt.ALL_GOOD)

    def test_it_is_never_new(self):   # replay (5dcd0a2: in daily's new)
        self.audit()
        self.settings("ask")
        out = self.run_cmd("daily", "--roots", *self.roots)[1].strip()
        new = [] if out.startswith("NO_CHANGES") else json.loads(out).get("new", [])
        self.assertFalse([f for f in new if f["rule"] == "WT-C002"], out)

    def test_always_allow_stays_critical(self):   # guard
        f = wt.label_findings(wt.lint_settings({"local_execution": "always"}, "settings"))
        self.assertEqual([(x["rule"], x["severity"], x["label"]) for x in f], [("WT-C001", "critical", wt.CONFIRMED)])
        self.settings("allow")
        r = self.audit()
        self.assertEqual(r["open_by_severity"]["critical"], 1)
        self.assertEqual(r["status"], wt.ACT_NOW)

    def test_an_unknown_value_says_nothing_as_before(self):   # guard
        self.assertEqual(wt.lint_settings({"local_execution": "sometimes"}, "settings"), [])
        self.assertEqual(wt.lint_settings({"local_execution": "never"}, "settings"), [])

    def test_auto_review_off_stays_high(self):   # guard
        f = wt.label_findings(wt.lint_settings({"local_execution": "ask", "auto_review": False}, "settings"))
        self.assertEqual([(x["severity"], x["label"]) for x in f if x["rule"] == "WT-C003"], [("high", wt.CONFIRMED)])


if __name__ == "__main__":
    unittest.main()
