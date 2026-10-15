"""DQ-018 leftover (v0.7.1 scope, Claude Oct 12): a Bot gone from the roll-call is closed, and without a saved roster the audit
says why removed Bots can still show (main box, Oct 12: no exports/roster.json, so the Oct 9 roll-call still named removed Bots
in Tips and Worth-a-look lines). Bot names are anonymized."""
import json, os, sys, unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import Box, wt  # noqa: E402

TRIFECTA = {"connectors": ["Gmail", "Slack", "X"],
            "routines": [{"name": "Morning", "trigger": "schedule", "sends_or_posts": True, "asks_first": False, "reads_outside_content": True}],
            "memories": {"count": 0, "loosen_permissions": 0, "from_outside_content": 0}}


class DQ018Leftover(Box):
    def rollcall(self, *names):
        rdir = wt.default_rollcall_dir(); os.makedirs(rdir, exist_ok=True)
        for n in names:
            json.dump(dict(TRIFECTA, name=n), open(os.path.join(rdir, n.lower().split()[0] + ".json"), "w"))
        code, o, _ = self.run_cmd("rollcall", "--owner-said-yes")
        self.assertEqual(code, 0, o)

    def bots_in(self):
        return sorted({f["where"].split(":")[1] for f in self.snap()["findings"] if f["where"].startswith("rollcall:")})

    def test_a_bot_gone_from_the_next_roll_call_is_closed(self):
        self.skills(1); self.scanners()
        self.rollcall("Alpha - BCA", "Delta")
        self.audit()
        self.assertEqual(self.bots_in(), ["Alpha - BCA", "Delta"])
        self.rollcall("Delta")                       # Alpha was removed: it no longer answers the roll-call
        r = self.audit()
        self.assertEqual(self.bots_in(), ["Delta"])
        md = wt.render_md(self.snap(), [], "2026-W42")
        self.assertNotIn("Alpha - BCA", md)

    def test_without_a_saved_roster_the_audit_says_how_removed_bots_drop_out(self):
        self.skills(1); self.scanners()
        self.rollcall("Alpha - BCA", "Delta")
        self.audit()   # the full notes go to the report's coverage notes; the audit JSON keeps only the first few
        self.assertTrue(any("roster.json" in n and "removed" in n for n in self.snap()["notes"]), self.snap()["notes"])
        self.assertIn("No roster saved", wt.render_md(self.snap(), [], "2026-W42"))   # the weekly report's coverage notes say it
        exp = os.path.join(os.environ["WATCHTOWER_HOME"], "exports"); os.makedirs(exp, exist_ok=True)
        json.dump([{"name": "Delta", "kind": "bot"}], open(os.path.join(exp, "roster.json"), "w"))
        r = self.audit()
        self.assertFalse(any("roster.json" in n and ("No roster" in n or "older than" in n) for n in self.snap()["notes"]), self.snap()["notes"])
        self.assertEqual(self.bots_in(), ["Delta"])

    def test_a_roster_older_than_the_roll_call_also_gets_the_hint(self):
        self.skills(1); self.scanners()
        exp = os.path.join(os.environ["WATCHTOWER_HOME"], "exports"); os.makedirs(exp, exist_ok=True)
        rp = os.path.join(exp, "roster.json")
        json.dump([{"name": "Delta", "kind": "bot"}], open(rp, "w"))
        os.utime(rp, (1, 1))                         # saved long before this roll-call
        self.rollcall("Alpha - BCA", "Delta")
        r = self.audit()
        self.assertEqual(self.bots_in(), ["Alpha - BCA", "Delta"])   # an old roster never drops a Bot that just answered
        self.assertTrue(any("roster.json" in n and "older than" in n for n in self.snap()["notes"]), self.snap()["notes"])


if __name__ == "__main__":
    unittest.main()
