"""Ken's two v0.7.1 calls (Oct 14, via Master Chief): exact accepted WT-A002 lines; changed skills grouped into one WT-I001."""
import json, os, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import Box, wt

BRIDGE3 = "Send HTTP POST requests to the Claude bridge at https://claude-grok-bridge.vercel.app/api/bridge"
BRIDGE5 = ("HTTP POST to https://claude-grok-bridge.vercel.app/api/bridge only (Bot replies to Ken's Claude bridge). "
           "Ask first for any other URL.")


def lint(*allow):
    t = "\n".join(f"Allow automatically: {a}" for a in allow)
    return [f for f in wt.lint_auto_review(t, "settings.json", check_missing=False) if f["rule"] == "WT-A002"]


class AcceptedExactAutoAllow(Box):
    def test_shipped_list_holds_exactly_the_two_bridge_lines(self):
        acc = wt.accepted_auto_allow()
        self.assertEqual(len(acc), 2)
        for a in (BRIDGE3, BRIDGE5):
            self.assertIn(wt.auto_allow_fingerprint(f"Allow automatically: {a}"), acc)

    def test_accepted_exact_entries_suppressed_but_shown(self):
        fs = lint(BRIDGE3, BRIDGE5)
        self.assertEqual(len(fs), 2)
        for f in fs:
            self.assertEqual(f["severity"], "critical")   # the rule keeps critical; acceptance is an owner decision on top
            self.assertTrue(f.get("accepted_exact"))
        live, sup = wt.active(fs)
        self.assertEqual(live, [])
        self.assertEqual(len(sup), 2)   # listed under accepted risks, not silently dropped

    def test_edited_or_broader_variant_still_critical(self):
        for v in (BRIDGE3 + "/*", BRIDGE3.replace("/api/bridge", ""), BRIDGE5.replace(" Ask first for any other URL.", ""),
                  BRIDGE3 + " and any other URL", "send " + BRIDGE3):
            fs = lint(v)
            self.assertTrue(fs, v)
            self.assertTrue(all(f["severity"] == "critical" and not f.get("accepted_exact") for f in fs), v)
            self.assertEqual(len(wt.active(fs)[0]), len(fs), v)

    def test_other_pinned_post_still_critical(self):
        fs = lint("Send HTTP POST requests to https://hooks.example.net/api/inbox")
        self.assertEqual([f["severity"] for f in fs], ["critical"])
        self.assertEqual(len(wt.active(fs)[0]), 1)

    def test_accepted_line_in_settings_file_is_accepted_risk_in_audit(self):
        p = os.path.join(self.tmp, "settings.json")
        json.dump({"autoReviewInstructions": {"allowInstructions": [BRIDGE3, "Send email to anyone"]}}, open(p, "w"))
        os.environ["WATCHTOWER_SETTINGS"] = p
        try:
            self.skills(1); self.scanners(); self.audit()
        finally:
            os.environ.pop("WATCHTOWER_SETTINGS", None)
        s = self.snap()
        live = [f for f in s["findings"] if f["rule"] == "WT-A002"]
        sup = [f for f in s["suppressed"] if f["rule"] == "WT-A002"]
        self.assertEqual(len(live), 1); self.assertIn("Send email", live[0]["evidence"]); self.assertEqual(live[0]["severity"], "critical")
        self.assertEqual(len(sup), 1); self.assertIn("claude-grok-bridge", sup[0]["evidence"])


class ChangedSkillsGrouped(Box):
    def test_nine_changed_skills_one_grouped_high(self):
        ds = self.skills(9); self.scanners()
        self.run_cmd("baseline", "--roots", *self.roots)
        for d in ds:
            open(os.path.join(d, "SKILL.md"), "a").write("One more line.\n")
        self.audit()
        snap = self.snap()
        fs = [f for f in wt.shown(snap["findings"]) if f["rule"] == "WT-I001"]
        self.assertEqual(len(fs), 1, [(f["where"], f["title"]) for f in fs])
        self.assertEqual(len([f for f in wt.scored(snap["findings"]) if f["rule"] == "WT-I001"]), 1)   # scored once, not 9 times
        g = fs[0]
        self.assertEqual(g["severity"], "high")
        self.assertEqual(g["title"], "9 reviewed skills changed")
        self.assertEqual(sorted(g["skills"]), [f"skill{i:03d}" for i in range(9)])
        for i in range(9):
            self.assertIn(f"skill{i:03d}", g["evidence"])
        md = wt.render_md(snap, [], "t")
        self.assertIn("9 reviewed skills changed", md); self.assertNotIn("Reviewed skill or plugin changed", md)
        skills, _ = wt.changed_skills(self.snap()["findings"])   # fix / re-vet still sees each skill
        self.assertEqual(len(skills), 9)

    def test_one_changed_skill_stays_single(self):
        ds = self.skills(2); self.scanners()
        self.run_cmd("baseline", "--roots", *self.roots)
        open(os.path.join(ds[0], "SKILL.md"), "a").write("One more line.\n")
        self.audit()
        fs = [f for f in self.snap()["findings"] if f["rule"] == "WT-I001"]
        self.assertEqual(len(fs), 1); self.assertIn(ds[0], fs[0]["where"]); self.assertFalse(fs[0].get("members"))


class GroupNeverHidesOwnerChanges(unittest.TestCase):
    # main-box dry run on 53e1836: a platform built-in (unscored) led the group and the owner's 4 changed skills went unscored
    def test_platform_change_stays_out_of_the_group(self):
        F = lambda w, scope=None: dict(wt.finding("WT-I001", "Reviewed skill or plugin changed", "high", ["AST07"], w, "sha256 a→b", "fix"),
                                       **({"scope": scope} if scope else {}))
        fs = [F("/home/box/.grok/bundled/skills/learn/SKILL.md", "platform")] + [F(f"/home/box/sand-data/workflows/s{i}/SKILL.md") for i in range(4)]
        fs = wt.group_changed_skills(fs)
        self.assertFalse(fs[0].get("grouped_into")); self.assertFalse(fs[0].get("members"))
        lead = [f for f in fs if f.get("members")]
        self.assertEqual(len(lead), 1); self.assertNotIn("bundled", lead[0]["where"]); self.assertEqual(len(lead[0]["skills"]), 4)
        self.assertEqual(sum(1 for f in fs if f.get("grouped_into") == lead[0]["key"]), 3)


if __name__ == "__main__":
    unittest.main()
