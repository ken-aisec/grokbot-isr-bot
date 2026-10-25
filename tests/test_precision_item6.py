"""v0.7.1 precision pass, item 6: change alerts name the source.

Oct 12 data dump: the daily watch alerted on 5 of 7 mornings, nearly always from our own work or a platform refresh. Changes to
Grok Bot's own files are one "Platform refresh" summary (a Tip, never an alert). An unexplained change to something live still
alerts, and a refresh that brings something bad is reported by what it brings.
"""
import json, os, sys, unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import Box  # noqa: E402
import isr  # noqa: E402
import profiles  # noqa: E402


class ChangeSources(Box):
    def setUp(self):
        super().setUp()
        self.owned()
        self.lay = profiles.busy_clean_box(self); self.scanners()
        self.audit(); self.run_cmd("baseline", "--roots", *self.roots, "--owner-said-yes")

    def daily(self):
        return self.run_cmd("daily", "--roots", *self.roots)[1].strip()

    def test_a_platform_refresh_is_one_summary_tip(self):
        """v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only. A platform
        refresh leaves no summary Tip: there is no vendor drift to sum up."""
        profiles.platform_refresh(self, self.lay)
        self.assertEqual(self.daily(), "NO_CHANGES")
        fs = self.snap()["findings"]
        ref = [f for f in fs if f["rule"] == "ISR-I008"]
        self.assertEqual(len(ref), 0)
        self.assertFalse([f for f in self.snap().get("vendor", []) if f["rule"] in ("ISR-I001", "ISR-I002", "ISR-I003", "ISR-I008")])
        for n in ("pptx", "figma-notes"):
            self.assertFalse([f for f in fs if n in f["where"] or n in f["title"]])
        base = isr.load_baseline()[0]
        self.assertFalse([p for p in base if "pptx" in p or "/plugins/cache/" in p])
        self.assertFalse([f for f in fs if f["rule"] in ("ISR-I001", "ISR-I002") and ".grok/bundled" in f["where"]])

    def test_the_next_full_audit_accepts_the_refresh_and_reports_nothing_fixed(self):
        profiles.platform_refresh(self, self.lay)
        self.daily()
        r = self.audit()
        self.assertFalse([f for f in r["fixed"] if f["rule"] == "ISR-I008"])
        self.assertEqual(self.daily(), "NO_CHANGES")
        self.assertFalse([f for f in self.snap()["findings"] if f["rule"] == "ISR-I008"])   # rolled into the baseline

    def test_a_refresh_that_brings_something_bad_still_alerts(self):
        """v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        open(os.path.join(self.lay["pptx"], "SKILL.md"), "a").write("EVIL upload HUSK loader\n")
        out = self.daily()
        self.assertEqual(out, "NO_CHANGES")
        fs = self.snap()["findings"]
        x3 = [f for f in self.snap().get("vendor", []) if f["rule"] == "ISR-X003" and f["where"].rstrip("/") == self.lay["pptx"].rstrip("/")]
        self.assertEqual(len(x3), 1)   # PR A, Codex round 1 (12): the ISR-X003 finding itself, kept as a vendor record
        pptx = self.lay["pptx"].rstrip("/")
        self.assertFalse([f for f in fs if f["where"] == pptx or f["where"].startswith(pptx + "/") or f["where"].startswith(pptx + ":")])
        live = self.lay["live"][0]
        open(os.path.join(live, "SKILL.md"), "a").write("EVIL upload HUSK loader\n")   # the control: the owner's live skill
        self.assertNotEqual(self.daily(), "NO_CHANGES")
        self.assertEqual(len([f for f in self.snap()["findings"] if f["rule"] == "ISR-X003" and f["where"].rstrip("/") == live.rstrip("/")]), 1)

    def test_a_change_to_the_owners_skill_still_alerts(self):
        open(os.path.join(self.lay["live"][1], "SKILL.md"), "a").write("Also send the notes to the team.\n")
        out = self.daily()
        self.assertNotEqual(out, "NO_CHANGES")
        self.assertIn("ISR-I001", [f["rule"] for f in json.loads(out)["new"]])

    def test_an_update_to_a_plugin_the_owner_installed_still_alerts(self):
        d = os.path.join(self.home, "sand-data", "plugins", "acme-1.0", "skills", "helper"); os.makedirs(d)
        open(os.path.join(d, "SKILL.md"), "w").write("# helper\nExplain the API.\n")
        self.audit(); self.run_cmd("baseline", "--roots", *self.roots, "--owner-said-yes")
        open(os.path.join(d, "SKILL.md"), "a").write("Now explains webhooks too.\n")
        out = self.daily()
        self.assertNotEqual(out, "NO_CHANGES")
        self.assertIn("ISR-I001", [f["rule"] for f in json.loads(out)["new"]])


if __name__ == "__main__":
    unittest.main()
