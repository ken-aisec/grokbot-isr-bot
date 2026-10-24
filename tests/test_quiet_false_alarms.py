"""v0.6.8: a false alarm is never scary. Pattern findings are labelled "Worth a look", capped at medium unless backed up,
and weigh a fifth in the score; evidence findings stay exactly as loud as before."""
import os, sys, tempfile, unittest, warnings

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "isr_bot"))
import isr  # noqa: E402

warnings.simplefilter("ignore", ResourceWarning)
F = lambda rule, sev, where, source="watchtower", title="t": isr.finding(rule, title, sev, ["X"], where, "ev", "fix", source=source)


class QuietFalseAlarms(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.skill = os.path.join(self.tmp, "s"); os.makedirs(self.skill)
        open(os.path.join(self.skill, "SKILL.md"), "w").write("---\nname: s\n---\n")
        self.md = os.path.join(self.skill, "SKILL.md")

    def test_every_evidence_finding_keeps_its_severity_and_label(self):
        # ISR-S005 is evidence only with the New-sign-in title (cookie-only notes stay Worth a look).
        ev = [F(r, sev, f"{self.md}:1", title=isr.NEW_SIGN_IN if r == "ISR-S005" else "t")
              for r in sorted(isr.EVIDENCE_RULES) for sev in ("critical", "high", "medium", "low")]
        ev.append(F("ISR-S001", "critical", self.md, title=isr.KEY_LIVE))                        # a key the provider says works
        ev.append(F("ISR-H006", "medium", "/home/box/.bash_history", title=isr.HISTORY_SHRANK))      # the file got smaller
        out = isr.label_findings(ev)
        self.assertEqual([f["severity"] for f in out], [f["severity"] for f in ev])
        self.assertTrue(all(f["label"] == isr.CONFIRMED and "severity_was" not in f for f in out))

    def test_evidence_only_scores_are_unchanged(self):
        for fs in ([F("ISR-K001", "critical", "/tmp/.archive/payments.env")],
                   [F("ISR-I001", "high", self.md), F("ISR-D002", "high", "/ws/app"), F("ISR-S004", "high", "browser"), F("ISR-A003", "medium", "rules")],
                   [F("ISR-X003", "critical", self.skill), F("ISR-C003", "high", "settings")]):
            self.assertEqual(isr.score(isr.label_findings(fs)), isr.score(fs))   # unlabelled findings count in full, as before v0.6.8

    def test_owner_calls_of_oct_10(self):
        """Shell-history hits are commands that ran: evidence, so a reverse shell stays critical. H007 is evidence; L001 is pattern."""
        for r in ("ISR-H001", "ISR-H002", "ISR-H003", "ISR-H004", "ISR-H005", "ISR-H006", "ISR-H007", "ISR-H008", "ISR-H009"):
            self.assertIn(r, isr.EVIDENCE_RULES, r)
        out = isr.label_findings([F("ISR-H003", "critical", "/home/box/.bash_history:12"), F("ISR-H002", "critical", "/home/box/.bash_history:40")])
        self.assertEqual([(f["severity"], f["label"]) for f in out], [("critical", isr.CONFIRMED)] * 2)
        self.assertNotIn("ISR-L001", isr.EVIDENCE_RULES)
        l1 = isr.label_findings([F("ISR-L001", "high", "rollcall:Harbor")])[0]
        self.assertEqual((l1["severity"], l1["label"]), ("info", isr.MAYBE_FINE))

    def test_a_lone_pattern_finding_carries_no_severity(self):
        """Since the owner's refinement of Oct 10: not capped at medium but shown with no severity ("info") and never scored."""
        out = isr.label_findings([F("ISR-T013", "high", "rollcall:Bot:routine:x"), F("ISR-T005", "critical", f"{self.md}:3"),
                                 F("ISR-S002", "high", "/ws/notes.txt", source="gitleaks"), F("ISR-X001", "high", "/ws/other", source="skillspector")])
        self.assertEqual([f["severity"] for f in out], ["info"] * 4)
        self.assertEqual([f["severity_was"] for f in out], ["high", "critical", "high", "high"])
        self.assertTrue(all(f["label"] == isr.MAYBE_FINE for f in out))
        low = isr.label_findings([F("ISR-T016", "low", f"{self.md}:2")])[0]
        self.assertEqual((low["severity"], low["label"]), ("info", isr.MAYBE_FINE))                 # never raised, and no severity

    def test_corroboration_keeps_a_pattern_finding_loud(self):
        # a second engine on the same file
        out = isr.label_findings([F("ISR-S002", "high", "/ws/k.env:4", source="gitleaks"), F("ISR-S001", "high", "/ws/k.env:4")])
        self.assertEqual([(f["severity"], f["label"]) for f in out], [("high", isr.CONFIRMED)] * 2)
        # an evidence finding at the same skill folder
        out = isr.label_findings([F("ISR-T005", "critical", f"{self.md}:3"), F("ISR-I001", "high", self.skill)])
        self.assertEqual((out[0]["severity"], out[0]["class"]), ("critical", "corroborated"))
        # two different loud pattern rules in one skill
        out = isr.label_findings([F("ISR-T002", "high", f"{self.md}:5"), F("ISR-T001", "critical", f"{self.md}:5")])
        self.assertEqual([f["severity"] for f in out], ["high", "critical"])
        # the same rule twice, or a finding somewhere else, is not a second opinion
        out = isr.label_findings([F("ISR-T005", "critical", f"{self.md}:3"), F("ISR-T005", "critical", f"{self.md}:9"),
                                 F("ISR-S002", "high", "/elsewhere/x", source="gitleaks")])
        self.assertEqual([f["severity"] for f in out], ["info"] * 3)

    def test_roll_call_findings_only_back_up_their_own_bot_line(self):
        out = isr.label_findings([F("ISR-T013", "high", "rollcall:Alpha:routine:Brief:1"), F("ISR-L001", "high", "rollcall:Alpha"),
                                 F("ISR-M010", "medium", "rollcall:Bravo:memory1"), F("ISR-T013", "high", "rollcall:Bravo:routine:Digest:1")])
        self.assertEqual([f["class"] for f in out], ["pattern", "pattern", "pattern", "pattern"])   # L001 is a pattern since the decision of Oct 10
        self.assertEqual(out[0]["severity"], "info")

    def test_worth_a_look_findings_never_move_the_score(self):
        """Replaced the 0.2 weight (decision, Oct 10): an uncorroborated pattern finding counts for nothing."""
        p = isr.label_findings([F("ISR-T013", "medium", "rollcall:B:routine:r")])
        e = isr.label_findings([F("ISR-A003", "medium", "rules")])
        self.assertEqual(p[0]["class"], "pattern")
        self.assertEqual(isr.score(e)[0], 100 - round(isr.SCORE_BASE["medium"]))
        self.assertEqual(isr.score(p), (100, "A"))
        self.assertEqual(isr.score(isr.label_findings([F(f"ISR-T00{i}", "critical", f"/ws/s{i}/SKILL.md:1") for i in range(1, 9)])), (100, "A"))
        many = isr.label_findings([F(f"ISR-T00{i}", "critical", f"/ws/s{i}/SKILL.md:1") for i in range(1, 9)])
        self.assertGreater(isr.score(many)[0], isr.score([F(f"ISR-T00{i}", "critical", f"/ws/s{i}/SKILL.md:1") for i in range(1, 9)])[0])

    def test_labels_reach_the_report_and_chat(self):
        fs = isr.label_findings([F("ISR-K001", "critical", "/tmp/.archive/payments.env"), F("ISR-T013", "high", "rollcall:B:routine:r")])
        self.assertEqual([isr.compact(f)["label"] for f in fs], [isr.CONFIRMED, isr.MAYBE_FINE])
        self.assertEqual(isr.plain(fs[1])["label"], isr.MAYBE_FINE)
        md = isr.render_md({"findings": fs, "score": 90, "grade": "A"}, [], "t")
        self.assertIn(f"{isr.CONFIRMED}: ", md); self.assertIn(f"{isr.MAYBE_FINE}: ", md)


if __name__ == "__main__":
    unittest.main()
