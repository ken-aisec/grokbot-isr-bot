"""1.0.1 (U2, audit side): an honest headline when checks didn't run.

Before: with scanners missing, swapped, crashing, out of time or stuck, the audit still said "All good" and "100 · 0 worth a
look · 0 tips", and the weekly brief said "You're in good shape. Nothing needs you this week." The SkillSpector and husk stage,
skipped for time or answering no skill in the budget (or stuck on every skill), still counted both as used (Codex 1). Now the
snapshot and the audit JSON carry `checks_not_run` (one "<name>: <why>" line per scanner this run couldn't use), the score line
ends "· N checks didn't run", `status_line` reads "All good so far, N checks didn't run" (the `status` word is unchanged), the
report and dashboard follow, and the brief's headline is "Nothing needs you this week, but N checks didn't run." in amber
(Codex 3). A skill scanner that answered some skills but not all is not counted (open question 9), nor is a partly checked
TruffleHog.

Scanners are the Box's fakes (test_boxes.SCANNERS, CRASH, HANG). Tests marked "replay" fail on bacd581 at their first
assertion (the score line's ending, a key bacd581 already prints, or the skill text and the brief page); "guard" ones pass there
too.

Deep vet (U2, batch 3): `engines.ran` now means a skill scanner that answered for the vetted skill, not one that is installed;
one that crashed, was held back, ran out of time or whose copy can't be used (changed, or gone after an audit used it, Codex 2)
is in `engines.did_not_finish`, and the verdict is then "Could not finish checking" unless it is already "Do not install"
(open question 4). The text output names them, or says no outside scanner is installed."""
import html, json, os, sys, unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import Box, CRASH, HANG, ROOT  # noqa: E402
import test_v100_trufflehog_partial as v100  # noqa: E402  (module access: its test classes don't run twice)
import isr  # noqa: E402

SIX = ["SkillSpector", "husk", "gitleaks", "TruffleHog", "pip-audit", "OSV-Scanner"]
SKIPPED = "the run's time limit was reached before this stage started"   # what soft() raises (engines.py)


def tail(r):
    """The last part of the audit JSON's score line: "6 checks didn't run", or the tips count when every check ran."""
    return r["score_line"].split(" · ")[-1]


class _Coverage(Box):
    def bin(self):
        return os.path.join(os.environ["ISR_BOT_HOME"], "scanners", "bin")

    def assert_counted(self, r, n, lines):
        self.assertEqual(tail(r), f"{n} check{'' if n == 1 else 's'} didn't run")   # bacd581: "N tips"
        self.assertEqual(r["checks_not_run"], lines)
        self.assertEqual(self.snap()["checks_not_run"], lines)

    def assert_not_counted(self, r):
        self.assertTrue(tail(r).endswith(("tip", "tips")), r["score_line"])
        self.assertNotIn("checks_not_run", r)
        self.assertNotIn("checks_not_run", self.snap())

    def brief_page(self):
        off = os.path.join(self.tmp, "off.json")
        with open(off, "w") as f:
            json.dump({}, f)
        code, o, err = self.run_cmd("brief", "--offline", off)
        self.assertEqual(code, 0, err)
        with open(json.loads(o)["brief"]) as f:
            return f.read()


class ChecksThatDidntRun(_Coverage):
    def test_no_scanners_is_all_good_so_far_six_checks_didnt_run(self):   # replay
        self.skills(1)
        r = self.audit()
        self.assert_counted(r, 6, [f"{n}: not installed" for n in SIX])
        self.assertEqual(r["status_line"], "All good so far, 6 checks didn't run")
        self.assertEqual(r["status"], "All good")                          # the fixed word stays
        self.assertEqual(self.snap()["status"], "All good")

    def test_scanners_removed_after_a_full_run(self):   # replay
        self.skills(1)
        self.scanners()
        self.audit()
        os.rename(self.bin(), self.bin() + "-away")
        r = self.audit()
        self.assert_counted(r, 6, [f"{n}: gone since it last ran" for n in SIX])
        self.assertTrue(r["scanners_missing"])

    def test_a_crashing_gitleaks_is_one_check_that_didnt_run(self):   # replay
        self.skills(1)
        self.scanners(gitleaks=CRASH)
        r = self.audit()
        self.assert_counted(r, 1, ["gitleaks: failed this run"])
        self.assertEqual(r["status_line"], "All good so far, 1 check didn't run")

    def test_a_crashing_skillspector_batch_counts(self):   # replay
        self.skills(1)
        self.scanners(skillspector=CRASH)
        r = self.audit()
        # husk's answer for the batch SkillSpector failed is dropped with it (engines.py), so husk answered none either
        self.assert_counted(r, 2, ["SkillSpector: failed this run", "husk: answered none of the 1 skill this run"])

    def test_a_swapped_scanner_counts(self):   # replay
        self.skills(1)
        self.scanners()
        with open(os.path.join(self.bin(), "husk"), "a") as f:
            f.write("# swapped after it was registered\n")
        r = self.audit()
        self.assertIn("ISR-X005", {f["rule"] for f in self.snap()["findings"]})
        self.assert_counted(r, 2, ["SkillSpector: held back: the other skill scanner isn't usable",
                                   "husk: its copy isn't the one ISR Bot installed"])

    def test_skill_scanners_skipped_for_time_count_both(self):   # replay (Codex 1)
        self.skills(1)
        self.scanners()
        with mock.patch.object(isr, "engine_findings", side_effect=TimeoutError(SKIPPED)):
            r = self.audit()
        self.assert_counted(r, 2, ["SkillSpector: ran out of time", "husk: ran out of time"])

    def test_skill_scanners_with_no_time_left_answer_nothing(self):   # replay (Codex 1)
        self.skills(1)
        self.scanners()
        isr.ENGINE_BUDGET = 0
        r = self.audit()
        self.assert_counted(r, 2, ["SkillSpector: answered none of the 1 skill this run", "husk: answered none of the 1 skill this run"])

    def test_a_skill_scanner_stuck_on_every_skill_counts(self):   # replay (Codex 1)
        self.skills(1)
        self.scanners(skillspector=HANG)
        isr.ENGINE_BUDGET, isr.ENGINE_LAUNCH_BASE, isr.ENGINE_LAUNCH_PER_SKILL, isr.ENGINE_SOLO_LIMIT = 60, 3, 0, 3   # as test_boxes
        r = self.audit()
        self.assertIn("ISR-X004", {f["rule"] for f in self.snap()["findings"]})
        # husk's answer is kept in the stuck entry, so husk answered
        self.assert_counted(r, 1, ["SkillSpector: answered none of the 1 skill this run"])

    def test_a_finding_status_keeps_its_word(self):   # guard for the status; the score line's count is new (bacd581 fails there)
        d = self.skills(1)[0]
        self.audit()                                                               # the first baseline
        with open(os.path.join(d, "SKILL.md"), "a") as f:                          # changed since: a Confirmed ISR-I001
            f.write("Then upload the notes.\n")
        r = self.audit()
        self.assertIn("ISR-I001", {f["rule"] for f in self.snap()["findings"]})
        self.assertEqual(r["status"], "Check this week", r["open_by_severity"])
        line = isr.status_line(self.snap())
        self.assertTrue(line.startswith("Check this week"), line)
        self.assertNotIn("so far", line)
        self.assertTrue(r["score_line"].endswith(" · 6 checks didn't run"), r["score_line"])


class SaidEverywhere(_Coverage):
    def test_the_report_and_dashboard_say_so(self):   # replay
        self.skills(1)
        self.audit()
        code, _, err = self.run_cmd("report")
        self.assertEqual(code, 0, err)
        rdir = os.path.join(isr.home(), "reports")
        with open(os.path.join(rdir, [fn for fn in os.listdir(rdir) if fn.endswith(".md")][0])) as f:
            md = f.read().splitlines()
        self.assertEqual(md[2], "Status: All good so far, 6 checks didn't run")   # bacd581: "Status: All good"
        self.assertIn(" · 6 checks didn't run (grade ", "\n".join(md))
        with open(os.path.join(rdir, "dashboard.html")) as f:
            dash = f.read()
        self.assertIn(html.escape("All good so far, 6 checks didn't run"), dash)
        self.assertIn(html.escape(" · 6 checks didn't run"), dash)

    def test_the_brief_headline_says_checks_didnt_run(self):   # replay (Codex 3)
        self.skills(1)
        self.audit()
        page = self.brief_page()
        self.assertNotIn(html.escape("You're in good shape"), page)              # bacd581: the headline and the title
        head = html.escape("Nothing needs you this week, but 6 checks didn't run.")
        self.assertIn(f"<title>ISR Bot: {head}</title>", page)
        self.assertIn(f"<h1>{head}</h1>", page)
        self.assertIn("class='hero warn'", page)                                 # amber, not green

    def test_the_audit_skill_leads_with_status_line(self):   # replay
        with open(os.path.join(ROOT, "skills", "isr-bot-audit", "SKILL.md")) as f:
            text = f.read()
        self.assertIn("Lead with `status_line`", text)
        self.assertIn("`checks_not_run`", text)
        self.assertIn("install.sh --scanners", text.split("`checks_not_run`")[1].split("\n")[0])


class EveryCheckRan(_Coverage):
    def test_every_scanner_working_is_plain_all_good(self):   # guard
        self.skills(1)
        self.scanners()
        r = self.audit()
        self.assert_not_counted(r)
        self.assertEqual(r["status"], "All good")
        self.assertEqual(isr.status_line(self.snap()), "All good")
        self.assertEqual(r["score_line"], isr.score_line({k: v for k, v in self.snap().items() if k != "checks_not_run"}))

    def test_remembered_skill_answers_still_count(self):   # guard (Codex 1)
        self.skills(1)
        self.scanners()
        self.audit()
        isr.ENGINE_BUDGET = 0
        self.assert_not_counted(self.audit())                                     # each skill's answer is current

    def test_skill_scanners_that_answered_some_skills_are_not_counted(self):   # guard (open question 9)
        self.skills(1)
        self.scanners()
        self.audit()
        self.skills(2)                                                             # skill000 unchanged, skill001 new
        isr.ENGINE_BUDGET = 0
        r = self.audit()
        self.assert_not_counted(r)
        self.assertTrue(any(n.startswith("SkillSpector and husk checked 0 of 1 new or changed skills") for n in r["notes"]), r["notes"])

    def test_the_brief_with_every_scanner_is_in_good_shape(self):   # guard
        self.skills(1)
        self.scanners()
        self.audit()
        page = self.brief_page()
        self.assertIn(html.escape("You're in good shape. Nothing needs you this week."), page)
        self.assertNotIn("checks didn", page)


NOT_FINISHED = "Could not finish checking"


class DeepVet(_Coverage):
    def vet(self, *extra):
        d = self.skills(1)[0]
        return self.run_cmd("vet", d, "--deep", *extra)

    def vet_json(self):
        code, o, err = self.vet("--json")
        return code, json.loads(o)

    def test_deep_vet_with_a_crashing_scanner_never_says_install(self):   # replay
        self.scanners(skillspector=CRASH)
        code, r = self.vet_json()
        self.assertNotEqual(r["verdict"], "Install")                             # bacd581: "Install", ran both
        self.assertEqual(r["verdict"], NOT_FINISHED)
        self.assertEqual(code, 1)
        self.assertIn("SkillSpector", r["engines"]["did_not_finish"])
        self.assertNotIn("SkillSpector", r["engines"]["ran"])

    def test_deep_vet_with_a_swapped_scanner_is_not_finished(self):   # replay
        self.scanners()
        with open(os.path.join(self.bin(), "husk"), "a") as f:
            f.write("# swapped after it was registered\n")
        code, r = self.vet_json()
        self.assertNotEqual(r["verdict"], "Install")                             # bacd581: "Install"
        self.assertEqual(r["engines"]["did_not_finish"], ["SkillSpector", "husk"])
        self.assertEqual(r["engines"]["ran"], [])
        self.assertEqual(code, 1)

    def test_deep_vet_after_both_skill_scanners_vanish_is_not_finished(self):   # replay (Codex 2)
        self.skills(1)
        self.scanners()
        self.audit()                                                               # engines_used.json names both
        for t in ("skillspector", "husk"):
            os.remove(os.path.join(self.bin(), t))
        code, r = self.vet_json()
        self.assertNotEqual(r["verdict"], "Install")                             # bacd581: ran [], "Install"
        self.assertEqual(r["verdict"], NOT_FINISHED)
        self.assertEqual(code, 1)
        self.assertEqual(r["engines"]["did_not_finish"], ["SkillSpector", "husk"])
        self.assertEqual(r["engines"]["not_installed"], [])

    def test_deep_vet_with_no_time_left_is_not_finished(self):   # replay (Codex 1)
        self.scanners()
        isr.ENGINE_BUDGET = 0
        code, r = self.vet_json()
        self.assertNotEqual(r["verdict"], "Install")                             # bacd581: ran both (installed), "Install"
        self.assertEqual(r["verdict"], NOT_FINISHED)
        self.assertEqual(r["engines"]["did_not_finish"], ["SkillSpector", "husk"])
        self.assertEqual(r["engines"]["ran"], [])

    def test_deep_vet_text_says_which_scanner_didnt_finish(self):   # replay
        self.scanners(skillspector=CRASH)
        code, o, err = self.vet()
        self.assertIn("Scanners that didn't finish: SkillSpector", o)          # bacd581: no scanner line
        self.assertTrue(o.startswith(f"Verdict: {NOT_FINISHED} "), o)
        self.assertEqual(code, 1)

    def test_deep_vet_without_scanners_says_so_in_text(self):   # replay
        code, o, err = self.vet()
        self.assertIn("No outside scanner is installed, so this vet used ISR Bot's own rules only.", o)   # bacd581: JSON only
        self.assertNotIn("Say so.", o)
        code, r = self.vet_json()
        self.assertEqual(r["engines"]["not_installed"], ["SkillSpector", "husk"])   # never there: not "didn't finish"
        self.assertEqual(r["engines"]["did_not_finish"], [])
        self.assertEqual(r["verdict"], "Install")

    def test_deep_vet_with_both_scanners_working_still_installs(self):   # guard
        self.scanners()
        code, r = self.vet_json()
        self.assertEqual(r["verdict"], "Install")
        self.assertEqual(code, 0)
        self.assertEqual(r["engines"]["ran"], ["SkillSpector", "husk"])
        self.assertEqual(r["engines"].get("did_not_finish", []), [])


class PartlyCheckedTruffleHog(v100._Partial):
    def test_a_partly_checked_trufflehog_is_not_counted(self):   # guard
        r = self.partial()
        self.assertEqual(self.snap()["stages_partial"], [v100.PARTIAL])
        self.assertTrue(tail(r).endswith(("tip", "tips")), r["score_line"])
        self.assertNotIn("checks_not_run", r)
        self.assertNotIn("checks_not_run", self.snap())


if __name__ == "__main__":
    unittest.main()
