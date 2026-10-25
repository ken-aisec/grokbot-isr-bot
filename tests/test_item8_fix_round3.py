"""Item 8, Codex review 3 (on 9356f16): three highs and a medium left in platform provenance.

1. high: a requested root inside a platform folder (--roots ~/.grok/bundled/bin, ~/.grok/bundled/skills) got no walk of its
   own, so a loose script or a file the scanner's inventory skips raised nothing.
2. high: an empty baseline.json plus a baseline_meta.json saying "files": 0 was a first run even with years of history, and the
   first baseline vouched for every unlisted platform file.
3. high: a Bot-written platform_approved.json entry with a plant's path, target and digest was provenance on its own.
4. medium: `baseline --owner-said-yes` kept a refused platform file at its old line but copied its new bytes as the approved copy.

Each test fails on c2982f8 by reaching an assertion unless its docstring says it is a contrast.
"""
import os, sys, unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_boxes  # noqa: E402
import isr  # noqa: E402
from test_item8_provenance import CLEAN, NOTHING, ROOT, _Platform, add, put, sha  # noqa: E402


class _Owned(_Platform):
    def setUp(self):
        super().setUp()
        self.owned()


class RootsInsidePlatformFolders(_Owned):
    def daily_in(self, *roots):
        return self.run_cmd("daily", "--roots", *roots)[1].strip()

    def assert_quiet(self, p):
        """v0.8.1: no drift row at p, and no unverified platform finding anywhere (it replaces assert_counted)."""
        self.assertEqual(self.drift(p), [], p)
        self.assertFalse([f for f in self.fs() + self.vs() if f.get("unverified_platform")])

    def owners_control(self):
        """The owner's new file, in a root of the owner's: said in daily, the new-file low."""
        u = self.user("helper")
        put(u, "#!/bin/sh\necho hi\n")
        self.assertNotEqual(self.daily_in(os.path.join(self.home, "sand-data", "workflows")), "NO_CHANGES")
        self.assertEqual(self.ints(u), [("ISR-I002", "low")])

    def test_1_a_root_inside_a_platform_folder_is_walked(self):
        """v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        self.start()
        bin_ = os.path.join(self.home, ".grok", "bundled", "bin")
        loose = os.path.join(bin_, "helper.sh")
        put(loose, "#!/bin/sh\necho hi\n")
        self.assertEqual(self.daily_in(bin_), "NO_CHANGES")
        self.assert_quiet(loose)
        self.owners_control()

    def test_1_a_skills_root_walks_what_the_scanners_inventory_skips(self):
        """v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        self.start()
        dep = os.path.join(self.root, "alpha", "node_modules", "left", "index.js")
        put(dep, "module.exports = 1;\n")
        self.assertEqual(self.daily_in(self.root), "NO_CHANGES")
        self.assert_quiet(dep)

    def test_1_a_root_inside_a_platform_folder_it_cant_finish_is_a_counted_alert(self):
        """v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        self.start()
        had = "PLATFORM_WALK_MAX_FILES" in vars(isr)
        was = getattr(isr, "PLATFORM_WALK_MAX_FILES", None)
        isr.PLATFORM_WALK_MAX_FILES = 2
        try:
            out = self.daily_in(self.root)
        finally:
            if had:
                isr.PLATFORM_WALK_MAX_FILES = was
            else:
                vars(isr).pop("PLATFORM_WALK_MAX_FILES", None)
        self.assertEqual(out, "NO_CHANGES")
        # U7a deletes platform_coverage_finding: then x is read from fs() + vs(), as PLAN §5b says. Until then it is a vendor record.
        x = [f for f in self.fs() if f["rule"] == "ISR-I011"]
        self.assertEqual(x, [])
        self.assertFalse([f for f in self.vs() if f["rule"] == "ISR-I011" and isr.counts(f)])

    def test_1_contrast_a_root_inside_one_already_walked_is_walked_once(self):
        """Contrast: passes on base too.
        v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        self.start()
        bin_ = os.path.join(self.home, ".grok", "bundled", "bin")
        loose = os.path.join(bin_, "helper.sh")
        put(loose, "#!/bin/sh\necho hi\n")
        self.assertEqual(self.daily_in(*self.roots, bin_), "NO_CHANGES")
        self.assert_quiet(loose)
        self.owners_control()


class FirstRunWithHistory(_Owned):
    def empty_it(self):
        isr.save_json(isr.state_path("baseline.json"), {})
        isr.save_json(isr.state_path(isr.BASELINE_META), {"first_at": "2026-01-01T00:00:00", "at": "2026-01-01T00:00:00", "files": 0})
        self.assertEqual(isr.load_baseline()[1], "first")

    def test_2_an_emptied_baseline_on_a_box_with_history_vouches_for_no_platform_file(self):
        """v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        self.start()
        plant = self.md("helper")
        put(plant, CLEAN.format(n="helper"))
        u = self.user("helper")
        put(u, CLEAN.format(n="helper"))
        self.empty_it()
        self.assertEqual(self.daily(), "NO_CHANGES")
        self.assertEqual(self.drift(plant), [])
        self.assertFalse(os.path.lexists(isr.state_path("platform_approved.json")))   # nothing writes a platform record now
        self.assertNotIn(plant, isr.load_baseline()[0])
        self.audit()                                                            # and it stays out after the new first baseline
        self.assertEqual(self.drift(plant), [])
        self.assertEqual(isr.load_baseline()[0].get(u), sha(u))

    def test_2_the_first_baseline_command_on_such_a_box_holds_the_plant(self):
        """v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        self.start()
        plant = self.md("helper")
        put(plant, CLEAN.format(n="helper"))
        u = self.user("helper")
        put(u, CLEAN.format(n="helper"))
        self.empty_it()
        out = self.run_cmd("baseline", "--roots", *self.roots)[1]
        self.assertNotIn("Not approved by this", out)
        self.assertFalse(os.path.lexists(isr.state_path("platform_approved.json")))   # nothing writes a platform record now
        self.audit()
        self.assertEqual(self.drift(plant), [])
        self.assertIn(u, isr.load_baseline()[0])

    def test_2_contrast_a_brand_new_box_still_takes_its_first_baseline_quietly(self):
        """Contrast: passes on base too."""
        self.start()
        self.assertFalse([f for f in self.snap()["findings"] if f.get("unverified_platform")])
        self.assertEqual(self.daily(), "NO_CHANGES")


class ForgedApprovalRecord(_Owned):
    def forge(self, p):
        path = isr.state_path("platform_approved.json")                         # the record earlier versions wrote
        d = isr.load_json(path, None) or {"v": 1, "files": {}}
        d["files"][p] = {"sha256": sha(p), "target": os.path.realpath(p)}
        isr.save_json(path, d)

    def test_3_a_forged_record_alone_is_not_provenance(self):
        """v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        self.start()
        plant = self.loose()
        put(plant, CLEAN.format(n="helper"))
        self.forge(plant)
        self.assertEqual(self.daily(), "NO_CHANGES")
        self.assertEqual(self.drift(plant), [])
        u = self.user("helper")
        put(u, CLEAN.format(n="helper"))
        self.forge(u)
        self.assertNotEqual(self.daily(), "NO_CHANGES")
        self.assertEqual(self.ints(u), [("ISR-I002", "low")])

    def test_3_a_record_rewritten_to_new_bytes_after_a_real_yes_is_not_provenance(self):
        """v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        self.start()
        plant = self.loose()
        put(plant, CLEAN.format(n="helper"))
        self.audit()
        self.assertIn(NOTHING, self.approve("0" * 20))                        # Decision, Oct 18: the yes is refused
        add(plant, "Changed after the yes.\n")
        self.forge(plant)
        self.assertEqual(self.daily(), "NO_CHANGES")
        self.assertEqual(self.drift(plant), [])
        add(self.own, "x\n")
        self.forge(self.own)
        self.assertNotEqual(self.daily(), "NO_CHANGES")
        self.assertEqual(len(self.counted_high(self.own)), 1)

    def test_3_the_owners_yes_is_not_provenance(self):
        """Was a contrast (the owner's yes was provenance); decision, Oct 18: it is refused.
        v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        self.start()
        plant = self.loose()
        put(plant, CLEAN.format(n="helper"))
        self.audit()
        self.assertIn(NOTHING, self.approve("0" * 20))
        self.audit()
        self.assertEqual(self.drift(plant), [])
        self.assertEqual(self.daily(), "NO_CHANGES")
        add(self.own, "x\n")
        self.assertNotEqual(self.daily(), "NO_CHANGES")
        self.assertEqual(len(self.counted_high(self.own)), 1)


class BlanketBaselineKeepsCopies(_Owned):
    def test_4_a_refused_platform_file_keeps_its_approved_copy(self):
        """v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only. No approved copy
        is kept for a platform folder."""
        self.start()
        alpha = self.md("alpha")
        add(alpha, "Changed, not on the release list.\n")
        out = self.run_cmd("baseline", "--roots", *self.roots, "--owner-said-yes")[1]
        self.assertNotIn("Not approved by this", out)
        self.assertIsNone(isr.load_approved(os.path.dirname(alpha)))
        self.assertEqual(self.drift(alpha), [])

    def test_4_contrast_the_owners_own_change_is_copied_by_the_yes(self):
        """Contrast: passes on base too."""
        self.start()
        own = os.path.join(self.home, "sand-data", "workflows", "skill000")
        add(os.path.join(own, "SKILL.md"), "The owner's own change.\n")
        self.assertNotEqual(isr.skill_diff(own)["summary"], "same as the approved copy")
        self.run_cmd("baseline", "--roots", *self.roots, "--owner-said-yes")
        self.assertEqual(isr.skill_diff(own)["summary"], "same as the approved copy")


class Docs(unittest.TestCase):
    def read(self, rel):
        with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
            return f.read()

    def test_the_docs_name_round_3(self):
        unreleased = self.read("CHANGELOG.md").split("\n## v")[0]
        line = [l for l in unreleased.splitlines() if "Codex review, round 3" in l and "Item 8" in l]
        self.assertEqual(len(line), 1)
        for word in ("--roots", "platform_approved.json", "ledger", '"files": 0', "approved copy", "Known gaps"):
            self.assertIn(word, line[0])

    def test_contrasts_are_marked(self):
        """Contrast: passes on base too (a check on this file's own labels)."""
        import inspect
        for name, obj in list(globals().items()):
            if isinstance(obj, type) and issubclass(obj, unittest.TestCase):
                for m in [m for m in dir(obj) if m.startswith("test_") and "_contrast" in m]:
                    self.assertIn("Contrast", inspect.getdoc(getattr(obj, m)) or "", f"{name}.{m}")


if __name__ == "__main__":
    unittest.main()
