"""Item 8, Codex review 2 (on b8617aa): three highs and three mediums left in platform provenance.

1. high: the platform files were only what the scanner's inventory kept, so a baselined SKILL.md turned into a link into
   ISR Bot's quarantine (a "not live" skill), a folder link, a loose script and a file under node_modules escaped the gate.
2. high: a plant whose finding was copied into last_findings.json in advance was never "new", and daily said NO_CHANGES.
3. high: a matching line in Bot-writable baseline.json skipped provenance, and `baseline --owner-said-yes` wrote such lines.
4. medium: approved files kept their slots in `fix`'s 200-file list, and refused ones starved the files after them.
5. medium: revet saved the digest it checked but made the approved copy from a second read.
6. medium: a platform name linked to the owner's own file raised a high nothing could approve.

Each test fails on b8617aa by reaching an assertion unless its docstring says it is a contrast.
"""
import json, os, sys, unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_boxes  # noqa: E402
import isr  # noqa: E402
from test_item8_provenance import CLEAN, FLAGGED, NOTHING, ROOT, _Platform, add, put, sha  # noqa: E402
import profiles  # noqa: E402
import rename_v080 as rn  # noqa: E402


def forged(p, key=None):
    """v0.8.1: a v0.8.0-shaped unverified platform finding, built with finding() (unverified_platform_finding goes in U7a)."""
    f = dict(isr.finding("ISR-I002", "forged", "high", ["AST09"], p, "0" * 12, "x"), unverified_platform=True)
    return dict(f, key=key) if key else f


class _Quiet(_Platform):
    def setUp(self):
        super().setUp()
        self.owned()

    def assert_quiet(self, p):
        """v0.8.1: no drift row at p, and no unverified platform finding anywhere (it replaces assert_counted)."""
        self.assertEqual(self.drift(p), [], p)
        self.assertFalse([f for f in self.fs() + self.vs() if f.get("unverified_platform")])


class OwnWalk(_Quiet):
    def test_1_a_skill_turned_into_a_link_into_quarantine_is_held_to_the_list(self):
        """v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only. The link leads
        into quarantine (the owner's), so it is the owner's file: a new one (PLAN §8 E3 expected nothing; the walk finds it)."""
        self.start()
        p = self.md("alpha")
        q = os.path.join(isr.home(), "quarantine", "alpha", "SKILL.md")
        put(q, CLEAN.format(n="alpha") + "Planted where nothing scans.\n")
        os.remove(p)
        os.symlink(q, p)
        self.assertTrue(isr.platform_ish(p))
        out = self.daily()
        self.assertNotEqual(out, "NO_CHANGES")
        self.assertEqual(isr.owner_of(p), "user")
        self.assertEqual(self.ints(p), [("ISR-I002", "low")])

    def test_1_a_folder_link_in_a_platform_folder_is_walked(self):
        """v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        self.start()
        outside = os.path.join(self.tmp, "elsewhere", "helper")
        put(os.path.join(outside, "SKILL.md"), CLEAN.format(n="helper"))
        os.symlink(outside, os.path.join(self.root, "helper"))
        self.assertNotEqual(self.daily(), "NO_CHANGES")
        self.assertEqual(isr.owner_of(self.md("helper")), "user")
        self.assertEqual(self.ints(self.md("helper")), [("ISR-I002", "low")])

    def test_1_a_loose_script_and_a_node_modules_file_are_held_to_the_list(self):
        """v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        self.start()
        loose = os.path.join(self.home, ".grok", "bundled", "bin", "helper.sh")
        dep = os.path.join(self.root, "alpha", "node_modules", "left", "index.js")
        put(loose, "#!/bin/sh\necho hi\n")
        put(dep, "module.exports = 1;\n")
        self.assertEqual(self.daily(), "NO_CHANGES")
        self.assert_quiet(loose)
        self.assert_quiet(dep)
        us = os.path.join(os.path.dirname(self.own), "bin", "helper.sh")
        put(us, "#!/bin/sh\necho hi\n")
        self.assertNotEqual(self.daily(), "NO_CHANGES")
        self.assertEqual(self.ints(us), [("ISR-I002", "low")])

    def test_1_a_folder_too_big_to_walk_is_a_counted_alert(self):
        """v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        self.start()
        had = "PLATFORM_WALK_MAX_FILES" in vars(isr)
        was = getattr(isr, "PLATFORM_WALK_MAX_FILES", None)
        isr.PLATFORM_WALK_MAX_FILES = 2
        try:
            out = self.daily()
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
        self.assertNotIn("platform_unverified", out)

    def test_1_contrast_a_folder_link_loop_is_walked_once_and_stays_quiet(self):
        """Contrast: passes on base too."""
        os.symlink(self.root, os.path.join(self.root, "alpha", "loop"))
        self.start()
        self.assertFalse([f for f in self.snap()["findings"] if f["rule"] == "ISR-I011"])
        self.assertEqual(self.daily(), "NO_CHANGES")


class DailyNeverQuiet(_Quiet):
    def test_2_a_finding_copied_into_last_findings_never_silences_daily(self):
        """v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        self.start()
        plant = self.loose()
        put(plant, CLEAN.format(n="helper"))
        snap = self.snap()
        snap["findings"].append(forged(plant))                                  # a v0.8.0 finding for it, in advance
        isr.save_json(isr.state_path("last_findings.json"), snap)
        out = self.daily()
        self.assertNotIn("platform_unverified", out)
        self.assertEqual(self.drift(plant), [])
        self.assertFalse([f for f in self.fs() if f.get("unverified_platform")])

    def test_2_yesterdays_alert_is_still_said_today(self):
        """v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        self.start()
        plant = self.loose()
        put(plant, CLEAN.format(n="helper"))
        self.assertEqual(self.daily(), "NO_CHANGES")
        out = self.daily()                                                      # nothing new since yesterday
        self.assertEqual(out, "NO_CHANGES")
        self.assertNotIn(plant, out)


class BaselineIsNotProvenance(_Quiet):
    def test_3_a_forged_baseline_line_is_not_provenance(self):
        """b8i4 (decision, Oct 22): a baseline line makes a path "already existing", so a forged one plus clean bytes in a
        platform skill folder is the middle path's quiet case (an accepted limit: the baseline is Bot-writable); no yes
        approves anything.
        v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        self.start()
        plant = self.md("helper")
        put(plant, CLEAN.format(n="helper"))
        base = isr.load_baseline()[0]
        base[plant] = sha(plant)
        isr.save_json(isr.state_path("baseline.json"), base)
        self.assertEqual(self.daily(), "NO_CHANGES")
        self.assertEqual(len(self.counted_high(plant)), 0)
        self.assertNotIn("platform_unverified", self.preview())
        self.assertIn(NOTHING, self.approve("0" * 20))                        # Decision, Oct 18: no yes approves it
        self.audit()
        self.assertEqual(len(self.counted_high(plant)), 0)

    def test_3_a_blanket_baseline_yes_never_approves_a_platform_file(self):
        """b8i4: alpha's clean update at its listed path is the quiet line in daily; the loose plant stays a counted high.
        v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        self.start()
        plant = self.loose()
        put(plant, CLEAN.format(n="helper"))
        alpha = self.md("alpha")
        was = isr.load_baseline()[0].get(alpha)
        add(alpha, "Changed, not on the release list.\n")
        add(self.own, "x\n")
        out = self.run_cmd("baseline", "--roots", *self.roots, "--owner-said-yes")[1]
        base = isr.load_baseline()[0]
        self.assertNotIn(plant, base)
        self.assertNotIn(alpha, base, was)                                      # no platform line is kept or written
        self.assertNotIn("Not approved by this", out)
        self.assertNotIn("--approve-platform", out)
        self.assertEqual(self.daily(), "NO_CHANGES")
        self.assertEqual(self.drift(plant), [])
        self.assertEqual(len(self.counted_high(alpha)), 0)
        self.assertEqual(base[self.own], sha(self.own))                         # the owner's change is approved by the yes

    def test_3_the_approval_binds_where_the_name_leads(self):
        """v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only. The name leads
        outside every platform folder, so it is the owner's file: a new one."""
        self.start()
        p = self.md("alpha")
        with open(p) as f:
            body = f.read()
        same = os.path.join(self.tmp, "elsewhere", "alpha.md")
        put(same, body)                                                         # the very same bytes, somewhere else
        os.remove(p)
        os.symlink(same, p)
        self.assertNotIn(p, isr.load_baseline()[0])
        self.assertNotEqual(self.daily(), "NO_CHANGES")
        self.assertEqual([f["rule"] for f in self.at(p) if f["rule"] in ("ISR-I001", "ISR-I002")], ["ISR-I002"])


class Pages(_Quiet):
    def forge(self, names, text=CLEAN, at=None):
        snap = self.snap()
        for n in names:
            p = (at or self.md)(n)
            put(p, text.format(n=n))
            snap["findings"].append(forged(p, key=sha(p)[:16]))
        isr.save_json(isr.state_path("last_findings.json"), snap)

    def test_4_the_list_is_the_exact_count_with_no_code_or_pages(self):
        """v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        self.start()
        n = isr.PLATFORM_OPEN_SHOWN + 1
        self.forge([f"p{i:04d}" for i in range(n)])
        pv = self.preview()
        self.assertNotIn("platform_unverified", pv)
        self.assertFalse({"code", "next_page"} & set(pv), pv)
        self.assertIn(NOTHING, self.approve("0" * 20))
        pv2 = self.preview()
        self.assertEqual(pv2, pv)                                               # nothing left the list
        self.assertIn(NOTHING, self.approve("0" * 20))

    def test_4_no_page_or_code_approves_anything(self):
        """v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        self.start()
        self.forge([f"a{i:04d}" for i in range(isr.PLATFORM_OPEN_SHOWN)], text=FLAGGED)
        self.forge(["zz-clean"], at=self.loose)                                 # b8i4: loose, so never the middle path's quiet line
        pv = self.preview()
        self.assertNotIn("next_page", pv)
        nxt = self.md("a0049").encode().hex()                                   # what a page cursor used to look like
        out = self.run_cmd("fix", "--platform-from", nxt, "--roots", *self.roots)[1]
        self.assertNotIn("platform-release.lock", out)
        self.assertIn("NOT APPROVED", self.approve("0" * 20))
        out = self.run_cmd("fix", "--approve-platform", "0" * 20, "--platform-from", nxt, "--owner-said-yes", "--roots", *self.roots)[1]
        self.assertIn(NOTHING, out)
        self.assertNotIn(self.loose("zz-clean"), isr.load_baseline()[0])
        add(self.own, "x\n")
        self.audit()
        self.assertEqual(self.drift(self.loose("zz-clean")), [])
        self.assertEqual(len(self.counted_high(self.own)), 1)


class ApprovedCopyOneRead(_Quiet):
    def test_5_the_approved_copy_is_the_bytes_that_were_checked(self):
        """v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only. revet keeps no
        copy or fingerprint of a platform folder; the owner's skill's copy is the bytes that were checked."""
        self.start()
        p = self.md("alpha")
        add(p, "Version 2.\n")
        v2 = sha(p)
        profiles.vendor_release(self, p)
        real, swapped = isr.platform_listed, []

        def listed_then_swap(q, h):
            ok = real(q, h)
            if ok and q == p and not swapped:                                   # version 3, unlisted, right after the check
                add(p, "Swapped in after the check.\n")
                swapped.append(q)
            return ok
        isr.platform_listed = listed_then_swap
        try:
            r = isr.revet([os.path.dirname(p)], approve=True)
        finally:
            isr.platform_listed = real
        self.assertEqual(swapped, [], r)
        self.assertNotIn(p, isr.load_baseline()[0], v2)
        self.assertIsNone(isr.load_approved(os.path.dirname(p)))
        own = self.own                                                          # the same swap, through the one read of the owner's skill
        add(own, "Version 2.\n")
        uv2 = sha(own)
        real_read, sw = isr.read_snapshot, []

        def read_then_swap(q, *a, **k):
            s = real_read(q, *a, **k)
            if q == own and not sw:                                             # version 3, right after the read
                add(own, "Swapped in after the check.\n")
                sw.append(q)
            return s
        isr.read_snapshot = read_then_swap
        try:
            r = isr.revet([os.path.dirname(own)], approve=True)
        finally:
            isr.read_snapshot = real_read
        self.assertEqual(sw, [own], r)
        self.assertEqual([x["result"] for x in r], ["re-approved"], r)
        self.assertEqual(isr.load_baseline()[0][own], uv2)
        copy = isr.load_approved(os.path.dirname(own))
        self.assertEqual(copy["hashes"]["SKILL.md"], uv2)
        self.assertNotIn("Swapped in", copy["files"]["SKILL.md"])
        d = isr.skill_diff(os.path.dirname(own))
        self.assertNotEqual(d["summary"], "same as the approved copy")
        self.assertIn("Swapped in after the check", d["text"])


class LinkToTheOwnersFile(_Quiet):
    def counted(self, own, plat):
        """The owner's counted highs on the file: the inventory keeps one name per real file, here the platform name."""
        return self.counted_high(own) + self.counted_high(plat)

    def layout(self):
        own = os.path.join(self.home, "sand-data", "workflows", "helper", "SKILL.md")
        put(own, CLEAN.format(n="helper"))
        plat = self.md("helper")
        os.makedirs(os.path.dirname(plat))
        os.symlink(own, plat)
        self.start()
        add(own, "Changed through the link.\n")
        self.audit()
        self.assertEqual(len(self.counted(own, plat)), 1)
        self.assertEqual(isr.owner_of(plat), "user")
        return own, plat

    def test_6_a_platform_link_to_the_owners_file_stays_high(self):
        """v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        own, plat = self.layout()
        self.assertNotIn("platform_unverified", self.preview())
        self.assertEqual(self.vend(plat), [])
        self.assertIn(NOTHING, self.approve("0" * 20))                        # Decision, Oct 18: no yes approves it
        self.audit()
        self.assertEqual(len(self.counted(own, plat)), 1)
        add(own, "Changed again.\n")                                            # other bytes: a new alert
        self.audit()
        self.assertEqual(len(self.counted(own, plat)), 1)

    def test_6_a_link_moved_at_any_time_grants_nothing(self):
        """v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        own, plat = self.layout()
        other = os.path.join(self.tmp, "elsewhere", "other.md")
        put(other, CLEAN.format(n="other"))
        os.remove(plat)
        os.symlink(other, plat)
        self.audit()
        self.assertNotIn("platform_unverified", self.preview())
        self.assertEqual(self.vend(plat), [])
        self.assertIn(NOTHING, self.approve("0" * 20))
        self.audit()
        self.assertEqual(len(self.counted(own, plat)), 1)


class Docs(unittest.TestCase):
    def read(self, rel):
        with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
            return f.read()

    def test_the_docs_name_round_2(self):
        unreleased = self.read("CHANGELOG.md").split("\n## v")[0]
        line = [l for l in unreleased.splitlines() if "Codex review, round 2" in l and "Item 8" in l]
        self.assertEqual(len(line), 1)
        for word in ("platform_approved.json", "--platform-from", rn.old_rule("ISR-I011"), "Known gaps"):   # v0.8.0 h2: the old ID
            self.assertIn(word, line[0])
        self.assertIn("--platform-from", self.read("skills/isr-bot-fix/SKILL.md"))
        self.assertIn("platform_unverified", self.read("routines/daily-watch.md"))

    def test_contrasts_are_marked(self):
        """Contrast: passes on base too (a check on this file's own labels)."""
        import inspect
        for name, obj in list(globals().items()):
            if isinstance(obj, type) and issubclass(obj, unittest.TestCase):
                for m in [m for m in dir(obj) if m.startswith("test_") and "_contrast" in m]:
                    self.assertIn("Contrast", inspect.getdoc(getattr(obj, m)) or "", f"{name}.{m}")


if __name__ == "__main__":
    unittest.main()
