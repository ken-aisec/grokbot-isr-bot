"""Item 8, Codex review 2 (on b8617aa): three highs and three mediums left in platform provenance.

1. high: the platform files were only what the scanner's inventory kept, so a baselined SKILL.md turned into a link into
   Watchtower's quarantine (a "not live" skill), a folder link, a loose script and a file under node_modules escaped the gate.
2. high: a plant whose finding was copied into last_findings.json in advance was never "new", and daily said NO_CHANGES.
3. high: a matching line in Bot-writable baseline.json skipped provenance, and `baseline --owner-said-yes` wrote such lines.
4. medium: approved files kept their slots in `fix`'s 200-file list, and refused ones starved the files after them.
5. medium: revet saved the digest it checked but made the approved copy from a second read.
6. medium: a platform name linked to the owner's own file raised a high nothing could approve.

Each test fails on b8617aa by reaching an assertion unless its docstring says it is a contrast.
"""
import json, os, sys, unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import wt  # noqa: E402
from test_item8_provenance import CLEAN, FLAGGED, ROOT, _Platform, add, put, sha  # noqa: E402
import profiles  # noqa: E402


class OwnWalk(_Platform):
    def assert_counted(self, p):
        x = self.counted_high(p)
        self.assertEqual(len(x), 1, [(f["rule"], f["severity"], f.get("class"), wt.counts(f)) for f in self.snap()["findings"] if f.get("unverified_platform")])
        self.assertTrue(x[0].get("unverified_platform"))

    def test_1_a_skill_turned_into_a_link_into_quarantine_is_held_to_the_list(self):
        self.start()
        p = self.md("alpha")
        q = os.path.join(wt.home(), "quarantine", "alpha", "SKILL.md")
        put(q, CLEAN.format(n="alpha") + "Planted where nothing scans.\n")
        os.remove(p)
        os.symlink(q, p)
        self.assertTrue(wt.platform_ish(p))
        out = self.daily()
        self.assertNotEqual(out, "NO_CHANGES")
        self.assert_counted(p)

    def test_1_a_folder_link_in_a_platform_folder_is_walked(self):
        self.start()
        outside = os.path.join(self.tmp, "elsewhere", "helper")
        put(os.path.join(outside, "SKILL.md"), CLEAN.format(n="helper"))
        os.symlink(outside, os.path.join(self.root, "helper"))
        self.assertNotEqual(self.daily(), "NO_CHANGES")
        self.assert_counted(self.md("helper"))

    def test_1_a_loose_script_and_a_node_modules_file_are_held_to_the_list(self):
        self.start()
        loose = os.path.join(self.home, ".grok", "bundled", "bin", "helper.sh")
        dep = os.path.join(self.root, "alpha", "node_modules", "left", "index.js")
        put(loose, "#!/bin/sh\necho hi\n")
        put(dep, "module.exports = 1;\n")
        self.assertNotEqual(self.daily(), "NO_CHANGES")
        self.assert_counted(loose)
        self.assert_counted(dep)

    def test_1_a_folder_too_big_to_walk_is_a_counted_alert(self):
        self.start()
        had = "PLATFORM_WALK_MAX_FILES" in vars(wt)
        was = getattr(wt, "PLATFORM_WALK_MAX_FILES", None)
        wt.PLATFORM_WALK_MAX_FILES = 2
        try:
            out = self.daily()
        finally:
            if had:
                wt.PLATFORM_WALK_MAX_FILES = was
            else:
                vars(wt).pop("PLATFORM_WALK_MAX_FILES", None)
        self.assertNotEqual(out, "NO_CHANGES")
        x = [f for f in self.snap()["findings"] if f["rule"] == "WT-I011"]
        self.assertEqual([(f["severity"], wt.counts(f)) for f in x], [("high", True)])
        self.assertIn("WT-I011", [r["rule"] for r in json.loads(out)["platform_unverified"]["files"]])

    def test_1_contrast_a_folder_link_loop_is_walked_once_and_stays_quiet(self):
        """Contrast: passes on base too."""
        os.symlink(self.root, os.path.join(self.root, "alpha", "loop"))
        self.start()
        self.assertFalse([f for f in self.snap()["findings"] if f["rule"] == "WT-I011"])
        self.assertEqual(self.daily(), "NO_CHANGES")


class DailyNeverQuiet(_Platform):
    def test_2_a_finding_copied_into_last_findings_never_silences_daily(self):
        self.start()
        plant = self.md("helper")
        put(plant, CLEAN.format(n="helper"))
        snap = self.snap()
        snap["findings"].append(wt.unverified_platform_finding(plant, sha(plant)))   # its deterministic finding and key, in advance
        wt.save_json(wt.state_path("last_findings.json"), snap)
        out = self.daily()
        self.assertNotEqual(out, "NO_CHANGES")
        d = json.loads(out)
        self.assertEqual(d["platform_unverified"]["open"], 1)
        self.assertEqual([r["where"] for r in d["platform_unverified"]["files"]], [plant])

    def test_2_yesterdays_alert_is_still_said_today(self):
        self.start()
        plant = self.md("helper")
        put(plant, CLEAN.format(n="helper"))
        self.assertNotEqual(self.daily(), "NO_CHANGES")
        out = self.daily()                                                      # nothing new since yesterday
        self.assertNotEqual(out, "NO_CHANGES")
        self.assertIn(plant, [r["where"] for r in json.loads(out)["platform_unverified"]["files"]])


class BaselineIsNotProvenance(_Platform):
    def test_3_a_forged_baseline_line_is_not_provenance(self):
        self.start()
        plant = self.md("helper")
        put(plant, CLEAN.format(n="helper"))
        base = wt.load_baseline()[0]
        base[plant] = sha(plant)
        wt.save_json(wt.state_path("baseline.json"), base)
        self.assertNotEqual(self.daily(), "NO_CHANGES")
        self.assertEqual(len(self.counted_high(plant)), 1)
        pv = self.preview()["platform_unverified"]
        self.assertEqual([f["where"] for f in pv["files"]], [plant])
        self.assertIn("platform-release.lock", self.approve("0" * 20))        # Ken's decision (Oct 18): no yes approves it
        self.audit()
        self.assertEqual(len(self.counted_high(plant)), 1)

    def test_3_a_blanket_baseline_yes_never_approves_a_platform_file(self):
        self.start()
        plant = self.md("helper")
        put(plant, CLEAN.format(n="helper"))
        alpha = self.md("alpha")
        was = wt.load_baseline()[0][alpha]
        add(alpha, "Changed, not on the release list.\n")
        out = self.run_cmd("baseline", "--roots", *self.roots, "--owner-said-yes")[1]
        base = wt.load_baseline()[0]
        self.assertNotIn(plant, base)
        self.assertEqual(base[alpha], was)                                      # keeps its line, so it still shows as changed
        self.assertIn("platform-release.lock", out)
        self.assertNotIn("--approve-platform", out)
        self.assertNotEqual(self.daily(), "NO_CHANGES")
        self.assertEqual(len(self.counted_high(plant)), 1)
        self.assertEqual(len(self.counted_high(alpha)), 1)

    def test_3_the_approval_binds_where_the_name_leads(self):
        self.start()
        p = self.md("alpha")
        with open(p) as f:
            body = f.read()
        same = os.path.join(self.tmp, "elsewhere", "alpha.md")
        put(same, body)                                                         # the very same bytes, somewhere else
        os.remove(p)
        os.symlink(same, p)
        self.assertEqual(sha(p), wt.load_baseline()[0][p])
        self.assertNotEqual(self.daily(), "NO_CHANGES")
        self.assertEqual(len(self.counted_high(p)), 1)


class Pages(_Platform):
    def forge(self, names, text=CLEAN):
        snap = self.snap()
        for n in names:
            p = self.md(n)
            put(p, text.format(n=n))
            snap["findings"].append(dict(wt.unverified_platform_finding(p, "0" * 64), key=sha(p)[:16]))
        wt.save_json(wt.state_path("last_findings.json"), snap)

    def test_4_the_list_is_the_exact_count_with_no_code_or_pages(self):
        self.start()
        n = wt.PLATFORM_OPEN_SHOWN + 1
        self.forge([f"p{i:04d}" for i in range(n)])
        pv = self.preview()["platform_unverified"]
        self.assertEqual((pv["open"], len(pv["files"]), pv.get("more")), (n, n - 1, 1))
        self.assertFalse({"code", "next_page"} & set(pv), pv)
        self.assertIn("platform-release.lock", self.approve("0" * 20))
        pv2 = self.preview()["platform_unverified"]
        self.assertEqual(pv2, pv)                                               # nothing left the list
        self.assertIn("platform-release.lock", self.approve("0" * 20))

    def test_4_no_page_or_code_approves_anything(self):
        self.start()
        self.forge([f"a{i:04d}" for i in range(wt.PLATFORM_OPEN_SHOWN)], text=FLAGGED)
        self.forge(["zz-clean"])
        pv = self.preview()["platform_unverified"]
        self.assertNotIn("next_page", pv)
        nxt = self.md("a0049").encode().hex()                                   # what a page cursor used to look like
        out = self.run_cmd("fix", "--platform-from", nxt, "--roots", *self.roots)[1]
        self.assertIn("platform-release.lock", out)
        self.assertIn("NOT APPROVED", self.approve("0" * 20))
        out = self.run_cmd("fix", "--approve-platform", "0" * 20, "--platform-from", nxt, "--owner-said-yes", "--roots", *self.roots)[1]
        self.assertIn("platform-release.lock", out)
        self.assertNotIn(self.md("zz-clean"), wt.load_baseline()[0])
        self.audit()
        self.assertEqual(len(self.counted_high(self.md("zz-clean"))), 1)


class ApprovedCopyOneRead(_Platform):
    def test_5_the_approved_copy_is_the_bytes_that_were_checked(self):
        self.start()
        p = self.md("alpha")
        add(p, "Version 2.\n")
        v2 = sha(p)
        profiles.vendor_release(self, p)
        real, swapped = wt.platform_listed, []

        def listed_then_swap(q, h):
            ok = real(q, h)
            if ok and q == p and not swapped:                                   # version 3, unlisted, right after the check
                add(p, "Swapped in after the check.\n")
                swapped.append(q)
            return ok
        wt.platform_listed = listed_then_swap
        try:
            r = wt.revet([os.path.dirname(p)], approve=True)
        finally:
            wt.platform_listed = real
        self.assertEqual([x["result"] for x in r], ["re-approved"], r)
        self.assertEqual(wt.load_baseline()[0][p], v2)
        copy = wt.load_approved(os.path.dirname(p))
        self.assertEqual(copy["hashes"]["SKILL.md"], v2)
        self.assertNotIn("Swapped in", copy["files"]["SKILL.md"])
        d = wt.skill_diff(os.path.dirname(p))
        self.assertNotEqual(d["summary"], "same as the approved copy")
        self.assertIn("Swapped in after the check", d["text"])


class LinkToTheOwnersFile(_Platform):
    def layout(self):
        own = os.path.join(self.home, "sand-data", "workflows", "helper", "SKILL.md")
        put(own, CLEAN.format(n="helper"))
        plat = self.md("helper")
        os.makedirs(os.path.dirname(plat))
        os.symlink(own, plat)
        self.start()
        add(own, "Changed through the link.\n")
        self.audit()
        self.assertEqual(len(self.counted_high(plat)), 1)
        return own, plat

    def test_6_a_platform_link_to_the_owners_file_stays_high(self):
        own, plat = self.layout()
        pv = self.preview()["platform_unverified"]
        self.assertIn(plat, [f["where"] for f in pv["files"]], pv)
        self.assertIn("platform-release.lock", self.approve("0" * 20))        # Ken's decision (Oct 18): no yes approves it
        self.audit()
        self.assertEqual(len(self.counted_high(plat)), 1)
        add(own, "Changed again.\n")                                            # other bytes: a new alert
        self.audit()
        self.assertEqual(len(self.counted_high(plat)), 1)

    def test_6_a_link_moved_at_any_time_grants_nothing(self):
        own, plat = self.layout()
        other = os.path.join(self.tmp, "elsewhere", "other.md")
        put(other, CLEAN.format(n="other"))
        os.remove(plat)
        os.symlink(other, plat)
        self.audit()
        pv = self.preview()["platform_unverified"]
        self.assertIn(plat, [f["where"] for f in pv["files"]])
        self.assertIn("platform-release.lock", self.approve("0" * 20))
        self.audit()
        self.assertEqual(len(self.counted_high(plat)), 1)


class Docs(unittest.TestCase):
    def read(self, rel):
        with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
            return f.read()

    def test_the_docs_name_round_2(self):
        unreleased = self.read("CHANGELOG.md").split("\n## v")[0]
        line = [l for l in unreleased.splitlines() if "Codex review, round 2" in l and "Item 8" in l]
        self.assertEqual(len(line), 1)
        for word in ("platform_approved.json", "--platform-from", "WT-I011", "Known gaps"):
            self.assertIn(word, line[0])
        self.assertIn("--platform-from", self.read("skills/watchtower-fix/SKILL.md"))
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
