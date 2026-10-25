"""b8i4 fix round 3: the Codex verify of d2d24e5 (fix round 2), 2 high, and the owner's decision on daily (Oct 23).

1. A quiet platform update whose real-path check failed after settlement (a platform folder moved out and replaced by a link
   between settlement and the roll) wasn't rolled, but it stayed the info Platform refresh line, with no counted high. Every run
   checks each quiet update again before the roll's gate (hold_unbound_updates), and roll_builtin checks it once more before it
   writes the baseline; one that fails is a counted high, with every place a merged finding names, and keeps its old hash.
2. A grouped result saved before fix round 2 (gitleaks's ISR-S002 on a folder, without `affected_files`), carried by a daily or by
   an audit whose gitleaks failed, held no file. A grouped result that doesn't name all its files holds every candidate under its
   folder until a scan that finishes gives the files again (coverage_gaps).
3. Daily on a box with a missing scanner prints what f7c28e6 printed again (fix round 2's scanner-alert change undone).

Each test marked R in its docstring fails on d2d24e5's sources (the changed engine files stashed) at an assertion; G
is a guard (a contrast) that passes there and here.
"""
import json, os, sys, unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import CRASH  # noqa: E402
import isr  # noqa: E402
from test_item8_provenance import CLEAN, FLAGGED, add, put, sha  # noqa: E402
from test_b8i4_middle_path import _Middle  # noqa: E402
from test_b8i4_fix_round1 import NEEDLE, leaks_in  # noqa: E402
import profiles  # noqa: E402

MISSING = "SCANNERS_MISSING {}: run `bash /workspace/isr-bot/app/scripts/install.sh --scanners`, then `isr.py daily` again"


class LateRedirect(_Middle):
    """Codex 1: a binding that failed after settlement left the update the quiet Platform refresh line."""

    def redirect(self, d):
        """Move the platform folder d outside every platform folder and leave a link to it in its place (its bytes kept)."""
        if not os.path.islink(d):
            out = os.path.join(self.tmp, "outside", os.path.basename(d))
            os.makedirs(os.path.dirname(out), exist_ok=True)
            os.rename(d, out)
            os.symlink(out, d)

    def moved_first(self, name, d):
        """Patch isr.py's `name` (one namespace for every part) so the folder d is redirected just before it runs."""
        real = getattr(isr, name)

        def wrapped(*a, **k):
            self.redirect(d)
            return real(*a, **k)
        return mock.patch.object(isr, name, wrapped)

    def bundled(self):
        return os.path.join(self.home, ".grok", "bundled")

    def assert_held(self, *pv):
        """v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only. Once its folder
        leads outside every platform folder, the file is the owner's: the next audit shows it as a new one (low), never rolled in."""
        self.audit()
        for p, v1 in pv:
            x = [f for f in self.fs() if f["where"] == p and f["rule"] in ("ISR-I001", "ISR-I002")]
            self.assertEqual([(f["rule"], f["severity"]) for f in x], [("ISR-I002", "low")],
                             [(f["rule"], f["severity"], f["where"]) for f in self.snap()["findings"]])
            self.assertEqual(x[0]["title"], "New skill or plugin file")
            self.assertFalse([f for f in self.tip() if self.rel(p) in f.get("files", [])], self.tip())
            self.assertNotIn(p, isr.load_baseline()[0])

    def test_a_redirect_just_before_the_roll_is_a_counted_high(self):
        """R: alpha's clean update, and .grok/bundled redirected after settlement, just before roll_builtin: a counted high, no
        Platform refresh entry for it, and the old baseline hash (d2d24e5: not rolled, but the quiet refresh line).
        v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        self.start()
        v1 = sha(self.md("alpha"))
        add(self.md("alpha"), "One more line.\n")
        with self.moved_first("roll_builtin", self.bundled()):
            self.audit()
        self.assertTrue(os.path.islink(self.bundled()))
        self.assert_held((self.md("alpha"), v1))

    def test_a_redirect_right_after_settlement_is_a_counted_high(self):
        """R: the same, redirected right after settlement (as audit() merges the managed-skills mirrors), in a full audit and in a
        daily: a counted high both times, never the refresh line (d2d24e5: the quiet line, and daily said NO_CHANGES).
        v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only. The mirror merge
        is gone with the release list, so the folder is redirected as the scanner check runs."""
        self.start()
        v1 = sha(self.md("alpha"))
        add(self.md("alpha"), "One more line.\n")
        with self.moved_first("scanner_x005", self.bundled()):
            self.assertNotIn("platform_unverified", self.daily())
        self.assert_held((self.md("alpha"), v1))
        os.remove(self.bundled())
        os.rename(os.path.join(self.tmp, "outside", "bundled"), self.bundled())   # back where it was
        with self.moved_first("scanner_x005", self.bundled()):
            self.audit()
        self.assert_held((self.md("alpha"), v1))

    def test_a_merged_mirror_with_one_place_moved_is_held_at_both(self):
        """R: the same clean update at sand-data's and agent-data's managed skills (one merged finding, also_at), and agent-data's
        managed-skills folder redirected just before the roll: both places are held, one counted high (the mirror fold: the
        sand-data place, naming the agent-data one in also_at), neither is in the refresh line, and both keep their old hashes
        (d2d24e5: the quiet line naming both).
        v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only. The moved
        agent-data place leads outside, so it is the owner's new file; the sand-data place stays the platform's."""
        s = os.path.join(self.home, "sand-data", "managed-skills", "x", "SKILL.md")
        g = os.path.join(self.home, "agent-data", "managed-skills", "x", "SKILL.md")
        put(s, CLEAN.format(n="x")); put(g, CLEAN.format(n="x"))
        profiles.vendor_release(self, s, g)
        self.start()
        v1 = sha(s)
        for p in (s, g):
            add(p, "One more line.\n")
        with self.moved_first("roll_builtin", os.path.join(self.home, "agent-data", "managed-skills")):
            self.audit()
        self.assert_held((g, v1))
        self.assertEqual(self.drift(s), [])
        self.assertFalse([f for f in self.tip() if self.rel(g) in f.get("files", [])], self.tip())
        self.assertNotIn(s, isr.load_baseline()[0])

    def test_the_same_update_without_a_move_is_quiet_and_rolls_in(self):
        """G: the contrast, the same patch points with nothing moved.
        v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        self.start()
        add(self.md("alpha"), "One more line.\n")
        real = isr.roll_builtin
        with mock.patch.object(isr, "roll_builtin", lambda *a, **k: real(*a, **k)):
            self.audit()
        self.quiet(self.md("alpha"))
        self.assertNotIn(self.md("alpha"), isr.load_baseline()[0])


class LegacyGroupedSecrets(_Middle):
    """Codex 2: a grouped ISR-S002 saved before fix round 2 (no `affected_files`) held none of its files."""

    def files(self, needle):
        ps = [os.path.join(self.home, ".grok", "bundled", f"{n}.json") for n in ("a", "b", "c", "d")]
        for p in ps:
            put(p, json.dumps({"note": f"Config value: {needle}"}) + "\n")
        return ps

    def group(self):
        """v0.8.1 (decision, Oct 24): the vendor group is a platform note, read from the snapshot's vendor records."""
        d = os.path.join(self.home, ".grok", "bundled")
        return [f for f in self.vs() if f["rule"] == "ISR-S002" and f["where"] == d]

    def legacy(self):
        """Four baselined files under .grok/bundled with a key hit each (one grouped ISR-S002 on the folder), then the saved line
        made as 47d3aba saved it: no `affected_files`, a Platform line (info, severity_was medium).
        v0.8.1 (decision, Oct 24): the saved line is the snapshot's vendor record."""
        ps = self.files(NEEDLE)
        profiles.vendor_release(self, *ps)
        self.start(gitleaks=leaks_in("/.grok/bundled/"))
        snap = self.snap()
        gs = [f for f in snap.get("vendor", []) if f["rule"] == "ISR-S002" and f["where"] == os.path.dirname(ps[0])]
        self.assertEqual(len(gs), 1)
        gs[0].pop("affected_files", None)
        gs[0]["severity"], gs[0]["severity_was"] = "info", "medium"
        isr.save_json(isr.state_path("last_findings.json"), snap)
        return ps, {p: sha(p) for p in ps}

    def assert_held(self, ps, old):
        """v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        base = isr.load_baseline()[0]
        for p in ps:
            self.assertEqual(self.drift(p), [], [(f["rule"], f["severity"], f["where"]) for f in self.snap()["findings"]])
            self.assertNotIn(p, base, p)
        self.assertFalse([f for f in self.fs() if f["rule"] == "ISR-S002" and f["where"] == os.path.dirname(ps[0])])
        self.assertNotIn("affected_files", self.group()[0])                      # still the line from before the upgrade

    def test_a_carried_legacy_group_holds_every_file(self):
        """R: the four files changed; a daily (no gitleaks) and then a full audit whose gitleaks fails carry the legacy line: four
        counted highs both times and the old baseline hashes (d2d24e5: zero highs).
        v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        ps, old = self.legacy()
        for p in ps:
            add(p, "\n")
        self.assertEqual(self.daily(), "NO_CHANGES")
        self.assert_held(ps, old)
        self.scanners(gitleaks=CRASH)
        r = self.audit()
        self.assertTrue([s for s in r.get("stages_skipped", []) if "gitleaks" in s], r.get("stages_skipped"))
        self.assert_held(ps, old)

    def test_a_scan_that_finishes_ends_the_folder_hold(self):
        """G: the keys taken out of the four files and a full audit whose gitleaks finishes (nothing found): quiet, rolled in.
        v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        ps, old = self.legacy()
        self.files("none")
        self.audit()
        self.assertEqual(self.group(), [])
        base = isr.load_baseline()[0]
        for p in ps:
            self.assertEqual(self.counted_high(p), [], p)
            self.assertNotIn(p, base, p)

    def test_a_root_cause_group_with_unnamed_members_holds_its_skill_folder(self):
        """R: a root-cause group that names fewer members than it has (`also_count` over its `also_flagged_by` list) holds a file
        in its skill folder it doesn't name (d2d24e5: no hold).
        v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only. The hold is gone
        with the release list; a root-cause group whose members are all the platform's never reaches the owner's findings."""
        d = os.path.dirname(self.md("alpha"))
        self.start()
        for n in ["ref"] + [f"n{i}" for i in range(5)]:
            put(os.path.join(d, f"{n}.md"), FLAGGED.format(n=n))
        self.audit()
        self.assertFalse([f for f in self.fs() if f["where"].startswith(d)])
        self.assertTrue([f for f in self.vs() if f["where"].startswith(d)])


class DailyScannersMissing(_Middle):
    """Item 3 (the owner's decision, Oct 23): daily on a box with a missing scanner prints what f7c28e6 printed."""

    def swap(self, *names):
        for n in names:
            add(os.path.join(os.environ["ISR_BOT_HOME"], "scanners", "bin", n), "# changed after ISR Bot installed it\n")
        isr._SCANNER_OK.clear()

    def x005(self):
        return sorted(os.path.basename(f["where"]) for f in self.snap()["findings"] if f["rule"] == "ISR-X005")

    def test_a_missing_scanner_with_an_open_alert_is_the_missing_line(self):
        """R: a swapped gitleaks (ISR-X005, said the first day), then a daily with nothing changed: f7c28e6's SCANNERS_MISSING
        line, exactly (d2d24e5: full JSON with scanner_alerts)."""
        self.start()
        self.swap("gitleaks")
        self.assertTrue(self.daily().startswith("{"))
        self.assertEqual(self.x005(), ["gitleaks"])
        self.assertEqual(self.daily(), MISSING.format("gitleaks"))
        self.assertEqual(self.x005(), ["gitleaks"])

    def test_scanners_never_installed_right_with_open_alerts_is_not_checked(self):
        """R: a box whose SkillSpector, husk, gitleaks and TruffleHog were never the copies ISR Bot installed (four ISR-X005 from
        the first audit): daily with nothing changed is f7c28e6's NO_CHANGES_BUT_NOT_CHECKED line, exactly (d2d24e5: full JSON
        with four scanner_alerts)."""
        self.scanners()
        self.swap("skillspector", "husk", "gitleaks", "trufflehog")
        self.audit()
        self.assertEqual(self.x005(), ["gitleaks", "husk", "skillspector", "trufflehog"])
        self.assertEqual(self.daily(), "NO_CHANGES_BUT_NOT_CHECKED SkillSpector and husk: these were not checked this run "
                                       "(last results kept)")


if __name__ == "__main__":
    unittest.main()
