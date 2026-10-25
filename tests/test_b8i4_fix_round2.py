"""b8i4 fix round 2: the Codex verify of 47d3aba (fix round 1), 4 high and 1 medium.

1. `isr.py baseline` saved no findings, so a new skill folder its first baseline held was a "new-skill" candidate on the next run
   (quiet). Every baseline now keeps what it held outside the middle path (state/platform_held.json, save_platform_held).
2. A candidate's real path was checked only before the engines ran: a platform folder moved out and replaced by a link while
   they scanned (its bytes kept) stayed quiet and rolled in. Each candidate is bound to its real path and checked again before
   it is settled and before it rolls (platform_still_bound).
3. A metadata JSON file's string values were read as instructions only when they had a blank in them: "eval\\u0028payload\\u0029"
   (eval(payload) once decoded) passed. Every decoded string value is read now.
4. gitleaks's grouped ISR-S002 (four or more files in one folder) names the folder, and only exact file paths held a candidate,
   so the files' updates were quiet and rolled in. A grouped finding keeps its files (`affected_files`), and settlement, daily's
   carried lines and the roll use them.
5. Daily said NO_CHANGES over an open ISR-X005 (a scanner that isn't the copy ISR Bot installed) once nothing else was open.
   Fix round 3 undid this change (the owner's decision, Oct 23): daily on a box with a missing scanner prints what f7c28e6 printed,
   and DailyScannerAlerts asserts that now.

Each test marked R in its docstring fails on 47d3aba's sources (the changed engine files stashed) at an assertion; G is
a guard (a contrast) that passes there and here.
"""
import json, os, sys, unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import CRASH  # noqa: E402
import isr  # noqa: E402
from test_item8_provenance import CLEAN, add, put, sha  # noqa: E402
from test_b8i4_middle_path import _Middle  # noqa: E402
from test_b8i4_fix_round1 import NEEDLE, leaks_in  # noqa: E402
import profiles  # noqa: E402

MOVE_ENGINE = ('#!/usr/bin/env python3\nimport json, os, sys\na = sys.argv[1:]; stage = a[1]; out = a[a.index("--output") + 1]\n'
               'b, o = %r, %r\n'
               'if not os.path.islink(b):\n'                                  # moves the platform folder out, a link left in its place
               '    os.makedirs(os.path.dirname(o), exist_ok=True); os.rename(b, o); os.symlink(o, b)\n'
               'json.dump({"multi_skill": True, "skills": [{"path": n, "risk_assessment": {"score": 5, "recommendation": "INSTALL"}, "issues": []} '
               'for n in sorted(os.listdir(stage))]}, open(out, "w"))\n')


class BaselineCommandHolds(_Middle):
    """Codex 1: the first-run hold has to survive every way a baseline is taken."""

    def helper(self):
        md, ref = self.md("helper"), os.path.join(self.root, "helper", "ref.md")
        put(md, CLEAN.format(n="helper")); put(ref, "Notes for the helper.\n")
        return md, ref

    def assert_held(self, *paths):
        """v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        for p in paths:
            self.assertEqual(self.drift(p), [], p)
            self.assertNotIn(p, isr.load_baseline()[0], p)

    def test_a_first_baseline_command_keeps_a_new_skill_folder_held(self):
        """R: a clean unlisted helper folder on a new box, then `isr.py baseline` (the first baseline): daily and a full audit
        both keep its files counted highs outside the baseline (47d3aba: daily said NO_CHANGES, the audit rolled them in).
        v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        self.scanners()
        md, ref = self.helper()
        out = self.run_cmd("baseline", "--roots", *self.roots)[1]
        self.assertNotIn("Not approved by this", out)
        self.assertEqual(isr.load_baseline()[1], "ok")
        d1 = json.loads(self.daily())                                          # the first findings to compare with (the command saved none)
        self.assertFalse([f for f in d1["new"] if f["where"].split(":")[0] in (md, ref)])
        self.assertEqual(self.daily(), "NO_CHANGES")
        self.assert_held(md, ref)
        self.audit()
        self.assert_held(md, ref)
        self.audit()
        self.assert_held(md, ref)

    def test_a_baseline_after_a_reset_keeps_a_new_skill_folder_held(self):
        """R: the baseline was deleted (a reset: nothing is approved), a clean unlisted helper folder appeared, and the owner's yes
        takes a new baseline: the next daily and audit keep the folder's files counted highs (47d3aba: quiet, then rolled in).
        v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        self.start()
        md, ref = self.helper()
        os.remove(isr.state_path("baseline.json"))
        self.assertEqual(isr.load_baseline()[1], "reset")
        self.run_cmd("baseline", "--roots", *self.roots, "--owner-said-yes")
        self.assertEqual(isr.load_baseline()[1], "ok")
        self.assertEqual(self.daily(), "NO_CHANGES")
        self.assert_held(md, ref)
        self.audit()
        self.assert_held(md, ref)

    def test_a_held_folder_stays_held_after_a_run_with_other_roots(self):
        """R: after the first baseline command, a daily that doesn't see the folder (other roots) doesn't make it new again
        (47d3aba: the next full daily said NO_CHANGES).
        v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        self.scanners()
        md, ref = self.helper()
        self.run_cmd("baseline", "--roots", *self.roots)
        self.run_cmd("daily", "--roots", os.path.join(self.home, "sand-data"))
        self.assertEqual(self.daily(), "NO_CHANGES")
        self.assert_held(md, ref)

    def test_a_clean_folder_added_after_the_baseline_command_is_quiet(self):
        """G: the contrast, the same folder added after the first baseline command (an update run)."""
        self.scanners()
        self.run_cmd("baseline", "--roots", *self.roots)
        self.daily()                                                            # the first findings to compare with
        md, ref = self.helper()
        self.assertEqual(self.daily(), "NO_CHANGES")
        self.quiet(md, ref)


class RedirectWhileScanning(_Middle):
    """Codex 2: the real-path check ran before the engines; settlement and the roll trusted it."""

    def test_a_platform_folder_moved_out_while_the_engines_ran_is_held(self):
        """R: alpha's clean update, and an engine that moves .grok/bundled outside every platform folder and leaves a link in its
        place (the bytes kept): a counted high, no Platform refresh entry for it, and the old baseline hash (47d3aba: quiet and
        rolled in).
        v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only. Once the folder
        leads outside every platform folder, alpha is the owner's file: a new one (low), never rolled in."""
        self.start()
        add(self.md("alpha"), "One more line.\n")
        bundled = os.path.join(self.home, ".grok", "bundled")
        outside = os.path.join(self.tmp, "outside", "bundled")
        self.scanners(skillspector=MOVE_ENGINE % (bundled, outside))
        self.audit()
        self.assertTrue(os.path.islink(bundled))                                 # the engine did move it
        self.audit()
        x = [f for f in self.fs() if f["where"] == self.md("alpha") and f["rule"] in ("ISR-I001", "ISR-I002")]
        self.assertEqual([(f["rule"], f["severity"]) for f in x], [("ISR-I002", "low")], [(f["rule"], f["where"]) for f in self.snap()["findings"]])
        self.assertEqual(x[0]["title"], "New skill or plugin file")
        self.assertFalse([f for f in self.tip() if self.rel(self.md("alpha")) in f.get("files", [])])
        self.assertNotIn(self.md("alpha"), isr.load_baseline()[0])

    def test_the_same_update_without_the_move_rolls_in(self):
        """G: the contrast, the same clean update with engines that leave the folder alone.
        v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        self.start()
        add(self.md("alpha"), "One more line.\n")
        self.audit()
        self.assertEqual(self.counted_high(self.md("alpha")), [])
        self.assertNotIn(self.md("alpha"), isr.load_baseline()[0])


class EscapedMetadata(_Middle):
    """Codex 3: a metadata string value without a blank wasn't read as an instruction."""

    def cache(self, body):
        """v0.8.1 (decision, Oct 24): the same JSON is also the owner's (u, in the owner's notes skill), which is where the counted
        high is now."""
        p = os.path.join(self.home, ".grok", "bundled", "cache.json")
        u = self.user("notes", "cache.json")
        put(self.user("notes"), CLEAN.format(n="notes"))                       # a skill folder, so its files are fingerprinted
        put(p, '{"name": "notes", "body": "Summarize the notes."}\n')
        put(u, '{"name": "notes", "body": "Summarize the notes."}\n')
        profiles.vendor_release(self, p)
        self.start()
        v1, uv1 = sha(p), sha(u)
        put(p, '{"name":"notes","body":"%s"}\n' % body)
        put(u, '{"name":"notes","body":"%s"}\n' % body)
        self.audit()
        return p, v1, u, uv1

    def assert_held(self, p, v1, u, uv1):
        """v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        x = [f for f in self.counted_high(u) if f["rule"] == "ISR-I001"]
        self.assertEqual(len(x), 1, [(f["rule"], f["severity"], f["where"]) for f in self.snap()["findings"]])
        self.assertEqual(self.drift(p), [])
        self.assertEqual(isr.load_baseline()[0][u], uv1)
        self.assertNotIn(p, isr.load_baseline()[0])

    def test_an_escaped_call_without_a_blank_is_held(self):
        """R: an existing cache.json updated to {"body":"eval\\u0028payload\\u0029"}: ISR-I001 high, and the baseline keeps the
        old bytes (47d3aba: quiet, rolled in).
        v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        self.assert_held(*self.cache("eval\\u0028payload\\u0029"))

    def test_the_escaped_call_with_blanks_is_held(self):
        """G: a control, the same escaped call inside a sentence (fix round 1 read it).
        v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        self.assert_held(*self.cache("Run eval\\u0028payload\\u0029 on the notes."))

    def test_the_literal_call_is_held(self):
        """G: a control, the call written plainly (the whole file's own scan reads it).
        v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        self.assert_held(*self.cache("Run eval(payload) on the notes."))

    def test_plain_values_without_blanks_stay_quiet(self):
        """G: values without a blank that say nothing (an id, a version, a hash) leave a clean update quiet."""
        p = os.path.join(self.home, ".grok", "bundled", "cache.json")
        put(p, '{"name": "notes", "version": "1.0.0", "id": "a1b2c3"}\n')
        profiles.vendor_release(self, p)
        self.start()
        put(p, '{"name":"notes","version":"1.0.1","id":"0b4c2f3e-5d6a-4b7c-8d9e-0f1a2b3c4d5e","sha":"%s"}\n' % ("ab" * 32))
        self.assertEqual(self.daily(), "NO_CHANGES")
        self.quiet(p)


class GroupedSecrets(_Middle):
    """Codex 4: gitleaks's ISR-S002 for four or more files in one folder names the folder, not the files."""

    def files(self, needle):
        ps = [os.path.join(self.home, ".grok", "bundled", f"{n}.json") for n in ("a", "b", "c", "d")]
        for p in ps:
            put(p, json.dumps({"note": f"Config value: {needle}"}) + "\n")
        return ps

    def group(self):
        """v0.8.1 (decision, Oct 24): the vendor group is a platform note, read from the snapshot's vendor records."""
        d = os.path.join(self.home, ".grok", "bundled")
        return [f for f in self.vs() if f["rule"] == "ISR-S002" and f["where"] == d]

    def assert_held(self, ps, old):
        """v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        base = isr.load_baseline()[0]
        for p in ps:
            self.assertEqual(self.drift(p), [], [(f["rule"], f["where"]) for f in self.snap()["findings"]])
            self.assertNotIn(p, base, p)

    def test_grouped_hits_hold_every_file(self):
        """R: four changed, baselined JSON files directly under .grok/bundled, each with a generic gitleaks hit (one grouped
        medium ISR-S002 on the folder): four counted highs and the old baseline hashes (47d3aba: four quiet updates, rolled in).
        v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only. The owner's
        four changed files are the counted highs."""
        ps = self.files("none")
        us = [self.user("keys", f"{n}.json") for n in "abcd"]
        put(self.user("keys"), CLEAN.format(n="keys"))                         # a skill folder, so its files are fingerprinted
        for p in us:
            put(p, json.dumps({"note": "Config value: none"}) + "\n")
        profiles.vendor_release(self, *ps)
        self.start()
        old = {p: sha(p) for p in ps}
        uold = {p: sha(p) for p in us}
        self.files(NEEDLE)
        for p in us:
            put(p, json.dumps({"note": f"Config value: {NEEDLE}"}) + "\n")
        self.scanners(gitleaks=leaks_in("/.grok/bundled/"))
        self.audit()
        self.assertEqual([f["rule"] for f in self.group()], ["ISR-S002"])
        self.assert_held(ps, old)
        base = isr.load_baseline()[0]
        for p in us:
            self.assertEqual(len(self.counted_high(p)), 1, p)
            self.assertEqual(base[p], uold[p], p)

    def test_carried_grouped_hits_hold_every_file(self):
        """R: the grouped line from the last full audit, carried by a daily (daily doesn't run gitleaks) and by a full audit whose
        gitleaks failed: the four changed files are counted highs both times and keep their old baseline hashes (47d3aba: quiet).
        v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only. The vendor group
        is carried as a platform note."""
        ps = self.files(NEEDLE)
        profiles.vendor_release(self, *ps)
        self.start(gitleaks=leaks_in("/.grok/bundled/"))
        self.assertEqual(len(self.group()), 1)
        old = {p: sha(p) for p in ps}
        for p in ps:
            add(p, "\n")
        self.assertEqual(self.daily(), "NO_CHANGES")
        self.assert_held(ps, old)
        self.scanners(gitleaks=CRASH)
        r = self.audit()
        self.assertTrue([s for s in r.get("stages_skipped", []) if "gitleaks" in s], r.get("stages_skipped"))
        self.assertEqual(len(self.group()), 1)
        self.assert_held(ps, old)

    def test_files_beside_the_group_stay_quiet(self):
        """G: a clean update of a skill file outside the grouped folder's files is the quiet line, rolled in.
        v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        ps = self.files(NEEDLE)
        profiles.vendor_release(self, *ps)
        self.start(gitleaks=leaks_in("/.grok/bundled/"))
        add(self.md("alpha"), "One more line.\n")
        self.audit()
        self.assertEqual(len(self.group()), 1)
        self.assertEqual(self.counted_high(self.md("alpha")), [])
        self.assertNotIn(self.md("alpha"), isr.load_baseline()[0])


class DailyScannerAlerts(_Middle):
    """Codex 5: an open ISR-X005 vanished from daily once no platform hold kept daily from its quiet answer."""

    def swap_gitleaks(self):
        p = os.path.join(os.environ["ISR_BOT_HOME"], "scanners", "bin", "gitleaks")
        add(p, "# changed after ISR Bot installed it\n")                     # no longer the digest ISR Bot registered
        isr._SCANNER_OK.clear()

    def alerts(self, out):
        return [(f["rule"], os.path.basename(f["where"])) for f in json.loads(out).get("scanner_alerts", [])]

    def test_an_open_scanner_alert_is_said_beside_a_quiet_platform_update(self):
        """G (changed in fix round 3, the owner's decision of Oct 23: daily on a box with a missing scanner prints what f7c28e6
        printed, no full alert): a swapped gitleaks (ISR-X005, new the first day, in scanner_alerts), then alpha's clean update
        (quiet): the next daily is f7c28e6's SCANNERS_MISSING line, which says how to put the scanner back, and the ISR-X005 stays
        open in the findings."""
        self.start()
        self.swap_gitleaks()
        self.assertIn(("ISR-X005", "gitleaks"), self.alerts(self.daily()))
        add(self.md("alpha"), "One more line.\n")
        out = self.daily()
        self.assertEqual(out, "SCANNERS_MISSING gitleaks: run `bash /workspace/isr-bot/app/scripts/install.sh --scanners`, "
                              "then `isr.py daily` again")
        self.assertEqual([os.path.basename(f["where"]) for f in self.snap()["findings"] if f["rule"] == "ISR-X005"], ["gitleaks"])
        self.assertEqual(self.counted_high(self.md("alpha")), [])
        self.assertEqual(self.unverified(), [])

    def test_without_an_alert_the_quiet_update_is_no_changes(self):
        """G: the contrast, the same quiet update with every scanner the one ISR Bot installed."""
        self.start()
        add(self.md("alpha"), "One more line.\n")
        self.assertEqual(self.daily(), "NO_CHANGES")


if __name__ == "__main__":
    unittest.main()
