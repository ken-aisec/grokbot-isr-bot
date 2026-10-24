"""Item 8, decision (Oct 18): a file in a platform folder is trusted only when ISR Bot's release list
(rules/platform-release.lock) has its path and exact sha256. Nothing on the computer approves one.

Two highs were open on 7ab522f:
H1. state/platform_approved.json plus a matching ledger line ("platform-approved" or "platform-first-baseline" with its bind), both
    in ISR Bot's state, which the Bot can write, was provenance; and the owner's yes (`fix --approve-platform`) wrote them.
H2. a brand-new box, or one whose ISR Bot state was wiped, took a first baseline that vouched for every unlisted platform file.
Also pinned here: the refused yes writes nothing (#9 medium a), an old install's vouched state turns back into alerts, and a held
platform file replaced by a link keeps its approved copy (#9 medium b).

Each test fails on 7ab522f by reaching an assertion unless its docstring says it is a contrast.
"""
import hashlib, json, os, shutil, sys, unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_boxes  # noqa: E402
import isr  # noqa: E402
from test_item8_provenance import CLEAN, _Platform, put, sha  # noqa: E402
import profiles  # noqa: E402


def file_sha(p):
    return sha(p) if os.path.exists(p) else None


class _ForgedState(_Platform):
    def plant(self, p=None):
        p = p or self.md("helper")
        put(p, CLEAN.format(n="helper"))
        return p

    def forge(self, p, event, baseline=True):
        """What 7ab522f wrote for an approved platform file: the record, its bound ledger line and the baseline line."""
        h, t = sha(p), os.path.realpath(p)
        isr.save_json(isr.state_path("platform_approved.json"), {"v": 1, "files": {p: {"sha256": h, "target": t}}})
        bind = hashlib.sha256(f"wt-platform-record-v1\n{os.path.normpath(p)}\t{h}\t{os.path.normpath(t)}\n".encode()).hexdigest()[:32]
        with open(isr.state_path("ledger.jsonl"), "a") as f:
            f.write(json.dumps({"event": event, "count": 1, "bind": [bind], "at": isr.now()}) + "\n")
        if baseline:
            base = isr.load_baseline()[0]
            base[p] = h
            isr.save_json(isr.state_path("baseline.json"), base)


class H1LocalRecords(_ForgedState):
    """b8i4 (decision, Oct 22): a baseline line makes a path "already existing", so a forged one plus clean bytes is the middle
    path's quiet case (an accepted limit: the baseline is Bot-writable). The record and the ledger line still grant nothing: the
    twins forge them without the baseline line, for a loose plant."""

    def test_h1_a_record_with_its_ledger_line_grants_nothing(self):
        self.start()
        plant = self.plant()
        self.forge(plant, "platform-approved")
        self.assertEqual(self.daily(), "NO_CHANGES")
        self.assertEqual(len(self.counted_high(plant)), 0)

    def test_h1_a_record_with_its_ledger_line_grants_nothing_without_a_baseline_line(self):
        self.start()
        plant = self.plant(self.loose())
        self.forge(plant, "platform-approved", baseline=False)
        self.assertNotEqual(self.daily(), "NO_CHANGES")
        self.assertEqual(len(self.counted_high(plant)), 1)

    def test_h1_a_first_baseline_ledger_line_grants_nothing(self):
        self.start()
        plant = self.plant()
        self.forge(plant, "platform-first-baseline")
        self.assertEqual(self.daily(), "NO_CHANGES")
        self.assertEqual(len(self.counted_high(plant)), 0)

    def test_h1_a_first_baseline_ledger_line_grants_nothing_without_a_baseline_line(self):
        self.start()
        plant = self.plant(self.loose())
        self.forge(plant, "platform-first-baseline", baseline=False)
        self.assertNotEqual(self.daily(), "NO_CHANGES")
        self.assertEqual(len(self.counted_high(plant)), 1)

    def test_h1_the_owners_yes_is_refused(self):
        self.start()
        plant = self.plant(self.loose())
        self.audit()
        code = self.preview().get("platform_unverified", {}).get("code", "0" * 20)
        out = self.approve(code)
        self.assertIn("platform-release.lock", out)
        self.assertNotIn(plant, isr.load_baseline()[0])
        self.audit()
        self.assertEqual(len(self.counted_high(plant)), 1)
        self.assertNotEqual(self.daily(), "NO_CHANGES")

    def test_h1_a_refused_yes_writes_nothing(self):
        self.start()
        self.plant()
        self.audit()
        code = self.preview().get("platform_unverified", {}).get("code", "0" * 20)
        files = [isr.state_path(n) for n in ("last_findings.json", "baseline.json")]
        before = [file_sha(p) for p in files]
        self.approve(code)
        self.assertEqual([file_sha(p) for p in files], before)
        self.assertFalse(os.path.lexists(isr.state_path("platform_approved.json")))


class H2FirstRunTrust(_ForgedState):
    """b8i4 fix round 1 (Codex 1): a new platform skill folder is the middle path's only in an update run, so on a first run (a
    new box or wiped state) it is a counted high and stays out of the first baseline, and it stays held on the runs after."""

    def test_h2_a_brand_new_box_trusts_no_unlisted_platform_file(self):
        plant = self.plant()
        self.start()
        self.assertEqual(len(self.counted_high(plant)), 1)
        self.assertNotIn(plant, isr.load_baseline()[0])
        self.assertNotEqual(self.daily(), "NO_CHANGES")

    def test_h2_wiped_state_trusts_nothing(self):
        self.start()
        plant = self.plant()
        shutil.rmtree(os.path.join(os.environ["ISR_BOT_HOME"], "state"))
        self.audit()
        self.assertEqual(len(self.counted_high(plant)), 1)
        self.assertNotIn(plant, isr.load_baseline()[0])

    def test_h2_the_first_baseline_command_holds_unlisted_files(self):
        self.scanners()
        plant = self.plant()
        out = self.run_cmd("baseline", "--roots", *self.roots)[1]
        self.assertIn("Not approved by this: 1", out)
        self.assertNotIn(plant, isr.load_baseline()[0])


class Migration(_ForgedState):
    def test_migration_a_vouched_baseline_line_is_the_middle_path_and_the_old_record_is_never_read(self):
        """b8i4: the vouched baseline line makes the clean plant's path "already existing" (the middle path's accepted limit), so
        it raises nothing; the old record is still never read, and the note about it stays."""
        self.start()
        plant = self.plant()
        self.forge(plant, "platform-first-baseline")                            # as 7ab522f's first baseline left it
        r = self.audit()
        x = self.counted_high(plant)
        self.assertEqual(x, [])
        self.assertTrue([n for n in r["notes"] if "platform_approved.json" in n], r["notes"])
        self.assertEqual(self.daily(), "NO_CHANGES")


class HeldLinkKeepsCopy(_Platform):
    def test_mb_a_refused_file_replaced_by_a_link_keeps_its_approved_copy(self):
        alpha = os.path.dirname(self.md("alpha"))
        notes = os.path.join(alpha, "notes.md")
        put(notes, "Version 1 notes.\n")
        profiles.vendor_release(self, notes)
        v1 = sha(notes)
        self.start()
        outside = os.path.join(self.tmp, "outside.md")
        put(outside, "Someone else's notes.\n")
        os.remove(notes)
        os.symlink(outside, notes)
        self.run_cmd("baseline", "--roots", *self.roots, "--owner-said-yes")
        self.assertEqual((isr.load_approved(alpha) or {}).get("hashes", {}).get("notes.md"), v1)
        self.assertIn("replaced by a link", isr.skill_diff(alpha)["text"])


class Contrast(_Platform):
    def test_contrast_listed_files_on_a_new_box_stay_quiet(self):
        """Contrast: passes on 7ab522f too."""
        self.start()
        self.assertFalse([f for f in self.snap()["findings"] if f.get("unverified_platform")])
        self.assertEqual(self.daily(), "NO_CHANGES")


class Labels(unittest.TestCase):
    def test_contrasts_are_marked(self):
        """Contrast: passes on 7ab522f too (a check on this file's own labels)."""
        import inspect
        for name, obj in list(globals().items()):
            if isinstance(obj, type) and issubclass(obj, unittest.TestCase):
                for m in [m for m in dir(obj) if m.startswith("test_") and "_contrast" in m]:
                    self.assertIn("Contrast", inspect.getdoc(getattr(obj, m)) or "", f"{name}.{m}")


if __name__ == "__main__":
    unittest.main()
