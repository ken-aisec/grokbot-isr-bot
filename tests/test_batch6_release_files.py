"""Batch 6 PR1, KL4 (#15 high 4): Watchtower's release files are held to MANIFEST.sha256 whatever the folder's layout.

A copy moved out of `app` without its commit record, or a renamed custom home with the record deleted, is a developer checkout to
installed_root and self_check (that classification is unchanged), and on 5dcd0a2 such a copy read a planted rules file as it was.
Every shipped rules file (the platform lock, the reviewed list, the normalization spec, the access vocabulary, the scanner lock
and its reader) is now refused unless it is the folder's MANIFEST.sha256 line, with a coverage note when the manifest is missing.

Tests marked "replay" fail on 5dcd0a2 on their assertion (measured with 5dcd0a2's watchtower/ sources, this file in place);
"guard" ones keep what must not change. Every folder is a temp folder; the planted files are JSON with no secret."""
import json, os, shutil, sys, unittest
from unittest import mock
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import Box, ROOT, wt
import test_batch5_codex_r1 as r1

SHIPPED = ("rules/platform-reviewed.json", "rules/platform-normalize.json", "rules/platform-release.lock", "rules/access_vocab.json",
           "scripts/scanner-bins.lock", "scripts/scanner_lock.py")
CACHES = ("_RELEASE", "_PLATFORM_REVIEWED_CACHE", "_PLATFORM_NORMALIZE_CACHE", "_PLATFORM_LOCK_CACHE", "_ACCESS_VOCAB_CACHE",
          "_SCANNER_LOCK_CACHE")


def forget():
    for name in CACHES:
        if hasattr(wt, name):
            getattr(wt, name).clear()


class _Copies(Box):
    install, plant = r1.InstalledCopyIdentity.install, r1.InstalledCopyIdentity.plant

    def forget(self):
        forget()

    def setUp(self):
        super().setUp()
        self.addCleanup(forget)

    def at(self, real):
        """Run this process as the copy in `real`: its sources' folder and each shipped rules file there (module constants)."""
        for name, value in (("SELF_ROOT", real), ("HERE", os.path.join(real, "watchtower")),
                            ("PLATFORM_REVIEWED", os.path.join(real, wt.PLATFORM_REVIEWED_REL)),
                            ("PLATFORM_NORMALIZE", os.path.join(real, wt.PLATFORM_NORMALIZE_REL)),
                            ("PLATFORM_LOCK", os.path.join(real, wt.PLATFORM_LOCK_REL)),
                            ("ACCESS_VOCAB", os.path.join(real, wt.ACCESS_VOCAB_REL)),
                            ("SCANNER_LOCK", os.path.join(real, "scripts", "scanner-bins.lock"))):
            p = mock.patch.object(wt, name, value)
            p.start()
            self.addCleanup(p.stop)
        forget()

    def refused(self):
        self.assertIsNone(wt.installed_root())   # still a checkout to the self-check (unchanged)
        self.assertIsNone(wt.self_check())
        self.assertIn("MANIFEST.sha256", wt.platform_reviewed_problem())
        self.assertIn("MANIFEST.sha256", wt.platform_normalize_problem())
        self.assertEqual(wt._platform_reviewed_state()[0], [])


class MovedInstall(_Copies):
    def test_a_copy_moved_out_of_app_without_its_record_refuses_the_planted_list(self):   # replay (5dcd0a2: accepted)
        self.install()
        self.plant()
        real = os.path.join(self.tmp, "src", "other")
        os.makedirs(os.path.dirname(real))
        os.rename(self.app, real)
        self.at(real)
        self.refused()

    def test_a_renamed_custom_home_with_the_record_deleted_refuses_it(self):   # replay (5dcd0a2: accepted)
        self.install()
        self.plant()
        os.remove(os.path.join(self.wth, "state", "installed_commit"))
        real = os.path.join(self.wth, "renamed")
        os.rename(self.app, real)
        self.at(real)
        self.refused()

    def test_another_watchtower_home_changes_nothing(self):   # replay (5dcd0a2: accepted)
        self.install()
        self.plant()
        real = os.path.join(self.tmp, "src", "other")
        os.makedirs(os.path.dirname(real))
        os.rename(self.app, real)
        other = os.path.join(self.tmp, "elsewhere")
        os.makedirs(other)
        with mock.patch.dict(os.environ, {"WATCHTOWER_HOME": other}):
            self.at(real)
            self.refused()

    def test_the_shipped_files_of_a_moved_copy_still_work(self):   # guard: only what isn't the manifest's line is refused
        self.install()
        real = os.path.join(self.tmp, "src", "other")
        os.makedirs(os.path.dirname(real))
        os.rename(self.app, real)
        self.at(real)
        self.assertEqual((wt.platform_reviewed_problem(), wt.platform_normalize_problem()), ("", ""))


class NoManifest(_Copies):
    def checkout(self, manifest):
        """A checkout-like copy of every shipped rules file and the scanner lock's reader, with or without its MANIFEST.sha256."""
        real = os.path.join(self.tmp, "src", "checkout")
        for rel in SHIPPED:
            os.makedirs(os.path.dirname(os.path.join(real, rel)), exist_ok=True)
            shutil.copyfile(os.path.join(ROOT, rel), os.path.join(real, rel))
        os.makedirs(os.path.join(real, "watchtower"))
        if manifest:
            with open(os.path.join(real, "MANIFEST.sha256"), "w") as f:
                for rel in sorted(SHIPPED):
                    f.write(f"{wt.sha256_file(os.path.join(real, rel))}  {rel}\n")
        self.at(real)
        return real

    def test_every_release_file_is_refused_without_a_manifest(self):   # replay (5dcd0a2: every one used as it was)
        self.checkout(manifest=False)
        for problem in (wt.platform_reviewed_problem(), wt.platform_normalize_problem(), wt.platform_lock_problem(), wt.access_vocab_problem()):
            self.assertIn("Chief Worry Bot's release files can't be checked", problem)
        self.assertEqual(wt.access_vocab(), [])
        self.assertEqual(wt.scanner_lock(), {})
        self.assertTrue(wt.scanner_list_changed())

    def test_the_audit_says_so(self):   # replay (5dcd0a2: no note)
        self.checkout(manifest=False)
        notes = self.audit()["notes"]
        said = [n for n in notes if "Chief Worry Bot's release files can't be checked" in n]
        self.assertTrue(any(wt.PLATFORM_LOCK_REL in n for n in said), notes)
        self.assertTrue(any(wt.PLATFORM_REVIEWED_REL in n for n in said), notes)

    def test_a_manifest_listing_them_makes_them_usable(self):   # guard
        self.checkout(manifest=True)
        self.assertEqual((wt.platform_reviewed_problem(), wt.platform_normalize_problem(), wt.platform_lock_problem(),
                          wt.access_vocab_problem()), ("", "", "", ""))
        self.assertFalse(wt.scanner_list_changed())

    def test_one_byte_more_in_a_rules_file_refuses_it(self):   # replay (5dcd0a2: used)
        real = self.checkout(manifest=True)
        with open(os.path.join(real, wt.PLATFORM_LOCK_REL), "a") as f:
            f.write("# one more line\n")
        forget()
        self.assertIn("isn't the file this release of Chief Worry Bot shipped (MANIFEST.sha256)", wt.platform_lock_problem())


class DeveloperCheckout(_Copies):
    def test_the_checkout_reads_its_own_files(self):   # guard: this checkout's MANIFEST.sha256 is current
        self.at(os.path.realpath(ROOT))
        self.assertIsNone(wt.self_check())
        self.assertEqual((wt.platform_reviewed_problem(), wt.platform_normalize_problem(), wt.platform_lock_problem(),
                          wt.access_vocab_problem()), ("", "", "", ""))
        self.assertFalse(wt.scanner_list_changed())

    def test_a_file_a_test_points_a_constant_at_is_read_as_it_is(self):   # guard: the in-process test seam (never the environment)
        forget()
        with open(self.platform_lock, "a") as f:
            f.write(f"{'a' * 64}  .grok/bundled/skills/x/SKILL.md\n")
        self.assertEqual(wt.platform_lock_problem(), "")
        self.assertEqual(wt.platform_lock(), {".grok/bundled/skills/x/SKILL.md": {"a" * 64}})

    def test_the_environment_never_points_at_another_file(self):   # guard
        planted = os.path.join(self.tmp, "planted.json")
        with open(planted, "w") as f:
            json.dump({"entries": []}, f)
        with mock.patch.dict(os.environ, {"WATCHTOWER_PLATFORM_REVIEWED": planted, "WATCHTOWER_PLATFORM_NORMALIZE": planted}):
            self.at(os.path.realpath(ROOT))
            self.assertEqual(os.path.realpath(wt.PLATFORM_REVIEWED), os.path.realpath(os.path.join(ROOT, wt.PLATFORM_REVIEWED_REL)))


if __name__ == "__main__":
    unittest.main()
