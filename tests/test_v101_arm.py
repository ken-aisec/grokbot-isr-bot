"""1.0.1 (U4): on a computer that isn't x86_64, install.sh skips gitleaks, TruffleHog and OSV-Scanner and says so.

Before: on aarch64 install.sh downloaded the arm64 builds of the three, but scripts/scanner-bins.lock has x86_64 lines only for
them, so they never ran and the audit only said "not listed". Now install.sh installs none of them there and prints why, and an
ARM box still holding 1.0's downloads lists them as checks that didn't run (U2). Tests marked "replay" fail on bacd581 at their
first assertion; the "guard" passes there too. The install runs are test_scripts.InstallScanners's harness (stand-ins for pip,
curl and uname; nothing reaches the network)."""
import os, shutil, sys, unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import Box  # noqa: E402
import test_scripts  # noqa: E402  (module access: its test classes don't run twice)
import isr  # noqa: E402

THREE = ("gitleaks", "trufflehog", "osv-scanner")


class _Install(unittest.TestCase):
    """InstallScanners's set-up and runner, without its tests, serving the arm64 release files beside the x86_64 ones."""
    setUp = test_scripts.InstallScanners.setUp
    binaries = test_scripts.InstallScanners.binaries
    run_install = test_scripts.InstallScanners.run_install

    def release_files(self):
        test_scripts.InstallScanners.release_files(self)
        for fn in os.listdir(self.serve):   # the same bytes under the arm64 names, and their checksum lines
            p = os.path.join(self.serve, fn)
            if "_x64" in fn or "_amd64" in fn:
                shutil.copyfile(p, os.path.join(self.serve, fn.replace("_x64", "_arm64").replace("_amd64", "_arm64")))
        for fn in ("gitleaks_8.30.1_checksums.txt", "trufflehog_3.97.9_checksums.txt", "osv-scanner_SHA256SUMS"):
            p = os.path.join(self.serve, fn)
            with open(p) as f:
                text = f.read()
            with open(p, "a") as f:
                f.write(text.replace("_x64", "_arm64").replace("_amd64", "_arm64"))

    def computer(self, arch):
        test_scripts.stub(self.bin, "uname", f"echo {arch}\n")


class ArmInstall(_Install):
    def test_arm_skips_the_three_downloads_and_says_so(self):   # replay
        self.computer("aarch64")
        r, calls = self.run_install()
        self.assertEqual(self.binaries(), [], r.stdout)                            # bacd581: all three installed
        self.assertEqual([c for c in calls if c.startswith("curl") and any(t in c for t in THREE)], [])
        self.assertIn("NOT installed", r.stdout)
        self.assertIn("aarch64", r.stdout)
        self.assertIn("gitleaks, TruffleHog and OSV-Scanner NOT installed", r.stdout)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)                     # exit code unchanged

    def test_x86_64_still_installs_the_three(self):   # guard
        self.computer("x86_64")
        r, calls = self.run_install()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.binaries(), ["gitleaks", "osv-scanner", "trufflehog"], r.stdout)
        self.assertNotIn("NOT installed", r.stdout)


class ArmBox(Box):
    def test_an_arm_box_with_old_downloads_counts_three_checks(self):   # replay
        self.skills(1)
        self.scanners()
        for t in THREE:   # 1.0's downloads: on this computer no checked copy lists them
            isr.SCANNER_LOCK_EXTRA.pop(t, None)
        with mock.patch.object(isr, "scanner_arch", return_value="aarch64"):
            r = self.audit()
        self.assertTrue(r["score_line"].endswith(" · 3 checks didn't run"), r["score_line"])   # bacd581: "N tips"
        self.assertEqual(r["checks_not_run"], [f"{n}: no checked copy for this computer (aarch64)"
                                               for n in ("gitleaks", "TruffleHog", "OSV-Scanner")])
        self.assertEqual(r["status_line"], "All good so far, 3 checks didn't run")


if __name__ == "__main__":
    unittest.main()
