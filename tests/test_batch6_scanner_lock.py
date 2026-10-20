"""Batch 6 PR3, C (code part): the scanner lock that ships empty is tested, visibly, and install.sh extracts without ownership.

scripts/scanner-bins.lock lists no program yet: Ken fills it before a release (docs/KNOWN-LIMITS.md, the plan's section 5), and
publish.sh refuses to publish until every required scanner has a line. Until then the release-complete test is an expected
failure, reported as one on every run. Once the lock is filled it becomes an unexpected success, which fails the run on Python
3.11 and later until its decorator is removed; from then on it guards against emptying the lock. A tripwire both ways.

TruffleHog's tarball carries an owner that a user namespace can't map ("tar: Cannot change ownership"); `--no-same-owner`
extracts as the user running install.sh, which it does anyway outside namespaces.

The test marked "replay" fails on 1aed58a on its assertion (measured with 1aed58a's scripts/, this file in place); the rest are
guards and the tripwire. No line is added to the lock here."""
import importlib.util, os, re, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import ROOT

LOCK = os.path.join(ROOT, "scripts", "scanner-bins.lock")
spec = importlib.util.spec_from_file_location("scanner_lock_under_test", os.path.join(ROOT, "scripts", "scanner_lock.py"))
scanner_lock = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner_lock)


def read(*rel):
    with open(os.path.join(ROOT, *rel)) as f:
        return f.read()


def shipped():
    text, why = scanner_lock.read_lock(LOCK)
    return text, why


class EmptyScannerLock(unittest.TestCase):
    def test_an_empty_lock_names_all_six_scanners(self):   # guard
        problems = scanner_lock.release_problems("# comments only\n\n")
        self.assertEqual(len(problems), 6)
        for name in ("skillspector", "husk", "gitleaks", "trufflehog", "osv-scanner", "pip-audit"):
            self.assertIn(f"scripts/scanner-bins.lock has no checksum for {name}", problems)

    def test_publish_runs_the_reader_and_stops_on_it(self):   # guard
        text = read("scripts", "publish.sh")
        self.assertRegex(text, r'LOCK_PROBLEM="\$\(python3 -I scripts/scanner_lock\.py scripts/scanner-bins\.lock 2>&1\)" \\\n\s*\|\| stop ')

    def test_every_line_of_the_shipped_lock_is_well_formed(self):   # guard (per line, filled or not)
        text, why = shipped()
        self.assertIsNone(why)
        for n, line in enumerate(text.splitlines(), 1):
            if line.strip() and not line.lstrip().startswith("#"):
                self.assertRegex(line, scanner_lock.LINE, f"line {n}")
        self.assertEqual(scanner_lock.parse(text)[1], [])

    @unittest.expectedFailure   # tripwire: remove this decorator when Ken fills the lock (it then fails as an unexpected success)
    def test_the_shipped_lock_is_release_complete(self):
        text, why = shipped()
        self.assertIsNone(why)
        self.assertEqual(scanner_lock.release_problems(text), [])


class TarWithoutOwnership(unittest.TestCase):
    def test_both_scanner_tarballs_extract_without_ownership(self):   # replay (1aed58a: no --no-same-owner)
        lines = [l for l in read("scripts", "install.sh").splitlines() if re.search(r"\btar\s", l)]
        self.assertEqual(len(lines), 2)
        for l in lines:
            self.assertIn("tar --no-same-owner -xzf", l)


if __name__ == "__main__":
    unittest.main()
