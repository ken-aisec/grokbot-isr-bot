"""Batch 8 (v0.7.4 dev), item b8i1: TruffleHog's launch.

In 0.7.3 every scanner ran from a sealed in-memory copy (/proc/self/fd/N). TruffleHog 3.97.9 always runs overseer, whose master
asks the system for its own program file, gets "/memfd:watchtower-scanner (deleted)", can't stat it and exits ("failed to stat
binary") before scanning anything. The stage failed and the last key status was kept, but scanner_used() only checked the
program file, so engines_used.json and score_history.csv's fingerprint still said TruffleHog ran.

Now TruffleHog runs from a checked copy on disk, in a private folder of this run's own, checked again before it starts, while it
runs and after it exits; a change gives WT-X005 and its results are discarded. And a scanner whose stage failed is not used.
The stand-in for TruffleHog is this computer's own /bin/sh (a native program, like TruffleHog), registered in this process only.
Each test fails on 1a4805c at its assertion (T5 and T6 contrasts are marked).
"""
import errno, os, subprocess, sys, tempfile, time, unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import wt  # noqa: E402
import test_batch3_scanners as b3  # noqa: E402  (module access: its test classes don't run twice)
from test_batch6_example_keys import token  # noqa: E402

REAL_POPEN = subprocess.Popen
with open(os.path.realpath("/bin/sh"), "rb") as _f:
    SH = _f.read()
RERUN = 'x=$(readlink /proc/$$/exe); [ -e "$x" ] || { echo "failed to stat binary" >&2; exit 1; }; "$x" -c "echo child-ok"'
SWAP_DURING = ('x=$(readlink /proc/$$/exe); cat "$x" > "$x.n"; printf \'\\0\' >> "$x.n"; chmod 700 "$x.n"; mv "$x.n" "$x"; '
               '"$x" -c "echo child-results"')


def x005(name):
    return [(f["rule"], f["severity"], os.path.basename(f["where"])) for f in wt.scanner_x005() if f["where"].endswith("/" + name)]


class _T(b3._Scanners):
    def setUp(self):
        super().setUp()
        wt.SCANNERS_HELD.clear()
        self.addCleanup(wt.SCANNERS_HELD.clear)
        self.tmpd = os.path.join(self.tmp, "tmpd")
        os.makedirs(self.tmpd)
        p = mock.patch.object(tempfile, "tempdir", self.tmpd)
        p.start(); self.addCleanup(p.stop)
        self.seen, self.swap, self.refuse = [], None, False
        p = mock.patch.object(wt.subprocess, "Popen", self.popen)
        p.start(); self.addCleanup(p.stop)

    def popen(self, *a, **k):
        """Records the program file each launch starts; can swap a different file in over it, or fail the start."""
        exe = k.get("executable")
        self.seen.append(exe)
        if self.swap is not None and self.under(exe):
            new = exe + ".n"
            with open(new, "wb") as f:
                f.write(self.swap)
            os.chmod(new, 0o700)
            os.rename(new, exe)
        if self.refuse and exe is not None:
            raise OSError(errno.ENOEXEC, "Exec format error")
        return REAL_POPEN(*a, **k)

    def under(self, path):
        return isinstance(path, str) and path.startswith(self.tmpd + os.sep)

    def sh_as_trufflehog(self):
        p = os.path.join(self.bin, "trufflehog")
        os.makedirs(self.bin, exist_ok=True)
        with open(p, "wb") as f:
            f.write(SH)
        os.chmod(p, 0o755)
        wt.SCANNER_LOCK_EXTRA["trufflehog"] = wt.scanner_digest(p)
        return p


class Launch(_T):
    def test_1_a_scanner_that_reruns_its_own_path_runs(self):
        p = self.sh_as_trufflehog()
        code, out, err = wt.run([p, "-c", RERUN], 20)
        self.assertEqual((code, out), (0, "child-ok\n"), err)
        self.assertNotIn("trufflehog", wt.SCANNER_PROBLEMS)
        self.assertEqual(wt.scanner_x005(), [])

    def test_2_a_copy_swapped_before_exec_is_x005_and_no_results(self):
        p = self.sh_as_trufflehog()
        self.swap = SH + b"\0"
        code, out, err = wt.run([p, "-c", "echo results"], 20)
        self.assertEqual((code, out), (126, ""), err)
        self.assertTrue(err.startswith("results discarded"), err)
        self.assertEqual(wt.SCANNER_PROBLEMS["trufflehog"][0], "changed")
        self.assertEqual(x005("trufflehog"), [("WT-X005", "high", "trufflehog")])

    def test_3_a_copy_swapped_during_the_run_is_x005_and_no_results(self):
        p = self.sh_as_trufflehog()
        code, out, err = wt.run([p, "-c", SWAP_DURING], 20)
        self.assertEqual((code, out), (126, ""), err)
        self.assertTrue(err.startswith("results discarded"), err)
        self.assertEqual(wt.SCANNER_PROBLEMS["trufflehog"][0], "changed")
        self.assertEqual(x005("trufflehog"), [("WT-X005", "high", "trufflehog")])

    def test_4_the_private_folder_is_always_removed(self):
        p = self.sh_as_trufflehog()
        # "; exit 0": sh -c may replace itself with a lone last command, and a native program running another file is a change
        for case, argv, timeout in (("success", [p, "-c", RERUN], 20), ("exit 1", [p, "-c", "exit 1"], 20),
                                    ("swap", [p, "-c", "echo results"], 20), ("timeout", [p, "-c", "sleep 30; exit 0"], 2),
                                    ("start fails", [p, "-c", "echo results"], 20)):
            with self.subTest(case):
                wt.SCANNER_PROBLEMS.clear(); wt.SCANNERS_HELD.clear()
                self.seen[:] = []
                self.swap = SH + b"\0" if case == "swap" else None
                self.refuse = case == "start fails"
                t0 = time.monotonic()
                code = wt.run(argv, timeout)[0]
                took = time.monotonic() - t0
                self.assertTrue([e for e in self.seen if self.under(e)], self.seen)
                self.assertEqual(os.listdir(self.tmpd), [])
                if case == "timeout":
                    self.assertEqual(code, 124)
                    self.assertLess(took, 10)


class EnginesUsed(_T):
    def test_5_a_failed_trufflehog_stage_is_not_an_engine_used(self):
        with open(os.path.join(self.ws, "deploy.env"), "w") as f:
            f.write("GITHUB_TOKEN=" + token("ghp_", 36) + "\n")
        log = os.path.join(self.tmp, "trufflehog.log")

        def engines_and_fingerprint():
            used = wt.load_json(wt.state_path("engines_used.json"), {})["engines"]
            with open(wt.state_path("score_history.csv")) as f:
                last = f.read().splitlines()[-1]
            return used, last.rsplit(",", 1)[1].split("|", 1)[1].split("+")
        self.scanners()
        self.audit()
        used, fp = engines_and_fingerprint()
        self.assertIn("TruffleHog", used)                    # contrast: a stage that finished counts (passes on 1a4805c too)
        self.assertIn("TruffleHog", fp)
        self.scanners(trufflehog=b3.logged("#!/bin/sh\necho 'failed to stat binary' >&2\nexit 1\n", log))
        self.audit()
        self.assertTrue(os.path.exists(log))                 # the stage ran
        snap = self.snap()
        self.assertIn("TruffleHog (which keys still work)", snap["stages_skipped"])
        used, fp = engines_and_fingerprint()
        self.assertNotIn("TruffleHog", used)
        self.assertNotIn("TruffleHog", fp)
        self.assertEqual(snap["scanners_missing"], ["TruffleHog"])

    def test_6_a_failed_stage_drops_each_single_scanner(self):
        saved = list(wt.STAGE_FAILED)
        self.addCleanup(lambda: wt.STAGE_FAILED.__setitem__(slice(None), saved))
        del wt.STAGE_FAILED[:]   # an earlier audit's failed stages stay in it until the next audit
        for name, stage in (("gitleaks", "gitleaks (keys in files)"), ("pip-audit", "pip-audit (installed Python packages)"),
                            ("osv-scanner", "OSV-Scanner (project dependencies)"), ("trufflehog", "TruffleHog (which keys still work)")):
            with self.subTest(name):
                self.put(name, "#!/bin/sh\nexit 0\n")
                wt.STAGE_FAILED.append(stage)
                self.assertFalse(wt.scanner_used(name))
                wt.STAGE_FAILED.remove(stage)
                self.assertTrue(wt.scanner_used(name))       # contrast: used again once its stage didn't fail


if __name__ == "__main__":
    unittest.main()
