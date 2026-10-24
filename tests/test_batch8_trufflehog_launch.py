"""Batch 8 (v0.7.4 dev), item b8i1: TruffleHog's launch.

In 0.7.3 every scanner ran from a sealed in-memory copy (/proc/self/fd/N). TruffleHog 3.97.9 runs overseer unless it is given
its hidden `--local-dev` flag; overseer's master asks the system for its own program file, gets "/memfd:isr-bot-scanner
(deleted)", can't stat it and exits ("failed to stat binary") before scanning anything. The stage failed and the last key status
was kept, but scanner_used() only checked the program file, so engines_used.json and score_history.csv's fingerprint still said
TruffleHog ran.

Now TruffleHog runs from the sealed copy like every other scanner, with `--local-dev` (overseer never starts), and nothing on disk
runs after the check. Its stage counts as finished only on exit 0 (or 183) with its "finished scanning" log line; a silent exit 0
(its signal handler exits 0) or a non-zero exit with partial output is a failed stage, and a scanner whose stage failed is not
used. The stand-ins for TruffleHog are /bin/sh scripts, registered in this process only; OVERSEER fails as overseer does unless
it is given --local-dev. Expected values are literals, so an older ISR Bot fails at an assertion instead of erroring.
Measured: T1-T3 and T4 (a)-(c) fail on 4c89284 or 1a4805c at their assertions (see CHANGELOG); T5 and T6 contrasts are marked.
Fix round 2: TruffleHog also gets --fail-on-scan-errors, and a stage that logged "encountered errors during scan" failed whatever
its exit; run() kills a timed-out program's whole process group. On 23476f2 T3 (the new flag assertion), T4 (h), T9 and T10
fail at their assertions; T4 (e), (g) and T8 pass there too (contrasts: the exit code and the finished line each count alone).
"""
import json, os, subprocess, sys, tempfile, time, unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import ROOT  # noqa: E402
import isr  # noqa: E402
import test_batch3_scanners as b3  # noqa: E402  (module access: its test classes don't run twice)
from test_batch6_example_keys import token  # noqa: E402

REAL_POPEN = subprocess.Popen
DONE = '{"level":"info-0","logger":"trufflehog","msg":"finished scanning","chunks":1}'
# Fix round 2: what upstream logs for non-fatal scan errors (it still logs DONE and exits 0 without --fail-on-scan-errors)
SCAN_ERR_TEXT = "open /srv/unreadable-scan-target: permission denied"
SCAN_ERRORS = json.dumps({"level": "error", "logger": "trufflehog", "msg": "encountered errors during scan", "errors": [SCAN_ERR_TEXT]})
# Launched from the sealed copy, $0 is /proc/self/fd/N; it links to "/memfd:isr-bot-scanner (deleted)", which can't be stat'ed
OVERSEER_CHECK = ('case " $* " in *" --local-dev "*) ;; *) x=$(readlink "$0" || echo "$0"); '
                  '[ -e "$x" ] || { echo "failed to stat binary" >&2; exit 1; };; esac\n')


def result(path):
    return "echo '" + json.dumps({"SourceMetadata": {"Data": {"Filesystem": {"file": path, "line": 1}}},
                                  "DetectorName": "Github", "Verified": True}) + "'\n"


class _T(b3._Scanners):
    def setUp(self):
        super().setUp()
        isr.SCANNERS_HELD.clear()
        self.addCleanup(isr.SCANNERS_HELD.clear)
        self.tmpd = os.path.join(self.tmp, "tmpd")
        os.makedirs(self.tmpd)
        p = mock.patch.object(tempfile, "tempdir", self.tmpd)
        p.start(); self.addCleanup(p.stop)
        self.seen, self.swap = [], None
        p = mock.patch.object(isr.subprocess, "Popen", self.popen)
        p.start(); self.addCleanup(p.stop)
        self.env_file = os.path.join(self.ws, "deploy.env")
        with open(self.env_file, "w") as f:
            f.write("GITHUB_TOKEN=" + token("ghp_", 36) + "\n")
        self.good = "#!/bin/sh\n" + result(self.env_file) + "echo '" + DONE + "' >&2\n"
        self.log = os.path.join(self.tmp, "evil.log")

    def popen(self, *a, **k):
        """Records each launch's argv[0], program file and what its passed descriptor links to; on TruffleHog's launch (after
        ISR Bot's checks) it can rename a different program over bin/trufflehog."""
        argv, fds = list(a[0] if a else k["args"]), k.get("pass_fds") or ()
        link = os.readlink(f"/proc/self/fd/{fds[0]}") if fds else None
        self.seen.append((argv[0], k.get("executable"), link))
        th = os.path.join(self.bin, "trufflehog")
        if self.swap is not None and argv[0] == th:
            with open(th + ".n", "w") as f:
                f.write(self.swap)
            os.chmod(th + ".n", 0o755)
            os.rename(th + ".n", th)
        return REAL_POPEN(*a, **k)

    def launches(self):
        return [(exe, link) for a0, exe, link in self.seen if a0 == os.path.join(self.bin, "trufflehog")]

    def engines_and_fingerprint(self):
        used = isr.load_json(isr.state_path("engines_used.json"), {})["engines"]
        with open(isr.state_path("score_history.csv")) as f:
            last = f.read().splitlines()[-1]
        return used, last.rsplit(",", 1)[1].split("|", 1)[1].split("+")


class Launch(_T):
    def test_1_an_overseer_like_trufflehog_runs_with_local_dev(self):
        self.put("trufflehog", "#!/bin/sh\n" + OVERSEER_CHECK + result(self.env_file) + "echo '" + DONE + "' >&2\n")
        notes = []
        status = isr.trufflehog_status([self.env_file], notes)
        self.assertEqual(status, {self.env_file: [{"detector": "Github", "status": "live", "line": 1, "guide": None}]}, notes)
        self.assertFalse([n for n in notes if "FAILED" in n], notes)

    def test_2_trufflehog_runs_from_the_sealed_copy(self):
        self.put("trufflehog", self.good)
        self.swap = "#!/bin/sh\necho evil >> " + repr(self.log) + "\n"
        status = isr.trufflehog_status([self.env_file], [])
        (exe, link), = self.launches()
        self.assertRegex(exe or "", r"^/proc/self/fd/\d+$")
        self.assertTrue((link or "").startswith("/memfd:"), link)
        self.assertFalse(os.path.exists(self.log))           # the program renamed in after the check never ran
        self.assertEqual(status, {self.env_file: [{"detector": "Github", "status": "live", "line": 1, "guide": None}]})
        self.assertEqual(os.listdir(self.tmpd), [])          # nothing was copied to disk

    def test_3_argv_has_local_dev_and_no_update(self):
        args = os.path.join(self.tmp, "args.txt")
        self.put("trufflehog", "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + repr(args) + "\necho '" + DONE + "' >&2\n")
        isr.trufflehog_status([self.env_file], [])
        with open(args) as f:
            got = f.read().splitlines()
        self.assertEqual(got[0], "filesystem")
        for flag in ("--local-dev", "--no-update", "--json"):
            self.assertIn(flag, got)
        self.assertIn("--fail-on-scan-errors", got)          # fix round 2: a scan error is a non-zero exit

    def test_4_a_trufflehog_that_did_not_finish_is_a_failed_stage(self):
        self.scanners(trufflehog=self.good)
        self.audit()
        good = isr.load_json(isr.state_path("key_status.json"), {})
        self.assertEqual(list(good.get("files", {})), [self.env_file])   # guard: the good run's key status
        log = os.path.join(self.tmp, "trufflehog.log")
        for case, body in (("exit 0, nothing said", "#!/bin/sh\nexit 0\n"),
                           ("a result, exit 0, no finished line", "#!/bin/sh\n" + result(self.env_file) + "exit 0\n"),
                           ("a result, an error line, exit 1",
                            "#!/bin/sh\n" + result(self.env_file) + "echo 'error scanning chunk' >&2\nexit 1\n"),
                           ("a fatal line, exit 1, no output", "#!/bin/sh\necho 'fatal: could not start' >&2\nexit 1\n"),
                           # fix round 2: (e) the exit code counts on its own; (g) only a log line's msg says it finished; (h) a scan error
                           ("(e) a result, the finished line, exit 1",
                            "#!/bin/sh\n" + result(self.env_file) + "echo '" + DONE + "' >&2\nexit 1\n"),
                           ("(g) the finished text inside another field, exit 0",
                            "#!/bin/sh\n" + result(self.env_file) + "echo '" + json.dumps(
                                {"level": "info-0", "logger": "trufflehog", "msg": "scanning", "detail": "finished scanning"}) + "' >&2\nexit 0\n"),
                           ("(g) the finished text on a plain line, exit 0",
                            "#!/bin/sh\n" + result(self.env_file) + "echo 'finished scanning' >&2\nexit 0\n"),
                           ("(h) exit 0, the finished line and a scan-errors line",
                            "#!/bin/sh\n" + result(self.env_file) + "echo '" + SCAN_ERRORS + "' >&2\necho '" + DONE + "' >&2\nexit 0\n")):
            with self.subTest(case):
                if os.path.exists(log):
                    os.remove(log)
                isr.save_json(isr.state_path("key_status.json"), good)   # each case starts from the good run (an earlier case may have saved)
                self.scanners(trufflehog=b3.logged(body, log))
                r = self.audit()
                self.assertTrue(os.path.exists(log))             # the stage ran
                self.assertIn("TruffleHog (which keys still work)", self.snap()["stages_skipped"])
                used, fp = self.engines_and_fingerprint()
                self.assertNotIn("TruffleHog", used)
                self.assertNotIn("TruffleHog", fp)
                self.assertTrue([n for n in r["notes"] if "TruffleHog FAILED" in n], r["notes"])
                self.assertEqual(isr.load_json(isr.state_path("key_status.json"), {}), good)

    def test_8_exit_183_with_results_and_the_finished_line_is_a_finished_stage(self):
        """Fix round 2 (f): 183 is TruffleHog's "results found" exit, not a failure (contrast: passes on 23476f2 too)."""
        self.scanners(trufflehog="#!/bin/sh\n" + result(self.env_file) + "echo '" + DONE + "' >&2\nexit 183\n")
        r = self.audit()
        self.assertNotIn("TruffleHog (which keys still work)", self.snap()["stages_skipped"])
        used, fp = self.engines_and_fingerprint()
        self.assertIn("TruffleHog", used)
        self.assertIn("TruffleHog", fp)
        self.assertFalse([n for n in r["notes"] if "TruffleHog FAILED" in n], r["notes"])
        got = isr.load_json(isr.state_path("key_status.json"), {})["files"]
        self.assertEqual(got, {self.env_file: [{"detector": "Github", "status": "live", "line": 1, "guide": None}]})

    def test_9_scan_errors_fail_the_stage_without_their_text_in_the_note(self):
        """Fix round 2 (h): exit 0 and "finished scanning", but it logged "encountered errors during scan"."""
        self.put("trufflehog", "#!/bin/sh\n" + result(self.env_file) + "echo '" + SCAN_ERRORS + "' >&2\necho '" + DONE + "' >&2\n")
        notes = []
        self.assertEqual(isr.trufflehog_status([self.env_file], notes), {})
        self.assertEqual([n for n in notes if "TruffleHog FAILED" in n],
                         ["TruffleHog FAILED (it hit errors while scanning): live/dead key status is unavailable this run."])
        self.assertFalse([n for n in notes if "permission denied" in n or "unreadable-scan-target" in n], notes)


class Timeout(_T):
    def test_10_a_scanner_s_child_is_killed_with_it_on_time_out(self):
        """Fix round 2: run() starts each program in its own session and kills its process group on time-out, so a child it
        started (a detector's helper) doesn't go on running."""
        pidfile = os.path.join(self.tmp, "child.pid")
        exe = self.put("trufflehog", "#!/bin/sh\nsleep 300 &\necho $! > " + repr(pidfile) + "\nwait\n")
        child = []

        def gone(pid):
            try:
                with open(f"/proc/{pid}/cmdline", "rb") as f:
                    if f.read() != b"sleep\x00300\x00":
                        return True                                         # gone (a zombie's is empty), or the pid was reused
                with open(f"/proc/{pid}/stat") as f:
                    return f.read().rsplit(")", 1)[1].split()[0] == "Z"
            except FileNotFoundError:
                return True

        def cleanup():
            if child and not gone(child[0]):
                os.kill(child[0], 9)   # an older run() left it running: don't leave it behind the test
        self.addCleanup(cleanup)
        code, out, err = isr.run([exe], 2)
        self.assertEqual(code, 124, err)
        with open(pidfile) as f:
            child.append(int(f.read()))
        end = time.monotonic() + 5
        while not gone(child[0]) and time.monotonic() < end:
            time.sleep(0.05)
        self.assertTrue(gone(child[0]), f"the scanner's child {child[0]} is still running")


class EnginesUsed(_T):
    def test_5_a_failed_trufflehog_stage_is_not_an_engine_used(self):
        with open(os.path.join(self.ws, "deploy.env"), "w") as f:
            f.write("GITHUB_TOKEN=" + token("ghp_", 36) + "\n")
        log = os.path.join(self.tmp, "trufflehog.log")

        def engines_and_fingerprint():
            used = isr.load_json(isr.state_path("engines_used.json"), {})["engines"]
            with open(isr.state_path("score_history.csv")) as f:
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
        saved = list(isr.STAGE_FAILED)
        self.addCleanup(lambda: isr.STAGE_FAILED.__setitem__(slice(None), saved))
        del isr.STAGE_FAILED[:]   # an earlier audit's failed stages stay in it until the next audit
        for name, stage in (("gitleaks", "gitleaks (keys in files)"), ("pip-audit", "pip-audit (installed Python packages)"),
                            ("osv-scanner", "OSV-Scanner (project dependencies)"), ("trufflehog", "TruffleHog (which keys still work)")):
            with self.subTest(name):
                self.put(name, "#!/bin/sh\nexit 0\n")
                isr.STAGE_FAILED.append(stage)
                self.assertFalse(isr.scanner_used(name))
                isr.STAGE_FAILED.remove(stage)
                self.assertTrue(isr.scanner_used(name))       # contrast: used again once its stage didn't fail


class Pin(unittest.TestCase):
    def test_7_the_flags_are_pinned_to_trufflehog_3_97_9(self):
        """A tripwire: --local-dev is an undocumented upstream flag, and "finished scanning" is the log line run() ends with."""
        why = ("TruffleHog's pin moved: re-check in the new release's upstream main.go that --local-dev still skips overseer and "
               "that run() still ends by logging \"finished scanning\" (trufflehog_status relies on both), and that "
               "--fail-on-scan-errors and the \"encountered errors during scan\" line are unchanged, then update this test.")
        with open(os.path.join(ROOT, "scripts", "scanner-bins.lock")) as f:
            rows = [l for l in f if not l.startswith("#") and l.split()[1:2] == ["trufflehog"]]
        self.assertTrue(rows, why)
        for row in rows:
            self.assertIn("TruffleHog 3.97.9 ", row, why)
        with open(os.path.join(ROOT, "scripts", "install.sh")) as f:
            self.assertIn('TRUFFLEHOG_VERSION="3.97.9"', f.read(), why)


if __name__ == "__main__":
    unittest.main()
