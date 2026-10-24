"""The golden check for the isr.py split (tests/golden_split.py, scripts/golden-check.sh) fails loudly instead of passing quietly.

Codex round 1 on the split: without unshare the check fed the runner's envelope to norm_items and crashed, so nothing was
compared (H1); an ONLY that matched no scenario printed "post == pre on every tier run" after no comparison (H2); and
golden-check.sh compared against HEAD when no baseline was given, which fails step 0 once the split is committed (H3). These
tests drive the harness with stubs (no unshare, no sandbox run, no real path): the sandbox and the runs are replaced, and the
script runs from a copy with stub git and python3 first on PATH."""
import os, shutil, subprocess, sys, tempfile, unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import golden_split as gs  # noqa: E402  (the module, never its TestCase: that would run the real check here)

ITEMS = {"001 --version :rc": "0", "001 --version :stdout": "isr.py 1.0\n", "001 --version :stderr": ""}


class _Harness(unittest.TestCase):
    def harness(self, sandbox=True, post_items=ITEMS):
        """A GoldenSplit whose tree runs are stubs: every run returns ITEMS (post returns post_items) and is recorded."""
        class Harness(gs.GoldenSplit):
            report, failed, MODE, pre, post = [], False, "quick", "<pre tree>", "<post tree>"
        Harness.sandbox = sandbox
        h, calls = Harness("test_1_tiers"), []

        def run(sid, plan, tag):
            calls.append((sid, tag))
            return {"items": dict(post_items if tag == "post" else ITEMS)}
        h.place = lambda tree: None
        h.run_sandboxed = run
        h.run_plain = run          # the fallback the check had before round 1; the check must never use it
        h.timing = lambda: self.fail("timing never runs in quick mode")
        return h, calls

    def outcome(self, h):
        try:
            h.test_1_tiers()
        except AssertionError as e:
            return "failed: " + str(e)
        except Exception as e:
            return f"crashed: {type(e).__name__}: {e}"
        return "passed"

    def assertFailedLoudly(self, h, out, why):
        self.assertTrue(out.startswith("failed: "), out)
        self.assertIn(why, out)
        self.assertTrue(type(h).failed, "the failure keeps the check's folder")
        self.assertFalse([l for l in type(h).report if l.startswith("RESULT")], type(h).report)


class H1NoSandbox(_Harness):
    def test_without_unshare_the_check_fails_and_compares_nothing(self):
        h, calls = self.harness(sandbox=False)
        with mock.patch.dict(os.environ, {"ISR_GOLDEN_ONLY": ""}):
            out = self.outcome(h)
        self.assertFailedLoudly(h, out, "sealed sandbox")
        self.assertEqual(calls, [], "no tree runs unsealed")


class H2EmptySelection(_Harness):
    def test_an_only_that_matches_no_scenario_fails(self):
        h, calls = self.harness()
        with mock.patch.dict(os.environ, {"ISR_GOLDEN_ONLY": "no-such-scenario"}):
            out = self.outcome(h)
        self.assertFailedLoudly(h, out, "matches no quick scenario")
        self.assertEqual(calls, [])

    def test_a_run_that_compared_nothing_fails(self):
        h, calls = self.harness()
        h.scenarios = lambda: []
        out = self.outcome(h)
        self.assertFailedLoudly(h, out, "no scenario was compared")

    def test_one_matching_scenario_is_compared_and_counted(self):
        h, calls = self.harness()
        with mock.patch.dict(os.environ, {"ISR_GOLDEN_ONLY": "^tierA$"}):
            out = self.outcome(h)
        self.assertEqual(out, "passed")
        self.assertEqual(calls, [("tierA", "pre1"), ("tierA", "pre2"), ("tierA", "post")])
        self.assertIn("RESULT: post == pre on every tier run (1 scenarios compared)", type(h).report)

    def test_a_post_that_differs_is_still_caught(self):
        h, _ = self.harness(post_items=dict(ITEMS, **{"001 --version :stdout": "isr.py 1.1\n"}))
        with mock.patch.dict(os.environ, {"ISR_GOLDEN_ONLY": "^tierA$"}):
            out = self.outcome(h)
        self.assertFailedLoudly(h, out, "1 problems")


class H3BaselineRequired(unittest.TestCase):
    """scripts/golden-check.sh from a copy: stub git accepts every ref, stub python3 prints what it was given."""
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="isr-bot-golden-harness-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        for d in ("scripts", "bin"):
            os.makedirs(os.path.join(self.tmp, d))
        self.script = os.path.join(self.tmp, "scripts", "golden-check.sh")
        shutil.copy2(os.path.join(ROOT, "scripts", "golden-check.sh"), self.script)
        for name, body in (("git", "exit 0\n"), ("python3", 'echo "STUB python3 pre=$ISR_GOLDEN_PRE tiers=$ISR_GOLDEN_TIERS"\n')):
            p = os.path.join(self.tmp, "bin", name)
            with open(p, "w") as f:
                f.write("#!/bin/sh\n" + body)
            os.chmod(p, 0o755)

    def check(self, *argv):
        env = {"PATH": os.path.join(self.tmp, "bin") + ":/usr/bin:/bin", "LC_ALL": "C.UTF-8"}
        return subprocess.run([shutil.which("bash") or "/bin/bash", self.script, *argv], capture_output=True, text=True, env=env,
                              cwd=self.tmp, timeout=60)

    def test_no_baseline_is_a_usage_error(self):
        for argv in ((), ("",)):
            p = self.check(*argv)
            self.assertEqual((p.returncode, p.stdout), (2, ""), (argv, p.stdout, p.stderr))
            self.assertIn("no baseline ref given", p.stderr)
            self.assertIn("usage: scripts/golden-check.sh PRE_REF", p.stderr)

    def test_a_given_baseline_is_passed_on(self):
        p = self.check("9b106b9", "quick")
        self.assertEqual((p.returncode, p.stdout.strip()), (0, "STUB python3 pre=9b106b9 tiers=quick"), p.stderr)


if __name__ == "__main__":
    unittest.main()
