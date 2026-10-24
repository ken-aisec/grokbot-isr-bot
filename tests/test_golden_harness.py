"""The golden check for the isr.py split (tests/golden_split.py, scripts/golden-check.sh) fails loudly instead of passing quietly.

Codex round 1 on the split: without unshare the check fed the runner's envelope to norm_items and crashed, so nothing was
compared (H1); an ONLY that matched no scenario printed "post == pre on every tier run" after no comparison (H2); and
golden-check.sh compared against HEAD when no baseline was given, which fails step 0 once the split is committed (H3). These
tests drive the harness with stubs (no unshare, no sandbox run, no real path): the sandbox and the runs are replaced, and the
script runs from a copy with stub git and python3 first on PATH."""
import json, os, shutil, subprocess, sys, tempfile, unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import golden_split as gs  # noqa: E402  (the module, never its TestCase: that would run the real check here)
import rename_v080 as rn  # noqa: E402

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


class CrossLayouts(_Harness):
    def test_each_tree_runs_in_its_own_layout(self):   # v0.8.0 unit i: layout_of, the plans, and the old tree's env names
        tmp = tempfile.mkdtemp(prefix="isr-bot-golden-harness-")
        self.addCleanup(shutil.rmtree, tmp, True)
        for name, L in gs.LAYOUTS.items():
            os.makedirs(os.path.join(tmp, name, L["pkg"]))
            open(os.path.join(tmp, name, L["pkg"], L["main"]), "w").close()
            self.assertEqual(gs.layout_of(os.path.join(tmp, name)), name)
        os.makedirs(os.path.join(tmp, "neither", rn.NEW["pkg"]))
        with self.assertRaises(ValueError):
            gs.layout_of(os.path.join(tmp, "neither"))
        # an old pre tree: pre1 and pre2 run in the old layout, post in the new one; the box builder always gets the new env names
        h, _ = self.harness()
        type(h).pre_layout = "old"
        plans = []
        h.run_sandboxed = lambda sid, plan, tag: plans.append((tag, plan)) or {"items": dict(ITEMS)}
        with mock.patch.dict(os.environ, {"ISR_GOLDEN_ONLY": "^tierA$"}):
            self.assertEqual(self.outcome(h), "passed")
        envs = {n: {k: L["env"][k] for k in ("home", "settings", "decoy_root")} for n, L in gs.LAYOUTS.items()}
        self.assertEqual([(t, p["layout"]["name"], p["layout"]["env"], p["builder_env"], p["cross"]) for t, p in plans],
                         [("pre1", "old", envs["old"], envs["new"], False), ("pre2", "old", envs["old"], envs["new"], False),
                          ("post", "new", envs["new"], envs["new"], False)])
        # (the unit c note) the runner's env for the old tree carries the old names (the table's) and its home the old one
        plan = os.path.join(tmp, "plan.json")
        with open(plan, "w") as f:
            json.dump(dict(plans[0][1], scratch=os.path.join(tmp, "run"), sealed=False, tree=tmp), f)
        prefix, sep, _ = gs.RUNNER.partition("\nn_cmd = [0]\n")   # the runner up to its env(): definitions only, nothing runs
        self.assertTrue(sep)
        ns = {}
        with mock.patch.object(sys, "argv", ["runner.py", plan]):
            exec(compile(prefix, "runner.py", "exec"), ns)
        for name, code in (("runner", gs.RUNNER), ("driver", ns["DRIVER"]), ("builder", ns["BUILDER"])):
            compile(code, name, "exec")   # the whole runner and the two programs it starts still compile
        home = ns["X"] + "/" + rn.OLD["sandbox_home"]
        e, b = ns["env"](), ns["env"](names=ns["PLAN"]["builder_env"])
        self.assertEqual([e.get(n) for n in envs["old"].values()], [home, ns["HOME_DIR"] + "/agent-data/settings.json", ns["X"] + "/decoys"])
        self.assertFalse(set(envs["new"].values()) & set(e))
        self.assertEqual([b.get(n) for n in envs["new"].values()], [home, ns["HOME_DIR"] + "/agent-data/settings.json", ns["X"] + "/decoys"])
        self.assertFalse(set(envs["old"].values()) & set(b))


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
