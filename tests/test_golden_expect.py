"""Batch 5, item 0: the golden check's expect mode (tests/golden_split.py, scripts/golden-check.sh --expect FILE --items A,B).

Batch 5 changes behavior on purpose, so the golden check accepts a difference between pre and post only when an entry of an
enabled item in the expect file names its lines; anything else, and a must_see entry that matched nothing, fails it. Without
--expect it is exactly the split check (step 0's byte comparison included). Like test_golden_harness, these drive the harness
with stubs: no sandbox, no tree run, no git archive."""
import os, shutil, subprocess, sys, tempfile, unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import golden_split as gs  # noqa: E402  (the module, never its TestCase)

PRE = {"001 audit :rc": "0", "001 audit :stdout": '{\n "masked": 3,\n "status": "ok"\n}\n', "001 audit :stderr": ""}
POST = dict(PRE, **{"001 audit :stdout": '{\n "masked": 4,\n "status": "ok"\n}\n'})


def entry(**kw):
    e = {"item": "c", "scenario_rx": "^tierA$", "key_rx": r"audit :stdout$", "lines_rx": [r'^[-+] "masked": [34],$'],
         "must_see": False, "why": "MASK_VERSION 3 -> 4"}
    e.update(kw)
    return e


class _Expect(unittest.TestCase):
    def harness(self, entries, items, post=POST):
        class Harness(gs.GoldenSplit):
            report, failed, MODE, pre, post = [], False, "quick", "<pre tree>", "<post tree>"
            ITEMS = list(items)
        Harness.sandbox = True
        Harness.expect = gs.parse_expect({"entries": entries}, items)
        h = Harness("test_1_tiers")
        h.place = lambda tree: None
        h.run_sandboxed = lambda sid, plan, tag: {"items": dict(post if tag == "post" else PRE)}
        h.timing = lambda: None
        return h

    def outcome(self, h):
        with mock.patch.dict(os.environ, {"WT_GOLDEN_ONLY": "^tierA$"}):
            try:
                h.test_1_tiers()
            except AssertionError as e:
                return "failed: " + str(e)
        return "passed"


class ExpectedDifferences(_Expect):
    def test_an_unlisted_difference_fails(self):
        h = self.harness([], [])
        self.assertTrue(self.outcome(h).startswith("failed: 1 problems"))
        self.assertTrue(any('-"masked":3,' in l.replace(" ", "") for l in type(h).report), type(h).report)
        self.assertFalse([l for l in type(h).report if l.startswith("RESULT")])

    def test_a_listed_difference_passes_and_is_counted(self):
        h = self.harness([entry()], ["c"])
        self.assertEqual(self.outcome(h), "passed", type(h).report)
        rep = "\n".join(type(h).report)
        self.assertIn("c 2 lines by 1 entries", rep)
        self.assertIn("RESULT: post == pre on every tier run except the expected differences of c", rep)

    def test_a_listed_line_in_another_item_or_scenario_is_not_expected(self):
        for e in (entry(key_rx="report :stdout$"), entry(scenario_rx="^box-")):
            h = self.harness([e], ["c"])
            self.assertTrue(self.outcome(h).startswith("failed: 1 problems"), e)

    def test_one_unlisted_line_among_listed_ones_fails(self):
        post = dict(POST, **{"001 audit :stdout": '{\n "masked": 4,\n "status": "Act now"\n}\n'})
        h = self.harness([entry()], ["c"], post=post)
        self.assertTrue(self.outcome(h).startswith("failed: 1 problems"))
        self.assertIn('"status": "Act now"', "\n".join(type(h).report))

    def test_an_unmet_must_see_fails(self):
        h = self.harness([entry(must_see=True)], ["c"], post=PRE)
        out = self.outcome(h)
        self.assertTrue(out.startswith("failed: 1 problems"), out)
        self.assertIn("must_see entry 0 matched nothing", "\n".join(type(h).report))

    def test_a_must_see_whose_scenario_did_not_run_is_not_a_problem(self):
        h = self.harness([entry(), entry(scenario_rx="^box-platform_refresh", must_see=True)], ["c"])
        self.assertEqual(self.outcome(h), "passed", type(h).report)

    def test_entries_of_items_not_enabled_are_ignored(self):
        h = self.harness([entry(item="d1", must_see=True)], ["c"])
        self.assertTrue(self.outcome(h).startswith("failed: 1 problems"))
        self.assertNotIn("must_see", "\n".join(type(h).report))

    def test_a_new_item_is_a_line_of_its_own(self):
        post = dict(PRE, **{"tree workspace/watchtower/state/new.json": "file 0600\n{}"})
        self.assertEqual(gs.diff_lines(None, "file 0600\n{}"), [gs.NEW_ITEM, "+file 0600", "+{}"])
        self.assertEqual(gs.diff_lines("a\n", None), [gs.GONE_ITEM, "-a"])
        self.assertEqual(gs.diff_lines("a\n", "a"), ["~line ends differ"])
        e = entry(key_rx=r"^tree workspace/watchtower/state/new\.json$", lines_rx=[r"^\+<new item>$", r"^\+file 0600$", r"^\+\{\}$"])
        h = self.harness([e], ["c"], post=post)
        self.assertEqual(self.outcome(h), "passed", type(h).report)


class NarrowPatterns(unittest.TestCase):
    def test_catch_all_line_patterns_are_refused(self):
        for rx in (".*", ".+", "", "   ", "^.*$", "^[-+]", "[+-].*", r"^\+", "^-", "(?s).", "x|"):
            with self.assertRaises(ValueError, msg=rx):
                gs.parse_expect({"entries": [entry(lines_rx=[r'^[-+] "masked"', rx])]}, ["c"])

    def test_refused_in_a_disabled_item_too(self):
        with self.assertRaises(ValueError):
            gs.parse_expect({"entries": [entry(item="b", lines_rx=[".*"])]}, ["c"])

    def test_malformed_entries_are_refused(self):
        for bad in ({"entries": "x"}, [], {"entries": [dict(entry(), extra=1)]}, {"entries": [entry(why=" ")]},
                    {"entries": [entry(lines_rx=[])]}, {"entries": [entry(must_see="yes")]}, {"entries": [entry(key_rx="(")]}):
            with self.assertRaises(ValueError, msg=repr(bad)):
                gs.parse_expect(bad, ["c"])

    def test_the_shipped_file_parses_with_every_item(self):
        import json
        with open(os.path.join(ROOT, "tests", "golden_expect", "batch5.json")) as f:
            doc = json.load(f)
        items = sorted({e["item"] for e in doc["entries"]})
        self.assertEqual(len(gs.parse_expect(doc, items)), len(doc["entries"]))


class StepZero(unittest.TestCase):
    """Without --expect the byte comparison runs exactly as for the split; with it, only compile and loader checks."""
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wt-golden-expect-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        os.makedirs(os.path.join(self.tmp, "watchtower", "wt_parts"))
        with open(os.path.join(self.tmp, "watchtower", "wt.py"), "wb") as f:
            f.write(b"x = 1\n")

    def step0(self, pre_bytes, expect):
        class Harness(gs.GoldenSplit):
            report, failed, MODE, PRE, untracked = [], False, "quick", "151e40c", []
            ITEMS = []
        Harness.post = self.tmp
        Harness.expect = expect
        h = Harness("test_0_reassembly")
        show = lambda *a, **k: b"151e40c\n" if a[0] == "rev-parse" else pre_bytes
        with mock.patch.object(gs, "git", show):
            try:
                h.test_0_reassembly()
            except AssertionError as e:
                return "failed: " + str(e), type(h).report
        return "passed", type(h).report

    def test_no_expect_mode_still_compares_bytes(self):
        out, rep = self.step0(b"x = 2\n", None)
        self.assertTrue(out.startswith("failed: step 0: the reassembled wt.py differs"), out)
        out, rep = self.step0(b"x = 1\n", None)
        self.assertEqual(out, "passed")
        self.assertIn("byte-equal", rep[-1])

    def test_expect_mode_checks_compile_and_the_loader_block(self):
        out, rep = self.step0(b"x = 2\n" + gs.LOADER_BEGIN, [])
        self.assertEqual(out, "passed")
        self.assertIn("step 0: behavior-change mode, byte check not applicable", rep[-1])
        out, rep = self.step0(b"x = 2\n", [])
        self.assertIn("no wt_parts loader block", out)
        with open(os.path.join(self.tmp, "watchtower", "wt.py"), "wb") as f:
            f.write(b"x = (\n")
        out, rep = self.step0(gs.LOADER_BEGIN, [])
        self.assertIn("does not compile", out)


class Script(unittest.TestCase):
    """scripts/golden-check.sh from a copy with stub git and python3 (as test_golden_harness.H3)."""
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wt-golden-expect-sh-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        for d in ("scripts", "bin"):
            os.makedirs(os.path.join(self.tmp, d))
        self.script = os.path.join(self.tmp, "scripts", "golden-check.sh")
        shutil.copy2(os.path.join(ROOT, "scripts", "golden-check.sh"), self.script)
        with open(os.path.join(self.tmp, "x.json"), "w") as f:
            f.write('{"entries": []}')
        for name, body in (("git", "exit 0\n"), ("python3", 'echo "STUB pre=$WT_GOLDEN_PRE tiers=$WT_GOLDEN_TIERS only=$WT_GOLDEN_ONLY '
                                                            'expect=$WT_GOLDEN_EXPECT items=$WT_GOLDEN_ITEMS"\n')):
            p = os.path.join(self.tmp, "bin", name)
            with open(p, "w") as f:
                f.write("#!/bin/sh\n" + body)
            os.chmod(p, 0o755)

    def check(self, *argv):
        env = {"PATH": os.path.join(self.tmp, "bin") + ":/usr/bin:/bin", "LC_ALL": "C.UTF-8"}
        return subprocess.run([shutil.which("bash") or "/bin/bash", self.script, *argv], capture_output=True, text=True, env=env,
                              cwd=self.tmp, timeout=60)

    def test_expect_and_items_are_passed_on(self):
        p = self.check("151e40c", "quick", "--expect", "x.json", "--items", "c,d1")
        self.assertEqual((p.returncode, p.stdout.strip()), (0, "STUB pre=151e40c tiers=quick only= expect=x.json items=c,d1"), p.stderr)
        p = self.check("--expect", "x.json", "--items", "", "151e40c", "full", "^tierA$")
        self.assertEqual(p.stdout.strip(), "STUB pre=151e40c tiers=full only=^tierA$ expect=x.json items=", p.stderr)

    def test_without_expect_nothing_changes(self):
        p = self.check("151e40c", "quick")
        self.assertEqual(p.stdout.strip(), "STUB pre=151e40c tiers=quick only= expect= items=", p.stderr)

    def test_usage_errors(self):
        for argv, why in ((("151e40c", "--items", "c"), "--items needs --expect"), (("151e40c", "--expect", "nosuch.json"), "no expect file"),
                          (("151e40c", "--expect"), "--expect needs a file"), (("--expect", "x.json"), "no baseline ref given")):
            p = self.check(*argv)
            self.assertEqual((p.returncode, p.stdout), (2, ""), argv)
            self.assertIn(why, p.stderr)


if __name__ == "__main__":
    unittest.main()
