"""Environment profiles (v0.6.9): the tool degrades gracefully on every kind of computer."""
import ast, json, os, re, subprocess, sys, unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import Box, wt, ROOT  # noqa: E402
import profiles  # noqa: E402

WT = os.path.join(ROOT, "watchtower", "wt.py")


class Profiles(Box):
    def everyday(self, *extra):
        """What the routines run. run_cmd already fails on any traceback."""
        r = self.audit(*extra)
        self.assertIsInstance(r["score"], int)
        self.assertIn("score_line", r)
        code, o, _ = self.run_cmd("daily", "--roots", *self.roots)
        self.assertEqual(code, 0)
        self.assertEqual(self.run_cmd("report")[0], 0)
        self.assertEqual(self.run_cmd("doctor")[0], 0)
        return r

    def test_empty_account(self):
        profiles.empty_account(self); self.scanners()
        r = self.everyday()
        self.assertEqual(r["inventory"]["skills"], 0)
        self.assertEqual(self.run_cmd("rollcall", "--owner-said-yes")[0], 0)      # no replies: nothing to do, no error
        import urllib.error
        with mock.patch.object(wt, "http_get", side_effect=urllib.error.URLError("offline")):
            self.assertEqual(self.run_cmd("brief")[0], 0)

    def test_power_user(self):
        ds = profiles.power_user(self); self.scanners()
        self.assertGreaterEqual(len(ds), 100)
        code, o, _ = self.run_cmd("rollcall", "--owner-said-yes")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(o)["bots_checked"], 24)                       # the list may be trimmed to fit; the count never is
        r = self.everyday("--everything")   # v0.7.1 item 1: half of these sit in ~/projects, checked once the owner says "scan everything"
        self.assertGreaterEqual(r["inventory"]["skills"], 100)
        self.assertEqual(wt.load_json(wt.state_path("engines.json"), {})["waiting"], 0)

    def test_no_git_and_no_scanners(self):
        self.skills(3); self.scanners(all=None)
        empty = os.path.join(self.tmp, "emptybin"); os.makedirs(empty)
        with mock.patch.dict(os.environ, {"PATH": empty}):
            r = self.everyday()
        self.assertTrue(any("not installed" in n or "SCANNERS" in n.upper() for n in r.get("notes", [])) or r.get("scanners_missing"), r)

    def test_old_python(self):
        src = open(WT).read()
        ast.parse(src, feature_version=(3, 8))                                     # the grammar is 3.8's
        for api in ("removeprefix(", "removesuffix(", "zip(strict", "math.lcm", "tomllib", "ExceptionGroup", "from zoneinfo"):
            self.assertNotIn(api, src, api)                                         # nothing newer than 3.8 at run time
        p = subprocess.run([sys.executable, "-c", "import sys; sys.version_info = (3, 7, 9, 'final', 0); p = sys.argv[1]; "
                            "exec(compile(open(p).read(), p, 'exec'), {'__name__': '__main__', '__file__': p})", WT, "audit"],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 3, p.stdout + p.stderr)
        self.assertIn("needs Python 3.8", p.stdout + p.stderr); self.assertNotIn("Traceback", p.stderr)

    def test_github_and_pypi_blocked(self):
        import urllib.error
        self.skills(2); self.scanners()
        self.audit()
        with mock.patch.object(wt, "http_get", side_effect=urllib.error.URLError("blocked by network policy")):
            code, o, e = self.run_cmd("brief")
        self.assertEqual(code, 0, o + e)
        self.assertTrue(json.loads(o).get("brief"))

    def test_odd_permissions_and_layouts(self):
        profiles.odd_layout(self); self.scanners()
        r = self.everyday()
        self.assertGreaterEqual(r["inventory"]["skills"], 2)

    def test_strict_auto_review(self):
        profiles.strict_auto_review(self); self.scanners()
        r = self.everyday()
        fs = self.snap()["findings"]
        self.assertFalse([f for f in fs if f["rule"].startswith("ISR-A0")], [f["rule"] for f in fs])
        self.assertFalse([f for f in fs if f["rule"] == "ISR-T013" and f.get("class") != "tip"])

    def test_emoji_and_non_english_names(self):
        ds = profiles.emoji_names(self); self.scanners()
        code, o, _ = self.run_cmd("rollcall", "--owner-said-yes")
        self.assertEqual(code, 0); self.assertIn("Ïris 🤖", json.loads(o)["bots"])
        r = self.everyday()
        self.assertGreaterEqual(r["inventory"]["skills"], len(ds))
        md = open(os.path.join(os.environ["WATCHTOWER_HOME"], "reports", sorted(os.listdir(os.path.join(os.environ["WATCHTOWER_HOME"], "reports")))[0]), encoding="utf-8").read()
        self.assertTrue(md)
        stage = os.path.join(self.tmp, "stage", "Bot"); os.makedirs(stage)
        open(os.path.join(stage, "routine-a.md"), "w").write("Never send without my approval. José reads it; Танго drafts.\n")
        code, o, _ = self.run_cmd("prepublish", stage, "--json")
        self.assertEqual(sorted(f["evidence"] for f in json.loads(o)["findings"] if f["rule"] == "ISR-PP08"), ["José", "Танго"])
