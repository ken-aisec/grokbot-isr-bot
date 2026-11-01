"""v0.8.4 (a): the cleanup preview trims what it shows, but tidy_plan.json keeps every step and `fix --apply` does every step.

Before: a scrub of 20 chat logs was trimmed to about 6 rows to fit the preview, only those 6 were saved, and `--apply` did the
6 and said nothing about the other 14. Now the preview says how many steps it hides, the saved list has all of them, and apply
says one line per saved step (done, could not, or not touched and why) and ends with "done N of M".

Tests marked "replay" fail on abea324 at their assertion; the "control" passes there too."""
import json, os, sys, time, unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import Box  # noqa: E402
import isr  # noqa: E402


def fake_key(i):
    return "gh" + "p_" + ("q7W" + f"{i:03d}") * 6          # GitHub-shaped, built here, never a real key


def read(p):
    with open(p) as f:
        return f.read()


class TrimmedTidyPlan(Box):
    def logs(self, n=20):
        d = os.path.join(self.home, ".codex", "sessions", "2026", "10", "20"); os.makedirs(d)
        paths = []
        for i in range(n):
            p = os.path.join(d, f"rollout-2026-10-20T08-{i:02d}-00-" + "0123abcd" * 12 + ".jsonl")
            with open(p, "w") as f:
                f.write('{"role": "user", "text": "use ' + fake_key(i) + ' for the repo"}\n')
            paths.append(p)
        return paths

    def preview(self, paths):
        with mock.patch.object(isr, "scrub_targets_from_findings", return_value=list(paths)):
            code, o, _ = self.run_cmd("fix", "--roots", *self.roots)
        return json.loads(o)

    def apply(self, paths, *extra):
        with mock.patch.object(isr, "scrub_targets_from_findings", return_value=list(paths)):
            code, o, _ = self.run_cmd("fix", "--apply", "--owner-said-yes", *extra, "--roots", *self.roots)
        return json.loads(o)["done"]

    def tidy_plan(self):
        return isr.load_json(isr.state_path("tidy_plan.json"), {})

    def test_the_saved_list_has_every_step_and_the_preview_says_how_many_it_hides(self):
        """replay"""
        paths = self.logs()
        shown = self.preview(paths)
        self.assertIn("safe_fixes", shown.get("truncated", {}))
        n = len(shown["safe_fixes"])
        saved = self.tidy_plan()
        self.assertEqual([x["path"] for x in saved["items"]], paths)
        self.assertEqual([(x["id"], x["action"], x["files"], x["count"]) for x in saved["items"]],
                         [(str(i), "scrub_keys", 1, 1) for i in range(1, 21)])
        self.assertTrue(all(x.get("owner") for x in saved["items"]))
        self.assertEqual((saved["shown"], saved["hidden"]), (n, 20 - n))
        self.assertLess(n, 20)
        note = shown["safe_fixes_not_shown"]
        self.assertIn(f"Showing {n} of 20 cleanup steps", note)
        self.assertIn(f"the other {20 - n} (ids {n + 1} to 20: {20 - n} key scrubs in chat, session or log files)", note)
        self.assertIn("done too when the owner says yes", note)
        self.assertLessEqual(len(json.dumps(shown, indent=1)), 6000)

    def test_yes_scrubs_all_twenty_with_one_line_each_and_done_20_of_20(self):
        """replay"""
        paths = self.logs()
        self.preview(paths)
        done = self.apply(paths)
        texts = [read(p) for p in paths]
        self.assertEqual([fake_key(i) in t for i, t in enumerate(texts)], [False] * 20)
        self.assertTrue(all(isr.REDACTED in t for t in texts))
        self.assertEqual(len(done), 21, done)
        for p in paths:
            self.assertEqual(len([d for d in done if os.path.basename(p) in d]), 1, (p, done))
        self.assertTrue(done[-1].startswith("done 20 of 20"), done[-1])

    def test_skipped_changed_and_failing_steps_each_get_a_line_and_the_rest_are_done(self):
        """replay"""
        paths = self.logs()
        self.preview(paths)
        ids = {x["path"]: x["id"] for x in self.tidy_plan()["items"]}
        skipped, changed, failing = paths[2], paths[9], paths[15]
        with open(changed, "w") as f:                                   # its key taken out by hand since the preview
            f.write('{"role": "user", "text": "nothing here now"}\n')
        os.makedirs(failing + ".isr-bot-tmp")                           # the scrub can't write its new copy
        done = self.apply(paths, "--skip", ids[skipped])
        self.assertEqual([fake_key(i) in read(p) for i, p in enumerate(paths) if p not in (skipped, changed, failing)], [False] * 17)
        self.assertIn(fake_key(2), read(skipped))
        self.assertIn(fake_key(15), read(failing))
        self.assertEqual(len(done), 21, done)
        line = lambda p: [d for d in done if os.path.basename(p) in d]
        for p in paths:
            self.assertEqual(len(line(p)), 1, (p, done))
        self.assertTrue(line(skipped)[0].startswith("Left alone as you asked"), line(skipped))
        self.assertTrue(line(changed)[0].startswith("Not touched because it is no longer on the list"), line(changed))
        self.assertTrue(line(failing)[0].startswith("Could not scrub_keys"), line(failing))
        self.assertTrue(done[-1].startswith("done 17 of 20"), done[-1])

    def test_a_list_that_fits_has_no_hidden_count_and_no_done_n_of_m_line(self):
        """control"""
        paths = self.logs(3)
        shown = self.preview(paths)
        self.assertNotIn("truncated", shown)
        self.assertNotIn("safe_fixes_not_shown", shown)
        done = self.apply(paths)
        self.assertEqual(len(done), 3, done)
        self.assertFalse([d for d in done if d.startswith("done ")], done)


class OverlappingRootsAndTightPreview(Box):
    """v0.8.4 (a), Codex review: (1) with overlapping roots the same folder is on the saved list twice under two ids, and
    skipping one id still emptied it through the other; (2) the second trim could hide a step of another kind, so the note
    grew past the room kept for it and the preview went over 6000 characters."""

    def shared_cache(self):
        d = os.path.join(self.ws, "project", "agent-tools"); os.makedirs(d)
        old = time.time() - 3 * 86400
        for i in range(3):
            p = os.path.join(d, f"result-{i}.json")
            with open(p, "w") as f:
                f.write("{}\n")
            os.utime(p, (old, old))
        os.utime(d, (old, old))
        return d

    def run_fix(self, *extra):
        roots = [self.ws, os.path.join(self.ws, "project")]
        code, o, _ = self.run_cmd("fix", *extra, "--roots", *roots)
        return json.loads(o)

    def test_skipping_one_id_leaves_the_folder_alone_under_both_ids(self):
        """replay"""
        d = self.shared_cache()
        self.run_fix()
        items = isr.load_json(isr.state_path("tidy_plan.json"), {})["items"]
        self.assertEqual([(x["action"], x["path"]) for x in items], [("empty_tool_cache", d)] * 2)
        done = self.run_fix("--apply", "--owner-said-yes", "--skip", items[0]["id"])["done"]
        self.assertEqual(len(os.listdir(d)), 3, done)
        self.assertEqual(len([x for x in done if x.startswith("Left alone as you asked") and d in x]), 2, done)
        self.assertFalse([x for x in done if x.startswith("Emptied")], done)

    def test_without_a_skip_the_folder_listed_twice_is_emptied_once(self):
        """replay"""
        d = self.shared_cache()
        self.run_fix()
        done = self.run_fix("--apply", "--owner-said-yes")["done"]
        self.assertEqual(os.listdir(d), [])
        self.assertEqual([x for x in done if x.startswith("Emptied")], [f"Emptied {d} (3 files)"], done)
        self.assertEqual(len(done), 2, done)

    def test_a_mixed_eighteen_step_preview_stays_within_6000_characters(self):
        """replay: 16 tool caches, 1 key scrub and 1 old-report clean-up with long paths; the old preview was 6016 characters"""
        pad = 181
        plan = [{"id": str(i), "action": "empty_tool_cache", "path": f"/workspace/proj{i:02d}-" + "c" * pad + "/agent-tools",
                 "files": 40, "owner": "Cursor"} for i in range(1, 17)]
        plan.append({"id": "17", "action": "scrub_keys", "path": "/workspace/logs/run17-" + "s" * pad + ".jsonl", "files": 1,
                     "count": 2, "owner": "Codex"})
        plan.append({"id": "18", "action": "prune_reports", "path": "/workspace/reports18-" + "r" * pad, "files": 30, "owner": "ISR Bot"})
        with mock.patch.object(isr, "fix_plan", return_value=(plan, {"skipped_recent": [], "transcripts": []})), \
                mock.patch.object(isr, "python_upgrades", return_value=[]), mock.patch.object(isr, "npm_projects", return_value=[]), \
                mock.patch.object(isr, "cargo_projects", return_value={}):
            code, o, _ = self.run_cmd("fix", "--roots", *self.roots)
        out = o.rstrip("\n")
        self.assertLessEqual(len(out), 6000)
        shown = json.loads(out)
        n = len(shown["safe_fixes"])
        saved = isr.load_json(isr.state_path("tidy_plan.json"), {})
        self.assertEqual((saved["shown"], saved["hidden"]), (n, 18 - n))
        self.assertIn(f"Showing {n} of 18 cleanup steps", shown["safe_fixes_not_shown"])
        self.assertIn(f"the other {18 - n} (ids {n + 1} to 18:", shown["safe_fixes_not_shown"])


if __name__ == "__main__":
    unittest.main()
