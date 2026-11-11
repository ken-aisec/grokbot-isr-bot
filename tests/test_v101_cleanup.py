"""1.0.1 (U1, U1b): "fix it" cleans keys only out of the three known agent chat-log folders, and keeps an undo copy.

Before: any flagged file whose path held chat, session or log (a project's chat-service/config.json, src/session/store.json, a
project's logs/server.log) was put on the tidy list, and the yes cut the key out of it with no copy kept. Now only files under
~/.grok/sessions, ~/.codex/sessions and ~/.cursor/projects/<project>/terminals are cleaned, each is copied first into
<the bot's home folder>/backups/cleanup-<UTC stamp>/ (mode 0700), the done line names the copy, and no copy means no change. The weekly
tidy offers to delete undo folders older than 14 days (prune_undo).

Each box runs a real audit with ISR Bot's own key rule and no scanners. Tests marked "replay" fail on bacd581 at their
assertion; the "guard" passes there too.

1.1.1: each planted key is an ISR Bot test fixture (isr.make_isr_fixture). An audit scores none of them; it names their files on
the snapshot's fixture_paths, which the cleanup reads beside the key findings, so a fixture in a chat log is still cleaned. No
assertion here echoes a planted key (assert_has_key / assert_lacks_key say a masked form only)."""
import datetime as dt, json, os, stat, sys, unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import Box, ROOT  # noqa: E402
import isr  # noqa: E402
from test_isr_bot import assert_has_key, assert_lacks_key  # noqa: E402


def planted(i):
    """A GitHub-shaped ISR Bot test fixture, built here at test time (never a real key)."""
    return isr.make_isr_fixture("ghp_", 36, seed=1010 + i)


def read(p):
    with open(p, "rb") as f:
        return f.read()


class Cleanup(Box):
    def put(self, p, i):
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write('{"role": "user", "text": "use ' + planted(i) + ' for the repo"}\n')
        return p

    def keyed(self, p):
        """The audit recognized the planted key in this file (so the cleanup has something to act on). 1.1.1: a fixture is no
        scored finding (none may name this file); the audit names the file on the snapshot's fixture_paths instead."""
        snap = self.snap()
        self.assertEqual([f["rule"] for f in snap.get("findings", []) if f["rule"] in ("ISR-S001", "ISR-S002")
                          and f["where"].split(":")[0] == p], [], "a planted fixture is never a scored key finding")
        return p in (snap.get("fixture_paths") or [])

    def preview(self):
        code, o, _ = self.run_cmd("fix", "--roots", *self.roots)
        self.assertEqual(code, 0)
        return [x["path"] for x in isr.load_json(isr.state_path("tidy_plan.json"), {}).get("items", [])
                if x.get("action") == "scrub_keys"]

    def apply(self):
        code, o, _ = self.run_cmd("fix", "--apply", "--owner-said-yes", "--roots", *self.roots)
        self.assertEqual(code, 0)
        return json.loads(o)["done"]

    def left_alone(self, p, i):
        self.put(p, i)
        before = read(p)
        self.audit()
        self.assertTrue(self.keyed(p), "the audit should flag the planted key")
        self.assertNotIn(p, self.preview())
        self.apply()
        self.assertEqual(read(p), before)

    def test_a_project_chat_service_config_is_not_touched(self):
        """replay (bacd581: a scrub_keys step for it, "chat")"""
        self.left_alone(os.path.join(self.ws, "chat-service", "config.json"), 1)

    def test_a_project_session_store_is_not_touched(self):
        """replay (bacd581: "session" puts it on the list)"""
        self.left_alone(os.path.join(self.ws, "app", "src", "session", "store.json"), 2)

    def test_a_project_log_is_not_touched(self):
        """replay (bacd581: /logs/ and .log put it on the list)"""
        self.left_alone(os.path.join(self.ws, "app", "logs", "server.log"), 3)

    def test_a_look_alike_folder_is_not_listed(self):
        """replay: .grok/sessions inside a workspace folder is not a home base's (bacd581: "session" lists it)"""
        p = self.put(os.path.join(self.ws, "notes", ".grok", "sessions", "x.json"), 4)
        self.audit()
        self.assertTrue(self.keyed(p))
        self.assertNotIn(p, self.preview())

    def test_a_grok_session_log_is_cleaned_with_an_undo_copy(self):
        """replay (bacd581: cleaned, no copy kept)"""
        p = self.put(os.path.join(self.home, ".grok", "sessions", "s1.jsonl"), 5)
        before = read(p)
        self.audit()
        self.assertIn(p, self.preview())
        done = self.apply()
        text = read(p).decode()
        assert_lacks_key(self, text, planted(5))
        self.assertIn(isr.REDACTED, text)
        line = [d for d in done if d.startswith("Removed ") and p in d]
        self.assertEqual(len(line), 1, done)
        self.assertIn("undo copy:", line[0])
        self.assertTrue(line[0].endswith(")"), line[0])
        copy = line[0].split("(undo copy: ", 1)[1][:-1]
        folder = os.path.dirname(copy)
        self.assertEqual(os.path.dirname(folder), os.path.join(isr.home(), "backups"))
        self.assertTrue(os.path.basename(folder).startswith("cleanup-"), folder)
        self.assertEqual(read(copy), before)
        self.assertEqual(stat.S_IMODE(os.stat(folder).st_mode), 0o700)
        with open(isr.state_path("ledger.jsonl")) as f:
            tidy = [e for e in (json.loads(x) for x in f if x.strip()) if e.get("event") == "tidy"]
        self.assertEqual(tidy[-1].get("undo"), folder)

    def test_no_undo_copy_no_change(self):
        """replay (bacd581: no copy tried, the file is cleaned)"""
        p = self.put(os.path.join(self.home, ".grok", "sessions", "s2.jsonl"), 6)
        self.audit()
        self.assertIn(p, self.preview())
        b = os.path.join(isr.home(), "backups")
        os.makedirs(b, exist_ok=True)
        os.chmod(b, 0o500)
        try:
            done = self.apply()
        finally:
            os.chmod(b, 0o700)
        assert_has_key(self, read(p), planted(6))   # 1.1.1: the Nov 5 incident line; never echoes the key
        self.assertTrue([d for d in done if d.startswith("Could not scrub_keys") and p in d], done)

    def test_the_fix_skill_says_where_the_undo_copy_is(self):
        """replay (bacd581: the skill never mentions it)"""
        with open(os.path.join(ROOT, "skills", "isr-bot-fix", "SKILL.md")) as f:
            self.assertIn("undo copy", f.read())

    def test_codex_sessions_and_cursor_terminals_are_still_listed(self):
        """guard (passes on bacd581 too)"""
        a = self.put(os.path.join(self.home, ".codex", "sessions", "2026", "11", "03", "rollout-a.jsonl"), 7)
        b = self.put(os.path.join(self.home, ".cursor", "projects", "w", "terminals", "1.txt"), 8)
        self.audit()
        listed = self.preview()
        self.assertIn(a, listed)
        self.assertIn(b, listed)

    def test_old_undo_folders_are_offered_for_deletion(self):
        """replay, U1b (bacd581: no such step)"""
        b = os.path.join(isr.home(), "backups")
        now = dt.datetime.now(dt.timezone.utc)
        old, new = [os.path.join(b, "cleanup-" + (now - dt.timedelta(days=d)).strftime("%Y%m%dT%H%M%SZ")) for d in (15, 1)]
        for d in (old, new):
            os.makedirs(d, mode=0o700)
            with open(os.path.join(d, "1-s1.jsonl"), "w") as f:
                f.write("{}\n")
        code, o, _ = self.run_cmd("fix", "--roots", *self.roots)
        steps = [x for x in isr.load_json(isr.state_path("tidy_plan.json"), {}).get("items", []) if x.get("action") == "prune_undo"]
        self.assertEqual([(x["path"], x["files"]) for x in steps], [(b, 1)])
        self.apply()
        self.assertFalse(os.path.exists(old))
        self.assertTrue(os.path.isdir(new))


if __name__ == "__main__":
    unittest.main()
