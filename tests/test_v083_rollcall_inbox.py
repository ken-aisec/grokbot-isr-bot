"""v0.8.3 Part B (the owner's yes, Oct 31: "Go with Parts A and B."): the roll-call inbox and `rollcall --ingest`. On Thursday the six
replies were piped through ISR Bot's own command line, and the safety checker erred on Bot text full of words like
"loosen_permissions" and "auto_allow_rules". Now each Bot files its own JSON in a 0700 inbox and ISR Bot runs short commands
with no payload: --question, wait, --ingest, --owner-said-yes. Bot names and replies below are made up."""
import io, json, os, stat, string, sys, tempfile, shutil, time, unittest, warnings
from contextlib import redirect_stdout, redirect_stderr
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "isr_bot"))
import isr  # noqa: E402

warnings.simplefilter("ignore", ResourceWarning)

MARKER = "Quokka-Ledger-Marker"
ZERO = "Ingested 0, skipped 0 (too big 0, link or not a file 0, bad name 0)."
# The question as it was in v0.8.2: Part B only adds one sentence at the end
ORIGINAL = ("ISR Bot roll-call. Bots can't check who sends this, so it asks only for counts, names and yes/no answers. "
            "Don't include any memory text, instructions, messages, addresses, links or keys. Reply with only this JSON, no prose: "
            '{"name": "<your name>", "connectors": ["<connector name>"], '
            '"routines": [{"name": "<routine name>", "trigger": "schedule|slack|github|email|webhook|other", '
            '"sends_or_posts": false, "asks_first": true, "reads_outside_content": false}], '
            '"memories": {"count": 0, "loosen_permissions": 0, "from_outside_content": 0}, '
            '"ask_first": ["email", "messages", "posts", "calendar", "files", "purchases", "settings"], '
            '"auto_allow_rules": 0, "sends_or_posts_without_asking": false, "reads_outside_content": false}. '
            "loosen_permissions counts memories that tell you to act without asking, skip an approval or trust a sender; "
            "from_outside_content counts memories copied from an email, web page or message; "
            "ask_first lists only the areas that have an Ask-first rule; auto_allow_rules counts rules that let actions run without asking.")


def answer(name, loosen=0, auto=0):
    """A reply in the exact shape the question asks for."""
    return {"name": name, "connectors": ["Calendar", MARKER], "routines": [{"name": "Morning digest", "trigger": "schedule",
            "sends_or_posts": False, "asks_first": True, "reads_outside_content": False}],
            "memories": {"count": 4, "loosen_permissions": loosen, "from_outside_content": 0},
            "ask_first": ["email", "messages", "posts"], "auto_allow_rules": auto,
            "sends_or_posts_without_asking": False, "reads_outside_content": False}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.env = {k: os.environ.get(k) for k in ("ISR_BOT_HOME", "ISR_BOT_DECOY_ROOT")}
        os.environ["ISR_BOT_HOME"] = os.path.join(self.tmp, "isr_home")
        os.environ["ISR_BOT_DECOY_ROOT"] = os.path.join(self.tmp, "decoys")
        self.rdir = os.path.join(os.environ["ISR_BOT_HOME"], "private", "rollcall")
        self.inbox = os.path.join(self.rdir, "inbox")

    def tearDown(self):
        for k, v in self.env.items():
            os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_isr(self, *argv, stdin=None):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err), mock.patch.object(sys, "stdin", stdin or io.StringIO("")):
            try:
                code = isr.main(list(argv))
            except SystemExit as e:                     # an unknown flag (the base) is a code, not a crash
                code = e.code
        return code, out.getvalue(), err.getvalue()

    def make_inbox(self):
        os.makedirs(self.inbox, mode=0o700, exist_ok=True)
        return self.inbox

    def file(self, name, data):
        p = os.path.join(self.make_inbox(), name)
        with open(p, "w") as f:
            f.write(data if isinstance(data, str) else json.dumps(data))
        return p

    def staged(self):
        return sorted(f for f in os.listdir(self.rdir) if f.endswith(".json")) if os.path.isdir(self.rdir) else []

    def ledger(self):
        p = isr.state_path("ledger.jsonl")
        if not os.path.exists(p):
            return []
        with open(p) as f:
            return [json.loads(l) for l in f]


class ThursdayReplay(Base):
    def test_ingest_alone_stages_six_filed_replies_then_the_owner_yes_analyses_them(self):
        names = ["Harbor", "Echo", "Atlas Ops", "bot-d", "bot_e", "F.1"]
        for n in names:
            self.file(f"{n}.json", answer(n, loosen=2 if n == "Echo" else 0, auto=3 if n == "Echo" else 0))
        code, o, e = self.run_isr("rollcall", "--ingest")
        self.assertEqual(code, 0, o + e)                                        # base: unknown flag, code 2
        self.assertEqual(o.strip(), "Ingested 6, skipped 0 (too big 0, link or not a file 0, bad name 0).")
        self.assertEqual(os.listdir(self.inbox), [])
        self.assertEqual(self.staged(), ["Atlas_Ops.json", "Echo.json", "F.1.json", "Harbor.json", "bot-d.json", "bot_e.json"])
        for fn in self.staged():
            self.assertEqual(stat.S_IMODE(os.stat(os.path.join(self.rdir, fn)).st_mode), 0o600)
        self.assertTrue(os.path.isfile(isr.state_path("rollcall_round.json")))   # ingesting opens the round
        code, o, e = self.run_isr("rollcall", "--owner-said-yes")
        self.assertEqual(code, 0, o + e)
        r = json.loads(o)
        self.assertEqual(r["bots_checked"], 6)
        self.assertEqual(sorted(r["bots"]), sorted(names))
        self.assertEqual(r["raw_replies_deleted"], 6)
        self.assertEqual([f["where"] for f in r["findings"] if f["rule"] == "ISR-M010"], ["rollcall:Echo:memories"])
        self.assertEqual(self.staged(), [])
        self.assertEqual(os.listdir(self.rdir), ["inbox"])
        self.assertEqual(os.listdir(self.inbox), [])


class SkippedEntries(Base):
    def test_links_oversize_bad_names_other_files_and_folders_are_skipped_and_removed(self):
        target = os.path.join(self.tmp, "owner-notes.json")
        with open(target, "w") as f:
            f.write(json.dumps(answer(MARKER + "-target")))
        before = os.stat(target)
        os.symlink(target, os.path.join(self.make_inbox(), "Kestrel-link.json"))
        self.file("Kestrel-huge.json", "x" * 16385)
        self.file("Kestrel:bad.json", answer("Kestrel"))
        self.file("K" * 61 + ".json", answer("Kestrel"))
        self.file("Kestrel-notes.txt", answer("Kestrel"))
        os.makedirs(os.path.join(self.inbox, "Kestrel-dir.json", "inner"))
        self.file(os.path.join("Kestrel-dir.json", "inner", "x.json"), answer("Kestrel"))
        os.mkfifo(os.path.join(self.inbox, "Kestrel-pipe.json"))
        code, o, e = self.run_isr("rollcall", "--ingest")
        self.assertEqual(code, 0, o + e)
        self.assertEqual(o.strip(), "Ingested 0, skipped 7 (too big 1, link or not a file 3, bad name 3).")
        self.assertEqual(os.listdir(self.inbox), [])
        self.assertEqual(self.staged(), [])
        self.assertFalse(os.path.isfile(isr.state_path("rollcall_round.json")))  # nothing ingested, no round opened
        with open(target) as f:                                                  # the link went, its target stays as it was
            self.assertEqual(f.read(), json.dumps(answer(MARKER + "-target")))
        self.assertEqual(os.stat(target).st_mtime_ns, before.st_mtime_ns)

    def test_a_reply_of_exactly_16_kb_is_ingested(self):
        body = json.dumps(answer("Edge"))
        self.file("Edge.json", body + " " * (16384 - len(body)))
        code, o, e = self.run_isr("rollcall", "--ingest")
        self.assertEqual((code, o.strip()), (0, "Ingested 1, skipped 0 (too big 0, link or not a file 0, bad name 0)."))
        self.assertEqual(self.staged(), ["Edge.json"])

    def test_the_output_names_no_reply_text_and_no_skipped_file(self):
        self.file("Harbor.json", answer("Harbor"))
        self.file("Kestrel:bad.json", answer(MARKER))
        self.file("Kestrel-huge.json", MARKER * 2000)
        code, o, e = self.run_isr("rollcall", "--ingest")
        self.assertEqual(code, 0, o + e)
        self.assertEqual(o.strip(), "Ingested 1, skipped 2 (too big 1, link or not a file 0, bad name 1).")
        for word in (MARKER, "Kestrel", "Calendar", "Morning digest", "loosen_permissions", "auto_allow_rules"):
            self.assertNotIn(word, o + e)


class EmptyOrMissing(Base):
    def test_a_missing_or_empty_inbox_prints_zero_counts_and_reads_no_stdin(self):
        for make in (False, True):
            with self.subTest(inbox_exists=make):
                if make:
                    self.make_inbox()
                stdin = io.StringIO(json.dumps(answer("Stdin")))
                code, o, e = self.run_isr("rollcall", "--ingest", stdin=stdin)
                self.assertEqual((code, o.strip()), (0, ZERO), e)
                self.assertEqual(stdin.tell(), 0)
                self.assertEqual(self.staged(), [])


class TheInboxFolder(Base):
    def test_the_inbox_is_made_0700_with_the_folder_and_by_the_question(self):
        isr.ensure_rollcall_dir()
        self.assertTrue(os.path.isdir(self.inbox))
        os.chmod(self.inbox, 0o755)
        isr.ensure_rollcall_dir()
        self.assertEqual(stat.S_IMODE(os.stat(self.inbox).st_mode), 0o700)
        shutil.rmtree(os.environ["ISR_BOT_HOME"])
        code, o, _ = self.run_isr("rollcall", "--question")
        self.assertEqual(code, 0)
        self.assertTrue(os.path.isdir(self.inbox))                               # where the question tells Bots to write
        self.assertEqual(stat.S_IMODE(os.stat(self.inbox).st_mode), 0o700)

    def test_a_link_in_place_of_the_inbox_is_refused(self):
        os.makedirs(self.rdir, mode=0o700)
        elsewhere = os.path.join(self.tmp, "shared"); os.makedirs(elsewhere)
        with open(os.path.join(elsewhere, "Harbor.json"), "w") as f:
            f.write(json.dumps(answer("Harbor")))
        os.symlink(elsewhere, self.inbox)
        with self.assertRaises(OSError):
            isr.ensure_rollcall_dir()
        code, o, _ = self.run_isr("rollcall", "--ingest")
        self.assertEqual(code, 2); self.assertIn("NOT INGESTED", o)
        self.assertEqual(os.listdir(elsewhere), ["Harbor.json"])                # nothing read or removed through the link
        self.assertEqual(self.staged(), [])
        code, o, _ = self.run_isr("rollcall", "--save", "Harbor", stdin=io.StringIO("{}"))
        self.assertEqual(code, 2); self.assertIn("NOT SAVED", o)
        self.assertEqual(os.listdir(elsewhere), ["Harbor.json"])


class DailySweep(Base):
    def test_the_daily_check_sweeps_inbox_files_older_than_an_hour(self):
        old, fresh = self.file("Old.json", answer("Old")), self.file("Fresh.json", answer("Fresh"))
        os.utime(old, (time.time() - 2 * 3600,) * 2)
        target = os.path.join(self.tmp, "kept.json")
        with open(target, "w") as f:
            f.write("{}")
        link = os.path.join(self.inbox, "Link.json")
        os.symlink(target, link)
        os.utime(link, (time.time() - 2 * 3600,) * 2, follow_symlinks=False)
        with mock.patch.object(isr, "run_audit", side_effect=isr.Busy), redirect_stdout(io.StringIO()):
            self.assertEqual(isr.cmd_daily(mock.Mock()), 0)
        self.assertFalse(os.path.exists(old))
        self.assertFalse(os.path.lexists(link))                                  # a link goes as a link
        self.assertTrue(os.path.exists(fresh))
        self.assertTrue(os.path.isfile(target))
        e = [x for x in self.ledger() if x["event"] == "rollcall-inbox-swept"]
        self.assertEqual([(x["count"], x["older_than_seconds"]) for x in e], [(2, 3600)])
        self.assertTrue(os.path.isdir(self.inbox))


class RepliesAndTheInboxApart(Base):
    def test_the_owner_yes_neither_reads_nor_deletes_the_inbox(self):
        """The inbox is a folder in the roll-call folder: it is never read as a reply, tightened, deleted or counted. Passes on
        the base too (a control)."""
        code, o, _ = self.run_isr("rollcall", "--save", "Harbor", stdin=io.StringIO(json.dumps(answer("Harbor"))))
        self.assertEqual(code, 0, o)
        pending = self.file("Late.json", answer("Late"))
        code, o, e = self.run_isr("rollcall", "--owner-said-yes")
        self.assertEqual(code, 0, o + e)
        r = json.loads(o)
        self.assertEqual((r["bots_checked"], r["bots"], r["raw_replies_deleted"]), (1, ["Harbor"], 1))
        self.assertNotIn("ISR-R010", [f["rule"] for f in r["findings"]])
        self.assertEqual(os.listdir(self.rdir), ["inbox"])
        self.assertTrue(os.path.isfile(pending))
        self.assertEqual(stat.S_IMODE(os.stat(self.inbox).st_mode), 0o700)
        self.assertEqual(isr.delete_raw_replies(self.rdir), 0)
        self.assertTrue(os.path.isdir(self.inbox))


class TheQuestion(Base):
    def test_the_question_names_the_inbox_and_keeps_every_original_word(self):
        q = isr.ROLLCALL_PROMPT
        self.assertIn("Write that JSON to /workspace/isr-bot/private/rollcall/inbox/<your name>.json", q)
        self.assertIn('reply only "filed"', q)
        self.assertIn("if you cannot write files, reply in chat with only the JSON", q)
        self.assertTrue(q.startswith(ORIGINAL))
        self.assertTrue(q.isascii())
        self.assertEqual(self.run_isr("rollcall", "--question")[1].strip(), q)

    def test_the_question_states_the_file_name_rule_ingest_uses(self):
        """Fix round 1 (Codex): a Bot called "Research & Ops" filed under that name, replied "filed", and --ingest removed the
        file as "bad name". The question now says which characters a file name may have, and the words match INBOX_NAME."""
        q = isr.ROLLCALL_PROMPT
        words = {"letters A-Z and a-z": string.ascii_letters, "digits": string.digits, "spaces": " ", "dots": ".",
                 "underscores": "_", "hyphens": "-"}
        for w in words:
            self.assertIn(w, q)
        self.assertIn("(leave out any other character)", q)
        self.assertIn("at most 60 characters", q)
        self.assertIn("if you cannot write files, reply in chat with only the JSON", q)
        allowed = "".join(words.values())
        for c in map(chr, range(32, 127)):                                       # every printable ASCII character
            self.assertEqual(bool(isr.INBOX_NAME.fullmatch(c)), c in allowed, repr(c))
        self.assertTrue(isr.INBOX_NAME.fullmatch((allowed * 2)[:60]))
        self.assertFalse(isr.INBOX_NAME.fullmatch((allowed * 2)[:61]))
        name = "Research & Ops"
        self.assertFalse(isr.INBOX_NAME.fullmatch(name))
        kept = "".join(c for c in name if c in allowed)                          # the question's advice: leave out "&"
        self.assertEqual(kept, "Research  Ops")
        self.file(kept + ".json", answer(name))
        code, o, e = self.run_isr("rollcall", "--ingest")
        self.assertEqual((code, o.strip()), (0, "Ingested 1, skipped 0 (too big 0, link or not a file 0, bad name 0)."), e)


class Controls(Base):
    """--save and --owner-said-yes work as before (pass on the base too)."""
    def test_save_then_owner_yes_unchanged(self):
        code, o, _ = self.run_isr("rollcall", "--save", "Harbor", stdin=io.StringIO(json.dumps(answer("Harbor"))))
        self.assertEqual(code, 0)
        self.assertTrue(o.startswith("Saved Harbor.json (mode 0600) in ISR Bot's private roll-call folder."))
        self.assertNotIn(MARKER, o)
        self.assertEqual(self.staged(), ["Harbor.json"])
        code, o, _ = self.run_isr("rollcall")
        self.assertEqual(code, 2); self.assertIn("NOT RUN", o)
        self.assertEqual(self.staged(), ["Harbor.json"])
        code, o, _ = self.run_isr("rollcall", "--owner-said-yes")
        self.assertEqual(code, 0)
        r = json.loads(o)
        self.assertEqual((r["bots_checked"], r["raw_replies_deleted"], r["counted_in_score"]), (1, 1, False))
        self.assertEqual(self.staged(), [])


if __name__ == "__main__":
    unittest.main()
