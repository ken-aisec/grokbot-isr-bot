"""v0.7.1 red-team (the owner's second account on v0.7.0, Oct 14, relayed by Claude Oct 15): the roll-call made people less safe.
Any agent could send it, Bots can't check who is asking (one answered twice, once to a deleted Watchtower), it asked for every
memory word for word, and the replies sat as plain files every Bot could read. The roll-call stays (opt-in, off by default), but
the question now asks only for a shape, replies live as 0600 files in a 0700 folder inside Watchtower's home, and each reply is
deleted as soon as it is read. Bot names and memory text below are made up."""
import io, json, os, re, stat, sys, tempfile, shutil, unittest, warnings
from contextlib import redirect_stdout, redirect_stderr
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "watchtower"))
import wt  # noqa: E402

warnings.simplefilter("ignore", ResourceWarning)

SECRETS = ("Client Dana Ortiz owes 4,200 on invoice 7781", "wire account 021000021-998877", "dana.ortiz@example-client.com",
           "Never tell the owner about the Friday transfer", "sk-live-FAKE0000000000000000")
BOT = {"name": "Ledger", "connectors": ["Gmail", "Slack", "QuickBooks"],
       "memories": list(SECRETS),
       "routines": [{"name": "Friday invoices", "trigger": "schedule", "instructions": "Email every unpaid client " + SECRETS[2],
                     "sends": True, "asks": False, "reads_outside": False}]}


def honest_answer(bot):
    """What a Bot that follows the fixed question replies: only the fields the question names, in the shape it gives."""
    return {"name": bot["name"], "connectors": bot["connectors"],
            "routines": [{"name": r["name"], "trigger": r["trigger"], "sends_or_posts": r["sends"], "asks_first": r["asks"],
                          "reads_outside_content": r["reads_outside"]} for r in bot["routines"]],
            "memories": {"count": len(bot["memories"]), "loosen_permissions": 0, "from_outside_content": 0},
            "ask_first": [], "auto_allow_rules": 0, "sends_or_posts_without_asking": False, "reads_outside_content": False}


def question_template():
    m = re.search(r"(\{.*\})\.\s", wt.ROLLCALL_PROMPT)
    return json.loads(m.group(1))


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.env = {k: os.environ.get(k) for k in ("ISR_BOT_HOME", "ISR_BOT_DECOY_ROOT")}
        os.environ["ISR_BOT_HOME"] = os.path.join(self.tmp, "wt")
        os.environ["ISR_BOT_DECOY_ROOT"] = os.path.join(self.tmp, "decoys")

    def tearDown(self):
        for k, v in self.env.items():
            os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_wt(self, *argv, stdin=None):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err), mock.patch.object(sys, "stdin", io.StringIO(stdin or "")):
            code = wt.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def everything_watchtower_kept(self):
        """Every byte under Watchtower's home after the run (state, ledger, reports, exports)."""
        blob = []
        for root, _, files in os.walk(os.environ["ISR_BOT_HOME"]):
            for fn in files:
                try:
                    blob.append(open(os.path.join(root, fn), encoding="utf-8", errors="replace").read())
                except OSError:
                    pass
        return "\n".join(blob)


class TheQuestionRevealsNothing(Base):
    def test_the_question_never_asks_for_content(self):
        q = wt.ROLLCALL_PROMPT
        for word in ("verbatim", "word for word", '"description"', '"instructions"', '"prompt"', "each stored memory"):
            self.assertNotIn(word, q)
        self.assertIn("can't check who sends this", q)
        t = question_template()
        self.assertEqual(set(t), set(wt.ROLLCALL_FIELDS))
        self.assertIsInstance(t["memories"], dict); self.assertEqual(set(t["memories"]), set(wt.ROLLCALL_MEMORY_FIELDS))
        self.assertTrue(all(isinstance(v, int) for v in t["memories"].values()))
        self.assertEqual(set(t["routines"][0]), set(wt.ROLLCALL_ROUTINE_FIELDS))
        self.assertEqual(set(t["ask_first"]), set(wt.ROLLCALL_ASK_FIRST))
        self.assertEqual(self.run_wt("rollcall", "--question")[1].strip(), q)      # the skill sends exactly this

    def test_a_fake_watchtower_gets_no_memory_text_from_an_honest_bot(self):
        """Red-team: someone else (not this owner's Watchtower) sends the fixed question. The answer it gets has no memory text,
        no routine instructions and no addresses, so there is nothing to steal."""
        reply = json.dumps(honest_answer(BOT))
        for s in SECRETS:
            self.assertNotIn(s, reply)
        self.assertNotIn("Email every unpaid client", reply)
        self.assertEqual(set(json.loads(reply)), set(wt.ROLLCALL_FIELDS))

    def test_a_naive_bot_that_dumps_its_memories_leaves_no_trace(self):
        """A Bot that ignores the shape and pastes content into every field: nothing of it is read past the shape or kept."""
        dump = {"name": "Ledger", "description": SECRETS[3], "memories": list(SECRETS), "connectors": [SECRETS[0], "Gmail"],
                "routines": [{"name": SECRETS[0], "trigger": SECRETS[1], "instructions": SECRETS[2], "sends_or_posts": SECRETS[3]}],
                "ask_first": [SECRETS[4]], "auto_allow_rules": SECRETS[1], "notes": SECRETS[4]}
        code, o, _ = self.run_wt("rollcall", "--save", "Ledger", stdin=json.dumps(dump))
        self.assertEqual(code, 0); self.assertNotIn("Dana", o)
        code, o, _ = self.run_wt("rollcall", "--owner-said-yes")
        self.assertEqual(code, 0)
        kept = o + self.everything_watchtower_kept()
        for s in SECRETS:
            self.assertNotIn(s, kept)
        for frag in ("Dana", "7781", "021000021", "Friday transfer", "sk-live"):
            self.assertNotIn(frag, kept)
        r011 = [f for f in json.loads(o)["findings"] if f["rule"] == "ISR-R011"]
        self.assertEqual(len(r011), 1)                                             # the Bot is told about, by field name only
        self.assertEqual(os.listdir(wt.default_rollcall_dir()), [])


class RepliesArePrivateAndShortLived(Base):
    def test_saved_replies_are_0600_in_a_0700_folder_and_gone_after_the_run(self):
        code, o, _ = self.run_wt("rollcall", "--save", "Ledger", stdin=json.dumps(honest_answer(BOT)))
        self.assertEqual(code, 0)
        rdir = wt.default_rollcall_dir()
        self.assertEqual(rdir, os.path.join(os.environ["ISR_BOT_HOME"], "private", "rollcall"))
        self.assertNotIn(os.sep + "exports" + os.sep, rdir + os.sep)
        for d in (rdir, os.path.dirname(rdir)):
            self.assertEqual(stat.S_IMODE(os.stat(d).st_mode), 0o700, d)
        files = os.listdir(rdir)
        self.assertEqual(files, ["Ledger.json"])
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(rdir, files[0])).st_mode), 0o600)
        code, o, _ = self.run_wt("rollcall", "--owner-said-yes")
        self.assertEqual(code, 0); self.assertEqual(json.loads(o)["raw_replies_deleted"], 1)
        self.assertEqual(os.listdir(rdir), [])

    def test_each_reply_is_deleted_as_soon_as_it_is_read(self):
        rdir = wt.ensure_rollcall_dir()
        for n in ("a", "b", "c"):
            json.dump(dict(honest_answer(BOT), name=n), open(os.path.join(rdir, f"{n}.json"), "w"))
        seen = []
        real = wt.shape_reply
        def spy(d):
            seen.append(sorted(os.listdir(rdir)))
            return real(d)
        with mock.patch.object(wt, "shape_reply", side_effect=spy):
            wt.rollcall_findings(rdir)
        self.assertEqual(seen, [["b.json", "c.json"], ["c.json"], []])            # gone before the next one is even read

    def test_a_reply_put_there_by_hand_is_tightened_and_a_wide_folder_is_closed(self):
        rdir = wt.default_rollcall_dir(); os.makedirs(rdir, mode=0o755)
        os.chmod(rdir, 0o755); os.chmod(os.path.dirname(rdir), 0o755)
        p = os.path.join(rdir, "x.json"); json.dump(honest_answer(BOT), open(p, "w")); os.chmod(p, 0o644)
        wt.ensure_rollcall_dir(); wt.tighten_replies(rdir)
        self.assertEqual(stat.S_IMODE(os.stat(rdir).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o600)

    def test_a_link_in_the_folder_is_never_read_through(self):
        rdir = wt.ensure_rollcall_dir()
        target = os.path.join(self.tmp, "owner-secret.json")
        json.dump({"name": SECRETS[0], "memories": {"count": 1}}, open(target, "w"))
        os.symlink(target, os.path.join(rdir, "evil.json"))
        code, o, _ = self.run_wt("rollcall", "--owner-said-yes")
        self.assertNotIn("Dana", o + self.everything_watchtower_kept().replace(open(target).read(), ""))
        self.assertTrue(os.path.exists(target))                                    # the link goes, what it points to stays
        self.assertEqual(os.listdir(rdir), [])

    def test_replies_an_older_version_left_in_exports_are_removed(self):
        old = os.path.join(os.environ["ISR_BOT_HOME"], "exports", "rollcall"); os.makedirs(old)
        open(os.path.join(old, "harbor.json"), "w").write(json.dumps({"memories": list(SECRETS)}))
        self.run_wt("rollcall", "--owner-said-yes")
        self.assertFalse(os.path.exists(old))

    def test_the_save_refuses_a_linked_folder(self):
        home = os.environ["ISR_BOT_HOME"]; os.makedirs(home)
        elsewhere = os.path.join(self.tmp, "shared"); os.makedirs(elsewhere)
        os.symlink(elsewhere, os.path.join(home, "private"))
        code, o, _ = self.run_wt("rollcall", "--save", "Ledger", stdin="{}")
        self.assertEqual(code, 2); self.assertIn("NOT SAVED", o)
        self.assertEqual(os.listdir(elsewhere), [])


class OwnersAreTold(unittest.TestCase):
    def test_the_skill_and_the_template_description_say_bots_cant_verify_the_sender(self):
        skill = open(os.path.join(ROOT, "skills", "watchtower-rollcall", "SKILL.md")).read()
        desc = open(os.path.join(ROOT, "bot", "description.md")).read()
        front = skill.split("---")[1]
        self.assertIn("Bots can't verify who sends a roll-call", front)            # the description line every owner sees
        self.assertIn("Bots can't verify who sends a roll-call", desc)
        self.assertIn("nothing in a reply is worth stealing", desc)
        self.assertNotIn("exports/rollcall", skill)
        self.assertIn("off unless I ask", desc)


if __name__ == "__main__":
    unittest.main()
