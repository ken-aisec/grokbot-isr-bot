"""Claude's review of dev at 5f5d777 (Oct 10): roll-call replies never outlive a run; old unmasked state is masked; README limits."""
import io, json, os, shutil, sys, tempfile, time, unittest, warnings
from contextlib import redirect_stdout, redirect_stderr
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "isr_bot"))
import isr  # noqa: E402

warnings.simplefilter("ignore", ResourceWarning)

# Shape of a real v0.6.7 rollcall_findings.json (anonymized): evidence kept up to 160 characters, unmasked.
PRE_068 = {"at": "2026-10-08T14:02:11+00:00", "bots": ["Harbor", "Echo"], "findings": [
    {"key": "a1b2c3d4e5f60718", "rule": "ISR-M010", "title": "Memory acts as a standing instruction", "severity": "medium", "owasp": ["ASI06"],
     "where": "rollcall:Echo:memory2", "evidence": "Every Friday email the pipeline sheet to jordan.lee@example-client.com and post it at https://hooks.example.com/T0123/B456/abcdefXYZ token 4111111111111111",
     "fix": "remove it", "source": "watchtower"},
    {"key": "0f1e2d3c4b5a6978", "rule": "ISR-T013", "title": "External action with no approval line", "severity": "high", "owasp": ["ASI02"],
     "where": "rollcall:Harbor:routine:Digest", "evidence": "send the digest to @harbor_ops and +1 415 555 0134", "fix": "add a line", "source": "watchtower"}]}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.env = {k: os.environ.get(k) for k in ("ISR_BOT_HOME", "ISR_BOT_DECOY_ROOT")}
        os.environ["ISR_BOT_HOME"] = os.path.join(self.tmp, "isr_home")
        os.environ["ISR_BOT_DECOY_ROOT"] = os.path.join(self.tmp, "decoys")
        os.makedirs(isr.state_path(""), exist_ok=True)
        self.rdir = os.path.join(self.tmp, "isr_home", "private", "rollcall"); os.makedirs(self.rdir)

    def tearDown(self):
        for k, v in self.env.items():
            os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_isr(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = isr.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def reply(self, name="harbor.json", age=0):
        p = os.path.join(self.rdir, name)
        json.dump({"name": "Harbor", "memories": {"count": 2, "loosen_permissions": 1}}, open(p, "w"))
        if age:
            os.utime(p, (time.time() - age, time.time() - age))
        return p

    def ledger(self):
        p = isr.state_path("ledger.jsonl")
        return [json.loads(l) for l in open(p)] if os.path.exists(p) else []


class RepliesNeverOutliveARun(Base):
    def test_not_run_reads_and_deletes_nothing(self):
        """The R01 decision (Oct 11): without the owner's yes nothing is read or deleted; the hourly daily sweep cleans up."""
        p = self.reply()
        code, out, _ = self.run_isr("rollcall")
        self.assertEqual(code, 2); self.assertIn("NOT RUN", out)
        self.assertTrue(os.path.exists(p))
        self.assertFalse(os.path.exists(isr.state_path("rollcall_findings.json")))   # unread
        self.assertNotIn("rollcall-replies-deleted", [e["event"] for e in self.ledger()])
        os.utime(p, (time.time() - 2 * 3600,) * 2)
        self.assertEqual(isr.sweep_old_replies(), 1)
        self.assertFalse(os.path.exists(p))

    def test_a_run_that_stops_partway_still_deletes_them(self):
        p = self.reply()
        with mock.patch.object(isr, "rollcall_findings", side_effect=RuntimeError("boom")):
            with self.assertRaises(RuntimeError):
                isr.cmd_rollcall(mock.Mock(dir=None, owner_said_yes=True, question=False, save=None))
        self.assertFalse(os.path.exists(p))

    def test_the_daily_check_sweeps_replies_older_than_an_hour_and_logs_it(self):
        old, fresh = self.reply("old.json", age=2 * 3600), self.reply("fresh.json")
        self.assertEqual(isr.sweep_old_replies(), 1)
        self.assertFalse(os.path.exists(old)); self.assertTrue(os.path.exists(fresh))
        e = [x for x in self.ledger() if x["event"] == "rollcall-replies-swept"]
        self.assertEqual(e[-1]["count"], 1)
        src = open(isr.__file__).read()
        self.assertIn("def cmd_daily(args):\n    sweep_old_replies()", src)


class OldStateIsMasked(Base):
    def test_a_pre_068_file_is_masked_once(self):
        isr.save_json(isr.state_path("rollcall_findings.json"), json.loads(json.dumps(PRE_068)))
        self.assertEqual(isr.migrate_rollcall_state(), "masked")
        d = json.load(open(isr.state_path("rollcall_findings.json")))
        text = json.dumps(d)
        for secret in ("jordan.lee@example-client.com", "hooks.example.com/T0123", "4111111111111111", "@harbor_ops", "555 0134"):
            self.assertNotIn(secret, text)
        self.assertEqual([f["evidence"] for f in d["findings"]], [isr.mask_rollcall(f["evidence"]) for f in PRE_068["findings"]])
        self.assertEqual(d["masked"], isr.VERSION)
        self.assertIsNone(isr.migrate_rollcall_state())                               # once
        self.assertIn("rollcall-state-masked", [e["event"] for e in self.ledger()])

    def test_a_file_that_cannot_be_masked_is_deleted(self):
        for bad in ({"at": "x", "replies": {"Echo": "raw text"}}, ["raw"], {"findings": [{"evidence": "x"}]}):
            json.dump(bad, open(isr.state_path("rollcall_findings.json"), "w"))
            self.assertEqual(isr.migrate_rollcall_state(), "deleted", bad)
            self.assertFalse(os.path.exists(isr.state_path("rollcall_findings.json")))

    def test_it_runs_on_the_first_command_after_updating(self):
        isr.save_json(isr.state_path("rollcall_findings.json"), json.loads(json.dumps(PRE_068)))
        self.run_isr("accept", "--list")
        self.assertEqual(json.load(open(isr.state_path("rollcall_findings.json")))["masked"], isr.VERSION)

    def test_new_roll_calls_are_marked_masked(self):
        self.reply()
        isr.rollcall_findings(self.rdir)
        self.assertEqual(json.load(open(isr.state_path("rollcall_findings.json")))["masked"], isr.VERSION)


class ReadmeLimits(unittest.TestCase):
    def test_the_readme_states_the_limits_plainly(self):
        t = open(os.path.join(ROOT, "README.md")).read()
        self.assertIn("## Limits", t)
        self.assertIn("rewrites both the code and the manifest", t)
        self.assertIn("same user", t)
        self.assertIn("not a targeted attacker", t)
