"""v0.6.9 scope (decision, Oct 10): DQ-013..016, daily dismissals, environment profiles, red-team."""
import io, json, os, shutil, sys, tempfile, time, unittest, warnings
from contextlib import redirect_stdout, redirect_stderr
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "isr_bot"))
import isr  # noqa: E402

warnings.simplefilter("ignore", ResourceWarning)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.env = {k: os.environ.get(k) for k in ("ISR_BOT_HOME", "ISR_BOT_DECOY_ROOT")}
        os.environ["ISR_BOT_HOME"] = os.path.join(self.tmp, "isr_home")
        os.environ["ISR_BOT_DECOY_ROOT"] = os.path.join(self.tmp, "decoys")
        os.makedirs(isr.state_path(""), exist_ok=True)

    def tearDown(self):
        for k, v in self.env.items():
            os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_isr(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = isr.main(list(argv))
        return code, out.getvalue(), err.getvalue()


class DQ014TimeoutIsNotASecondOpinion(Base):
    def test_the_topic_digest_case(self):
        """Replay of the main box, 2026-10-10 12:22Z: husk's SQL flag on a chat-message line, SkillSpector timed out."""
        skill = os.path.join(self.tmp, "home", "box", ".agents", "skills", "topic-digest")
        os.makedirs(os.path.join(skill, "scripts"))
        open(os.path.join(skill, "SKILL.md"), "w").write("---\nname: topic-digest\ndescription: Watch topics.\n---\n")
        lines = ["x = 1"] * 59 + ['    return f"\U0001F4F0 *topic-digest update: {topic}*\\n{new} new, {updated} updated"']
        open(os.path.join(skill, "scripts", "watchlist.py"), "w").write("\n".join(lines) + "\n")
        x2 = isr.finding("ISR-X002", "husk flagged this skill", "low", ["AST01"], os.path.join(skill, "scripts", "watchlist.py") + ":60",
                        "sql-injection: f-string", "Read it.", source="husk")
        x4 = isr.finding("ISR-X004", "A scanner couldn't finish this skill", "low", ["AST08"], skill,
                        "SkillSpector gave no answer in time", "Nothing to do.", source="skillspector")
        out = isr.label_findings([x2, x4])
        self.assertEqual(out[0]["label"], isr.MAYBE_FINE)
        self.assertEqual(out[0]["class"], "pattern")
        self.assertEqual(out[1]["label"], isr.CONFIRMED)                         # the timeout itself is still a fact
        # a real second engine at the same skill still corroborates
        x1 = isr.finding("ISR-X001", "SkillSpector: do not install", "high", ["AST01"], skill, "verdict", "fix", source="skillspector")
        self.assertEqual(isr.label_findings([x2, x1])[0]["label"], isr.CONFIRMED)


class Prepublish(Base):
    def stage(self, files, roster=None):
        d = os.path.join(self.tmp, "prepublish", "Watchtower"); os.makedirs(d)
        for n, t in files.items():
            open(os.path.join(d, n), "w").write(t)
        if roster is not None:
            os.makedirs(os.path.join(self.tmp, "isr_home", "exports"), exist_ok=True)
            json.dump(roster, open(os.path.join(self.tmp, "isr_home", "exports", "roster.json"), "w"))
        code, out, _ = self.run_isr("prepublish", d, "--json")
        return code, json.loads(out)

    def test_dq015_owner_and_bot_names_in_a_routine_are_flagged(self):
        """Replay: the daily-watch routine named the owner and another Bot, and prepublish said PASS."""
        os.makedirs(os.path.join(self.tmp, "isr_home", "exports"), exist_ok=True)
        open(os.path.join(self.tmp, "isr_home", "exports", "names.txt"), "w").write("Owner\n")
        routine = ("Every day at 6:00 AM run the daily check. Never send without my approval.\n"
                   "Owner's standing rule: Builder develops Watchtower; never message Builder.\n"
                   "The result goes to Owner in this chat.\n")
        code, r = self.stage({"routine-daily-watch.md": routine}, roster=[{"name": "Builder", "kind": "bot"}, {"name": "Watchtower", "kind": "bot"},
                                                                          {"name": "Ops room", "kind": "room"}])
        names = [f for f in r["findings"] if f["rule"] == "ISR-PP08"]
        self.assertEqual(sorted({f["where"].rsplit(":", 1)[1] for f in names}), ["2", "3"])
        self.assertEqual(r["verdict"], "FAIL"); self.assertEqual(code, 1)
        self.assertFalse(any("Watchtower" in f["evidence"] for f in names))       # the Bot being shared may name itself
        self.assertFalse(any("forged" in f["evidence"] for f in names))

    def test_dq015_no_names_known_means_nothing_invented(self):
        code, r = self.stage({"routine-a.md": "Never send without my approval. Owner reviews it."})
        self.assertFalse([f for f in r["findings"] if f["rule"] == "ISR-PP08"])

    def test_dq016_a_stale_getting_started_is_flagged(self):
        cur = open(os.path.join(ROOT, "bot", "getting-started.md")).read()
        old_name = os.path.basename(isr.OLD_CANARY_PATHS[0])
        stale = cur.replace("in /tmp and /var/tmp, with folder and file names picked at random for this computer", "at " + old_name)
        code, r = self.stage({"skill-getting-started.md": "---\nname: getting-started\n---\n" + stale})
        rules = {f["rule"] for f in r["findings"]}
        self.assertIn("ISR-PP09", rules); self.assertIn("ISR-PP10", rules)
        self.assertFalse(any(old_name in f["evidence"] for f in r["findings"]))   # never prints a decoy location
        self.assertEqual(r["verdict"], "FAIL")

    def test_dq016_a_current_getting_started_passes(self):
        cur = open(os.path.join(ROOT, "bot", "getting-started.md")).read()
        code, r = self.stage({"skill-getting-started.md": "---\nname: getting-started\ndescription: First run.\n---\n\n" + cur})
        self.assertFalse({"ISR-PP09", "ISR-PP10"} & {f["rule"] for f in r["findings"]}, r)


class DailyListsDismissals(Base):
    def test_the_routine_lists_what_it_dismissed(self):
        md = os.path.join(self.tmp, "s", "SKILL.md"); os.makedirs(os.path.dirname(md))
        open(md, "w").write("# x\nNever send anything.\n")
        f = isr.label_findings([isr.finding("ISR-T013", "t", "high", ["X"], md + ":2", "send", "fix")])[0]
        isr.save_json(isr.state_path("last_findings.json"), {"findings": [f]})
        code, out, _ = self.run_isr("dismiss", "--list")
        self.assertEqual(out.strip(), "NONE_DISMISSED")
        self.assertEqual(self.run_isr("dismiss", f["key"], "--reason", "the line says never send")[0], 0)
        code, out, _ = self.run_isr("dismiss", "--list")
        rows = json.loads(out)["dismissed"]
        self.assertEqual([(r["rule"], r["reason"]) for r in rows], [("ISR-T013", "the line says never send")])
        self.assertTrue(rows[0]["where"].endswith("SKILL.md:2"))
        code, out, _ = self.run_isr("dismiss", "--list", "--since", "2999-01-01")
        self.assertEqual(out.strip(), "NONE_DISMISSED")
        t = open(os.path.join(ROOT, "routines", "daily-watch.md")).read()
        self.assertIn("isr.py dismiss --list", t); self.assertIn("Dismissed: <rule> at <where>: <reason>", t)
        self.assertIn("even when the daily check printed NO_CHANGES", t)
