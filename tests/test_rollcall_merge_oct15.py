"""Roll-call merge (main box, Oct 15): ten Bots answered the roll-call, then Foxtrot's late reply was saved and run on its own.
That run rewrote state/rollcall_findings.json with Foxtrot alone, so the audit, `dismiss` and the report lost the other nine
Bots. A later run in the same roll-call round now merges per Bot: a Bot that answers again replaces only its own findings.
A round opens at `rollcall --question` or `rollcall --save` and lasts ROLLCALL_ROUND_DAYS; a run outside a round still
replaces (the DQ-018 leftover test relies on that). Bot names and answers below are made up."""
import datetime as dt, io, json, os, stat, sys, tempfile, shutil, threading, time, unittest, warnings
from contextlib import redirect_stdout, redirect_stderr
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "watchtower"))
import wt  # noqa: E402

warnings.simplefilter("ignore", ResourceWarning)

BOTS = ["Alpha", "Bravo", "Charlie", "Delta", "Echo", "Foxtrot", "Golf", "Hotel", "India", "Juliet"]
SECRETS = ("Client Rosa Vega owes 3,900 on invoice 5512", "routing 026009593-114455", "rosa.vega@example-client.com",
           "sk-live-FAKE1111111111111111")


def answer(name, sends_without_asking=False, routine=None, loosen=0):
    """A reply in the exact shape the question asks for."""
    rts = [] if routine is None else [{"name": routine, "trigger": "schedule", "sends_or_posts": True, "asks_first": False,
                                        "reads_outside_content": False}]
    return {"name": name, "connectors": [], "routines": rts, "memories": {"count": 3, "loosen_permissions": loosen, "from_outside_content": 0},
            "ask_first": [], "auto_allow_rules": 0, "sends_or_posts_without_asking": sends_without_asking, "reads_outside_content": False}


def first_answer(name):
    """Run 1 of the Oct 15 replay: every Bot raises at least one finding; Foxtrot says it sends without asking (WT-R013)."""
    if name == "Foxtrot":
        return answer(name, sends_without_asking=True)
    return answer(name, routine=f"{name} digest", loosen=1 if name in ("Bravo", "Hotel") else 0)


def load(p):
    with open(p) as f:
        return json.load(f)


def dump(obj, p):
    with open(p, "w") as f:
        json.dump(obj, f)


def raw(p):
    with open(p, "rb") as f:
        return f.read()


def bot_of(f):
    return f["where"].split(":")[1]


def iso(days_ago):
    return (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days_ago)).replace(microsecond=0).isoformat()


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.env = {k: os.environ.get(k) for k in ("WATCHTOWER_HOME", "WT_DECOY_ROOT")}
        os.environ["WATCHTOWER_HOME"] = os.path.join(self.tmp, "wt")
        os.environ["WT_DECOY_ROOT"] = os.path.join(self.tmp, "decoys")

    def tearDown(self):
        for k, v in self.env.items():
            os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def fresh_home(self):
        """A new, empty Watchtower home for the next subtest (inside setUp's folder, so tearDown removes it)."""
        os.environ["WATCHTOWER_HOME"] = tempfile.mkdtemp(dir=self.tmp)

    def run_wt(self, *argv, stdin=None):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err), mock.patch.object(sys, "stdin", io.StringIO(stdin or "")):
            code = wt.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def save(self, bot, reply):
        code, o, _ = self.run_wt("rollcall", "--save", bot, stdin=reply if isinstance(reply, str) else json.dumps(reply))
        self.assertEqual(code, 0, o)

    def run_rollcall(self):
        code, o, e = self.run_wt("rollcall", "--owner-said-yes")
        self.assertEqual(code, 0, o + e)
        self.assertEqual(os.listdir(wt.default_rollcall_dir()), [])          # raw replies gone after every run
        return json.loads(o)

    def state(self):
        return load(wt.state_path("rollcall_findings.json"))

    def by_bot(self, rc):
        out = {}
        for f in rc["findings"]:
            out.setdefault(bot_of(f), []).append(f)
        return out

    def seed(self, opened, bots=("Alpha",), shape_only=True, round_=None):
        """A findings file and round as an earlier run in the round opened at `opened` would have left them."""
        wt.save_json(wt.state_path("rollcall_round.json"), {"opened": opened})
        fs = [wt.finding("WT-R013", "Bot says it sends or posts without asking", "medium", ["ASI02"], f"rollcall:{b}",
                         "sends or posts without asking: yes (the Bot's own answer)", "Add Ask first.") for b in bots]
        rc = {"at": opened, "masked": wt.VERSION, "bots": list(bots), "findings": fs, "round": opened if round_ is None else round_}
        if shape_only:
            rc["shape_only"] = True
        wt.save_json(wt.state_path("rollcall_findings.json"), rc)

    def everything_watchtower_kept(self):
        blob = []
        for root, _, files in os.walk(os.environ["WATCHTOWER_HOME"]):
            for fn in files:
                try:
                    blob.append(raw(os.path.join(root, fn)).decode("utf-8", "replace"))
                except OSError:
                    pass
        return "\n".join(blob)


class Oct15Replay(Base):
    def test_a_late_reply_keeps_the_other_nine_bots(self):
        self.run_wt("rollcall", "--question")
        for b in BOTS:
            self.save(b, first_answer(b))
        self.run_rollcall()
        run1 = self.state()
        self.assertEqual(sorted(run1["bots"]), sorted(BOTS))
        first = self.by_bot(run1)
        self.assertEqual(sorted(first), sorted(BOTS))                            # every Bot raised something
        self.assertEqual([f["rule"] for f in first["Foxtrot"]], ["WT-R013"])

        self.save("Foxtrot", answer("Foxtrot", routine="Invoice chaser"))       # Foxtrot's late, corrected answer
        out = self.run_rollcall()
        rc = self.state()
        self.assertEqual(sorted(rc["bots"]), sorted(BOTS))                       # Oct 15: only Foxtrot was left
        now = self.by_bot(rc)
        for b in BOTS:
            if b != "Foxtrot":
                self.assertEqual(now.get(b), first[b], b)                       # the nine are exactly as run 1 left them
        self.assertEqual([f["rule"] for f in now["Foxtrot"]], ["WT-R012"])      # Foxtrot's own findings were replaced
        self.assertEqual(out["bots"], ["Foxtrot"])                               # the output still describes this run
        self.assertEqual(sorted(out["earlier_bots_kept"]), sorted(b for b in BOTS if b != "Foxtrot"))
        self.assertEqual(rc["shape_only"], True)
        self.assertEqual(rc["masked"], wt.VERSION)

    def test_asking_a_slow_bot_again_stays_in_the_same_round(self):
        self.run_wt("rollcall", "--question")
        opened = load(wt.state_path("rollcall_round.json"))["opened"]
        for b in ("Alpha", "Bravo"):
            self.save(b, first_answer(b))
        self.run_rollcall()
        code, o, _ = self.run_wt("rollcall", "--question")                     # re-ask Foxtrot
        self.assertEqual(o.strip(), wt.ROLLCALL_PROMPT)                         # still exactly the question
        self.assertEqual(load(wt.state_path("rollcall_round.json"))["opened"], opened)
        self.save("Foxtrot", first_answer("Foxtrot"))
        self.run_rollcall()
        self.assertEqual(sorted(self.state()["bots"]), ["Alpha", "Bravo", "Foxtrot"])
        self.assertEqual(self.state()["round"], opened)

    def test_a_valid_late_reply_replaces_that_bots_unparsed_one(self):
        self.run_wt("rollcall", "--question")
        self.save("Alpha", first_answer("Alpha"))
        self.save("Foxtrot", "Sure! Here is everything about me ...")         # not the asked JSON: WT-R010
        self.run_rollcall()
        self.assertEqual([f["rule"] for f in self.by_bot(self.state())["Foxtrot"]], ["WT-R010"])
        self.save("Foxtrot", first_answer("Foxtrot"))
        self.run_rollcall()
        rc = self.state()
        self.assertEqual([f["rule"] for f in self.by_bot(rc)["Foxtrot"]], ["WT-R013"])
        self.assertEqual(sorted(rc["bots"]), ["Alpha", "Foxtrot"])


class RoundBoundaries(Base):
    def test_a_new_roll_call_starts_fresh(self):
        self.seed(iso(wt.ROLLCALL_ROUND_DAYS + 1))                              # last month's round has closed
        self.save("Foxtrot", first_answer("Foxtrot"))                           # opens a new round
        self.run_rollcall()
        rc = self.state()
        self.assertEqual(rc["bots"], ["Foxtrot"])
        self.assertEqual(set(self.by_bot(rc)), {"Foxtrot"})
        self.assertNotEqual(rc["round"], None)

    def test_a_late_reply_inside_the_round_merges(self):
        self.seed(iso(wt.ROLLCALL_ROUND_DAYS - 1))
        self.save("Foxtrot", first_answer("Foxtrot"))
        self.run_rollcall()
        self.assertEqual(sorted(self.state()["bots"]), ["Alpha", "Foxtrot"])

    def test_a_file_from_another_round_is_not_merged_into(self):
        self.seed(iso(1), round_=iso(20))
        self.save("Foxtrot", first_answer("Foxtrot"))
        self.run_rollcall()
        self.assertEqual(self.state()["bots"], ["Foxtrot"])

    def test_a_file_from_before_shape_only_is_not_merged_into(self):
        self.seed(iso(1), shape_only=False)
        self.save("Foxtrot", first_answer("Foxtrot"))
        self.run_rollcall()
        self.assertEqual(self.state()["bots"], ["Foxtrot"])

    def test_a_garbled_or_future_round_counts_as_none(self):
        for opened in ("not a time", iso(-2), "2026-10-15T10:00:00"):        # garbled, in the future, no time zone
            wt.save_json(wt.state_path("rollcall_round.json"), {"opened": opened})
            self.assertIsNone(wt.current_rollcall_round(), opened)

    def test_without_a_round_a_second_run_replaces_as_before(self):
        rdir = wt.ensure_rollcall_dir()                                         # replies put in by hand, as in DQ-018
        for b in ("Alpha", "Delta"):
            dump(first_answer(b), os.path.join(rdir, b.lower() + ".json"))
        self.run_rollcall()
        dump(first_answer("Delta"), os.path.join(rdir, "delta.json"))
        out = self.run_rollcall()
        self.assertFalse(os.path.exists(wt.state_path("rollcall_round.json")))
        self.assertEqual(self.state()["bots"], ["Delta"])
        self.assertEqual(self.state()["round"], None)
        self.assertEqual(out["earlier_bots_kept"], [])

    def test_a_pruned_bot_does_not_come_back(self):
        self.run_wt("rollcall", "--question")
        for b in ("Alpha", "Bravo", "Foxtrot"):
            self.save(b, first_answer(b))
        self.run_rollcall()
        exp = os.path.join(os.environ["WATCHTOWER_HOME"], "exports"); os.makedirs(exp, exist_ok=True)
        rp = os.path.join(exp, "roster.json")
        dump([{"name": "Bravo", "kind": "bot"}, {"name": "Foxtrot", "kind": "bot"}], rp)
        os.utime(rp, (time.time() + 5, time.time() + 5))                       # saved after the roll-call: Alpha was removed
        rc, gone = wt.prune_removed_bots(wt.load_json(wt.state_path("rollcall_findings.json"), {}))
        self.assertEqual(gone, ["Alpha"])
        self.save("Foxtrot", answer("Foxtrot", routine="Invoice chaser"))
        out = self.run_rollcall()
        rc = self.state()
        self.assertEqual(sorted(rc["bots"]), ["Bravo", "Foxtrot"])
        self.assertNotIn("Alpha", self.by_bot(rc))
        self.assertEqual(out["earlier_bots_kept"], ["Bravo"])


class NothingSecretIsKept(Base):
    def test_no_reply_text_survives_a_merge(self):
        self.run_wt("rollcall", "--question")
        dump = dict(first_answer("Alpha"), memories=list(SECRETS), notes=SECRETS[0],
                    connectors=["Gmail", SECRETS[2]], routines=[{"name": "Pay", "trigger": "schedule", "instructions": SECRETS[1]}])
        self.save("Alpha", dump)
        self.save("Bravo", first_answer("Bravo"))
        o1 = self.run_rollcall()
        self.save("Foxtrot", first_answer("Foxtrot"))
        o2 = self.run_rollcall()
        self.assertEqual(sorted(self.state()["bots"]), ["Alpha", "Bravo", "Foxtrot"])
        kept, said = self.everything_watchtower_kept(), json.dumps([o1, o2])
        for s in SECRETS:
            for part in (s, s.split()[-1]):
                self.assertNotIn(part, kept)
                self.assertNotIn(part, said)


class TheFileIsWrittenSafely(Base):
    def test_the_findings_file_keeps_its_mode(self):
        for mode in (0o600, 0o640):
            self.seed(iso(1))
            os.chmod(wt.state_path("rollcall_findings.json"), mode)
            self.save("Foxtrot", first_answer("Foxtrot"))
            self.run_rollcall()
            p = wt.state_path("rollcall_findings.json")
            self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), mode)
            self.assertEqual(sorted(self.state()["bots"]), ["Alpha", "Foxtrot"])
            self.assertEqual([f for f in os.listdir(os.path.dirname(p)) if f.endswith(".tmp")], [])

    def test_a_failed_write_leaves_the_old_file_whole(self):
        p = wt.state_path("rollcall_findings.json")
        wt.save_json(p, {"bots": ["Alpha"], "findings": []})
        before = raw(p)
        with mock.patch.object(wt.json, "dump", side_effect=RuntimeError("disk full")):
            with self.assertRaises(RuntimeError):
                wt.save_json_keep_mode(p, {"bots": ["Foxtrot"], "findings": []})
        self.assertEqual(raw(p), before)
        self.assertEqual([f for f in os.listdir(os.path.dirname(p)) if f.endswith(".tmp")], [])

    def test_a_link_in_place_of_the_file_is_replaced_not_followed(self):
        opened = iso(1)
        wt.save_json(wt.state_path("rollcall_round.json"), {"opened": opened})
        elsewhere = os.path.join(self.tmp, "elsewhere.json")
        planted = {"at": opened, "round": opened, "masked": wt.VERSION, "shape_only": True, "bots": ["Mallory"], "findings": []}
        dump(planted, elsewhere)
        before = raw(elsewhere)
        p = wt.state_path("rollcall_findings.json")
        os.symlink(elsewhere, p)
        self.save("Foxtrot", first_answer("Foxtrot"))
        self.run_rollcall()
        self.assertFalse(os.path.islink(p))
        self.assertEqual(raw(elsewhere), before)                                # not written through
        self.assertEqual(self.state()["bots"], ["Foxtrot"])                     # and not read as the earlier run


class MergeUnit(unittest.TestCase):
    def test_a_bot_name_with_a_colon_goes_to_the_right_bot(self):
        f = lambda where, bot: {"rule": "WT-R013", "where": where, "evidence": "x", "key": where, "bot": bot}
        prev = {"round": "R", "masked": wt.VERSION, "shape_only": True, "bots": ["Alpha", "Alpha:Ops"],
                "findings": [f("rollcall:Alpha", "Alpha"), f("rollcall:Alpha:memories", "Alpha"), f("rollcall:Alpha:Ops", "Alpha:Ops"),
                             f("rollcall:Alpha:Ops:routine:Pay", "Alpha:Ops")]}
        rc = wt.merge_rollcall(prev, "R", [f("rollcall:Alpha", "Alpha")], ["Alpha"], ["Alpha"])
        self.assertEqual([x["where"] for x in rc["findings"]], ["rollcall:Alpha:Ops", "rollcall:Alpha:Ops:routine:Pay", "rollcall:Alpha"])
        self.assertEqual(rc["bots"], ["Alpha:Ops", "Alpha"])
        rc = wt.merge_rollcall(prev, "R", [], ["Alpha:Ops"], ["Alpha:Ops"])
        self.assertEqual([x["where"] for x in rc["findings"]], ["rollcall:Alpha", "rollcall:Alpha:memories"])
        rc = wt.merge_rollcall(prev, "other round", [], ["Alpha:Ops"], ["Alpha:Ops"])
        self.assertEqual(rc["findings"], [])
        self.assertEqual(rc["bots"], ["Alpha:Ops"])

    def test_the_owner_is_the_saved_bot_not_a_guess_from_where(self):
        """Codex round 1: Alpha's WT-M010 points at `rollcall:Alpha:memories`, the same text a Bot named "Alpha:memories" gets."""
        f = lambda where, bot: {"rule": "WT-M010", "where": where, "evidence": "x", "key": where + bot, "bot": bot}
        prev = {"round": "R", "masked": wt.VERSION, "shape_only": True, "bots": ["Alpha"],
                "findings": [f("rollcall:Alpha:memories", "Alpha"), f("rollcall:Alpha:routine:Pay", "Alpha")]}
        for late in ("Alpha:memories", "Alpha:routine:Pay"):
            rc = wt.merge_rollcall(prev, "R", [f(f"rollcall:{late}", late)], [late], [late])
            self.assertEqual([x["bot"] for x in rc["findings"]], ["Alpha", "Alpha", late], late)
            self.assertEqual(rc["bots"], ["Alpha", late])
        rc = wt.merge_rollcall(dict(prev, findings=prev["findings"] + [{"where": "rollcall:Alpha", "rule": "WT-R013"},
                                                                       {"where": "rollcall:Alpha", "rule": "WT-R013", "bot": ["Alpha"]}]),
                               "R", [], ["Alpha"], ["Alpha"])
        self.assertEqual([x.get("bot") for x in rc["findings"]], [None, ["Alpha"]])   # no saved Bot: kept, never dropped on a guess


class BotNamesThatLookLikeFindings(Base):
    """Codex round 1: names like "Alpha:memories" and "Alpha:routine:Pay" are accepted, and are exactly where Alpha's own
    WT-M010 and WT-R012 point. Each finding now carries its Bot, so neither Bot's findings are taken for the other's."""

    def alpha_first(self):
        self.run_wt("rollcall", "--question")
        self.save("Alpha", answer("Alpha", routine="Pay", loosen=1))           # WT-M010 at rollcall:Alpha:memories, WT-R012 at :routine:Pay
        self.run_rollcall()
        fs = self.state()["findings"]
        self.assertEqual(sorted((f["rule"], f["where"]) for f in fs),
                         [("WT-M010", "rollcall:Alpha:memories"), ("WT-R012", "rollcall:Alpha:routine:Pay")])
        return fs

    def test_a_late_bot_named_like_alphas_finding_leaves_alpha_alone(self):
        for late in ("Alpha:memories", "Alpha:routine:Pay"):
            with self.subTest(late=late):
                self.fresh_home()
                alpha = self.alpha_first()
                self.save(late, answer(late, sends_without_asking=True))
                out = self.run_rollcall()
                rc = self.state()
                self.assertEqual(rc["bots"], ["Alpha", late])
                self.assertEqual([f for f in rc["findings"] if f["bot"] == "Alpha"], alpha)
                self.assertEqual([(f["rule"], f["where"]) for f in rc["findings"] if f["bot"] == late], [("WT-R013", f"rollcall:{late}")])
                self.assertEqual(out["earlier_bots_kept"], ["Alpha"])

    def test_alpha_answering_again_replaces_only_its_own(self):
        self.run_wt("rollcall", "--question")
        self.save("Alpha:memories", answer("Alpha:memories", sends_without_asking=True))
        self.run_rollcall()
        self.save("Alpha", answer("Alpha", routine="Pay", loosen=1))           # its WT-M010 points at rollcall:Alpha:memories
        self.run_rollcall()
        self.save("Alpha", answer("Alpha"))                                     # Alpha cleaned up: no findings now
        self.run_rollcall()
        rc = self.state()
        self.assertEqual(rc["bots"], ["Alpha:memories", "Alpha"])
        self.assertEqual([(f["bot"], f["rule"]) for f in rc["findings"]], [("Alpha:memories", "WT-R013")])

    def test_pruning_uses_the_saved_bot_too(self):
        self.alpha_first()
        self.save("Alpha:memories", answer("Alpha:memories", sends_without_asking=True))
        self.run_rollcall()
        exp = os.path.join(os.environ["WATCHTOWER_HOME"], "exports"); os.makedirs(exp, exist_ok=True)
        rp = os.path.join(exp, "roster.json")
        dump([{"name": "Alpha:memories", "kind": "bot"}], rp)                  # Alpha was removed, "Alpha:memories" stays
        os.utime(rp, (time.time() + 5, time.time() + 5))
        rc, gone = wt.prune_removed_bots(self.state())
        self.assertEqual(gone, ["Alpha"])
        self.assertEqual([(f["bot"], f["rule"]) for f in rc["findings"]], [("Alpha:memories", "WT-R013")])


def fifo_unblocker(path):
    """Opening the write end lets a reader stuck on the FIFO see end-of-file, so a test that would hang fails instead."""
    try:
        os.close(os.open(path, os.O_WRONLY | os.O_NONBLOCK))
    except OSError:
        pass


class StateFilesSomeoneSwapped(Base):
    """Codex round 1: the saved findings and the round file are read without following a link or waiting on a FIFO, and the
    round file is written beside itself the same hardened way as the findings."""

    def run_within(self, fifo, *argv, stdin=None, seconds=10):
        res = {}
        t = threading.Thread(target=lambda: res.update(r=self.run_wt(*argv, stdin=stdin)), daemon=True)
        t.start()
        t.join(seconds)
        blocked = t.is_alive()
        if blocked:
            fifo_unblocker(fifo)
            t.join(seconds)
        self.assertFalse(blocked, f"{' '.join(argv)} waited on the FIFO at {os.path.basename(fifo)}")
        return res["r"]

    def test_a_fifo_for_the_findings_never_blocks_the_roll_call(self):
        for in_round in (False, True):
            with self.subTest(in_round=in_round):
                self.fresh_home()
                if in_round:
                    self.run_wt("rollcall", "--question")
                    self.save("Foxtrot", first_answer("Foxtrot"))
                else:
                    dump(first_answer("Foxtrot"), os.path.join(wt.ensure_rollcall_dir(), "foxtrot.json"))
                p = wt.state_path("rollcall_findings.json")
                os.mkfifo(p)
                code, o, e = self.run_within(p, "rollcall", "--owner-said-yes")
                self.assertEqual(code, 0, o + e)
                self.assertEqual(os.listdir(wt.default_rollcall_dir()), [])
                self.assertTrue(stat.S_ISREG(os.lstat(p).st_mode))
                self.assertEqual(self.state()["bots"], ["Foxtrot"])

    def test_a_fifo_for_the_round_never_blocks_the_question(self):
        p = wt.state_path("rollcall_round.json")
        os.mkfifo(p)
        code, o, _ = self.run_within(p, "rollcall", "--question")
        self.assertEqual((code, o.strip()), (0, wt.ROLLCALL_PROMPT))
        self.assertTrue(stat.S_ISREG(os.lstat(p).st_mode))
        self.assertIsNotNone(wt.current_rollcall_round())

    def test_a_link_swapped_in_after_any_check_is_still_not_followed(self):
        """The old code checked islink() and then opened by name, so a link put there between the two was followed. Here the
        check is made to see what it saw before the swap (no link); the open itself must still refuse the link."""
        self.run_wt("rollcall", "--question")
        opened = wt.current_rollcall_round()
        elsewhere = os.path.join(self.tmp, "elsewhere.json")
        dump({"at": opened, "round": opened, "masked": wt.VERSION, "shape_only": True, "bots": ["Mallory"],
              "findings": [dict(wt.finding("WT-R013", "x", "medium", [], "rollcall:Mallory", "x", "x"), bot="Mallory")]}, elsewhere)
        before = raw(elsewhere)
        p = wt.state_path("rollcall_findings.json")
        os.symlink(elsewhere, p)
        real = os.path.islink
        self.save("Foxtrot", first_answer("Foxtrot"))
        with mock.patch.object(wt.os.path, "islink", lambda q: False if q == p else real(q)):
            self.run_rollcall()
        self.assertFalse(os.path.islink(p))
        self.assertEqual(raw(elsewhere), before)
        self.assertEqual(self.state()["bots"], ["Foxtrot"])                     # Mallory's file was not read as the earlier run
        self.assertNotIn("Mallory", self.everything_watchtower_kept())

    def test_a_planted_temp_file_link_does_not_redirect_opening_a_round(self):
        for argv, stdin in ((("rollcall", "--question"), None), (("rollcall", "--save", "Foxtrot"), json.dumps(first_answer("Foxtrot")))):
            for tmpname in ("rollcall_round.json.tmp", f"rollcall_round.json.{os.getpid()}.tmp"):
                with self.subTest(argv=argv, tmp=tmpname):
                    self.fresh_home()
                    target = os.path.join(self.tmp, "victim.txt")
                    with open(target, "w") as f:
                        f.write("do not touch\n")
                    link = wt.state_path(tmpname)
                    os.symlink(target, link)
                    code, o, _ = self.run_wt(*argv, stdin=stdin)
                    self.assertEqual(code, 0, o)
                    self.assertEqual(raw(target), b"do not touch\n")             # the link's target is unchanged
                    rp = wt.state_path("rollcall_round.json")
                    self.assertTrue(stat.S_ISREG(os.lstat(rp).st_mode))
                    self.assertIsNotNone(wt.current_rollcall_round())

    def test_the_startup_migration_never_opens_or_follows_a_swapped_file(self):
        """Codex round 2: every command first runs migrate_rollcall_state, which checked isfile() and then opened the findings
        file by name. A FIFO or link put there between the two blocked the command or was followed. The check is made to see
        a regular file (as it would before the swap); the open itself must still refuse, and the target is never opened."""
        unmasked = {"at": iso(1), "bots": ["Mallory"], "findings": [wt.finding("WT-R013", "x", "medium", [], "rollcall:Mallory",
                                                                              SECRETS[0], "x")]}
        for kind in ("fifo", "link to a file", "link to a fifo"):
            with self.subTest(kind=kind):
                self.fresh_home()
                p = wt.state_path("rollcall_findings.json")
                target = os.path.join(tempfile.mkdtemp(dir=self.tmp), "elsewhere.json")
                if kind == "link to a file":
                    dump(unmasked, target)
                elif kind == "link to a fifo":
                    os.mkfifo(target)
                if kind == "fifo":
                    os.mkfifo(p)
                    target = p
                else:
                    os.symlink(target, p)
                before = os.lstat(target)
                real_isfile, real_open, real_os_open = os.path.isfile, open, os.open
                opened = []

                def spy_open(f, *a, **k):
                    if isinstance(f, (str, bytes, os.PathLike)) and os.path.realpath(f) == os.path.realpath(target):
                        opened.append(("open", f))
                    return real_open(f, *a, **k)

                def spy_os_open(f, flags, *a, **k):
                    if os.path.realpath(f) == os.path.realpath(target) and not flags & os.O_NOFOLLOW:
                        opened.append(("os.open", f))
                    return real_os_open(f, flags, *a, **k)

                with mock.patch.object(wt.os.path, "isfile", lambda q: True if q == p else real_isfile(q)), \
                        mock.patch("builtins.open", spy_open), mock.patch.object(wt.os, "open", spy_os_open):
                    code, o, _ = self.run_within(target, "rollcall", "--question")
                self.assertEqual((code, o.strip()), (0, wt.ROLLCALL_PROMPT))
                self.assertEqual(opened, [], "the migration opened what the findings file pointed at")
                self.assertFalse(os.path.lexists(p) and not stat.S_ISREG(os.lstat(p).st_mode))   # the swapped entry is gone
                if kind != "fifo":
                    after = os.lstat(target)
                    self.assertEqual((after.st_mode, after.st_size, after.st_mtime_ns),
                                     (before.st_mode, before.st_size, before.st_mtime_ns))  # the link's target is unchanged
                self.assertNotIn("rollcall-state-masked", self.everything_watchtower_kept())
                self.assertNotIn("Mallory", self.everything_watchtower_kept())


if __name__ == "__main__":
    unittest.main()
