"""v0.8.4 (the Nov 1 fixes): TruffleHog in batches, the score trend's baseline, the own gh token said beside its own hit.

Item 1: the Nov 1 audit's TruffleHog stage timed out (one run, 150 s, 200 of 242 files kept with no note), so it failed whole and
the report showed 5-day-old live/dead answers with nothing saying how old, under a SCANNERS MISSING note. Now it scans in
batches, each with its own limit, inside one budget: a finished batch's files get new answers, the rest keep their old ones,
marked with when they were made; the stage still fails; running out of time has its own note.
Item 2: "up 61 from last week" when the score went 88 -> 87: the baseline was the last full audit 6 days old (Oct 25, another
version). Now it is the latest full audit at least 12 hours older, named by its date, with a note when ISR Bot itself changed.
Item 3: an sk-ant finding said "the same token as this computer's own gh sign-in" because another hit in its file was the gh
token. Now the sentence goes beside the hit it is about, the shown key is named by its prefix, and only a GitHub-shaped key can
be marked own. Fake tokens are built when the test runs; gh is never run (Box patches own_gh_token).

Review fixes: the daily check's answers say their date too; a TruffleHog stage skipped because earlier stages used the run's
time is ran out of time, never SCANNERS MISSING; sizing a folder for the batches stops when the stage's budget is used.

Tests marked "replay" fail on 382af76 (v0.8.3) at their assertion; "control" ones pass there too. The "review fix" replays fail
on the first v0.8.4 change too."""
import json, os, sys, time, unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import Box, TH_DONE, temp_home  # noqa: E402
from test_isr_bot import fake_key  # noqa: E402
from test_batch6_example_keys import token  # noqa: E402
import test_v082_secrets as v82  # noqa: E402  (module access: its test classes don't run twice)
import isr  # noqa: E402

STAGE = "TruffleHog (which keys still work)"
OLD_AT = "2026-10-27T00:38:00+00:00"   # the last TruffleHog success before Nov 1: Oct 26 8:38 PM ET
OLD_ET = "Oct 26 8:38 PM ET"


def fake_trufflehog(count, slow_from=None):
    """A TruffleHog stand-in: one verified Github answer for each file it is given; from launch `slow_from` on it sleeps past any
    batch's limit (counted in the file `count`)."""
    slow = f'if [ "$n" -ge {slow_from} ]; then sleep 30; fi\n' if slow_from else ""
    return ("#!/bin/sh\n" f"n=$(cat {count!r} 2>/dev/null || echo 0); n=$((n+1)); echo $n > {count!r}\n" + slow +
            'for a in "$@"; do case "$a" in --*|filesystem) ;; *) printf \'{"SourceMetadata":{"Data":{"Filesystem":{"file":"%s","line":1}}},'
            '"DetectorName":"Github","Verified":true}\\n\' "$a";; esac; done\n'
            "echo '" + TH_DONE + "' >&2\n")


class TruffleHogBatches(Box):
    def files(self, n):
        """n key files, each with its own fake GitHub token; file i was changed i seconds after the first (the last is newest)."""
        d = os.path.join(self.ws, "keys")
        os.makedirs(d)
        out = []
        for i in range(n):
            p = os.path.join(d, f"k{i:03d}.env")
            with open(p, "w") as f:
                f.write("GITHUB_TOKEN=" + token("gh" + "p_", 36) + "\n")
            os.utime(p, (1_790_000_000 + i, 1_790_000_000 + i))
            out.append(p)
        return out

    def old_answers(self, paths, status="dead"):
        isr.save_json(isr.state_path("key_status.json"), {"at": OLD_AT, "ran": True, "files": {
            p: [{"detector": "Github", "status": status, "line": 1, "guide": None}] for p in paths}})

    def limits(self, batch, budget):
        for name, v in (("TRUFFLEHOG_BATCH_SECONDS", batch), ("TRUFFLEHOG_BUDGET", budget)):
            p = mock.patch.object(isr, name, v, create=True); p.start(); self.addCleanup(p.stop)

    def finding(self, p):
        got = [f for f in self.snap()["findings"] if f["rule"] == "ISR-S001" and f["where"].startswith(p + ":")]
        self.assertEqual(len(got), 1, got)
        return got[0]

    def test_a_batch_that_runs_out_of_time_keeps_what_finished(self):   # replay
        paths = self.files(250)
        self.skills(1)
        self.scanners(trufflehog=fake_trufflehog(os.path.join(self.tmp, "good.count")))
        self.audit()                                                    # TruffleHog ran: it is expected from now on
        self.old_answers(paths)
        self.limits(2, 5)
        self.scanners(trufflehog=fake_trufflehog(os.path.join(self.tmp, "slow.count"), slow_from=3))
        self.audit()
        notes = self.snap()["notes"]                                    # the audit's printed answer is cut to fit
        said = [n for n in notes if n.startswith("TruffleHog ran out of time")]
        self.assertEqual(said, [f"TruffleHog ran out of time: 50 of 250 files re-checked; the rest show answers from {OLD_ET}."], notes)
        self.assertIn(STAGE, self.snap()["stages_skipped"])            # fail closed stays
        self.assertFalse([n for n in notes if "SCANNERS MISSING" in n], notes)
        self.assertNotIn("TruffleHog", self.snap().get("scanners_missing") or [])
        files = isr.load_json(isr.state_path("key_status.json"), {})["files"]
        fresh = {p for p, ks in files.items() if not any(k.get("old") for k in ks)}
        self.assertEqual(fresh, set(paths[200:]))                      # the first two batches: the 50 newest files
        self.assertEqual({k["old"] for p in paths[:200] for k in files[p]}, {OLD_AT})
        self.assertEqual(self.finding(paths[249])["title"], isr.KEY_LIVE)
        self.assertIn(f"(answer from {OLD_ET})", self.finding(paths[0])["evidence"])
        log = isr.load_json(isr.state_path("trufflehog_batches.json"), {})["batches"]
        self.assertEqual([b["finished"] for b in log[:3]], [True, True, False])
        self.assertEqual({k for b in log for k in b}, {"files", "bytes", "seconds", "finished"})   # counts only, no content
        self.assertEqual(log[0]["files"], 25)

    def test_more_than_200_files_says_200_of_242(self):   # replay (the Nov 1 count)
        paths = self.files(242)
        self.skills(1)
        self.old_answers(paths)
        self.scanners(trufflehog=fake_trufflehog(os.path.join(self.tmp, "n.count")))
        self.audit()
        self.assertIn(f"TruffleHog checked 200 of 242 flagged files (the most serious and newest first); the rest show answers from {OLD_ET}.",
                      self.snap()["notes"])
        self.assertNotIn(STAGE, self.snap()["stages_skipped"])         # nothing failed: the cap is said, not a failure
        files = isr.load_json(isr.state_path("key_status.json"), {})["files"]
        self.assertEqual({p for p in paths if any(k.get("old") for k in files[p])}, set(paths[:42]))

    def test_carried_answers_say_their_date(self):   # replay
        p, = self.files(1)
        self.skills(1)
        self.old_answers([p], status="live")
        self.scanners(trufflehog="#!/bin/sh\necho 'fatal: could not start' >&2\nexit 1\n")
        self.audit()
        self.assertIn(STAGE, self.snap()["stages_skipped"])
        f = self.finding(p)
        self.assertIn(f"(answer from {OLD_ET})", f["evidence"])
        self.assertIn(f"Live/dead key answers shown are from {OLD_ET}: TruffleHog re-checked none this run.", self.snap()["notes"])
        self.assertIn(f"answer from {OLD_ET}", isr.render_md(self.snap(), [], "2026-W44"))

    def test_the_daily_check_says_when_its_answers_were_made(self):   # replay (review fix 1: the daily showed them as just "live")
        p, = self.files(1)
        self.skills(1)
        self.scanners(trufflehog=fake_trufflehog(os.path.join(self.tmp, "n.count")))
        self.audit()
        self.old_answers([p], status="live")                            # the last full audit's answers, made Oct 26
        code, _, e = self.run_cmd("daily", "--roots", *self.roots)
        self.assertEqual(code, 0, e)
        f = self.finding(p)
        self.assertEqual(f["title"], isr.KEY_LIVE)
        self.assertIn(f"(answer from {OLD_ET})", f["evidence"])
        self.assertIn(f"answer from {OLD_ET}", isr.render_md(self.snap(), [], "2026-W44"))

    def test_no_time_left_before_trufflehog_is_ran_out_of_time_not_missing(self):   # replay (review fix 2)
        p, = self.files(1)
        self.skills(1)
        count = os.path.join(self.tmp, "n.count")
        self.scanners(trufflehog=fake_trufflehog(count))
        self.audit()
        self.old_answers([p], status="live")
        os.remove(count)
        spent, own = [False], isr.self_findings                        # the stage just before TruffleHog uses up the run's time

        def own_tools(*a, **k):
            spent[0] = True
            return own(*a, **k)
        for name, v in (("self_findings", own_tools), ("time_left", lambda default=10 ** 6: 2 if spent[0] else default)):
            m = mock.patch.object(isr, name, v); m.start(); self.addCleanup(m.stop)
        self.audit()
        snap = self.snap()
        self.assertNotIn("TruffleHog", snap.get("scanners_missing") or [])
        self.assertFalse([n for n in snap["notes"] if "SCANNERS MISSING" in n and "TruffleHog" in n], snap["notes"])
        self.assertIn(f"TruffleHog ran out of time: skipped this run; the last live/dead answers are kept, from {OLD_ET}.", snap["notes"])
        self.assertIn(STAGE, snap["stages_skipped"])                   # still not checked this run
        self.assertFalse(os.path.exists(count))                         # never launched
        self.assertIn(f"(answer from {OLD_ET})", self.finding(p)["evidence"])

    def test_sizing_folders_stops_when_the_budget_is_used(self):   # replay (review fix 3: sizing walked before the budget began)
        d = os.path.join(self.ws, "group")                              # a gitleaks group's folder, sized file by file
        os.makedirs(d)
        for i in range(100):
            with open(os.path.join(d, f"f{i:03d}.txt"), "w") as f:
                f.write("x\n")
        self.scanners(trufflehog=fake_trufflehog(os.path.join(self.tmp, "n.count")))
        self.limits(60, 1)
        look = isr._look

        def slow_look(*a, **k):                                         # 100 files: 5 s of sizing on a slow disk
            time.sleep(0.05)
            return look(*a, **k)
        m = mock.patch.object(isr, "_look", slow_look); m.start(); self.addCleanup(m.stop)
        self.addCleanup(isr.SLOW_SCANNERS.clear)
        notes, t0 = [], time.monotonic()
        isr.trufflehog_status([d], notes)
        self.assertLess(time.monotonic() - t0, 3)                       # the 1-second budget, not the whole walk and then the budget
        self.assertIn("TruffleHog ran out of time: 0 of 1 files re-checked; the rest have no earlier answer.", notes)

    def test_a_finished_run_marks_nothing_old(self):   # control
        p, = self.files(1)
        self.skills(1)
        self.old_answers([p])
        self.scanners(trufflehog=fake_trufflehog(os.path.join(self.tmp, "n.count")))
        self.audit()
        self.assertEqual(isr.load_json(isr.state_path("key_status.json"), {})["files"],
                         {p: [{"detector": "Github", "status": "live", "line": 1, "guide": None}]})
        self.assertFalse([n for n in self.snap()["notes"] if "TruffleHog" in n], self.snap()["notes"])


class TrendBaseline(unittest.TestCase):
    def setUp(self):
        temp_home(self)

    def hist(self, *rows):
        """score_history.csv rows (at, score, version), full audits with gitleaks and TruffleHog, read back as the report reads them."""
        with open(isr.state_path("score_history.csv"), "w") as f:
            for at, score, version in rows:
                f.write(f"{at},{score},10,full,{isr.SCORE_ERA}:{version}|TruffleHog+gitleaks\n")
        return isr.load_history()

    NOV1 = (("2026-10-25T12:30:00+00:00", 26, "0.8.0"), ("2026-10-28T12:30:00+00:00", 88, "0.8.1"),
            ("2026-11-01T11:05:00+00:00", 87, "0.8.2"), ("2026-11-01T11:40:00+00:00", 87, "0.8.2"))

    def test_the_nov_1_rows_compare_with_oct_28(self):   # replay
        got = isr.trend(self.hist(*self.NOV1))
        self.assertIn("down 1 since Oct 28: 88", got)
        self.assertNotIn("61", got)
        self.assertNotIn("last week", got)
        self.assertIn("ISR Bot itself changed (0.8.1 -> 0.8.2), so the change may not be your computer", got)

    def test_two_audits_on_one_morning_are_not_compared(self):   # replay
        self.assertEqual(isr.trend(self.hist(*self.NOV1[2:])), "first week")
        got = isr.trend(self.hist(("2026-10-28T12:30:00+00:00", 88, "0.8.2"), ("2026-11-01T07:00:00+00:00", 90, "0.8.2"),
                                  ("2026-11-01T11:40:00+00:00", 87, "0.8.2")))
        self.assertEqual(got, "down 1 since Oct 28: 88")              # not the 07:00 audit, and no change note

    def test_one_prior_audit_three_days_old_still_compares(self):   # replay
        got = isr.trend(self.hist(("2026-10-29T12:30:00+00:00", 85, "0.8.2"), ("2026-11-01T11:40:00+00:00", 87, "0.8.2")))
        self.assertEqual(got, "up 2 since Oct 29: 85")

    def test_scanners_that_changed_are_named(self):   # replay
        rows = self.hist(("2026-10-28T12:30:00+00:00", 88, "0.8.2"), ("2026-11-01T11:40:00+00:00", 88, "0.8.2"))
        rows[-1] = rows[-1][:4] + (rows[-1][4].replace("TruffleHog+", ""),)
        self.assertEqual(isr.trend(rows), "no change since Oct 28: 88; ISR Bot itself changed (TruffleHog didn't run), "
                                          "so the change may not be your computer")

    def test_dates_are_eastern_on_both_sides_of_a_clock_change(self):   # new helper (et_time is new: errors on the base)
        for at, want in (("2026-11-01T05:59:00+00:00", "Nov 1 1:59 AM ET"), ("2026-11-01T06:00:00+00:00", "Nov 1 1:00 AM ET"),
                         ("2026-03-08T06:59:00+00:00", "Mar 8 1:59 AM ET"), ("2026-03-08T07:00:00+00:00", "Mar 8 3:00 AM ET"),
                         ("2026-01-01T03:00:00+00:00", "Dec 31 10:00 PM ET"), (OLD_AT, OLD_ET), ("not a time", "not a time")):
            with self.subTest(at):
                self.assertEqual(isr.et_time(at), want)

    def test_no_earlier_audit_is_the_first(self):   # control
        self.assertEqual(isr.trend(self.hist(self.NOV1[0])), "first week")
        self.assertEqual(isr.trend([]), "first week")


def ant(seed):
    """An Anthropic API key's shape, made now (never committed)."""
    return "sk-" + "ant-" + "api03-" + fake_key(93, seed=seed)


class OwnTokenPerHit(v82._Keys):
    def own(self, value):
        p = mock.patch.object(isr, "own_gh_token", return_value=value, create=True); p.start(); self.addCleanup(p.stop)

    def keyfile(self, *values):
        return self.put(os.path.join(self.ws, "projects", "app", "notes.txt"), "".join(f"KEY_{i}={v}\n" for i, v in enumerate(values)))

    def one(self, rule, p):
        got = [f for f in self.snap()["findings"] if f["rule"] == rule and f["where"].startswith(p + ":")]
        self.assertEqual(len(got), 1, [(f["rule"], f["where"]) for f in self.snap()["findings"]])
        return got[0]

    def assert_said_beside_the_github_hit(self, f):
        first, _, rest = f["evidence"].partition(";")
        self.assertNotIn("gh sign-in", first, f["evidence"])          # 382af76: "... - the same token as this computer's own gh sign-in"
        self.assertNotIn("GitHub", first)
        self.assertIn("GitHub key at notes.txt:2 - the same token as this computer's own gh sign-in (also holds 1 other key)", rest)
        self.assertEqual(f["fix"].count(isr.OWN_FIX), 1)                # added to its own fix, once
        self.assertEqual(f.get("own_token"), "gh")

    def test_isr_rule_finding_names_each_key(self):   # replay (ISR-S001, no TruffleHog)
        gh = v82.pat(11)
        self.own(gh)
        p = self.keyfile(ant(1), gh)
        self.skills(1); self.scanners(trufflehog=None)
        self.audit()
        f = self.one("ISR-S001", p)
        self.assertTrue(f["evidence"].startswith("Anthropic key sk-ant"), f["evidence"])
        self.assertIn("(2 in file)", f["evidence"])
        self.assert_said_beside_the_github_hit(f)
        self.assertIn("Revoke the key", f["fix"])

    def test_gitleaks_finding_says_it_beside_the_github_hit(self):   # replay (ISR-S002, TruffleHog finds nothing)
        gh, a = v82.pat(11), ant(1)
        self.own(gh)
        p = self.keyfile(a, gh)
        self.run_scan(v82.leaks(p, a, "anthropic-api-key") + v82.leaks(p, gh, "github-fine-grained-pat"), [])
        self.assert_said_beside_the_github_hit(self.one("ISR-S002", p))

    def test_key_status_answers_say_it_beside_the_github_hit(self):   # replay (key_status_severity)
        gh, a = v82.pat(11), ant(1)
        self.own(gh)
        p = self.keyfile(a, gh)
        self.run_scan(v82.leaks(p, a, "anthropic-api-key") + v82.leaks(p, gh, "github-fine-grained-pat"),
                      [v82.answer(p, 1, "Anthropic", True, a), v82.answer(p, 2, "Github", True, gh)])
        for rule in ("ISR-S001", "ISR-S002"):
            with self.subTest(rule):
                f = self.one(rule, p)
                self.assertEqual(f["title"], isr.KEY_LIVE)
                self.assertTrue(f["evidence"].startswith("Anthropic: 1 token"), f["evidence"])
                self.assert_said_beside_the_github_hit(f)

    def test_an_anthropic_key_is_never_marked_own(self):   # replay (the prefix check beside the fingerprint check)
        a = ant(1)
        self.own(a)                                                     # even when gh's token has the same fingerprint
        p = self.keyfile(a)
        self.run_scan(v82.leaks(p, a, "anthropic-api-key"), [v82.answer(p, 1, "Anthropic", True, a)])
        for rule in ("ISR-S001", "ISR-S002"):
            with self.subTest(rule):
                f = self.one(rule, p)
                self.assertNotIn("gh sign-in", f["evidence"])
                self.assertNotIn("own_token", f)
        self.assertFalse([k for ks in isr.load_json(isr.state_path("key_status.json"), {})["files"].values() for k in ks if k.get("own_token")])

    def test_another_gh_token_marks_nothing(self):   # control
        a = ant(1)
        self.own(v82.pat(99))
        p = self.keyfile(a)
        self.run_scan(v82.leaks(p, a, "anthropic-api-key"), [v82.answer(p, 1, "Anthropic", True, a)])
        for rule in ("ISR-S001", "ISR-S002"):
            with self.subTest(rule):
                f = self.one(rule, p)
                self.assertNotIn("gh sign-in", f["evidence"])
                self.assertNotIn(isr.OWN_FIX, f["fix"])
                self.assertNotIn("own_token", f)


if __name__ == "__main__":
    unittest.main()
