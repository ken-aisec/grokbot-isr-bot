"""1.0 (U1): TruffleHog said "skipped / not checked" when 31 of 32 batches answered.

On the live box one batch of 3 files runs past its 60-second limit every audit, and that one batch made the whole stage a
failed one: "Skipped this run" in the audit JSON (stages_skipped, not_checked_this_run), the report and the weekly brief, and
TruffleHog left out of the brief's "Checked by" line, although the other files got fresh answers. Worse, the audit then read
the answers back from state/key_status.json, which is saved without this run's key fingerprints, so one token in two files
read as two tokens (the Nov 1 bugs' LATER item 1). Now a run where a batch ran out of time but another finished is "partly checked",
one line with its counts (stages_partial, also in not_checked_this_run, the report and the brief), and the audit keeps the
fresh answers. A run where no batch finished, or a batch failed with an error, is still skipped (fail closed).

The TruffleHog stand-ins sleep past the batch limit only when one of their arguments ends in stuck.log; stuck.log holds a key
too (so it is a target) and is the oldest file, so it lands in the last batch. Old answers are seeded as test_v084_nov1 does.

Tests marked "replay" fail on 52351db (1.0 batch 1, whose TruffleHog code is 56ed018's, v0.8.5) at their assertion; "guard"
ones pass there too. Every token is made when the test runs (FAKE, never a real key); TruffleHog and gh are stand-ins."""
import json, os, sys, unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import Box, TH_DONE  # noqa: E402
from test_batch6_example_keys import token  # noqa: E402
import test_v082_secrets as v82  # noqa: E402  (module access: its test classes don't run twice)
import test_batch5_brief_access as b5  # noqa: E402  (module access: the brief harness; its tests don't run twice)
import isr  # noqa: E402

STAGE = "TruffleHog (which keys still work)"
OLD_AT = "2026-10-27T00:38:00+00:00"   # as test_v084_nov1: Oct 26 8:38 PM ET
OLD_ET = "Oct 26 8:38 PM ET"
PARTIAL = f"{STAGE}: 25 of 31 files re-checked; 6 kept their older answer"
T0 = 1_790_000_000

HANGS = 'for a in "$@"; do case "$a" in *stuck.log) sleep 30;; esac; done\n'
FAILS = 'for a in "$@"; do case "$a" in *stuck.log) echo "fatal: could not start" >&2; exit 1;; esac; done\n'


def stuck_trufflehog(stuck=HANGS):
    """Shaped like test_v084_nov1.fake_trufflehog: one verified Github answer for each file it is given; `stuck` decides what a
    batch holding stuck.log does (sleeps past any batch's limit, or fails)."""
    return ("#!/bin/sh\n" + stuck +
            'for a in "$@"; do case "$a" in --*|filesystem) ;; *) printf \'{"SourceMetadata":{"Data":{"Filesystem":{"file":"%s","line":1}}},'
            '"DetectorName":"Github","Verified":true}\\n\' "$a";; esac; done\n'
            "echo '" + TH_DONE + "' >&2\n")


# The answers in ANSWERS (as TruffleHog reports them, Raw included) for exactly the files it is given; it sleeps on stuck.log
TRUFFLEHOG_ANSWERS = r"""#!/usr/bin/env python3
import json, sys, time
a = [x for x in sys.argv[1:] if not x.startswith("--") and x != "filesystem"]
if any(x.endswith("stuck.log") for x in a):
    time.sleep(30)
for d in json.load(open(ANSWERS)):
    if d["SourceMetadata"]["Data"]["Filesystem"]["file"] in a:
        print(json.dumps(d))
sys.stderr.write(DONE + "\n")
"""


class _Partial(Box):
    def put(self, p, text, at=None):
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(text)
        if at is not None:
            os.utime(p, (at, at))
        return p

    def files(self, n):
        """n key files, each with its own fake GitHub token; file i was changed i seconds after the first (the last is newest)."""
        return [self.put(os.path.join(self.ws, "keys", f"k{i:03d}.env"), "GITHUB_TOKEN=" + token("gh" + "p_", 36) + "\n", T0 + i)
                for i in range(n)]

    def stuck(self):
        """stuck.log: a key file too, changed before every other one, so it is in the last batch."""
        return self.put(os.path.join(self.ws, "keys", "stuck.log"), "GITHUB_TOKEN=" + token("gh" + "p_", 36) + "\n", T0 - 1)

    def old_answers(self, paths):
        isr.save_json(isr.state_path("key_status.json"), {"at": OLD_AT, "ran": True, "files": {
            p: [{"detector": "Github", "status": "dead", "line": 1, "guide": None}] for p in paths}})

    def limits(self, batch, budget):
        for name, v in (("TRUFFLEHOG_BATCH_SECONDS", batch), ("TRUFFLEHOG_BUDGET", budget)):
            p = mock.patch.object(isr, name, v, create=True); p.start(); self.addCleanup(p.stop)

    def audit_with(self, paths, trufflehog, **scanners):
        """One audit with old answers for `paths`, 2-second batches inside a 20-second budget, and these stand-ins."""
        self.skills(1)
        self.old_answers(paths)
        self.limits(2, 20)
        self.scanners(trufflehog=trufflehog, **scanners)
        return self.audit()

    def partial(self):
        """30 key files and stuck.log: the 25 newest answer (batch 1), the batch with stuck.log runs out of time (batch 2)."""
        return self.audit_with(self.files(30) + [self.stuck()], stuck_trufflehog())

    def brief_page(self):
        return b5._Brief.brief(self, [("Routine update notes for office software", "")])[2]

    def batches_finished(self):
        return [b["finished"] for b in isr.load_json(isr.state_path("trufflehog_batches.json"), {})["batches"]]


class PartlyChecked(_Partial):
    def test_one_slow_batch_is_partly_checked_not_skipped(self):   # replay
        self.partial()
        snap = self.snap()
        self.assertNotIn(STAGE, snap["stages_skipped"])                # 52351db: in it, the whole stage "skipped"
        self.assertEqual(snap["stages_partial"], [PARTIAL])
        self.assertIn(f"TruffleHog ran out of time: 25 of 31 files re-checked; the rest show answers from {OLD_ET}.", snap["notes"])
        self.assertEqual(self.batches_finished(), [True, False])

    def test_not_checked_this_run_still_names_the_kept_files(self):   # replay
        r = self.partial()
        self.assertIn(PARTIAL, r["not_checked_this_run"])              # 52351db: [STAGE], the bare name
        self.assertEqual(r["stages_partial"], [PARTIAL])
        self.assertNotIn("stages_skipped", r)

    def test_the_report_says_partly_checked(self):   # replay
        self.partial()
        md = isr.render_md(self.snap(), [], "2026-W45")
        self.assertIn("\n## Partly checked this run\n\n- " + PARTIAL + ".\n", md)   # 52351db: no such section
        self.assertNotIn("## Skipped this run", md)

    def test_the_brief_says_partly_checked(self):   # replay (Codex 1)
        self.partial()
        page = self.brief_page()
        self.assertIn(f"<b>Partly checked this run:</b> {PARTIAL}.", page)   # 52351db: "Skipped this run: TruffleHog ..." only
        self.assertNotIn("Skipped this run", page)
        self.assertIn("TruffleHog", page.split("Checked by")[1].split("</p>")[0])   # it ran, so it is among the scanners

    def test_a_partial_run_keeps_one_token_in_two_copies(self):   # replay (the Nov 1 bugs' LATER item 1)
        tok = v82.pat(11)
        top = os.path.join(self.home, ".cursor", "projects")
        a = self.put(os.path.join(top, "q", "terminals", "a.txt"), f"x\nGH_TOKEN={tok}\n")
        b = self.put(os.path.join(top, "q", "terminals", "b.txt"), f"GH_TOKEN={tok}\n")
        stuck = self.stuck()
        report, said = os.path.join(self.tmp, "leaks.json"), os.path.join(self.tmp, "answers.json")
        with open(report, "w") as f:
            json.dump(v82.leaks(a, tok, "github-fine-grained-pat") + v82.leaks(b, tok, "github-fine-grained-pat"), f)
        with open(said, "w") as f:
            json.dump([v82.answer(a, 2, "Github", True, tok), v82.answer(b, 1, "Github", True, tok)], f)
        p = mock.patch.object(isr, "TRUFFLEHOG_BATCH_FILES", 1); p.start(); self.addCleanup(p.stop)   # stuck.log's batch alone hangs
        self.audit_with([stuck], TRUFFLEHOG_ANSWERS.replace("ANSWERS", repr(said)).replace("DONE", repr(TH_DONE)),
                        gitleaks=v82.GITLEAKS.replace("REPORT", repr(report)))
        fs = self.snap()["findings"]
        g = [f for f in fs if f["rule"] == "ISR-S002" and f["where"] == top]
        self.assertEqual(len(g), 1, [(f["rule"], f["where"]) for f in fs if f["rule"].startswith("ISR-S")])
        self.assertIn("1 token, 2 copies", g[0]["evidence"])          # 52351db: "2 tokens, 2 copies" (read back without fingerprints)
        self.assertEqual(g[0]["title"], isr.KEY_LIVE)
        self.assertIn(False, self.batches_finished())                  # it was a partial run
        self.assertIn(True, self.batches_finished())


class StillSkipped(_Partial):
    def test_no_batch_finishing_is_still_skipped(self):   # guard
        self.audit_with([self.stuck()], stuck_trufflehog())
        snap = self.snap()
        self.assertIn(STAGE, snap["stages_skipped"])
        self.assertNotIn("stages_partial", snap)
        self.assertEqual(self.batches_finished(), [False])
        page = self.brief_page()
        self.assertIn(STAGE, page.split("<b>Skipped this run:</b>")[1].split("</p>")[0])
        self.assertNotIn("Partly checked", page)

    def test_a_batch_error_is_still_skipped(self):   # guard (as test_v084_nov1's exit 1, here with the other batch finished)
        self.audit_with(self.files(30) + [self.stuck()], stuck_trufflehog(FAILS))
        snap = self.snap()
        self.assertIn(STAGE, snap["stages_skipped"])
        self.assertNotIn("stages_partial", snap)
        self.assertIn(f"TruffleHog FAILED (fatal: could not start): 25 of 31 files re-checked; the rest show answers from {OLD_ET}.",
                      snap["notes"])

    def test_every_batch_finishing_is_neither(self):   # guard
        r = self.audit_with(self.files(30), stuck_trufflehog())
        snap = self.snap()
        self.assertEqual(self.batches_finished(), [True, True])
        self.assertNotIn("stages_partial", snap)
        self.assertEqual(snap["stages_skipped"], [])
        for k in ("stages_partial", "stages_skipped", "not_checked_this_run"):
            self.assertNotIn(k, r)


if __name__ == "__main__":
    unittest.main()
