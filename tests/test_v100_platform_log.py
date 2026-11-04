"""1.0 (U3): the Grok CLI's own log, ~/.grok/logs/unified.jsonl, records the first 12 characters of its own sign-in key each
time it refreshes it. gitleaks read each as a key, so ISR Bot listed the log as the owner's file with possible secrets (one
Worth-a-look ISR-S002), new and fixed in the same run as it grew, and sent it to TruffleHog. Now hits measured from gitleaks'
own report as short key prefixes in that file are one platform note ("Grok Bot's own log: shows a short key prefix. Not
counted."); a longer key, a hit whose length can't be told for sure, another rule, another field, or the same prefix in any
other file still counts. The note keeps its own title and fix after TruffleHog's answers are applied (approved addition).

Calibration (once, before this fake was written): ISR Bot's own gitleaks (8.30.1), with ISR Bot's config and the flags
gitleaks_private uses, on synthetic logs holding made-up 12- and 40-character values, in a temp folder. What it wrote, which
the fake gitleaks here reproduces (leak()):
- Secret "REDACTED"; Match the compact field with the value redacted, up to its closing quote: key_prefix":"REDACTED" (the
  same for pre_key, post_key and old_key_prefix; with a space after the colon, key_prefix": "REDACTED"); Entropy a float;
  StartLine == EndLine, counted in the whole file.
- Columns in bytes, both ends inclusive: from 1 on line 1 (a field at byte 38 of line 1: StartColumn 39), from 2 on the lines
  after (byte 38: 40). gitleaks' first piece of a file was its first 125,000 bytes (100,000, then 25,000 more looking for a
  blank line); a hit on the next piece's first, partial line counted from 1 at that piece's start (a field at byte 125,033:
  StartColumn 34).
- EndColumn - StartColumn + 1 was the whole match's bytes wherever the hit was (26 for a 12-character value, 54 for 40), so
  span - (len(Match) - 8) gave 12 and 40 exactly at line 1, near 100 KB, at the second piece's start and near 160 KB.
- Two fields on one line were two hits: key_prefix":"REDACTED" (columns 39-64) and api_key":"REDACTED" (67-117).
- A 12-character value in a "password" field gave no hit in that run; the guard here has the fake report one anyway.

Tests marked "replay" fail on 56ed018 (v0.8.5) at their assertion; "guard" ones pass there too. Every value is made when the
test runs (FAKE, never a real key); TruffleHog and gh are stand-ins."""
import json, os, sys, unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import Box, TH_DONE  # noqa: E402
from test_isr_bot import fake_key  # noqa: E402
import test_v082_secrets as v82  # noqa: E402  (module access: its test classes don't run twice)
import isr  # noqa: E402

LINE = "Grok Bot's own log: shows a short key prefix. Not counted."
TITLE = "gitleaks: short key prefixes in Grok Bot's own log"
PIECE = 125_000   # where gitleaks' second piece of a file started in the calibration run
KEY = '{"msg":"auth.refresh.success","ctx":{"key_prefix":"%s"}}'
FIELD = 'key_prefix":"%s"'
API = 'api_key":"%s"'

GITLEAKS = r"""#!/usr/bin/env python3
import json, sys
a = sys.argv[1:]
if a and a[0] == "version":
    print("8.30.1"); sys.exit(0)
src = a[a.index("--source") + 1].rstrip("/") + "/"
open(a[a.index("--report-path") + 1], "w").write(json.dumps([h for h in json.load(open(REPORT)) if h["File"].startswith(src)]))
for p in json.load(open(GROW)):
    if p.startswith(src):
        open(p, "a").write('{"msg":"tick"}\n')
"""
ARGS_TRUFFLEHOG = "#!/bin/sh\nfor a in \"$@\"; do echo \"$a\" >> ARGS; done\necho '" + TH_DONE + "' >&2\n"


def leak(path, text, value, rule="generic-api-key", piece=None):
    """gitleaks' hit for the first `text` (the whole match as written in the file, holding `value`) in `path`, as the
    calibration run reported one. `piece`: where gitleaks' piece holding the hit started, for a hit on that piece's first line."""
    with open(path, "rb") as f:
        data = f.read()
    at = data.index(text.encode())
    n = data.count(b"\n", 0, at) + 1
    start = data.rfind(b"\n", 0, at) + 1
    col = at - piece + 1 if piece is not None and start <= piece <= at else at - start + (1 if n == 1 else 2)
    return {"RuleID": rule, "Description": "a stand-in's rule", "StartLine": n, "EndLine": n, "StartColumn": col,
            "EndColumn": col + len(text.encode()) - 1, "Match": text.replace(value, "REDACTED"), "Secret": "REDACTED", "File": path,
            "SymlinkFile": "", "Commit": "", "Entropy": isr.shannon_entropy(value), "Author": "", "Email": "", "Date": "", "Message": "",
            "Tags": [], "Fingerprint": f"{path}:{rule}:{n}"}


def padding(n):
    """n bytes (at least 9) of plain log lines with no key in them."""
    out, size, i = [], 0, 0
    while n - size > 60:
        t = '{"msg":"tick","seq":"%06d"}\n' % i
        out.append(t)
        size, i = size + len(t), i + 1
    out.append('{"p":"' + "x" * (n - size - 9) + '"}\n')
    return "".join(out)


class _Log(Box):
    def setUp(self):
        super().setUp()
        self.report, self.grow, self.args = (os.path.join(self.tmp, n) for n in ("leaks.json", "grow.json", "trufflehog-args.txt"))
        self.gitleaks = GITLEAKS.replace("REPORT", repr(self.report)).replace("GROW", repr(self.grow))
        self.log = os.path.join(self.home, ".grok", "logs", "unified.jsonl")
        self.skills(1)
        self.scanners(gitleaks=self.gitleaks)

    def put(self, p, text):
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(text)
        return p

    def scan(self, hits, grow=()):
        """One full audit, gitleaks reporting `hits` and then adding a line to each file in `grow`; the audit's printed answer."""
        for p, data in ((self.report, hits), (self.grow, list(grow))):
            with open(p, "w") as f:
                json.dump(data, f)
        return self.audit()

    def s002(self, path):
        return [f for f in self.snap()["findings"] if f["rule"] == "ISR-S002" and f["where"].startswith(path + ":")]

    def counted(self, path):
        return [f for f in self.s002(path) if isr.counts(f)]

    def platform(self, path):
        return [f for f in self.s002(path) if f.get("platform_log_prefix")]

    def lines(self):
        s = self.snap()
        return (isr.platform_notes(s["findings"], 100, s.get("vendor")) or {"lines": []})["lines"]

    def assert_note(self, path, evidence="1 short key prefix(es): generic-api-key"):
        self.assertEqual(self.counted(path), [])                                   # 56ed018: a counted Worth-a-look S002
        self.assertEqual([l for l in self.lines() if l == LINE], [LINE])
        note = self.platform(path)
        self.assertEqual([(f["title"], f["evidence"], f["severity"], isr.label_of(f)) for f in note], [(TITLE, evidence, "info", isr.PLATFORM)])
        return note[0]

    def assert_counted(self, path, evidence):
        got = self.counted(path)
        self.assertEqual(len(got), 1, [(f["where"], f["evidence"]) for f in self.s002(path)])
        self.assertTrue(got[0]["evidence"].startswith(evidence), got[0]["evidence"])
        self.assertEqual(self.platform(path), [])
        return got[0]


class ShortPrefixIsAPlatformNote(_Log):
    def test_a_short_prefix_in_the_platform_log_is_a_platform_note(self):   # replay
        v = fake_key(12, seed=1)
        self.put(self.log, KEY % v + "\n")
        r = self.scan([leak(self.log, FIELD % v, v)])
        self.assert_note(self.log)
        self.assertEqual([f for f in r["new"] if f["where"].startswith(self.log + ":")], [])

    def test_a_prefix_past_100_kb_is_a_platform_note(self):   # replay (Codex 2)
        v = fake_key(12, seed=2)
        self.put(self.log, padding(PIECE - 5) + KEY % v + "\n" + padding(2000))
        h = leak(self.log, FIELD % v, v, piece=PIECE)
        self.assertEqual((h["StartColumn"], h["EndColumn"]), (34, 59))   # as the calibration run's 12-character hit there (span 26)
        self.scan([h])
        self.assert_note(self.log)

    def test_a_prefix_while_the_log_changes(self):   # replay (Codex 2)
        v = fake_key(12, seed=3)
        size = os.path.getsize(self.put(self.log, KEY % v + "\n"))
        self.scan([leak(self.log, FIELD % v, v)], grow=[self.log])
        self.assertGreater(os.path.getsize(self.log), size)   # changed after the scan began: nothing can be read back
        self.assert_note(self.log)

    def test_the_prefix_only_log_is_not_sent_to_trufflehog(self):   # replay
        v, k = fake_key(12, seed=4), fake_key(40, seed=5)
        self.put(self.log, KEY % v + "\n")
        other = self.put(os.path.join(self.ws, "notes", "keys.jsonl"), '{"api_key":"%s"}\n' % k)
        self.scanners(gitleaks=self.gitleaks, trufflehog=ARGS_TRUFFLEHOG.replace("ARGS", repr(self.args)))
        self.scan([leak(self.log, FIELD % v, v), leak(other, API % k, k)])
        with open(self.args) as f:
            sent = {os.path.realpath(a) for a in f.read().splitlines() if a.startswith("/")}
        self.assertIn(os.path.realpath(other), sent)                 # TruffleHog ran, on the counted key file
        self.assertNotIn(os.path.realpath(self.log), sent)           # 56ed018: the log was sent too

    def test_a_growing_log_is_not_new_again(self):   # replay
        vs = [fake_key(12, seed=10 + i) for i in range(5)]
        self.put(self.log, "".join(KEY % v + "\n" for v in vs[:3]))
        self.scan([leak(self.log, FIELD % v, v) for v in vs[:3]])
        with open(self.log, "a") as f:
            f.write("".join(KEY % v + "\n" for v in vs[3:]))
        r = self.scan([leak(self.log, FIELD % v, v) for v in vs])
        self.assertEqual([f for f in r["new"] + r["fixed"] if f["where"].startswith(self.log + ":")], [])   # 56ed018: new and fixed
        self.assert_note(self.log, "5 short key prefix(es): generic-api-key")

    def test_after_trufflehog_answers_the_note_keeps_its_title_and_fix(self):   # replay (approved addition)
        """TruffleHog's answers are applied to every key record (key_status_severity): without the skip, the note became
        "Looks like a key (pattern match, not confirmed)" with the fix "Pattern match only…" (medium, shown as info)."""
        v, k = fake_key(12, seed=6), fake_key(40, seed=7)
        self.put(self.log, KEY % v + "\n")
        other = self.put(os.path.join(self.ws, "notes", "keys.jsonl"), '{"api_key":"%s"}\n' % k)
        said = os.path.join(self.tmp, "answers.json")
        with open(said, "w") as f:
            json.dump([v82.answer(other, 1, "Generic", True, k)], f)
        self.scanners(gitleaks=self.gitleaks, trufflehog=v82.TRUFFLEHOG.replace("ANSWERS", repr(said)).replace("DONE", repr(TH_DONE)))
        self.scan([leak(self.log, FIELD % v, v), leak(other, API % k, k)])
        self.assertEqual([f["title"] for f in self.counted(other)], [isr.KEY_LIVE])   # TruffleHog's answers were applied this run
        note = self.assert_note(self.log)
        self.assertEqual((note["fix"], note.get("severity_was")), (LINE, None))


class EverythingElseStillCounts(_Log):
    def test_a_40_char_key_in_the_platform_log_still_counts(self):   # guard (and past 100 KB, and while the log changes: Codex 2)
        k = fake_key(40, seed=20)
        self.put(self.log, KEY % k + "\n")
        self.scan([leak(self.log, FIELD % k, k)])
        self.assert_counted(self.log, "1 hit(s): generic-api-key")
        self.put(self.log, padding(PIECE - 5) + KEY % k + "\n" + padding(2000))
        h = leak(self.log, FIELD % k, k, piece=PIECE)
        self.assertEqual((h["StartColumn"], h["EndColumn"]), (34, 87))   # as the calibration run's 40-character hit there (span 54)
        self.scan([h])
        self.assert_counted(self.log, "1 hit(s): generic-api-key")
        self.put(self.log, KEY % k + "\n")
        self.scan([leak(self.log, FIELD % k, k)], grow=[self.log])
        self.assert_counted(self.log, "1 hit(s): generic-api-key")

    def test_both_on_one_line_both_survive(self):   # guard (Codex 3)
        v, k = fake_key(12, seed=21), fake_key(40, seed=22)
        self.put(self.log, '{"msg":"auth.refresh.success","ctx":{"key_prefix":"%s","api_key":"%s"}}\n' % (v, k))
        hits = [leak(self.log, FIELD % v, v), leak(self.log, API % k, k)]
        self.assertEqual([(h["StartColumn"], h["EndColumn"]) for h in hits], [(39, 64), (67, 117)])   # as the calibration run
        self.scan(hits)
        counted = self.counted(self.log)
        self.assertEqual([f["evidence"][:25] for f in counted], ["1 hit(s): generic-api-key"])   # the 40-character hit alone
        self.assertEqual([m["line"] for m in counted[0]["member_hits"]], [1])
        self.assertTrue(isr.counts(counted[0]))
        note = self.platform(self.log)
        self.assertEqual(len(note), 1)
        self.assertNotEqual(counted[0]["key"], note[0]["key"])

    def test_an_unclear_hit_stays_counted(self):   # guard (Codex 2)
        a, b, c = (fake_key(12, seed=23 + i) for i in range(3))
        e = fake_key(10, seed=26)
        self.put(self.log, "".join(t + "\n" for t in (KEY % a, '{"ctx":{"%skey_prefix":"%s"}}' % (e, e),
                                                      '{"msg":"auth.refresh.success","ctx":{"key_prefix": "%s"}}' % b, KEY % c)))
        over_two = dict(leak(self.log, FIELD % a, a), EndLine=2)                    # StartLine != EndLine
        twice = leak(self.log, '%skey_prefix":"%s"' % (e, e), e)                    # two REDACTED (field shape and length 12 both fit)
        spaced = leak(self.log, 'key_prefix": "%s"' % b, b)                         # "key_prefix": "…", as gitleaks writes it
        text_cols = leak(self.log, FIELD % c, c)
        text_cols["StartColumn"] = str(text_cols["StartColumn"])                     # a column that isn't an int
        self.assertEqual((twice["Match"].count("REDACTED"), spaced["Match"]), (2, 'key_prefix": "REDACTED"'))
        self.scan([over_two, twice, spaced, text_cols])
        self.assert_counted(self.log, "4 hit(s): generic-api-key")

    def test_another_rule_in_the_platform_log_still_counts(self):   # guard
        v = fake_key(12, seed=27)
        self.put(self.log, KEY % v + "\n")
        self.scan([leak(self.log, FIELD % v, v, rule="github-pat")])
        self.assert_counted(self.log, "1 hit(s): github-pat")

    def test_another_field_in_the_platform_log_still_counts(self):   # guard
        v = fake_key(12, seed=28)
        self.put(self.log, '{"msg":"auth.refresh.success","ctx":{"password":"%s"}}\n' % v)
        self.scan([leak(self.log, 'password":"%s"' % v, v)])
        self.assert_counted(self.log, "1 hit(s): generic-api-key")

    def test_a_short_prefix_in_another_file_still_counts(self):   # guard
        v = fake_key(12, seed=29)
        p = self.put(os.path.join(self.ws, "notes", "unified.jsonl"), KEY % v + "\n")
        self.scan([leak(p, FIELD % v, v)])
        self.assert_counted(p, "1 hit(s): generic-api-key")

    def test_a_look_alike_path_still_counts(self):   # guard (the realpath of the log's place, never its name)
        v = fake_key(12, seed=30)
        p = self.put(os.path.join(self.home, "projects", ".grok", "logs", "unified.jsonl"), KEY % v + "\n")
        self.scan([leak(p, FIELD % v, v)])
        self.assert_counted(p, "1 hit(s): generic-api-key")


if __name__ == "__main__":
    unittest.main()
