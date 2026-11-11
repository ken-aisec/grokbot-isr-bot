"""1.1.1: ISR Bot test fixtures are recognized by exact construction and never scored; one secret at one file:line counts once.

Since Nov 5 a live audit graded F on four Confirmed criticals: ISR-S001 and ISR-S002 on two replay logs that held a test's planted
GitHub-shaped token, echoed by a failed assertion. A fixture is now <one of KEY_PREFIXES> + "ISRFIX" + payload + MAC, the MAC made
with a published salt; only that whole construction is recognized (never a word near it, the line or the path). The same secret
found by ISR Bot's own key rule and by gitleaks at one file:line is one finding (also_rules), still Confirmed.

The values are built here with the published construction (build(): the salt is public, plan section 2.1), never with ISR Bot's
own maker, so on d5b5b47 each replay reaches its assertion instead of an error. Replays (F1, F2, F3, F5, F7, F9, F10) fail on
d5b5b47 at their assertion by construction: d5b5b47 has no recognizer, no merge and no fixture_paths, so the asserted absence,
count or field is wrong there (not run against d5b5b47 in this build: this checkout holds only the new tree). Guards (F4, F6, F8,
F11, F12) describe non-hiding behavior and the helpers. gitleaks is the column-accurate stand-in of test_v082_secrets (gitleaks'
redacted Match and Entropy, so ISR Bot reads each secret back from the file); F7 also runs once with the real gitleaks when it
is installed. TruffleHog is left out (no answers: a key keeps its rule's severity). No assertion echoes a planted value."""
import hashlib, json, os, re, shlex, string, sys, unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import Box  # noqa: E402
from test_isr_bot import REAL_GITLEAKS, assert_has_key, assert_lacks_key  # noqa: E402
import test_v082_secrets as v82  # noqa: E402  (module access: its test classes don't run twice)
import isr  # noqa: E402

TESTS = os.path.dirname(os.path.abspath(__file__))

# ---- the published construction (plan section 2.1), written out here so the tests don't lean on ISR Bot's own maker
SALT, MARK = "isr-bot-test-fixture-v1", "ISRFIX"
ALNUM = string.ascii_uppercase + string.ascii_lowercase + string.digits
UPPER = string.ascii_uppercase + string.digits
FIXED = {"AKIA": 16, "ASIA": 16, "AIza": 35, "glpat-": 20, "ghp_": 36, "gho_": 36, "ghu_": 36, "ghs_": 36, "ghr_": 36}
PREFIXES = [("ghp_", 36), ("gho_", 36), ("ghs_", 36), ("github_pat_", 82), ("sk-ant-api03-", 93), ("sk-ant-oat01-", 95),
            ("sk-proj-", 48), ("sk-", 48), ("sk_live_", 24), ("rk_test_", 24), ("AKIA", 16), ("ASIA", 16), ("AIza", 35),
            ("xoxb-", 40), ("glpat-", 20), ("xai-", 40), ("npm_", 36), ("pypi-", 60)]


def _alphabet(prefix):
    return UPPER if prefix in ("AKIA", "ASIA") else ALNUM


def build(prefix, n, seed=0):
    """make_isr_fixture's value, by the published construction: prefix, the marker, version tag "1" and seed characters, then the
    first bytes of sha256(salt + prefix + payload) written in the prefix's alphabet."""
    alphabet, rest = _alphabet(prefix), n - len(MARK)
    k = min(12, rest // 2)
    out, i = [], 0
    while len(out) < rest - k - 1:
        out += [alphabet[b % len(alphabet)] for b in hashlib.sha256(f"{SALT}|seed|{prefix}|{n}|{seed}|{i}".encode()).digest()]
        i += 1
    payload = "1" + "".join(out[:rest - k - 1])
    mac = "".join(alphabet[b % len(alphabet)] for b in hashlib.sha256((SALT + prefix + payload).encode()).digest()[:k])
    return prefix + MARK + payload + mac


def wrong_mac(prefix, n, seed):
    """A real-format value with the marker and a MAC that is wrong by its last character: not a fixture (F5)."""
    v, a = build(prefix, n, seed), _alphabet(prefix)
    return v[:-1] + a[(a.index(v[-1]) + 1) % len(a)]


def marker_inside(seed):
    """A ghp_ key of the right length whose body has ISRFIX after other characters (F5, F6)."""
    body = build("ghp_", 36, seed)[4 + len(MARK):]
    return "ghp_" + body[:10] + MARK + body[10:30]


SECRETS = ("ISR-S001", "ISR-S002")


class _Fix(Box):
    def setUp(self):
        super().setUp()
        self.hits = []
        self.skills(1)

    def put(self, p, text):
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(text)
        return p

    def leak(self, p, value, rule="github-pat"):
        """The gitleaks stand-in reports `value` on every line of `p` that holds it (columns, redacted Match, Entropy)."""
        self.hits += v82.leaks(p, value, rule)

    def run_audit(self, gitleaks=None):
        report = os.path.join(self.tmp, "leaks.json")
        with open(report, "w") as f:
            json.dump(self.hits, f)
        self.scanners(gitleaks=gitleaks or v82.GITLEAKS.replace("REPORT", repr(report)), trufflehog=None)
        return self.audit()

    def keys_at(self, p, fs=None):
        """The scored key findings (ISR-S001, ISR-S002) about file p."""
        fs = self.snap()["findings"] if fs is None else fs
        return [f for f in fs if f["rule"] in SECRETS and (f["where"] == p or f["where"].startswith(p + ":") or p in (f.get("affected_files") or []))]

    def fixture_paths(self):
        return self.snap().get("fixture_paths") or []


class F01Construction(unittest.TestCase):
    def test_f1_made_and_recognized_seeds_differ(self):   # replay (d5b5b47: no maker, no recognizer)
        make, known = getattr(isr, "make_isr_fixture", None), getattr(isr, "is_isr_fixture", None)
        self.assertTrue(callable(make) and callable(known))
        a, b = make("ghp_", 36, seed=1), make("ghp_", 36, seed=2)
        self.assertTrue(known(a) and known(b))
        self.assertNotEqual(a, b)
        self.assertEqual((a, b), (build("ghp_", 36, 1), build("ghp_", 36, 2)))   # the published construction, exactly
        for prefix, n in PREFIXES:
            v = make(prefix, n, seed=7)
            self.assertEqual((len(v), v == build(prefix, n, 7), known(v)), (len(prefix) + n, True, True), prefix)

    def test_f1_lengths_and_prefixes_it_wont_make(self):   # guard
        for prefix, n in (("ghp_", 35), ("AKIA", 20), ("sk-ant-", 3), ("nope_", 40)):
            with self.assertRaises(ValueError, msg=prefix):
                isr.make_isr_fixture(prefix, n)

    def test_f1_the_rules_and_the_scrub_still_match_a_fixture(self):   # guard: suppression is the only thing that changes
        rule = next(r for r in isr.load_rules()["rules"] if r["id"] == isr.SECRET_RULE)["rx"]
        for prefix, n in (("ghp_", 36), ("AKIA", 16), ("sk-ant-api03-", 93), ("AIza", 35), ("github_pat_", 82)):
            v = build(prefix, n, 3)
            self.assertEqual(rule.search(" " + v + " ").group(0), v, prefix)
            self.assertTrue(isr.SCRUB.search(" " + v + " "), prefix)

    def test_f1_unread_values_and_key_blocks_are_kept(self):   # guard: fail closed; a key block is never a fixture
        self.assertTrue(isr.keep_secret_hit(None))
        self.assertTrue(isr.keep_secret_hit(""))
        self.assertTrue(isr.keep_secret_hit("-----BEGIN RSA PRIVATE KEY-----"))
        self.assertFalse(isr.is_isr_fixture("-----BEGIN " + MARK + " PRIVATE KEY-----"))
        self.assertFalse(isr.keep_secret_hit(build("ghp_", 36, 4)))


class F02FixtureAnywhere(_Fix):
    def test_f2_an_echoed_fixture_in_replay_logs_is_no_finding(self):   # replay (the Nov 5 incident's shape)
        fx = build("ghp_", 36, 6)
        line = f"AssertionError: '{fx}' not found in '{{\"role\": \"user\", \"text\": \"use [removed] for the repo\"}}'\n"
        d = os.path.join(self.ws, "jobs", "build-1.0.1")   # a replay log in a work folder, scored like any owner file
        logs = [self.put(os.path.join(d, "replay-b1.log"), "Traceback (most recent call last):\n" * 86 + line),
                self.put(os.path.join(d, "replay-b1b.log"), "ok\n" * 68 + line),
                self.put(os.path.join(self.home, "notes", "keys.md"), f"use {fx} for the repo\n")]   # any other place too
        for p in logs:
            self.leak(p, fx)
        self.run_audit()
        for p in logs:
            self.assertEqual(self.keys_at(p), [], p)                     # d5b5b47: a Confirmed critical S001 and S002 each
        s = self.snap()
        self.assertNotEqual(s["status"], isr.ACT_NOW)
        self.assertNotEqual(s["grade"], "F")
        self.assertEqual(sorted(p for p in self.fixture_paths() if p in logs), sorted(logs))
        with open(isr.state_path("last_findings.json")) as f:
            assert_lacks_key(self, f.read(), fx)                         # paths only: no value is stored


class F03RealKeyBesideAFixture(_Fix):
    def test_f3_one_line_real_key_and_fixture(self):   # replay
        real, fx = wrong_mac("ghp_", 36, 31), build("ghp_", 36, 32)
        p = self.put(os.path.join(self.ws, "app", "chat.txt"), f"use {real} and {fx} for the repo\n")
        self.leak(p, real)
        self.leak(p, fx)
        self.run_audit()
        got = self.keys_at(p)
        self.assertEqual(len(got), 1, [(f["rule"], f["where"]) for f in got])   # d5b5b47: S001 (2 in file) and S002 (2 hits)
        f = got[0]
        self.assertIn("(1 in file)", f["evidence"])                     # the fixture is not one of its hits
        self.assertIn(isr.mask(real), f["evidence"])
        self.assertEqual((f["rule"], f.get("also_rules")), ("ISR-S001", ["ISR-S002"]))   # gitleaks' real hit joined it; its fixture hit is gone
        self.assertEqual((f.get("severity_was") or f["severity"], f["label"], isr.counts(f)), ("critical", isr.CONFIRMED, True))
        self.assertIn(p, self.fixture_paths())


class F04MarkerTextNearby(_Fix):
    def test_f4_a_real_key_with_the_marker_in_a_comment(self):   # guard
        real = wrong_mac("ghp_", 36, 41)
        p = self.put(os.path.join(self.ws, "app", "deploy.sh"),
                     f"# {MARK} test keys live in tests/, not here\nexport GH_TOKEN={real}  # {MARK}\necho {MARK}{real[4:]}\n")
        self.leak(p, real)
        self.run_audit()
        got = self.keys_at(p)
        self.assertEqual([(f["rule"], f.get("severity_was") or f["severity"], isr.counts(f)) for f in got], [("ISR-S001", "critical", True)])
        self.assertNotIn(p, self.fixture_paths())
        self.assertFalse(isr.is_isr_fixture(MARK))
        self.assertFalse(isr.is_isr_fixture(f"# {MARK} test keys"))


class F05LookalikesThatFailConstruction(_Fix):
    def test_f5_wrong_mac_short_body_no_prefix_marker_inside(self):   # replay (d5b5b47: no recognizer; the fixture beside them counts)
        known = getattr(isr, "is_isr_fixture", None)
        self.assertTrue(callable(known))
        short = build("sk-ant-api03-", 93, 52)[:len("sk-ant-api03-") + 30]
        looks = {"wrong-mac.txt": (wrong_mac("ghp_", 36, 51), "github-pat"), "short.txt": (short, "anthropic-api-key"),
                 "inside.txt": (marker_inside(53), "github-pat")}
        for v, _ in looks.values():
            self.assertFalse(known(v))
        self.assertFalse(known(build("ghp_", 36, 54)[4:]))              # the marker with no provider prefix
        self.assertFalse(known(" " + build("ghp_", 36, 54)))            # anything before the prefix
        self.assertFalse(known(build("ghp_", 36, 54) + "x"))            # anything after the body
        paths = {}
        for name, (v, rule) in looks.items():
            paths[name] = self.put(os.path.join(self.ws, "look", name), f"token: {v}\n")
            self.leak(paths[name], v, rule)
        ok = self.put(os.path.join(self.ws, "fixture", "ok.txt"), "token: " + build("ghp_", 36, 55) + "\n")
        self.leak(ok, build("ghp_", 36, 55))
        self.run_audit()
        for name, p in paths.items():
            got = self.keys_at(p)
            self.assertEqual([(f["rule"], f.get("severity_was") or f["severity"], isr.counts(f), f.get("also_rules")) for f in got],
                             [("ISR-S001", "critical", True, ["ISR-S002"])], name)   # still alerts, once
        self.assertEqual(self.keys_at(ok), [])                           # d5b5b47: the real fixture counts too


class F06SubstringIsNotEnough(_Fix):
    def test_f6_marker_after_other_characters_still_alerts(self):   # guard
        v = marker_inside(61)
        self.assertFalse(isr.is_isr_fixture(v))
        self.assertTrue(isr.keep_secret_hit(v))
        rules = isr.load_rules()
        self.assertIn("ISR-T011", {f["rule"] for f in isr.scan_text(f"Use {v} to call it.", "/s/SKILL.md", rules)})
        self.assertNotIn("ISR-T011", {f["rule"] for f in isr.scan_text(f"Use {build('ghp_', 36, 62)} to call it.", "/s/SKILL.md", rules)})
        p = self.put(os.path.join(self.ws, "app", "env.txt"), f"GH_TOKEN={v}\n")
        self.run_audit()
        self.assertEqual([(f["rule"], isr.counts(f)) for f in self.keys_at(p)], [("ISR-S001", True)])


class F07TwoScannersOneKey(_Fix):
    def one_key(self):
        real = wrong_mac("ghp_", 36, 71)
        p = self.put(os.path.join(self.ws, "app", "config.txt"), f"# app\nGH_TOKEN={real}\n")
        return p, real

    def assert_one_confirmed(self, p):
        got = self.keys_at(p)
        self.assertEqual(len(got), 1, [(f["rule"], f["where"]) for f in got])   # d5b5b47: S001 and S002, two Confirmed criticals
        f = got[0]
        self.assertIn(f["rule"], SECRETS)
        self.assertEqual(f.get("also_rules"), [r for r in SECRETS if r != f["rule"]])
        self.assertEqual((f.get("severity_was") or f["severity"], f["label"], isr.counts(f)), ("critical", isr.CONFIRMED, True))
        self.assertEqual([a["rule"] for a in f.get("also_flagged_by") or []], f["also_rules"])
        crit = [g for g in isr.scored(self.snap()["findings"]) if g["severity"] == "critical" and g["label"] == isr.CONFIRMED]
        self.assertEqual([g["key"] for g in crit], [f["key"]])         # one Confirmed critical, not a pair
        s = self.snap()
        self.assertEqual((s["status"], s["grade"]), (isr.ACT_NOW, "F"))   # still caps the grade, for the one
        return f

    def test_f7_one_finding_names_both_rules(self):   # replay
        p, real = self.one_key()
        self.leak(p, real)
        self.run_audit()
        self.assert_one_confirmed(p)
        assert_lacks_key(self, json.dumps(self.snap()), real)

    def test_f7_a_daily_keeps_gitleaks_vote_and_the_key(self):   # replay (the daily never runs gitleaks)
        p, real = self.one_key()
        self.leak(p, real)
        self.run_audit()
        key = self.assert_one_confirmed(p)["key"]
        code, o, e = self.run_cmd("daily", "--roots", *self.roots)
        self.assertEqual(code, 0, e)
        f = self.assert_one_confirmed(p)
        self.assertEqual(f["key"], key)                                   # never fixed-and-new between a full audit and a daily

    @unittest.skipUnless(os.access(REAL_GITLEAKS, os.X_OK), "gitleaks is not installed")
    def test_f7_with_the_real_gitleaks(self):   # replay, when the real gitleaks is installed (it is run, never changed or copied)
        p, real = self.one_key()
        fx = self.put(os.path.join(self.ws, "app2", "fixture.txt"), "GH_TOKEN=" + build("ghp_", 36, 72) + "\n")
        self.run_audit(gitleaks="#!/bin/sh\nexec " + shlex.quote(REAL_GITLEAKS) + ' "$@"\n')
        self.assertIn("gitleaks", isr.load_json(isr.state_path("engines_used.json"), {}).get("engines", []))   # it ran
        self.assertEqual(self.keys_at(fx), [])
        self.assert_one_confirmed(p)


class F08TwoSecretsOneFile(_Fix):
    def test_f8_two_secrets_and_a_gitleaks_only_one_stay_apart(self):   # guard
        a, b = wrong_mac("ghp_", 36, 81), wrong_mac("ghp_", 36, 82)
        hx = "".join(string.hexdigits[c % 16] for c in hashlib.sha256(b"f8").digest()[:20])
        p = self.put(os.path.join(self.ws, "app", "two.env"), f"A_TOKEN={a}\nB_TOKEN={b}\nAPI_SECRET={hx}\n")
        self.leak(p, a)
        self.leak(p, b)
        self.leak(p, hx, "generic-api-key")
        self.run_audit()
        got = sorted(self.keys_at(p), key=lambda f: f["rule"])
        self.assertEqual([(f["rule"], f["where"]) for f in got], [("ISR-S001", p + ":1"), ("ISR-S002", p + ":3")])
        self.assertIn("(2 in file)", got[0]["evidence"])                 # two secrets, never one
        self.assertEqual(got[0].get("also_rules"), ["ISR-S002"])
        self.assertEqual((got[1]["evidence"], [m["line"] for m in got[1]["member_hits"]]), ("1 hit(s): generic-api-key", [3]))


class F09OneFixtureEverywhere(_Fix):
    def test_f9_a_fixture_on_two_lines_hit_by_both_scanners(self):   # replay (d5b5b47: four findings across the two logs)
        fx = build("ghp_", 36, 91)
        logs = [self.put(os.path.join(self.ws, "runs", f"r{i}.log"), f"start\nkey {fx}\nmore\nkey {fx}\n") for i in (1, 2)]
        for p in logs:
            self.leak(p, fx)
        self.assertEqual(len(self.hits), 4)
        self.run_audit()
        self.assertEqual([f for p in logs for f in self.keys_at(p)], [])
        self.assertEqual([p for p in logs if p in self.fixture_paths()], logs)


class F10CleanupStillScrubs(_Fix):
    def preview(self):
        code, o, _ = self.run_cmd("fix", "--roots", *self.roots)
        self.assertEqual(code, 0)
        return [x["path"] for x in isr.load_json(isr.state_path("tidy_plan.json"), {}).get("items", []) if x.get("action") == "scrub_keys"]

    def test_f10_a_chat_log_fixture_is_cleaned_a_project_log_is_not(self):   # replay (d5b5b47: no fixture_paths)
        fx, other = build("ghp_", 36, 101), build("ghp_", 36, 102)
        chat = self.put(os.path.join(self.home, ".grok", "sessions", "s1.jsonl"), '{"role": "user", "text": "use ' + fx + ' for the repo"}\n')
        proj = self.put(os.path.join(self.ws, "app", "logs", "server.log"), "auth with " + other + "\n")
        before, proj_before = open(chat).read(), open(proj).read()
        self.run_audit()
        self.assertIn(chat, self.fixture_paths())
        self.assertIn(proj, self.fixture_paths())
        self.assertEqual(self.keys_at(chat) + self.keys_at(proj), [])
        listed = self.preview()
        self.assertIn(chat, listed)
        self.assertNotIn(proj, listed)                                   # 1.0.1 (U1): never a project's own log
        code, o, _ = self.run_cmd("fix", "--apply", "--owner-said-yes", "--roots", *self.roots)
        self.assertEqual(code, 0)
        assert_lacks_key(self, open(chat).read(), fx)
        self.assertIn(isr.REDACTED, open(chat).read())
        line = [d for d in json.loads(o)["done"] if d.startswith("Removed ") and chat in d]
        self.assertEqual(len(line), 1)
        copy = line[0].split("(undo copy: ", 1)[1][:-1]
        self.assertEqual(open(copy).read(), before)                       # the undo copy is kept
        assert_has_key(self, open(copy).read(), fx)
        self.assertEqual(open(proj).read(), proj_before)


class F11RedactedHelpers(unittest.TestCase):
    def test_f11_failure_messages_never_hold_the_value(self):   # guard
        v = build("ghp_", 36, 111)
        for helper, text in ((assert_has_key, "nothing here"), (assert_lacks_key, f"token {v} here")):
            with self.assertRaises(self.failureException) as cm:
                helper(self, text, v, "context")
            msg = str(cm.exception)
            self.assertFalse(v in msg, helper.__name__)
            self.assertFalse(v[4:] in msg or v[6:-4] in msg, helper.__name__)
            self.assertIn(isr.mask(v), msg)
            self.assertIn("context", msg)
        assert_has_key(self, f"token {v} here".encode(), v)             # bytes too
        assert_lacks_key(self, b"nothing", v)


# an assertIn or assertNotIn whose first argument is a call that makes a planted key
ECHO = re.compile(r"\bassert(?:Not)?In\(\s*(?:\w+\.)?(?:fake_key|key|make_isr_fixture|pat|oat)\(")


class F12NoEchoInTests(unittest.TestCase):
    def test_f12_no_test_asserts_a_planted_key_by_value(self):   # guard
        self.assertTrue(ECHO.search("self." + "assertIn" + "(fake_key(6), text)"))          # the scan sees the incident's line
        self.assertTrue(ECHO.search("self." + "assertNotIn" + "( isr.make_isr_fixture('ghp_', 36), t)"))
        self.assertFalse(ECHO.search("self.assertIn(k, keys)"))
        bad = []
        for dp, _, fns in os.walk(TESTS):
            for fn in sorted(fns):
                if fn.endswith(".py"):
                    with open(os.path.join(dp, fn), encoding="utf-8", errors="replace") as f:
                        bad += [f"{os.path.relpath(os.path.join(dp, fn), TESTS)}:{i}" for i, l in enumerate(f, 1) if ECHO.search(l)]
        self.assertEqual(bad, [])


if __name__ == "__main__":
    unittest.main()
