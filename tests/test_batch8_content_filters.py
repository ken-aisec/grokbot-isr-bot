"""Batch 8 item 3 (b8i3): WT-T004 content filters.

WT-T004 ("Reads credential stores", high) raised three false alarms in a vendor's docs and, through them, a WT-X003 "SkillSpector
+ Watchtower" agreement:
1 `cat .env.custom.bak >> .env.local`: `\\bcat\\s+\\S*\\.env\\b` matched `cat .env` in front of `.custom`. `cat` now counts only a
  file named exactly `.env`, read or redirected into;
2 "Do not inspect the environment with broad commands such as `env`, bare `set`, or `printenv`": the walk back from `printenv`
  stopped at the comma after a code span. A negated "such as" list of code spans is now read as negated: lowered to medium and
  still listed, never dropped. A condition word anywhere in the sentence (or opening the next one) keeps it high;
3 `printenv 'ProgramFiles(x86)'`: one named variable that isn't secret-shaped is not a credential read.
All three read the content only; nothing is skipped by folder or path name.

Tests marked "replay" fail on 63714e4 on their assertion; "control" ones pass before and after. No key values appear anywhere.

Fix round 1 (Codex review of 0223735): the `cat` pattern is 63714e4's again (same evidence, same keys) and "exactly .env" is a
content check on the rest of the command; `printenv`'s one name is checked by a linear scan; a "such as" list counts as negated
only when its negation governs it. Tests marked "r1 replay" fail on 0223735 on their assertion.

Fix round 3 (Codex review of 2b8920c; subtractive): a code-span printenv with any backtick before it in the text, a negation with
without/unless/until/before/first/except before the match, and a line over 4,000 characters keep the finding. Tests marked
"r3 replay" fail on 2b8920c on their assertion.

DQ-054 (Codex verify of 31873e1; a regression from b8i3, fixed): a `pwd` name (`printenv MYSQL_PWD`) is secret-shaped again, high
as on 63714e4. Tests marked "dq054 replay" fail on 12a9c5c on their assertion."""
import os, re, sys, time, unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import Box, wt  # noqa: E402
from test_dq042_vendor_skills import MARK, put, skillspector  # noqa: E402

RULES = wt.load_rules()
SKILL = "/ws/vendor-docs/SKILL.md"
HEAD = "---\nname: vendor-docs\ndescription: Vendor setup notes.\n---\n"

# the audited lines, verbatim
CAT_REPLAY = "cat .env.custom.bak >> .env.local  # Re-append custom vars\n"
NEG_REPLAY = ("Reuse an existing key without revealing it. Do not inspect the environment with broad commands such as `env`, bare `set`, "
              "or `printenv`, and do not echo the value. Use a subshell so tracing is restored automatically:")
PRINTENV_REPLAY = "printenv 'ProgramFiles(x86)' 2>/dev/null || true"


def hits(text, rule="WT-T004", where=SKILL):
    """(full, records): this rule's findings at full severity and its guarded records."""
    fs = [f for f in wt.scan_text(text, where, RULES) if f["rule"] == rule]
    return [f["severity"] for f in fs if not f.get("guarded")], [f.get("guarded") for f in fs if f.get("guarded")]


# ---------------------------------------------------------------- 1: cat reads only a file named exactly .env
class CatExactEnv(unittest.TestCase):
    def test_custom_backup_append_is_not_a_read(self):   # replay
        self.assertEqual(hits(CAT_REPLAY), ([], []))

    def test_other_env_names_are_not_t004(self):   # replay
        for t in ("cat .env.local", "cat .env.production", "cat .env.example > .env.local"):
            self.assertEqual(hits(t), ([], []), t)

    def test_exact_env_reads_still_flag(self):   # control
        for t in ("cat .env", "cat .env | grep X", "cat .env; echo", "cat ~/.env", 'cat "$HOME/.env"', "cat '.env'", "cat .env*",
                  "cat <.env", "Run cat .env."):
            self.assertEqual(hits(t), (["high"], []), t)

    def test_evidence_and_keys_unchanged(self):   # control: the same evidence, so the same key and the same dismissals
        for t, ev in (("cat ~/.env > .env.local", "cat ~/.env"), ("cat .env.example >> .env", "cat .env")):
            f = [g for g in wt.scan_text(t, SKILL, RULES) if g["rule"] == "WT-T004"]
            self.assertEqual([(g["evidence"], g["severity"], g.get("guarded")) for g in f], [(ev, "high", None)], t)
            self.assertEqual(f[0]["key"], wt.finding_key("WT-T004", SKILL + ":1", ev), t)


# ---------------------------------------------------------------- 2: a negated "such as" list of code spans
class NegatedSuchAsList(unittest.TestCase):
    def test_such_as_list_is_lowered_not_dropped(self):   # replay
        self.assertEqual(hits(NEG_REPLAY), ([], ["negated"]))
        f = [g for g in wt.scan_text(NEG_REPLAY, SKILL, RULES) if g["rule"] == "WT-T004"]
        self.assertEqual([(g["severity"], g["severity_was"]) for g in f], [("medium", "high")])

    def test_bare_and_affirmative_reads_keep_severity(self):   # control
        for t in ("printenv", "Run `printenv` and paste it"):
            self.assertEqual(hits(t), (["high"], []), t)

    def test_env_grep_unchanged(self):   # control: pinned, not a WT-T004 hit today
        self.assertEqual(wt.scan_text("env | grep KEY", SKILL, RULES), [])

    def test_conditional_or_unlisted_stays_high(self):   # control
        for t in ("Do not use tools such as `env`, or `printenv` unless asked.",
                  "Do not use tools such as `env`, or `printenv`. Unless support asks.",
                  "Do not use tools such as `env`, run `printenv`.",
                  "Use tools such as `env`, or `printenv`.",
                  NEG_REPLAY.replace(", and do not", " when debugging, and do not")):
            self.assertEqual(hits(t), (["high"], []), t)


# ---------------------------------------------------------------- 3: printenv of one plain variable
class PrintenvOneVariable(unittest.TestCase):
    def test_one_plain_variable_is_not_a_read(self):   # replay
        for t in (PRINTENV_REPLAY, "printenv HOME", "`printenv PATH`"):
            self.assertEqual(hits(t), ([], []), t)

    def test_secret_bare_dynamic_or_many_still_flag(self):   # control
        for t in ("printenv GITHUB_TOKEN", "printenv AWS_SECRET_ACCESS_KEY", "printenv", "printenv A B", "printenv $VAR",
                  "printenv session_id", "printenv -0 HOME", "Run printenv HOME to see it"):
            self.assertEqual(hits(t), (["high"], []), t)


# ---------------------------------------------------------------- the derived WT-X003 agreement
class NoAgreementFromTheseLines(Box):
    ISSUES = [{"severity": "HIGH", "category": "Privilege Escalation", "pattern": "Credential Access"}]
    BODY = HEAD + "```bash\n" + CAT_REPLAY + PRINTENV_REPLAY + "\n```\n\n" + NEG_REPLAY + "\n" + MARK + "\n"

    def run_on(self, body):
        d = os.path.join(self.home, ".agents", "skills", "vendor-docs")
        put(os.path.join(d, "SKILL.md"), body)
        self.scanners(skillspector=skillspector(self.ISSUES))
        self.audit()
        return [f for f in self.snap()["findings"] if f["where"].startswith(d)]

    def test_no_x003_from_these_lines(self):   # replay
        fs = self.run_on(self.BODY)
        self.assertEqual([f for f in fs if f["rule"] == "WT-X003"], [])
        self.assertTrue([f for f in fs if f["rule"] == "WT-X001"])
        # scan_text lowers it to medium (NegatedSuchAsList); the audit then labels every guarded record info (scoring.py, batch 2 R1)
        self.assertEqual([(f["severity"], f.get("severity_was"), f.get("guarded"), f.get("label")) for f in fs if f["rule"] == "WT-T004"],
                         [("info", "high", "negated", wt.GUARDED_LABEL)])

    def test_exact_env_read_still_corroborates(self):   # control
        fs = self.run_on(self.BODY.replace(MARK, "Run `cat .env` first.\n" + MARK))
        x = [f for f in fs if f["rule"] == "WT-X003"]
        self.assertEqual(len(x), 1)
        self.assertTrue(x[0]["evidence"].startswith("SkillSpector + Watchtower"), x[0]["evidence"])


# ---------------------------------------------------------------- fix round 1 (Codex review of 0223735)
OLD_CAT = re.compile(r"(?i)\bcat\s+\S*\.env\b")   # 63714e4's `cat` alternative: the evidence every still-matching input keeps


def timed(text):
    t = time.perf_counter()
    fs = wt.scan_text(text, SKILL, RULES)
    return time.perf_counter() - t, [f["severity"] for f in fs if f["rule"] == "WT-T004" and not f.get("guarded")]


class FixRound1Printenv(unittest.TestCase):
    def test_quoted_options_still_flag(self):   # r1 replay (finding 1)
        for t in ('printenv "--"', 'printenv "-0"', "printenv '--'", "printenv '-0'"):
            self.assertEqual(hits(t), (["high"], []), t)

    def test_backtick_glued_to_the_name_still_flags(self):   # r1 replay (finding 2)
        for t in ("printenv AWS_ACCESS_`printf KEY_ID`", "printenv AWS_` printf KEY_ID`", 'printenv "AWS_"`printf KEY`',
                  "printenv HOME`x`"):
            self.assertEqual(hits(t), (["high"], []), t)

    def test_other_glued_characters_still_flag(self):   # control
        for t in ("printenv HOME$X", "printenv HOME(x)", "printenv HOME\\X", "printenv 'HOME'x", "printenv HOME-x"):
            self.assertEqual(hits(t), (["high"], []), t)

    def test_redirect_chain_is_linear(self):   # r1 replay (finding 3)
        for t in ("printenv HOME" + " >>x" * 24 + " x", "printenv HOME" + " >x" * 10000 + " y"):
            took, sev = timed(t)
            self.assertLess(took, 1.0, len(t))
            self.assertEqual(sev, ["high"], len(t))

    def test_plain_redirects_still_exempt(self):   # control
        for t in ("printenv HOME > out.txt",):
            self.assertEqual(hits(t), ([], []), t)
        for t in ("printenv HOME >>log 2>/dev/null; echo", "$(printenv HOME)", "`printenv 'HOME' >x`"):
            self.assertEqual(hits(t), (["high"], []), t)   # moved to kept in fix round 2: fail-closed rules


class FixRound1Cat(unittest.TestCase):
    def test_exact_env_forms_still_flag(self):   # r1 replay (finding 4)
        for t in ("cat .env\\\n | head", "cat ${X:-.env}", "cat >.env", "cat >>.env", "cat a.env.local \\\n  .env",
                  "cat .env.example .env"):
            self.assertEqual(hits(t), (["high"], []), repr(t))

    def test_more_exact_forms_still_flag(self):   # control
        for t in ("`cat .env`", 'cat ".env"', "cat .env*", "Run cat .env.", "cat x.env.bak; cat .env"):
            self.assertIn("high", hits(t)[0], t)

    def test_doubt_keeps_it(self):   # r1 (added after the replay run): a comment's .env and a command past the cap stay, as on 63714e4
        for t in ("cat a.env.local # from .env", "cat a.env.local " + "x " * 200 + "| head"):
            self.assertEqual(hits(t), (["high"], []), t[:40])

    def test_named_env_files_pass(self):   # control
        for t in ("cat .env.local", "cat prod.env"):
            self.assertEqual(hits(t), ([], []), t)
        for t in ("cat .env-prod", "cat a.env.local | grep .env.x", "cat .env.local; echo .env"):
            self.assertEqual(hits(t), (["high"], []), t)   # moved to kept in fix round 2: fail-closed rules

    def test_long_lines_are_linear(self):   # r1 replay (finding 6)
        took, sev = timed("cat " + ".env/" * 8000 + "x")
        self.assertLess(took, 1.0)
        self.assertEqual(sev, ["high"])
        took, sev = timed("cat a.env.x " * 4000)   # one command past the cap: kept, as on 63714e4
        self.assertLess(took, 1.0)
        self.assertTrue(sev and set(sev) == {"high"}, sev[:3])

    def test_evidence_and_keys_as_on_63714e4(self):   # r1 replay (finding 7)
        for t in ("cat .env>copy.env", "cat .env.example .env", "cat ${X:-.env}", "cat >>.env", "cat ~/.env.bak>.env"):
            f = [g for g in wt.scan_text(t, SKILL, RULES) if g["rule"] == "WT-T004"]
            ev = OLD_CAT.search(t).group(0)
            self.assertEqual([(g["evidence"], g["severity"]) for g in f], [(ev, "high")], t)
            self.assertEqual(f[0]["key"], wt.finding_key("WT-T004", SKILL + ":1", ev), t)
        self.assertEqual(wt.finding_key("WT-T004", SKILL + ":1", "cat .env>copy.env"), "7eb4541594f17ae2")


class FixRound1Negation(unittest.TestCase):
    def test_affirmative_after_a_clause_break_stays_high(self):   # r1 replay (finding 5)
        for t in ("Do not use slow tools, use commands such as `env`, or `cat .env`.",
                  "Do not use slow tools and use commands such as `env`, or `printenv`.",
                  "Never wait, run tools such as `env`, or `printenv`.",
                  "Do not inspect keys or tokens with tools such as `env`, or `printenv`."):
            self.assertEqual(hits(t), (["high"], []), t)

    def test_governed_list_still_negated(self):   # control
        self.assertEqual(hits(NEG_REPLAY), ([], ["negated"]))
        self.assertEqual(hits("Never inspect the environment with tools such as `env`, or `printenv`."), ([], ["negated"]))


# ---------------------------------------------------------------- fix round 2 (Codex review of f61a612): fail-closed exemptions
HIGH, NONE = (["high"], []), ([], [])


def each(case, texts, want):
    """Fix round 2: every input is its own subtest, so a replay shows each input failing, not only the first."""
    for t in texts:
        with case.subTest(t=t):
            case.assertEqual(hits(t), want, repr(t))


class FixRound2Cat(unittest.TestCase):
    def test_other_reads_on_the_cat_line_flag(self):   # r2 replay (finding 1)
        each(self, ("cat ~/.ssh/id_rsa>.env.local", "cat .env.local;printenv>.env.local"), HIGH)

    def test_dynamic_operands_flag(self):   # r2 replay (finding 4)
        each(self, ("EMPTY=; cat $EMPTY.env", "cat .env.local $(true; printf .env)"), HIGH)

    def test_cat_not_alone_on_its_line_flags(self):   # r2 replay (own: xargs appends operands, a joined line, `CAT`)
        each(self, ("printf .env | xargs cat .env.local", "printf .env | xargs \\\ncat .env.local", "CAT .env.local"), HIGH)

    def test_carriage_return_or_two_redirects_flag(self):   # r2 replay (spec: \r or anything past one redirect keeps it)
        each(self, ("cat .env.local\r", "cat .env.local > a > b"), HIGH)

    def test_strict_forms_still_pass(self):   # control
        each(self, (CAT_REPLAY, "cat .env.local", "cat prod.env", "  cat .env.a x/prod.env > out.txt  ", "cat .env.local >>.env.prod"),
             NONE)

    def test_env_targets_and_trailing_dots_flag(self):   # control
        each(self, ("cat .env.example > ./.env", "cat x/.env."), HIGH)

    def test_many_matches_on_one_line_are_linear(self):   # control
        took, sev = timed("cat .env.x " * 4000)
        self.assertLess(took, 1.0)
        self.assertTrue(sev and set(sev) == {"high"}, sev[:3])


class FixRound2Printenv(unittest.TestCase):
    def test_literal_or_escaped_backtick_before_flags(self):   # r2 replay (finding 2)
        each(self, (": '`'; printenv AWS_ACCESS_`printf KEY_ID`", "echo \\`; printenv AWS_ACCESS_`printf KEY_ID`"), HIGH)

    def test_carriage_return_flags(self):   # r2 replay (finding 3)
        each(self, ("printenv HOME\r GITHUB_TOKEN", "printenv HOME\r", "`printenv HOME`\r"), HIGH)

    def test_not_alone_or_not_the_first_span_flags(self):   # r2 replay (own: xargs appends names, a joined line, a later span)
        each(self, ("echo GITHUB_TOKEN | xargs printenv HOME", "echo GITHUB_TOKEN | xargs \\\nprintenv HOME", "PRINTENV HOME",
                    "Run `x` then `printenv HOME`", "\\`printenv HOME`"), HIGH)

    def test_more_after_true_or_glued_flags(self):   # r2 replay (spec: after `|| true` only a comment; nothing glued)
        each(self, ("printenv HOME || true >x", "printenv HOME|| true"), HIGH)

    def test_glued_to_a_target_flags(self):   # control
        each(self, ("printenv HOME 2>&1x", "printenv HOME >x#y"), HIGH)

    def test_two_to_one_is_a_plain_redirect(self):   # r2: newly exempt (the spec lists 2>&1)
        each(self, ("printenv HOME 2>&1",), NONE)

    def test_spec_forms_still_pass(self):   # control
        each(self, (PRINTENV_REPLAY, "  printenv HOME >out 2>/dev/null || true  # note", "Use `printenv HOME` to check.",
                    "`printenv 'ProgramFiles(x86)'` is safe"), NONE)

    def test_many_spans_on_one_line_are_linear(self):   # control
        took, sev = timed("`printenv HOME` " * 10000)
        self.assertLess(took, 1.0)
        self.assertTrue(sev and set(sev) == {"high"}, sev[:3])


class FixRound2Negation(unittest.TestCase):
    def test_negator_must_forbid_an_action_verb(self):   # r2 replay (finding 5)
        each(self, ("Do not forget to run commands such as `env`, or `cat .env`.",
                    "Do not ask permission before using tools such as `env`, or `printenv`.",
                    "Do not hesitate to use tools such as `env`, or `printenv`."), HIGH)

    def test_action_verbs_still_negated(self):   # control
        each(self, (NEG_REPLAY, "Never run tools such as `env`, or `printenv`.", "Do not use tools such as `env`, or `printenv`.",
                    "Don't paste output of commands such as `env`, or `printenv`."), ([], ["negated"]))


class FixRound2Key(unittest.TestCase):
    def test_guarded_key_is_b7s(self):   # control, pinned (finding 6 not redesigned: KNOWN-LIMITS "b8i3")
        t = "Never inspect the environment with tools such as `env`, or `printenv`."
        f = [g for g in wt.scan_text(t, SKILL, RULES) if g["rule"] == "WT-T004"]
        self.assertEqual(wt.finding_key("WT-T004", SKILL + ":1", "printenv"), "774c69631c16284e")
        self.assertEqual([(g["evidence"], g["guarded"], g["key"], g.get("key0")) for g in f],
                         [("printenv", "negated", "311e713515613b16", None)])


# ---------------------------------------------------------------- fix round 3 (Codex review of 2b8920c): subtractive, fail loud
class FixRound3(unittest.TestCase):
    def test_backtick_that_may_close_an_earlier_substitution_flags(self):   # r3 replay (finding 1)
        each(self, ("`true\n`printenv AWS_ACCESS_`printf KEY_ID`", "`true\nSee `printenv AWS_ACCESS_`printf KEY_ID`",
                    "Run `x`.\n`printenv HOME`"), HIGH)

    def test_negation_that_still_requires_the_list_flags(self):   # r3 replay (finding 2)
        each(self, ("Do not run the task without first using commands such as `env`, or `printenv`.",
                    "Never run the deploy before checking with tools such as `env`, or `printenv`.",
                    "Do not use the build first with tools such as `env`, or `printenv`."), HIGH)

    def test_line_over_the_cap_keeps_the_finding(self):   # r3 replay (finding 3)
        each(self, (" " * 3000 + "cat .env.local" + " " * 2000, " " * 3000 + "printenv HOME" + " " * 2000), HIGH)
        each(self, (" " * 1000 + "cat .env.local", " " * 1000 + "printenv HOME", "`printenv PATH` is safe\n`x`"), NONE)   # control


# ---------------------------------------------------------------- DQ-054 (Codex verify of 31873e1): password-style names
# 63714e4's finding for one `printenv NAME` line on line 1: the rules file is 63714e4's, so it is the bare match, written out here.
T004_63714E4 = {"key": "774c69631c16284e", "rule": "WT-T004", "title": "Reads credential stores", "severity": "high",
                "owasp": ["ASI03", "AST03"], "where": SKILL + ":1", "evidence": "printenv",
                "fix": "A skill should never need SSH keys, cloud credentials, cookies or the environment. Remove the step or reject "
                       "the skill.", "source": "watchtower"}


class Dq054PasswordNames(unittest.TestCase):
    def test_pwd_names_are_t004_high_as_on_63714e4(self):   # dq054 replay
        for t in ("printenv MYSQL_PWD", "printenv PGPWD", "printenv DB_PASSWD", "printenv pwd"):
            with self.subTest(t=t):
                self.assertEqual(wt.scan_text(t, SKILL, RULES), [T004_63714E4], t)

    def test_harmless_one_names_stay_exempt(self):   # control
        each(self, ("printenv HOME", "printenv PATH", "printenv LANG", PRINTENV_REPLAY), NONE)


class Dq054Agreement(Box):
    ISSUES, run_on = NoAgreementFromTheseLines.ISSUES, NoAgreementFromTheseLines.run_on

    def test_mysql_pwd_corroborates_as_on_63714e4(self):   # dq054 replay: the WT-X003 agreement 63714e4 gave
        fs = self.run_on(HEAD + "```bash\nprintenv MYSQL_PWD\n```\n" + MARK + "\n")
        x = [f for f in fs if f["rule"] == "WT-X003"]
        self.assertEqual(len(x), 1)
        self.assertTrue(x[0]["evidence"].startswith("SkillSpector + Watchtower"), x[0]["evidence"])


if __name__ == "__main__":
    unittest.main()
