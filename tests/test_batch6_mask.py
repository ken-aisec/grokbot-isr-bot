"""Batch 6 PR2, KL3 (#15 high 3) and #15 medium 6: curl's cookie and OAuth bearer values are hidden, and masking is idempotent.

- `curl --cookie`, `-b`, an attached `-bVALUE` and `--cookie=` hide a value that has an = in it (a cookie, not a cookie-jar file
  name), only when the command is curl (`git checkout -b x` stays readable); `--oauth2-bearer` hides its next word. Both line
  readers know them, so the forms split by a backslash and a line break (Codex's three) are hidden too.
- A hidden value inside a quoted word ends at the value's last character: its closing quote stays, so the quotes left are paired
  and masking the masked text again changes nothing (it used to eat the quote, and a second pass hid the rest of the line).
- MASK_VERSION 8: copies masked by version 7 (approved skills, the engine cache) are masked again.

Tests marked "replay" fail on 5dcd0a2 on their assertion (measured with 5dcd0a2's engine sources, this file in place).
Every secret is FAKE."""
import gzip, json, os, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_boxes  # noqa: E402
import isr  # noqa: E402
from test_batch4_codex_review3 import History, ev

SPLIT = ("curl --coo\\\nkie 'sid=FAKEz' https://x.example",      # Codex's three (KL3)
         "curl -\\\nb 'sid=FAKEz' https://x.example",
         "curl --oauth2-bea\\\nrer FAKEz https://x.example",
         "curl \\\n  --cookie 'sid=FAKEz' https://x.example",
         "curl --cookie \\\n  'sid=FAKEz' https://x.example")
ONE_LINE = ("curl --cookie 'sid=FAKEz' https://x.example",
            "curl -b 'sid=FAKEz' https://x.example",
            "curl -b sid=FAKEz https://x.example",
            "curl -bsid=FAKEz https://x.example",
            "curl -b'sid=FAKEz' https://x.example",
            "curl --cookie=sid=FAKEz https://x.example",
            'curl -b "sid=FAKEz; theme=dark" https://x.example',
            "curl --oauth2-bearer FAKEz https://x.example",
            "curl --oauth2-bearer=FAKEz https://x.example",
            "/usr/bin/curl -s -b 'sid=FAKEz' https://x.example")
READABLE = ("git checkout -b feature/FAKEbranch", "git switch -c x && git checkout -b y", "curl -b jar.txt https://x.example",
            "curl --cookie cookies.txt https://x.example", 'curl -b "$COOKIE" https://x.example', "curl -c jar.txt https://x.example",
            "grep -b pattern notes.txt", "curl --oauth2-bearer \"$TOKEN\" https://x.example")
# the idempotence corpus: Codex's multi-line --user, quoted headers and assignments, the forms above
CORPUS = ("curl --user='admin:FAKEa\n" + "y" * 40 + "\nFAKEz' -T n.txt https://x.example",
          "curl -H 'Authorization: Bearer FAKEh7' https://x.example",
          "curl -H \"Cookie: sid=FAKEc; theme=dark\" https://x.example",
          'export "API_TOKEN=FAKEe9" && make',
          "curl -d 'token=FAKEd8&user=bob' https://x.example",
          "API_TOKEN='prefix'\"FAKEp11\" && make",
          "'API_TOKEN'='FAKEq10' make",
          '"API_TOKEN=FAKE"more && make',
          "curl -u 'admin:FAKEu5' https://x.example",
          "'-uadmin:FAKEu6' && ls",
          "mysql '-pFAKEm1' -h db.example && ls",
          "export \"API_TOKEN=FAKEa\\\nFAKEz\" && make") + SPLIT + ONE_LINE


def paired(s):
    """True when every quote in s is closed (read as the shell reads quotes, escapes included)."""
    q, i = None, 0
    while i < len(s):
        c = s[i]
        if c == "\\" and q != "'":
            i += 2
            continue
        if q is None and c in "'\"":
            q = c
        elif q is not None and c == q:
            q = None
        i += 1
    return q is None


class CurlCookieAndBearer(History):
    def test_codex_split_forms_are_hidden(self):   # replay (5dcd0a2 kept FAKEz in all three)
        for line in SPLIT:
            for got in (isr.mask_secrets(line), ev(line)):
                self.assertNotIn("FAKEz", got, line)
                self.assertIn("x.example", got, line)
            self.assertEqual(isr.mask_secrets(line).count("\n"), line.count("\n"), line)

    def test_single_line_forms_are_hidden(self):   # replay (5dcd0a2 kept FAKEz in --cookie, -b, -bsid= and --oauth2-bearer)
        for line in ONE_LINE:
            for got in (isr.mask_secrets(line), ev(line)):
                self.assertNotIn("FAKEz", got, line)
                self.assertIn("x.example", got, line)

    def test_in_an_approved_copy(self):   # replay (5dcd0a2 kept FAKEz in the copy)
        doc = self.copy_of("Run these:\n```\n" + "\n".join(SPLIT + ONE_LINE) + "\n```\nAsk before saving.")
        self.assertNotIn("FAKEz", doc)
        self.assertIn("Ask before saving.", doc)
        self.assertEqual(json.loads(doc)["masked"], isr.MASK_VERSION)

    def test_in_shell_history_state(self):   # guard (passes on 5dcd0a2 too: these lines aren't kept as history events)
        got = self.history("\n".join(SPLIT[:3] + ONE_LINE[:4]) + "\n")
        self.assertNotIn("FAKEz", got)

    def test_copies_masked_by_version_7_are_masked_again(self):   # replay (5dcd0a2's marker 7 left them as they were)
        d = self.skills(1)[0]
        self.audit()
        old = {"dir": d, "at": isr.now(), "hash": isr.skill_dir_hash(d), "hashes": {"SKILL.md": isr.sha256_file(os.path.join(d, "SKILL.md"))},
               "files": {"SKILL.md": "\n".join(SPLIT) + "\n"}, "masked": 7}
        with gzip.open(isr.approved_path(d), "wt") as f:
            json.dump(old, f)
        with open(isr.state_path("approved_masked"), "w") as f:
            f.write("7 " + isr.now() + "\n")   # what 5dcd0a2 wrote
        self.audit()
        with gzip.open(isr.approved_path(d), "rt") as f:
            doc = json.load(f)
        self.assertNotIn("FAKEz", json.dumps(doc))
        self.assertEqual(doc["masked"], 10)   # batch 7d: MASK_VERSION 10 (was 9, and "9" below; batch 7a: 9, was 8)
        self.assertEqual(open(isr.state_path("approved_masked")).read().split()[0], "10")

    def test_names_files_and_other_tools_stay_readable(self):   # guard
        for s in READABLE:
            self.assertEqual(isr.mask_secrets(s), s, s)


class QuotesAndIdempotence(unittest.TestCase):
    def test_a_hidden_value_keeps_its_closing_quote(self):   # replay (5dcd0a2 ate the closing quote)
        self.assertEqual(isr.mask_secrets("curl -d 'token=FAKEd8&user=bob' https://x.example"), "curl -d 'token=[hidden]' https://x.example")
        self.assertEqual(isr.mask_secrets('export "API_TOKEN=FAKEe9" && make'), 'export "API_TOKEN=[hidden]" && make')
        self.assertEqual(isr.mask_secrets("curl -u 'admin:FAKEu5' https://x.example"), "curl -u 'admin:[hidden]' https://x.example")

    def test_masked_text_keeps_its_quotes_paired(self):   # replay (5dcd0a2 left an open quote in several)
        for s in CORPUS:
            if paired(s):
                self.assertTrue(paired(isr.mask_secrets(s)), (s, isr.mask_secrets(s)))

    def test_masking_twice_is_masking_once(self):   # replay (5dcd0a2's second pass hid "&& make")
        for s in CORPUS:
            once = isr.mask_secrets(s)
            self.assertEqual(isr.mask_secrets(once), once, s)
            self.assertNotIn("FAKE", once.replace("FAKEbranch", ""), s)

    def test_a_quoted_value_with_a_quote_inside_is_still_whole(self):   # guard: the shapes that were already whole stay so
        self.assertEqual(isr.mask_secrets("API_TOKEN='prefix'\"FAKEp11\" && make"), "API_TOKEN=[hidden] && make")
        self.assertEqual(isr.mask_secrets("'API_TOKEN'='FAKEq10' make"), "'API_TOKEN'=[hidden] make")
        self.assertEqual(isr.mask_secrets("curl -H 'Authorization: Bearer FAKEh7' https://x.example"),
                         "curl -H 'Authorization: Bearer [hidden]' https://x.example")

    def test_the_version_is_8(self):   # replay (5dcd0a2: 7)
        self.assertEqual(isr.MASK_VERSION, 10)   # batch 7d: 10 (was 9; batch 7a: 9, was 8); the name is batch 6's, kept so no test disappears


if __name__ == "__main__":
    unittest.main()
