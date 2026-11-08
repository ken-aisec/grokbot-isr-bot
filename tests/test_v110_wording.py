"""1.1.0 Part B: the shared-file reach wording. Sentences only: no finding key, title, severity, where, score, grade or status
changes. The S004 titles stay the keys of PLAIN_BY_TITLE, S005's where stays "shared browser" and NEW_SIGN_IN stays evidence.

Tests marked "replay" fail on fa0525f on their assertion (the old sentences); "guard" ones keep what must not change. Every
planted value is FAKE…; the box is a temp folder, never this computer's own."""
import json, os, re, sys, unittest
from unittest import mock
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_batch5_brief_access import _Brief
import isr  # noqa: E402

OLD = ("so every Bot can use everything in the first list", "Shared by all Bots", "Shared by every Bot", "found no shared browser cookies",
       "so every Bot can reach it", "the shared browser is signed in", "all your Bots use the one shared browser", "Every Bot can read them",
       "Every Bot can now use this login", "Every Bot can reuse these logins", "These are cookies every Bot can see", "Every Bot uses the same logins",
       "Every Bot can read this file", "Sign the shared browser out", "but every Bot (and anything injected", "Browser: signed in to")
OLD_PLAIN = {"ISR-S004": ("The shared browser is logged in to sensitive sites", "Every Bot uses the same logins.")}


class TheNewSentences(_Brief):
    def test_w1_no_old_sentence_in_access_report_dashboard_breakdown_or_brief(self):   # replay (fa0525f: the old sentences)
        self.mapped()
        texts = {"access": self.access()[1]}
        texts["report"], texts["dashboard"] = self.report()
        texts["breakdown"] = self.run_cmd("breakdown")[1]
        texts["show"] = self.run_cmd("show", "ISR-S004")[1] + self.run_cmd("show", "ISR-S003")[1]
        r, out, page, _ = self.brief([("Gmail flaw lets attackers steal session tokens", ""), ("Slack MCP server flaw", "")])
        texts["brief"], texts["brief page"] = out, page
        self.assertTrue(all(texts.values()), [k for k, v in texts.items() if not v])
        for k, t in texts.items():
            for old in OLD:
                self.assertNotIn(old, t, k)
        self.assertIn("On this computer's shared files", texts["access"])
        self.assertIn("(on this computer's shared files; which Bot can use it isn't checked).", r["top_stories"][0]["here"])

    def test_w2_the_old_and_new_sentences_score_and_key_the_same(self):   # guard
        self.build()
        def ident(r, snap):
            fs = sorted((f["key"], f["rule"], f["title"], f["severity"], f["where"]) for f in snap["findings"])
            return fs, snap["score"], isr.snap_grade(snap), isr.status_line(snap), r.get("open_by_severity"), r.get("score")
        new = ident(self.audit_json(), self.snap())
        real_finding = isr.finding

        def old_fix(*a, **k):
            f = real_finding(*a, **k)
            f["fix"] = "Every Bot can read this file. " + f.get("fix", "")
            return f

        with mock.patch.object(isr, "finding", old_fix), mock.patch.dict(isr.PLAIN, OLD_PLAIN), \
                mock.patch.object(isr, "ACCESS_LEAD", "All your Bots share this computer, so every Bot can use everything in the first list."):
            old = ident(self.audit_json(), self.snap())
        self.assertEqual(new, old)
        self.assertTrue(new[0])


class TheIdentityStrings(unittest.TestCase):
    def test_w3_titles_where_and_evidence_are_unchanged(self):   # guard
        scope = open(os.path.join(os.path.dirname(isr.__file__), "isr_parts", "scope.py")).read()
        for title in ("Logged-in browser sessions shared by every Bot", "Shared browser cookies visible to every Bot"):
            self.assertIn(title, isr.PLAIN_BY_TITLE)
            self.assertIn(f'"{title}"', scope)
        self.assertEqual(scope.count('"shared browser"'), 2)
        self.assertEqual(isr.NEW_SIGN_IN, "New sign-in in the shared browser")
        f = isr.finding("ISR-S005", isr.NEW_SIGN_IN, "high", ["ASI03"], "shared browser", "mail.google.com first session today", "x", ident="mail.google.com")
        self.assertTrue(isr.is_evidence(f))
        g = isr.finding("ISR-S005", isr.NEW_SIGN_IN, "high", ["ASI03"], "shared browser", "mail.google.com first session today",
                        "Every Bot can now use this login.", ident="mail.google.com")
        self.assertEqual((f["key"], f["key0"]), (g["key"], g["key0"]))   # the fix text is no part of the key


class HereFits(_Brief):
    def test_w4_every_here_line_fits(self):   # guard (every line fits HERE_MAX); replay for the new tail (fa0525f: ", so every Bot can reach it.")
        m = isr.access_record(self.mapped())
        sh = m["shared"]
        sh["browser"]["products"] = [{"id": e["id"], "site": (e.get("domains") or ["x.example.invalid"])[0]} for e in isr.access_vocab()]
        sh["mcp"]["tools"] = [{"name": e["id"] + "-tool-with-a-long-name", "kind": "command"} for e in isr.access_vocab()][:40]
        for e in isr.access_vocab():
            s = isr.here_sentence(e, isr.access_touch(e, m))
            self.assertLessEqual(len(s), isr.HERE_MAX, s)
        gmail = next(e for e in isr.access_vocab() if e["id"] == "gmail")
        s = isr.here_sentence(gmail, {"bots": ["bot-001"], "bots_more": 0, "site": "mail.google.com", "mcp": None, "cli": None, "webhook": None,
                                      "browser": False, "cached": ""})
        self.assertEqual(s, "This is about Gmail. Here: 1 Bot said it uses a Gmail connector (bot-001) and browser cookie files on this computer "
                            "are signed in to mail.google.com (on this computer's shared files; which Bot can use it isn't checked).")
        self.assertLessEqual(len(s), isr.HERE_MAX)


if __name__ == "__main__":
    unittest.main()
