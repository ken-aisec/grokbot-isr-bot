"""Batch 6 PR1, B4: Ask-first rules written in another language (decision 2).

rules/ask_first_vocab.json (shipped, held to MANIFEST.sha256 like the access vocabulary) gives, for 13 languages, the words that
open an Ask-first rule and the stems of the five areas. A rule set Watchtower reads is linted over every language at once; one
it can't read (none of its words in any language) stays the counted medium, with every area missing, and gets a language Tip
beside it (fix round 1, Codex 5: 6cd1ab4 made it a Tip instead, so `["."]` hid the medium); no rule set at all stays the medium
"Ask-first rules not found". The English entry is today's regular expressions exactly.

Tests marked "replay" fail on 5dcd0a2 on their assertion (measured with 5dcd0a2's watchtower/ sources and rules, this file in
place); "guard" ones keep what must not change. Settings files are written into temp boxes."""
import json, os, re, sys, unittest
from unittest import mock
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import Box, ROOT, wt

AREAS = ["sending email or messages", "publishing or posting", "purchases or payments", "deleting data", "changing permissions or settings"]
SPANISH = ["Antes de enviar correos o mensajes", "Antes de publicar en redes", "Antes de hacer compras o pagos",
           "Antes de borrar o eliminar archivos", "Antes de cambiar permisos, configuración, rutinas o conectores"]
SPANISH_EXPORT = "\n".join("Pregúntame antes: " + s[len("Antes de "):] for s in SPANISH) + "\n"
JAPANESE = ["メールやメッセージを送信する前に確認する", "公開や投稿の前に確認する", "購入や支払いの前に確認する", "ファイルを削除する前に確認する",
            "権限や設定を変更する前に確認する"]
GREEK = ["Ρώτα με πρώτα πριν από αποστολή email ή μηνυμάτων", "Ρώτα με πρώτα πριν από δημοσίευση", "Ρώτα με πρώτα πριν από αγορές ή πληρωμές",
         "Ρώτα με πρώτα πριν από διαγραφή δεδομένων", "Ρώτα με πρώτα πριν από αλλαγή δικαιωμάτων ή ρυθμίσεων"]
SWAHILI = ["Uliza kwanza kabla ya kutuma barua", "Uliza kwanza kabla ya kununua"]   # a language the vocabulary doesn't have


def old_gaps(text):
    """5dcd0a2's ask_first_gaps, the English reference the shipped vocabulary must reproduce."""
    ask = " ".join(l for l in text.splitlines() if re.search(r"(?i)ask\s+first", l)).lower()
    return [w for w, rx in ((AREAS[0], r"send|email|message"), (AREAS[1], r"publish|post"), (AREAS[2], r"purchas|pay|buy"),
                            (AREAS[3], r"delet|remov"), (AREAS[4], r"permission|setting|routine|connector")) if not re.search(rx, ask)]


ENGLISH_CORPUS = [
    "Ask first: before sending any external email or message\nAsk first: before publishing, posting, buying or paying for anything\n"
    "Ask first: before deleting anything\nAsk first: before changing settings, routines or connectors\n",
    "Ask first: before sending email", "Ask first: sending email or messages\nAsk first: publishing or posting\n",
    "ask first before you post\nAllow automatically: send the weekly digest", "Ask   first: remove old files\nask first: change permissions",
    "Allow automatically when running git status in /workspace/reports", "", "Ask first: every shell command",
    "Ask me first before payments", "Otherwise ask first about display settings and purchases", "ASK FIRST: Buy, delete, publish",
    "Ask first: anything comprehensive or compulsory", "Ask first: before importing a pagination library",
    "Ask first: deploy to production\nAsk first: rotate the API keys\nAsk first: email the team",
]


class _Settings(Box):
    def native(self, ask=(), allow=()):
        p = os.path.join(self.home, "agent-data", "settings.json")
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            json.dump({"localToolPermission": "never", "autoReviewInstructions": {"askInstructions": list(ask), "allowInstructions": list(allow)}},
                      f, ensure_ascii=False)
        os.environ["ISR_BOT_SETTINGS"] = p
        self.addCleanup(os.environ.pop, "ISR_BOT_SETTINGS", None)

    def export(self, text):
        d = os.path.join(os.environ["ISR_BOT_HOME"], "exports")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "auto-review.txt"), "w") as f:
            f.write(text)

    def a003(self):
        self.audit()
        return [f for f in self.snap()["findings"] if f["rule"] == "ISR-A003"]

    def counted(self):
        return [(f["rule"], f["severity"], f["title"], f["evidence"]) for f in self.a003() if f.get("class") != "tip"]


class OtherLanguages(_Settings):
    def test_a_spanish_set_in_the_app_is_read(self):   # replay (5dcd0a2: medium, all five areas missing)
        self.native(ask=SPANISH)
        self.assertEqual(self.a003(), [])

    def test_a_spanish_set_in_an_export_is_read(self):   # replay (5dcd0a2: medium)
        self.export(SPANISH_EXPORT)
        self.assertEqual(self.a003(), [])

    def test_japanese_and_greek_sets_are_read(self):   # replay (5dcd0a2: medium)
        for rules in (JAPANESE, GREEK):
            self.native(ask=rules)
            self.assertEqual(self.a003(), [], rules[0])

    def test_a_spanish_set_without_payments_names_only_that(self):   # replay (5dcd0a2: all five)
        self.native(ask=[s for s in SPANISH if "pagos" not in s])
        self.assertEqual(self.counted(), [("ISR-A003", "medium", "Ask-first rules don't cover everything", "purchases or payments")])

    def test_a_language_watchtower_cant_read_stays_counted_with_a_tip(self):   # replay (5dcd0a2: the medium, no Tip)
        self.native(ask=SWAHILI)   # fix round 1 (Codex 5): the medium stays; the language Tip is added beside it
        fs = self.a003()
        self.assertEqual(sorted((f["class"], f["severity"]) for f in fs), [("evidence", "medium"), ("tip", "info")])
        self.assertEqual(self.counted(), [("ISR-A003", "medium", "Ask-first rules don't say what they cover", ", ".join(AREAS))])
        tip = next(f for f in fs if f["class"] == "tip")
        self.assertIn("ISR Bot can't check your Ask-first rules if it doesn't read their language", tip["title"])
        self.assertIn("The alert above stays", tip["fix"])
        r = self.audit()
        self.assertEqual(r["open_by_severity"]["medium"], 1, r)
        self.assertEqual(wt.ask_first_covered(self.snap()["findings"]), set())   # nothing is assumed covered

    def test_rules_that_name_no_area_stay_the_counted_medium(self):   # replay, Codex 5 (6cd1ab4: a Tip, nothing counted)
        for ask in (["."], ["every shell command"]):
            self.native(ask=ask)
            self.assertEqual(self.counted(), [("ISR-A003", "medium", "Ask-first rules don't say what they cover", ", ".join(AREAS))], ask)
            self.assertEqual(self.audit()["open_by_severity"]["medium"], 1, ask)

    def test_a_forged_tip_flag_never_lowers_the_medium(self):   # guard: the Tip is known by its own evidence, never the medium's
        med = wt.finding("ISR-A003", "Ask-first rules not found", "medium", ["ASI09"], "Auto-review rules", ", ".join(AREAS), "x")
        med["ask_first_unread"] = True
        self.assertFalse(wt.ask_first_unread(med))
        self.assertEqual(wt.label_findings([med])[0]["severity"], "medium")


class EnglishAsBefore(_Settings):
    def test_no_rules_is_still_the_medium_not_found(self):   # guard
        self.assertEqual(self.counted(), [("ISR-A003", "medium", "Ask-first rules not found", ", ".join(AREAS))])

    def test_only_allow_rules_is_still_not_found(self):   # guard
        self.native(allow=["Create Notion pages under the Team Wiki tree"])
        self.assertEqual(self.counted(), [("ISR-A003", "medium", "Ask-first rules not found", ", ".join(AREAS))])

    def test_an_english_partial_set_names_the_same_gaps(self):   # guard: same severity and gaps as 5dcd0a2
        self.export("Ask first: before sending email\n")
        self.assertEqual([(r, s, e) for r, s, _, e in self.counted()], [("ISR-A003", "medium", ", ".join(AREAS[1:]))])

    def test_an_english_full_set_is_still_quiet(self):   # guard
        self.export(ENGLISH_CORPUS[0])
        self.assertEqual(self.a003(), [])

    def test_english_parity_on_a_corpus(self):   # guard: the shipped English entry is 5dcd0a2's regexes, and no other language
        for text in ENGLISH_CORPUS:                  # makes an English rule set look covered
            self.assertEqual(wt.ask_first_gaps(text), old_gaps(text), text)

    def test_lint_auto_review_is_unchanged_for_english(self):   # guard (test_isr_bot's test_auto_review shape)
        t = open(os.path.join(ROOT, "tests", "fixtures", "exports", "auto-review.txt")).read()
        self.assertIn("ISR-A003", {f["rule"] for f in wt.lint_auto_review(t, "x")})
        self.assertEqual(len(wt.ask_first_gaps("Ask first: before sending email")), 4)


class Vocabulary(_Settings):
    def test_the_shipped_file_has_13_languages_and_is_released(self):   # replay (5dcd0a2: no such file)
        self.assertTrue(os.path.isfile(os.path.join(ROOT, "rules", "ask_first_vocab.json")))
        with open(os.path.join(ROOT, "rules", "ask_first_vocab.json"), encoding="utf-8") as f:
            doc = json.load(f)
        self.assertEqual([l["lang"] for l in doc["languages"]], ["en", "es", "fr", "de", "pt", "it", "ru", "zh", "ja", "ko", "ar", "el", "hi"])
        self.assertEqual(doc["languages"][0], {"lang": "en", "openers": [r"ask\s+first"],
                                               "areas": ["send|email|message", "publish|post", "purchas|pay|buy", "delet|remov",
                                                         "permission|setting|routine|connector"]})
        with open(os.path.join(ROOT, "MANIFEST.sha256")) as f:
            self.assertIn("  rules/ask_first_vocab.json\n", f.read())
        self.assertEqual(wt.ask_first_vocab_problem(), "")

    def test_a_malformed_file_is_refused_whole_and_english_still_works(self):   # replay (5dcd0a2: no vocabulary)
        self.assertTrue(hasattr(wt, "ASK_FIRST_VOCAB") and os.path.isfile(wt.ASK_FIRST_VOCAB))
        bad =os.path.join(self.tmp, "ask_first_vocab.json")
        with open(os.path.join(ROOT, "rules", "ask_first_vocab.json"), encoding="utf-8") as f:
            doc = json.load(f)
        doc["languages"][1]["areas"] = doc["languages"][1]["areas"][:4]   # one area short
        with open(bad, "w", encoding="utf-8") as f:
            json.dump(doc, f, ensure_ascii=False)
        with mock.patch.object(wt, "ASK_FIRST_VOCAB", bad):
            wt._ASK_FIRST_VOCAB_CACHE.clear()
            self.addCleanup(wt._ASK_FIRST_VOCAB_CACHE.clear)
            self.assertIn("entry 2", wt.ask_first_vocab_problem())
            self.assertEqual(wt.ask_first_gaps(ENGLISH_CORPUS[0]), [])
            self.native(ask=SPANISH)
            self.assertEqual([s for _, s, _, _ in self.counted()], ["medium"])   # Spanish is unread without the file: the medium (fix round 1)
            notes = self.snap()["notes"]
            self.assertTrue([n for n in notes if "rules/ask_first_vocab.json" in n and "entry 2" in n], notes)

    def test_a_file_that_isnt_the_released_one_is_refused(self):   # replay (5dcd0a2: no vocabulary)
        self.assertTrue(hasattr(wt, "_ASK_FIRST_VOCAB_CACHE"))
        real = wt.release_digest
        wt._ASK_FIRST_VOCAB_CACHE.clear()
        self.addCleanup(wt._ASK_FIRST_VOCAB_CACHE.clear)
        with mock.patch.object(wt, "release_digest", lambda rel: "0" * 64 if rel == wt.ASK_FIRST_VOCAB_REL else real(rel)):
            self.assertIn("MANIFEST.sha256", wt.ask_first_vocab_problem())
            self.assertEqual(len(wt.ask_first_vocab()), 1)   # the built-in English only


if __name__ == "__main__":
    unittest.main()
