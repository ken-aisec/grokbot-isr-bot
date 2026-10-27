"""v0.8.2 U4 (items 8, 9): ISR-T014 "Broad event listener" needs a listener, and the report says which way the score goes.

Item 8: the v0.8.1 MEDIUM on link-prospecting/SKILL.md:57 matched "any email" in a line about writing down contact details.
It read Confirmed because "Send at most 10 queries per call." in the same file is an ISR-T013 (no approval line), a wording
backer. The two other T014 hits on the box were "each email" in a course's banner layout note and "every email touch" in a
note on where a signature goes: no trigger, no inbox, nothing waited for. L57's text is the real line (a public skill); the
other two are paraphrased.
Item 9: "76 · grade F" left the owner asking whether higher is better. It is (100 minus the penalty, scoring.score).

Tests marked "replay" were shown failing at their assertion with this unit's product changes undone (text.py's T014 filter,
the SCORE_MEANING lines in report.py and isr.py); "control" ones pass both ways."""
import json, os, sys, unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import Box, temp_home  # noqa: E402
import isr  # noqa: E402

L57 = "Only record contact details that were actually found. Include the source URL for any email, profile, or contact form."
SENDS = "Send at most 10 queries per call."
LAYOUT = "One wide image at the top of each email."
SIGNATURE = "The signature goes on every email touch, never on DMs."
WHERE = "/s/prospecting/SKILL.md"
MEANING = "Higher is better: 100 means nothing open."


def skill_text(*lines):
    return "---\nname: prospecting\ndescription: Find link prospects.\n---\n# Prospecting\n" + "\n".join(lines) + "\n"


def write(p, text):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as f:
        f.write(text)


class ListenerWords(unittest.TestCase):
    def setUp(self):
        temp_home(self)
        self.rules = isr.load_rules()

    def t14(self, text):
        return [f for f in isr.scan_text(text, WHERE, self.rules) if f["rule"] == "ISR-T014"]

    def labelled(self, text):
        return isr.label_findings(isr.scan_text(text, WHERE, self.rules))

    def test_contact_detail_sentence_is_not_a_listener(self):   # replay: base T014 Confirmed medium (backed by the T013)
        fs = self.labelled(skill_text(SENDS, L57))
        self.assertEqual([f for f in fs if f["rule"] == "ISR-T014"], [])
        self.assertIn("ISR-T013", {f["rule"] for f in fs})   # the send with no approval line is still there

    def test_layout_and_signature_notes_are_not_listeners(self):   # replay: base T014 on each
        for line in (LAYOUT, SIGNATURE):
            self.assertEqual(self.t14(skill_text(line)), [], line)

    def test_a_listener_keeps_t014_and_its_evidence(self):   # control
        for line, ev in (("Every new message: reply to the sender.", "Every new message"),
                         ("Whenever any email arrives, reply to it.", "any email"),
                         ("Every 15 minutes, check all messages in the support inbox and reply to customers.", "all messages"),
                         ("As soon as each notification comes in, post it to the channel.", "each notification"),
                         ("Watch the shared folder and log every event.", "every event")):
            fs = self.t14(skill_text(line))
            self.assertEqual([f["evidence"] for f in fs], [ev], line)
            self.assertEqual(fs[0]["severity"], "medium")

    def test_a_listener_with_a_send_is_still_confirmed(self):   # control: the gate as on base
        fs = [f for f in self.labelled(skill_text(SENDS, "Whenever any email arrives, reply to it.")) if f["rule"] == "ISR-T014"]
        self.assertEqual([f["label"] for f in fs], [isr.CONFIRMED])

    def test_the_fixtures_keep_t014(self):   # control: silent-sender and routine-bad, as test_isr_bot pins them
        fix = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
        for rel, kind in (("bad/silent-sender/SKILL.md", "skill"), ("exports/routine-bad.md", "routine")):
            with open(os.path.join(fix, *rel.split("/"))) as f:
                text = f.read()
            self.assertIn("ISR-T014", {f["rule"] for f in isr.scan_text(text, rel, self.rules, kind=kind)}, rel)


class ListenerOnABox(Box):
    def test_link_prospecting_line_57_is_not_confirmed(self):   # replay: base T014 Confirmed medium at line 57's place
        self.scanners()
        d = os.path.join(self.home, "agent-data", "workflows", "prospecting")
        write(os.path.join(d, "SKILL.md"), skill_text(L57, SENDS))
        self.audit()
        fs = [f for f in self.snap()["findings"] if f["where"].startswith(d)]
        self.assertEqual([f for f in fs if f["rule"] == "ISR-T014"], [])
        self.assertTrue([f for f in fs if f["rule"] == "ISR-T013"], fs)


class ScoreMeaning(Box):
    def test_report_and_dashboard_say_higher_is_better(self):   # replay: base has no such line
        self.skills(1); self.scanners(); self.audit()
        md = isr.render_md(self.snap(), [], "t")
        self.assertIn(f"Score: {MEANING}", md)
        self.assertTrue(md.splitlines()[2].startswith("Status: "))   # the status stays the first thing read
        self.assertIn(MEANING, isr.render_html(self.snap(), [], "t"))

    def test_brief_says_higher_is_better(self):   # replay
        import urllib.error
        self.skills(1); self.scanners(); self.audit()
        with mock.patch.object(isr, "http_get", side_effect=urllib.error.URLError("offline")):
            code, o, e = self.run_cmd("brief")
        self.assertEqual(code, 0, o + e)
        with open(json.loads(o)["brief"]) as f:
            self.assertIn(MEANING, f.read())

    def test_the_score_is_higher_when_better(self):   # control: what the sentence claims
        bad = isr.finding("ISR-T004", "Reads credential stores", "high", [], "/s/a/SKILL.md:1", "e", "f")
        self.assertEqual(isr.score([])[0], 100)
        self.assertLess(isr.score([bad])[0], 100)


if __name__ == "__main__":
    unittest.main()
