"""Batch 6 PR2, KL6 (#16 high 2): a saved connector answer is read the way a fresh reply is.

A fresh reply with `connectors: [{"name": "Gmail"}]` was "couldn't read which connectors it uses"; the same answer kept in
rollcall_findings.json (writable by the Bot) went through _ax_said as an empty, complete list: "Golf: no connectors" and "found no
Gmail". Now one reader (connector_answer) serves both: a string is a name (a supported scalar keeps its label), anything else in the
list makes the answer partial, and no list at all is "didn't say".

Tests marked "replay" fail on 5dcd0a2 on their assertion (measured with 5dcd0a2's watchtower/ sources, this file in place). Every
planted value is FAKE…; the box is a temp folder, never this computer's own."""
import json, os, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import wt
from test_batch5_access_round2 import CANT, DAY
from test_batch5_access_round3 import GMAIL_STORY, _Round3

COULDNT = "- Golf: Watchtower couldn't read which connectors it uses."


class SavedAnswersAreReadLikeFreshOnes(_Round3):
    def golf(self):
        return json.loads(self.map_file())["bots"][0]

    def test_a_saved_list_of_objects_is_not_no_connectors(self):   # replay (5dcd0a2: "Golf: no connectors", "found no Gmail")
        self.small()
        self.answered(connectors=[{"name": "Gmail"}])
        self.audit_json()
        out = self.access()[1]
        self.assertIn(COULDNT, out)
        self.assertNotIn("no connectors", out)
        self.assertEqual(self.here(GMAIL_STORY), CANT.format("Gmail"))
        self.assertEqual(self.golf()["connectors_unknown"], "partial")
        self.assertFalse(json.loads(self.access("--json")[1])["bot_connectors_complete"])

    def test_a_saved_number_is_not_no_connectors(self):   # replay (5dcd0a2: "Golf: no connectors")
        self.small()
        self.answered(connectors=[123])
        self.audit_json()
        out = self.access()[1]
        self.assertIn(COULDNT, out)
        self.assertEqual(self.here(GMAIL_STORY), CANT.format("Gmail"))

    def test_a_name_beside_an_object_keeps_its_label_and_is_partial(self):   # replay (5dcd0a2: complete, Gmail only)
        self.small()
        self.answered(connectors=["Gmail", {"name": "Slack"}])
        self.audit_json()
        golf = self.golf()
        self.assertEqual((golf["connectors"], golf["connectors_unknown"]), (["Gmail"], "partial"))

    def test_a_saved_scalar_name_keeps_its_label(self):   # replay (5dcd0a2: unknown, Gmail lost)
        self.small()
        self.answered(connectors="Gmail")
        self.audit_json()
        golf = self.golf()
        self.assertEqual(golf["connectors"], ["Gmail"])
        self.assertIsNone(golf["connectors_unknown"])
        self.assertEqual(self.here(GMAIL_STORY), "This is about Gmail. Here: 1 Bot said it uses a Gmail connector (Golf).")

    def test_a_fresh_reply_reads_as_before(self):   # guard: the fresh reader is unchanged
        sh, _ = wt.shape_reply({"name": "Golf", "connectors": "Gmail"})
        self.assertEqual((sh["connector_labels"], sh["connectors_known"]), (["Gmail"], True))
        sh, _ = wt.shape_reply({"name": "Golf", "connectors": [{"name": "Gmail"}]})
        self.assertEqual((sh["connector_labels"], sh["connectors_known"]), ([], False))
        sh, _ = wt.shape_reply({"name": "Golf"})
        self.assertIsNone(sh["connectors_known"])
        for raw, known in (("", None), ("  ", None), ([], True), ({"name": "Gmail"}, False), ([123, "Gmail"], False)):
            sh, _ = wt.shape_reply({"name": "Golf", "connectors": raw})
            self.assertEqual(sh["connectors_known"], known, raw)

    def test_an_empty_saved_list_is_still_no_connectors(self):   # guard
        self.small()
        self.answered()
        self.audit_json()
        out = self.access()[1]
        self.assertIn("- Golf: no connectors.", out)
        self.assertTrue(self.here(GMAIL_STORY).startswith("This is about Gmail. Watchtower found no Gmail connector"))

    def test_a_kept_partial_mark_stays(self):   # guard: a fresh "partial" carried over is not made complete by its label list
        self.small()
        self.said({"Golf": {"said_at": DAY.isoformat(), "connectors": ["Gmail"], "connectors_unknown": "partial", "routines": []}})
        self.audit_json()
        self.assertEqual(self.golf()["connectors_unknown"], "partial")


if __name__ == "__main__":
    unittest.main()
