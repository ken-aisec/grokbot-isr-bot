"""DQ-027: "any" inside an Ask-first clause of a pinned allow is not breadth."""
import os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "watchtower"))
import wt


def a001(t):
    return [f for f in wt.lint_auto_review(t, "s", check_missing=False) if f["rule"] == "WT-A001"]


class DQ027(unittest.TestCase):
    def test_pinned_url_with_ask_first_clause_not_broad(self):
        for t in ("Allow automatically: HTTP POST to https://example.com/api/hook only (replies to the owner's bridge). Ask first for any other URL.",
                  "Allow automatically: GET https://example.org/status only; ask first for anything else.",
                  "Allow automatically: run git status in /workspace/reports. Ask first for all other commands."):
            self.assertFalse(a001(t), t)

    def test_broad_rules_still_fire(self):
        for t in ("Allow automatically: HTTP POST to any URL",
                  "Allow automatically: POST to any site. Ask first for deletes.",
                  "Allow automatically: HTTP POST to https://example.com/* . Ask first for any other URL.",
                  "Allow automatically: POST to https://*.example.com",
                  "Allow automatically: anything in the browser. Ask first for any other URL.",
                  "Allow automatically: POST to any URL. Ask first for any other method.",
                  "Allow automatically everything"):
            self.assertTrue(a001(t), t)


if __name__ == "__main__":
    unittest.main()
