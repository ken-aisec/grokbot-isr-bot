"""DQ-011 (4), main box v0.6.7 audit of 2026-10-09: husk flagged ~/.agents/skills/last30days with
"'scripts/watchlist.py': Line 60: an f-string containing a SQL keyword and an interpolated value is returned from a function
('return f"📰 *last30days update: {topic}*\\n{new} new, {updated') - the same injection risk as passing it directly to execute()".
Line 60 is a chat message; "update" is not SQL. The same skill's store.py really builds queries for execute(), and those stay.
"""
import json, os, sys, unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import Box, SCANNERS, wt  # noqa: E402

WATCHLIST_60 = '        return f"📰 *last30days update: {topic}*\\n{new} new, {updated} updated"'
MSG_RETURN = ("'scripts/watchlist.py': Line 60: an f-string containing a SQL keyword and an interpolated value is returned from a function "
              "('return f\"📰 *last30days update: {topic}*\\n{new} new, {updated') - the same injection risk as passing it directly to execute")
MSG_EXECUTE = ("'scripts/store.py': Line 3: SQL query built with an f-string/string-concatenation passed directly to 'execute()' "
               "('.execute(f\"') instead of a parameterized query - allows SQL injection through any interpolated value")


class FakeHusk(Box):
    def husk(self, says):
        """husk flags every skill named in `says` and reports those messages for it, as the real SARIF detail run does."""
        path = os.path.join(self.tmp, "husk-says.json"); json.dump(says, open(path, "w"))
        return ('#!/usr/bin/env python3\nimport json, os, sys\na = sys.argv[1:]\nsays = json.load(open(%r))\n'
                'if a[0] == "registry":\n    stage = a[-1]\n'
                '    flagged = {n: 1 for n in sorted(os.listdir(stage)) if open(os.path.join(stage, n, "SKILL.md"), errors="replace").read().split("name: ")[1].split("\\n")[0] in says}\n'
                '    print(json.dumps({"flagged": flagged})); sys.exit(0)\n'
                'name = open(os.path.join(a[1], "SKILL.md"), errors="replace").read().split("name: ")[1].split("\\n")[0]\n'
                'json.dump({"runs": [{"results": [{"message": {"text": t}} for t in says[name]]}]}, open(a[a.index("--output") + 1], "w"))\n' % path)

    def skill(self, name, files):
        d = os.path.join(self.home, ".agents", "skills", name); os.makedirs(os.path.join(d, "scripts"))
        open(os.path.join(d, "SKILL.md"), "w").write(f"---\nname: {name}\ndescription: Research the last 30 days.\n---\nRun the scripts.\n")
        for rel, lines in files.items():
            open(os.path.join(d, rel), "w").write("\n".join(lines) + "\n")
        return d

    def engine_rules(self, d):
        return [(f["rule"], f["severity"]) for f in self.snap()["findings"] if f["where"].startswith(d) and f["rule"].startswith("WT-X")]

    def watchlist(self):
        return ["# filler"] * 59 + [WATCHLIST_60, '    return f"last30days: {new} new findings"']

    def test_a_chat_message_with_the_word_update_is_not_sql(self):
        d = self.skill("last30days", {"scripts/watchlist.py": self.watchlist()})
        self.scanners(husk=self.husk({"last30days": [MSG_RETURN]})); self.audit()
        cache = wt.load_json(wt.state_path("engine_cache.json"), {})
        self.assertEqual(cache[d]["hk"], [MSG_RETURN])          # husk really ran and said it; the answer is kept as husk gave it
        self.assertEqual(self.engine_rules(d), [])               # v0.6.7: WT-X002 "husk flagged this skill"

    def test_a_query_passed_to_execute_still_counts(self):
        d = self.skill("last30days", {"scripts/watchlist.py": self.watchlist(),
                                      "scripts/store.py": ["import sqlite3", "def bump(c, t, v):",
                                                           '    c.execute(f"UPDATE {t} SET seen = 1 WHERE id = {v}")']})
        self.scanners(husk=self.husk({"last30days": [MSG_RETURN, MSG_EXECUTE]})); self.audit()
        x2 = [f for f in self.snap()["findings"] if f["where"].startswith(d) and f["rule"] == "WT-X002"]
        self.assertEqual(len(x2), 1)
        self.assertIn("store.py", x2[0]["evidence"])             # the real one leads; the chat message is gone

    def test_a_returned_f_string_that_is_a_real_query_still_counts(self):
        msg = MSG_RETURN.replace("watchlist.py", "query.py").replace("Line 60", "Line 2")
        d = self.skill("last30days", {"scripts/query.py": ["def q(t, v):", '    return f"UPDATE {t} SET name = \'{v}\'"']})
        self.scanners(husk=self.husk({"last30days": [msg]})); self.audit()
        self.assertIn("WT-X002", [r for r, _ in self.engine_rules(d)])

    def test_a_query_split_over_lines_still_counts(self):
        msg = MSG_RETURN.replace("watchlist.py", "query.py").replace("Line 60", "Line 2")
        d = self.skill("last30days", {"scripts/query.py": ["def q(t):", '    return (f"SELECT * "', '            f"FROM {t}")']})
        self.scanners(husk=self.husk({"last30days": [msg]})); self.audit()
        self.assertIn("WT-X002", [r for r, _ in self.engine_rules(d)])

    def test_a_message_without_file_and_line_is_kept(self):
        self.assertEqual(wt.husk_messages_that_count("/nowhere", ["obfuscated loader", "flagged (3 issues)"]),
                         ["obfuscated loader", "flagged (3 issues)"])
        self.assertEqual(wt.husk_messages_that_count("/nowhere", [MSG_RETURN]), [MSG_RETURN])   # can't read the line: keep it


if __name__ == "__main__":
    unittest.main()
