"""1.0.1 (U5): `/workspace/backups` and MCP configs in a layout ISR Bot doesn't know.

Backups: only backup.sh's own folders (`<workspace>/backups/isr-bot-*`) are ISR Bot's and silent; the owner's other backups are
the owner's and scored. MCP: a readable config where neither `mcpServers` nor `servers` is a {name: server} map says its tools
are unknown, never none; an empty map is still none.

Tests marked "replay" fail on bacd581 at their assertion; "guard" ones keep what must not change. Every planted value is FAKE or
built at test time; the box is a temp folder, never this computer's own."""
import json, os, sys, unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import Box  # noqa: E402
import isr  # noqa: E402
from test_v081_ownership import _Owned, key  # noqa: E402
from test_batch5_access_map import w  # noqa: E402
from test_batch5_access_round2 import _Small  # noqa: E402
from test_isr_fp_diff import _Daily, write_json  # noqa: E402

BK = "isr-bot-pre-upgrade-20261102-0900"   # backup.sh's folder name (scripts/backup.sh)
SLACK = {"mcpServers": {"slack": {"command": "npx"}}}
LIST_SHAPED = {"mcpServers": [{"name": "slack", "command": "npx"}]}
CANT_LAYOUT = ("- Tool connections (MCP): ISR Bot couldn't check all of it this time (a tool list there is in a layout ISR Bot "
               "doesn't know, so its tools are unknown).")
LAYOUT = "- ISR Bot doesn't know the layout of the tool list in {}, so the tools in it are unknown, not none."
NONE_LISTED = "- Tool connections (MCP): 1 file, with no tools listed in it."


# ---------------------------------------------------------------- backups
class Backups(_Owned):
    def keys_in(self, paths):
        for i, p in enumerate(paths):
            self.put(p, f"token = {key(i)}\n")
        return paths

    def s001_counted(self, p):
        return [f for f in self.F() if f["rule"] == "ISR-S001" and f["where"].startswith(p + ":") and isr.counts(f)]

    def test_the_owners_own_backups_are_scored(self):   # replay (bacd581: all of backups is ISR Bot's own, silent)
        p = self.keys_in([self.w("backups", "site-2026", "config.txt")])[0]
        self.skills(1); self.scanners(trufflehog=None)
        self.audit()
        self.assertTrue(self.s001_counted(p), self.F())

    def test_an_isr_bot_backup_stays_silent(self):   # guard
        self.keys_in([self.w("backups", BK, "state", "settings.txt")])
        self.skills(1); self.scanners(trufflehog=None)
        self.audit()
        self.assertFalse([f for f in self.F() if f["rule"] in ("ISR-S001", "ISR-S002")])
        p = self.keys_in([self.w("projects", "app", "config.txt")])[0]   # control: the same key shape elsewhere counts
        self.audit()
        self.assertTrue(self.s001_counted(p))


class OwnerOfBackups(Box):
    def w(self, *p):
        return os.path.join(self.ws, *p)

    def test_owner_of_backups(self):   # replay (bacd581: the first two are isr_self)
        for p in (self.w("backups"), self.w("backups", "old", "x.txt"), self.w("backups", "is" + "r-botany", "x")):
            self.assertEqual(isr.owner_of(p), "user", p)
        for p in (self.w("backups", BK, "state", "x.json"), self.w("backups", "isr-bot-v0.8.5-pre-1.0-20261104-0946", "x")):
            self.assertEqual(isr.owner_of(p), "isr_self", p)

    def test_a_backup_folder_link_out_is_the_owners(self):   # guard
        app = self.w("projects", "app")
        os.makedirs(app)
        with open(os.path.join(app, "config.txt"), "w") as f:
            f.write("x\n")
        os.makedirs(self.w("backups"))
        os.symlink(app, self.w("backups", "isr-bot-x"))
        self.assertEqual(isr.owner_of(self.w("backups", "isr-bot-x")), "user")
        self.assertEqual(isr.owner_of(self.w("backups", "isr-bot-x", "config.txt")), "user")


# ---------------------------------------------------------------- MCP configs in an unknown layout
class McpLayout(_Small):
    def mcp_lines(self, *files):
        """The access map's MCP lines after an audit of a small box holding these {path under home: document} configs."""
        self.small()
        for rel, doc in files:
            w(os.path.join(self.home, *rel.split("/")), doc)
        self.audit_json()
        return [x for x in self.access()[1].splitlines() if x.startswith("- Tool connections (MCP)") or "tool list" in x]

    def test_a_list_shaped_mcp_servers_is_unknown_not_none(self):   # replay (bacd581: "1 file, with no tools listed in it.")
        lines = self.mcp_lines((".cursor/mcp.json", LIST_SHAPED))
        self.assertNotIn(NONE_LISTED, lines)
        self.assertEqual(lines, [CANT_LAYOUT, LAYOUT.format("~/.cursor/mcp.json")])

    def test_a_renamed_servers_key_is_unknown(self):   # replay (bacd581: none)
        lines = self.mcp_lines((".cursor/mcp.json", {"mcp": {"servers": {"slack": {"command": "npx"}}}}))
        self.assertEqual(json.loads(self.map_file())["shared"]["incomplete"].get("mcp"), "unknown-shape")
        self.assertEqual(lines, [CANT_LAYOUT, LAYOUT.format("~/.cursor/mcp.json")])

    def test_known_tools_beside_an_unknown_file(self):   # replay (bacd581: no layout line)
        lines = self.mcp_lines((".cursor/mcp.json", SLACK), ("projects/tools/mcp.json", LIST_SHAPED))
        self.assertEqual(lines, ["- Tool connections (MCP): 1 tool in 2 files: slack.", LAYOUT.format("~/projects/tools/mcp.json")])

    def test_an_empty_mcp_servers_is_still_none(self):   # guard
        lines = self.mcp_lines((".cursor/mcp.json", {"mcpServers": {}}))
        self.assertEqual(lines, [NONE_LISTED])
        self.assertNotIn("mcp", json.loads(self.map_file())["shared"]["incomplete"])


class McpLayoutDaily(_Daily):
    def test_a_layout_change_is_not_tools_removed(self):   # replay (bacd581: slack reported removed)
        mcp = os.path.join(self.home, ".cursor", "mcp.json")
        self.settings()
        write_json(mcp, SLACK)
        self.audit()
        self.assertEqual(self.daily(), "NO_CHANGES")
        write_json(mcp, LIST_SHAPED)
        out = self.daily()
        chg = json.loads(out).get("rule_changes", {}) if out.startswith("{") else {}
        self.assertNotIn("names", chg)
        self.assertNotIn("mcp_tools", chg.get("map", {}))


if __name__ == "__main__":
    unittest.main()
