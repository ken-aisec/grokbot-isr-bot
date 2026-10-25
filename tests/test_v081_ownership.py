"""v0.8.1 (owner decision, Oct 24): ownership by location. ISR Bot scores only the owner's files; Grok Bot's, Codex's and Claude's own
folders are vendor (a platform-notes count), ISR Bot's own trees and copies of chat and tool output are silent. owner_of decides
by path prefixes, on the path as written and where it really leads, never by a list (PLAN v0.8.1 §3.1-3.2).

OwnerOf: the classifier on its own. On v0.8.0 every test errors: there is no owner_of."""
import os, sys, unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import Box  # noqa: E402
import isr  # noqa: E402
import rename_v080 as rn  # noqa: E402  (the dev checkout's folder name holds the old product word)

VENDOR_SUBS = ("sand-data/managed-skills", "agent-data/managed-skills", "sand-data/plugins/cache", "agent-data/plugins/cache",
               ".claude/plugins", ".codex/skills", ".codex/plugins", ".grok/bundled")


class OwnerOf(Box):
    def h(self, *p):
        return os.path.join(self.home, *p)

    def w(self, *p):
        return os.path.join(self.ws, *p)

    def put(self, p, text="x\n"):
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(text)
        return p

    def link(self, target, at):
        os.makedirs(os.path.dirname(at), exist_ok=True)
        os.symlink(target, at)
        return at

    def test_each_vendor_prefix_both_spellings(self):
        other = os.path.join(self.tmp, "home2", "box"); os.makedirs(other)
        with mock.patch.object(isr, "BOX_HOME", other):   # every home base, not only the home folder
            for base in (self.home, other):
                for sub in VENDOR_SUBS:
                    for p in (os.path.join(base, sub), os.path.join(base, sub, "x", "SKILL.md")):
                        self.assertEqual(isr.owner_of(p), "vendor", p)
        self.assertEqual(isr.owner_of("/tmp/hooks/expand_mcp_file_args.py"), "vendor")
        self.assertEqual(isr.owner_of("/tmp/hooks"), "vendor")
        # agent-data a link to sand-data (this box's layout): both names of one managed skill are vendor
        self.agent_data_link()
        self.put(self.h("sand-data", "managed-skills", "sign-in", "SKILL.md"))
        for name in ("sand-data", "agent-data"):
            self.assertEqual(isr.owner_of(self.h(name, "managed-skills", "sign-in", "SKILL.md")), "vendor", name)
            self.assertEqual(isr.owner_of(self.h(name, "plugins", "cache", "m", "p", "SKILL.md")), "vendor", name)
        # a spelling with "." and ".." still names the same place
        self.assertEqual(isr.owner_of(self.h("sand-data", "workflows", "..", "managed-skills", "a", "SKILL.md")), "vendor")

    def test_each_isr_self_prefix(self):
        for p in (isr.SELF_ROOT, os.path.join(isr.SELF_ROOT, "tests", "fixtures", "bad", "x", "SKILL.md"),
                  self.w(rn.OLD["pkg"] + "-dev", "tests", "t.py"), self.w("isr-bot-dev", "docs", "x.md"),
                  os.path.join(isr.home(), "tests", "t.py"), self.w("backups", "old", "settings.txt"), self.w("backups")):
            self.assertEqual(isr.owner_of(p), "isr_self", p)
        self.assertEqual(isr.owner_of(self.w("projects", "app", "config.txt")), "user")   # control

    def test_each_echo_prefix(self):
        for p in (self.h(".claude", "projects", "p", "tool-results", "a.txt"), self.h(".claude", "plans", "p.md"),
                  self.h(".cursor", "projects", "w", "agent-tools", "a.txt"), self.w("agent-tools", "a.txt"), self.w("agent-tools")):
            self.assertEqual(isr.owner_of(p), "fixture-echo", p)
        self.assertEqual(isr.owner_of(self.h(".cursor", "projects", "w", "agent-transcripts", "a.txt")), "user")   # control

    def test_cursor_agent_tools_needs_exactly_one_folder(self):
        projects = self.h(".cursor", "projects")
        self.assertEqual(isr.owner_of(os.path.join(projects, "w", "agent-tools")), "fixture-echo")
        self.assertEqual(isr.owner_of(os.path.join(projects, "w", "agent-tools", "d", "a.txt")), "fixture-echo")
        for p in (os.path.join(projects, "agent-tools", "a.txt"), os.path.join(projects, "w", "x", "agent-tools", "a.txt"),
                  os.path.join(projects, "w", "agent-tools-old", "a.txt"), os.path.join(projects, "w"), projects):
            self.assertEqual(isr.owner_of(p), "user", p)

    def test_agent_data_workflows_is_user(self):
        for p in (self.h("sand-data", "workflows", "x", "SKILL.md"), self.h("agent-data", "workflows", "x", "SKILL.md")):
            self.assertEqual(isr.owner_of(p), "user", p)
        self.agent_data_link()
        self.put(self.h("sand-data", "workflows", "x", "SKILL.md"))
        for p in (self.h("sand-data", "workflows", "x", "SKILL.md"), self.h("agent-data", "workflows", "x", "SKILL.md")):
            self.assertEqual(isr.owner_of(p), "user", p)

    def test_link_from_user_folder_into_vendor_is_user(self):
        real = self.put(self.h(".grok", "bundled", "skills", "x", "SKILL.md"))
        self.assertEqual(isr.owner_of(real), "vendor")   # control: the file where it really is
        self.link(os.path.dirname(real), self.h("sand-data", "workflows", "x"))
        self.assertEqual(isr.owner_of(self.h("sand-data", "workflows", "x", "SKILL.md")), "user")
        self.link(real, self.h(".agents", "skills", "y", "SKILL.md"))   # a file link, too
        self.assertEqual(isr.owner_of(self.h(".agents", "skills", "y", "SKILL.md")), "user")

    def test_link_from_vendor_folder_to_user_file_is_user(self):
        mine = self.put(self.h("sand-data", "workflows", "x", "notes.md"))
        at = self.link(mine, self.h(".grok", "bundled", "skills", "x", "SKILL.md"))
        self.assertEqual(isr.owner_of(at), "user")
        self.link(os.path.dirname(mine), self.h("sand-data", "managed-skills", "x"))   # a folder link
        self.assertEqual(isr.owner_of(self.h("sand-data", "managed-skills", "x", "notes.md")), "user")
        self.assertEqual(isr.owner_of(self.h(".grok", "bundled", "skills", "z", "SKILL.md")), "vendor")   # control
        # a vendor root that is itself a link elsewhere doesn't make elsewhere vendor (§3.1: the sub-folder's link isn't followed)
        outside = self.put(os.path.join(self.tmp, "outside", "skills", "y", "SKILL.md"))
        self.link(os.path.join(self.tmp, "outside"), self.h(".codex", "skills"))
        self.assertEqual(isr.owner_of(self.h(".codex", "skills", "skills", "y", "SKILL.md")), "user")
        self.assertEqual(isr.owner_of(outside), "user")

    def test_lookalike_names_are_user(self):
        for p in (self.h("sand-data", "workflows", "x", "managed-skills", "SKILL.md"), os.path.join(self.tmp, "x", ".grok", "bundled", "a.md"),
                  self.h(".grok", "bundled-evil", "x", "SKILL.md"), self.h(".grok"), "/tmp/hooks-old/x.py",
                  self.w("backups-2026", "x.txt"), self.w("projects", "agent-tools", "a.txt"), self.h(".claude", "projects-old", "a.txt"),
                  self.w("isr-bot-dev-copy", "x.md")):
            self.assertEqual(isr.owner_of(p), "user", p)

    def test_codex_auth_claude_credentials_and_hook_files_are_user(self):
        for p in (self.h(".codex", "auth.json"), self.h(".claude", ".credentials.json"), self.h(".claude", "settings.json"),
                  self.h(".cursor", "hooks.json"), self.w(".cursor", "hooks.json"), self.h("sand-data", "settings.json"),
                  self.h("sand-data", "plugins", "installed", "p", "SKILL.md"), self.h(".agents", "skills", "notes-helper", "SKILL.md")):
            self.assertEqual(isr.owner_of(p), "user", p)

    def test_isr_bot_state_exports_quarantine_are_user(self):
        for sub in ("state", "exports", "quarantine"):
            p = os.path.join(isr.home(), sub, "x.json")
            self.assertEqual(isr.owner_of(p), "user", p)
        self.assertEqual(isr.owner_of(os.path.join(isr.home(), "tests", "x.py")), "isr_self")   # control

    def test_non_path_wheres_are_user(self):
        for p in (None, "", "relative/x.txt", "~/.grok/bundled/x", 7):
            self.assertEqual(isr.owner_of(p), "user", p)
        for where in ("rollcall:Bot:routine:name:1", "auto-review.txt:1", ".grok/bundled/skills/x/SKILL.md:3", "", "cron"):
            f = isr.finding("ISR-T004", "t", "high", "LLM01", where, "e", "x")
            self.assertEqual(isr.owner_of_finding(f), "user", where)

    def test_decoy_rules_are_user_anywhere(self):
        for where in (self.h(".claude", "projects", "p", "x.txt"), self.w("agent-tools", "a.txt"), self.h(".grok", "bundled", "x.txt"),
                      self.w("backups", "x.txt")):
            for rule in ("ISR-K001", "ISR-K003"):
                self.assertEqual(isr.owner_of_finding(isr.finding(rule, "t", "critical", "LLM01", where, "e", "x")), "user", (rule, where))
            self.assertNotEqual(isr.owner_of_finding(isr.finding("ISR-S001", "t", "critical", "LLM01", where, "e", "x")), "user", where)

    def test_trailing_line_is_cut(self):
        mine = self.put(self.h("sand-data", "workflows", "x", "notes.md"))
        at = self.link(mine, self.h(".grok", "bundled", "skills", "x", "SKILL.md"))
        f = isr.finding("ISR-T008", "t", "critical", "LLM01", at + ":12", "e", "x")
        self.assertEqual(isr.owner_of_finding(f), "user")   # the file link is followed once ":12" is off
        self.assertEqual(isr.owner_of_finding(isr.finding("ISR-T008", "t", "critical", "LLM01", at + ":12", "e", "x", path=at)), "user")
        plain = self.put(self.h(".grok", "bundled", "skills", "v", "SKILL.md"))
        self.assertEqual(isr.owner_of_finding(isr.finding("ISR-T008", "t", "critical", "LLM01", plain + ":3", "e", "x")), "vendor")
        # a folder verdict keeps its name: a skill folder called "learn:3" is that folder, not "learn"
        self.put(self.h("sand-data", "workflows", "learn", "SKILL.md"))
        folder = self.link(self.h("sand-data", "workflows", "learn"), self.h(".grok", "bundled", "skills", "learn:3"))
        self.assertEqual(isr.owner_of_finding(isr.finding("ISR-X003", "t", "critical", "LLM01", folder, "e", "x")), "user")
        self.assertEqual(isr.owner_of_finding(isr.finding("ISR-X003", "t", "critical", "LLM01", folder[:-2], "e", "x")), "vendor")


if __name__ == "__main__":
    unittest.main()
