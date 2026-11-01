"""v0.8.3: ISR-A004 on a read-only rule (Item 1), the access map reading Grok Bot's settings file through a link (Item 2a,
Option A, the owner's yes Nov 1 2026), and the daily check's rule and map diff, `rule_changes` (Item 2b).

Tests marked "replay" fail on 767b34e on their assertion (this file in place); "guard" ones keep what must not change. Every box
is a temp folder (HOME, ISR_BOT_HOME, ISR_BOT_SETTINGS), never this computer's own; fake keys are built at test time."""
import builtins, json, os, shutil, stat, sys, tempfile, unittest
from unittest import mock
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import Box, temp_home  # noqa: E402
from test_isr_bot import fake_key  # noqa: E402
import isr  # noqa: E402

OWNER_RULE = "Read-only public X reads through the built-in X connector are always fine"   # the owner's own words, character for character
ALLOW = ["Run the test suite in ~/projects/app", "Summarize my notes each morning"]
ASK = ["sending email or messages, publishing or posting, purchases or payments, deleting data, changing permissions or settings"]


def native_only_home(test):
    """NATIVE_SETTINGS as the tests use it: the ~ path only (never this computer's real settings), no ISR_BOT_SETTINGS."""
    saved = list(isr.NATIVE_SETTINGS)
    test.addCleanup(isr.NATIVE_SETTINGS.__setitem__, slice(None), saved)
    isr.NATIVE_SETTINGS[:] = [p for p in saved if p.startswith("~")]
    p = mock.patch.dict(os.environ); p.start(); test.addCleanup(p.stop)
    os.environ.pop("ISR_BOT_SETTINGS", None)


def write_json(path, doc):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(doc if isinstance(doc, str) else json.dumps(doc))
    return path


def a004(text):
    return [f["rule"] for f in isr.lint_auto_review([f"Allow automatically: {text}"], "t", check_missing=False)]


# ---------------------------------------------------------------- Item 1: ISR-A004 on a read-only rule
class ReadOnlyRuleIsNotAnInstall(unittest.TestCase):
    def setUp(self):
        temp_home(self)

    def settings_file(self, doc):
        d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, d, True)
        p = write_json(os.path.join(d, "settings.json"), doc)
        e = mock.patch.dict(os.environ, {"ISR_BOT_SETTINGS": p}); e.start(); self.addCleanup(e.stop)
        return p

    def test_the_owners_rule_exact_text_gives_no_a004(self):   # replay (767b34e: ['ISR-A004'])
        rules = a004(OWNER_RULE)
        self.assertNotIn("ISR-A004", rules)
        self.assertNotIn("ISR-A001", rules)
        self.assertNotIn("ISR-A002", rules)

    def test_the_owners_rule_through_the_settings_file_gives_no_a004(self):   # replay (767b34e: ISR-A004 from native_settings)
        self.settings_file({"autoReviewInstructions": {"allowInstructions": [OWNER_RULE]}})
        text, settings, path = isr.native_settings()
        rules = [f["rule"] for f in isr.lint_auto_review(text, path)]
        self.assertNotIn("ISR-A004", rules)
        self.assertNotIn("ISR-A001", rules)
        self.assertNotIn("ISR-A002", rules)

    def test_a_real_write_grant_still_fires(self):   # guard
        self.assertIn("ISR-A004", a004("Use the Notion connector to add pages"))
        self.assertIn("ISR-A004", a004("install plugins from the catalog"))
        self.assertIn("ISR-A004", a004("Use sand_automation_write to create automations"))

    def test_a_mixed_rule_still_fires(self):   # guard
        self.assertIn("ISR-A004", a004("Read-only reads through the Linear connector, and install connectors"))

    def test_a_bare_mention_with_no_read_word_still_fires(self):   # guard: unknown stays flagged
        self.assertIn("ISR-A004", a004("Use the Linear connector"))

    # fix round 1 (Codex): a write word the first list missed let a write grant pass as read-only
    def test_read_and_overwrite_still_fires(self):   # replay (staged build: [])
        self.assertIn("ISR-A004", a004("Read and overwrite pages through the Notion connector"))

    def test_read_and_execute_still_fires(self):   # replay (staged build: [])
        self.assertIn("ISR-A004", a004("Read and execute routines through the connector"))

    def test_read_and_upload_still_fires(self):   # replay (staged build: [])
        self.assertIn("ISR-A004", a004("Read files and upload them through the Drive connector"))

    def test_read_and_append_still_fires(self):   # replay (staged build: [])
        self.assertIn("ISR-A004", a004("Read and append to a doc through the connector"))

    def test_an_underscore_tool_name_that_sends_still_fires(self):   # replay (staged build: [])
        self.assertIn("ISR-A004", a004("Use the slack_send_message connector tool, read-only otherwise"))

    def test_the_owners_rule_still_passes_with_the_longer_list(self):   # guard
        self.assertNotIn("ISR-A004", a004(OWNER_RULE))
        self.assertNotIn("ISR-A004", a004("Read-only reads through the Linear connector"))

    def test_the_access_map_files_it_under_other(self):   # replay (767b34e: area "installs")
        self.settings_file({"autoReviewInstructions": {"allowInstructions": [OWNER_RULE]}})
        rules, settings, st = isr._ax_auto_allow(isr._ax_bases([]))
        self.assertEqual(st, "found")
        self.assertEqual([r["area"] for r in rules], ["other"])


# ---------------------------------------------------------------- Item 2a: settings.json reached through a link (Option A)
SETTINGS = {"autoReviewInstructions": {"allowAutomatically": ["Run the test suite in ~/projects/app"]},
            "localToolPermission": "ask", "autoReview": True}


class SettingsThroughALink(Box):
    def setUp(self):
        super().setUp()
        native_only_home(self)

    def test_agent_data_as_a_link_is_read(self):   # replay (767b34e: (None, None, "unreadable"), map auto_allow [])
        sd = self.agent_data_link()
        write_json(os.path.join(sd, "settings.json"), SETTINGS)
        rules, settings, st = isr._ax_auto_allow(isr._ax_bases([self.home]))
        self.assertEqual(st, "found")
        self.assertIsNotNone(settings)
        self.assertEqual([r["says"] for r in rules or []], ["Run the test suite in ~/projects/app"])
        self.audit()
        sh = json.load(open(isr.state_path("access_map.json")))["shared"]
        self.assertEqual(len(sh["auto_allow"]), 1)
        self.assertIsNotNone(sh["auto_review"])

    def linked_to(self, target):
        os.makedirs(os.path.join(self.home, "agent-data"), exist_ok=True)
        os.symlink(target, os.path.join(self.home, "agent-data", "settings.json"))
        return isr._ax_auto_allow(isr._ax_bases([self.home]))

    def test_a_link_to_a_fifo_is_unreadable(self):   # guard
        fifo = os.path.join(self.tmp, "elsewhere", "settings.json"); os.makedirs(os.path.dirname(fifo))
        os.mkfifo(fifo)
        self.assertEqual(self.linked_to(fifo), (None, None, "unreadable"))

    def test_a_link_to_a_folder_is_unreadable(self):   # guard
        d = os.path.join(self.tmp, "elsewhere", "settings.json"); os.makedirs(d)
        self.assertEqual(self.linked_to(d), (None, None, "unreadable"))

    def test_a_link_to_another_users_file_is_unreadable(self):   # guard
        if os.getuid() != 0:
            self.skipTest("a file owned by another user can only be made as root")
        p = write_json(os.path.join(self.tmp, "elsewhere", "settings.json"), SETTINGS)
        os.chown(p, 65534, 65534)
        self.assertEqual(self.linked_to(p), (None, None, "unreadable"))

    def test_no_link_is_unchanged(self):   # guard
        write_json(os.path.join(self.home, "agent-data", "settings.json"), SETTINGS)
        rules, settings, st = isr._ax_auto_allow(isr._ax_bases([self.home]))
        self.assertEqual((len(rules), settings, st), (1, {"local_execution": "ask", "auto_review": True}, "found"))

    def test_only_settings_json_follows_a_link(self):   # guard: hooks, MCP files and ISR_BOT_SETTINGS still refuse a link
        real = os.path.join(self.tmp, "elsewhere", "conf")
        write_json(os.path.join(real, "hooks.json"), {"hooks": [{"command": "python3 ~/x.py"}]})
        write_json(os.path.join(real, "mcp.json"), {"mcpServers": {"FAKElinked": {"command": "x"}}})
        write_json(os.path.join(real, "settings.json"), SETTINGS)
        os.symlink(real, os.path.join(self.home, ".grok"))
        os.symlink(real, os.path.join(self.home, ".cursor"))
        bases = isr._ax_bases([self.home])
        hooks, ok = isr._ax_hooks([], [], bases)
        self.assertEqual((hooks, ok), ({"platform": 0, "other": 0}, False))
        mcp = isr._ax_mcp([os.path.join(self.home, ".cursor", "mcp.json")], bases)
        self.assertEqual((mcp["count"], mcp["unreadable"]), (0, 1))
        os.environ["ISR_BOT_SETTINGS"] = os.path.join(self.home, ".grok", "settings.json")   # not one of the two fixed paths
        self.assertEqual(isr._ax_auto_allow(bases), (None, None, "unreadable"))


# ---------------------------------------------------------------- Item 2b: the daily rule and map diff
class _Daily(Box):
    def setUp(self):
        super().setUp()
        native_only_home(self)
        self.cfg = os.path.join(self.tmp, "cfg", "settings.json")   # outside the scan roots: only the settings readers see it
        os.environ["ISR_BOT_SETTINGS"] = self.cfg

    def settings(self, allow=ALLOW, ask=ASK, local="ask"):
        doc = {"autoReviewInstructions": {"allowAutomatically": list(allow), "askFirst": list(ask)}}
        if local:
            doc["localToolPermission"] = local
        write_json(self.cfg, doc)

    def daily(self):
        code, out, err = self.run_cmd("daily", "--roots", *self.roots)
        self.assertEqual(code, 0, err)
        return out.strip()

    def changes(self, out):
        self.assertFalse(out.startswith(("NO_CHANGES", "SCANNERS_MISSING")), out)
        doc = json.loads(out)
        self.assertIn("rule_changes", doc, out)
        self.assertTrue(isinstance(doc.get("rule_changes_line"), str) and doc["rule_changes_line"], out)
        return doc["rule_changes"]

    def snapshot_path(self):
        return os.path.join(os.environ["ISR_BOT_HOME"], "state", "rules_snapshot.json")

    def start(self, **kw):
        """The audit, then the first daily run: nothing to compare yet, so it says nothing."""
        self.settings(**kw)
        self.audit()
        self.assertEqual(self.daily(), "NO_CHANGES")


class RuleChanges(_Daily):
    def test_first_daily_is_silent_and_writes_the_snapshot(self):   # replay (767b34e: no rules_snapshot.json)
        self.start()
        p = self.snapshot_path()
        self.assertTrue(os.path.isfile(p))
        self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o600)
        snap = json.load(open(p))
        self.assertEqual(sorted(r["kind"] for r in snap["rules"]), ["allow", "allow", "ask"])
        self.assertEqual(snap["settings"]["found"], "found")

    def test_an_added_rule_no_pattern_flags_is_said_once(self):   # replay (767b34e: NO_CHANGES)
        self.start()
        self.settings(allow=ALLOW + ["run scripts in /tmp/x"])
        chg = self.changes(self.daily())
        self.assertEqual(chg["rules"]["allow_added"], ["run scripts in /tmp/x"])
        self.assertEqual(chg["rules"]["counts"]["allow"], [2, 3])
        self.assertNotIn("allow_removed", chg["rules"])
        self.assertEqual(self.daily(), "NO_CHANGES")

    def test_a_removed_ask_first_rule_is_said(self):   # replay (767b34e: no rule_changes)
        self.start(ask=ASK + ["any purchase over ten dollars"])
        self.settings(ask=ASK)
        chg = self.changes(self.daily())
        self.assertEqual(chg["rules"]["ask_removed"], ["any purchase over ten dollars"])
        self.assertEqual(chg["rules"]["counts"]["ask"], [2, 1])

    def test_an_edited_rule_is_one_removed_and_one_added(self):   # replay (767b34e: NO_CHANGES)
        self.start()
        self.settings(allow=[ALLOW[0], "Summarize my notes each evening"])
        chg = self.changes(self.daily())
        self.assertEqual((chg["rules"]["allow_added"], chg["rules"]["allow_removed"]), (["Summarize my notes each evening"], [ALLOW[1]]))
        self.assertEqual(chg["rules"]["counts"]["allow"], [2, 2])

    def test_a_key_in_a_rule_is_never_kept_or_shown(self):   # replay (767b34e: no rule_changes)
        token = "ghp_" + fake_key(36)
        self.start()
        self.settings(allow=ALLOW + [f"Summarize the notes tagged {token}"])
        out = self.daily()
        chg = self.changes(out)
        self.assertEqual(len(chg["rules"]["allow_added"]), 1)
        self.assertNotIn(token, out)
        for fn in ("rules_snapshot.json", "access_map.json"):
            with open(os.path.join(os.environ["ISR_BOT_HOME"], "state", fn)) as f:
                self.assertNotIn(token, f.read(), fn)

    def test_an_unreadable_settings_file_is_not_all_rules_removed(self):   # replay (767b34e: no rules_not_compared)
        self.start()
        write_json(self.cfg, "{not json")
        out = self.daily()
        chg = self.changes(out)
        self.assertEqual(chg.get("rules_not_compared"), "settings.json unreadable")
        self.assertNotIn("rules", chg)
        out = self.daily()   # still unreadable: not said again
        self.assertNotIn("rules_not_compared", out)
        self.settings()      # back, the same rules: nothing added (the audit's own ISR-A003 shows as fixed, as before)
        self.assertNotIn("rule_changes", self.daily())

    def test_a_missing_settings_file_is_not_all_rules_removed(self):   # replay (767b34e: no rules_not_compared)
        self.start()
        os.remove(self.cfg)
        chg = self.changes(self.daily())
        self.assertEqual(chg.get("rules_not_compared"), "settings.json missing")
        self.assertNotIn("rules", chg)

    def test_local_execution_flipped_to_always_is_said(self):   # replay (767b34e: no rule_changes)
        self.start()
        self.settings(local="always")
        chg = self.changes(self.daily())
        self.assertEqual(chg["settings"]["local_execution"], ["ask", "always"])

    def test_a_new_mcp_tool_is_said(self):   # replay (767b34e: no rule_changes)
        self.start()
        write_json(os.path.join(self.home, ".cursor", "mcp.json"), {"mcpServers": {"FAKEtool": {"command": "x"}}})
        chg = self.changes(self.daily())
        self.assertEqual(chg["names"]["mcp_added"], ["FAKEtool"])
        self.assertEqual(chg["map"]["mcp_tools"], [0, 1])

    def test_a_map_field_not_seen_whole_is_not_compared(self):   # guard
        self.start()
        write_json(os.path.join(self.home, ".cursor", "mcp.json"), {"mcpServers": {"FAKEtool": {"command": "x"}}})
        write_json(os.path.join(self.home, "projects", "tools", "mcp.json"), "{not json")   # MCP tools aren't all known now
        out = self.daily()
        chg = json.loads(out).get("rule_changes", {}) if out.startswith("{") else {}
        self.assertNotIn("mcp_tools", chg.get("map", {}))
        self.assertNotIn("names", chg)

    def test_a_run_that_dies_before_its_output_says_it_again(self):   # replay (767b34e: no rules_snapshot.json)
        self.start()
        self.settings(allow=ALLOW + ["Tidy the downloads folder"])
        real, calls = builtins.print, []

        def dies_once(*a, **k):
            if not calls and a and str(a[0]).lstrip().startswith("{"):
                calls.append(1)
                raise RuntimeError("the output never got out")
            return real(*a, **k)
        with mock.patch("builtins.print", dies_once):
            self.run_cmd("daily", "--roots", *self.roots)
        self.assertEqual(calls, [1])
        snap = json.load(open(self.snapshot_path()))
        self.assertEqual(sum(r["kind"] == "allow" for r in snap["rules"]), 2)   # not moved on
        chg = self.changes(self.daily())
        self.assertEqual(chg["rules"]["allow_added"], ["Tidy the downloads folder"])

    def test_fifteen_added_rules_show_ten_and_a_count(self):   # replay (767b34e: NO_CHANGES)
        self.start()
        extra = [f"Summarize the meeting notes in the shared folder number {i:02d} and keep the summary short, plain and in English " * 2
                 for i in range(15)]
        self.settings(allow=ALLOW + extra)
        out = self.daily()
        chg = self.changes(out)
        shown = chg["rules"]["allow_added"]
        self.assertEqual(len(shown), 11)
        self.assertEqual(shown[-1], "+5 more")
        self.assertTrue(all(len(t) <= 200 for t in shown))
        self.assertEqual(chg["rules"]["counts"]["allow"], [2, 17])
        self.assertLess(len(out), 6000)

    def test_the_owners_rule_alone_gives_no_a004_and_a_silent_first_run(self):   # replay (767b34e: ISR-A004 open, no snapshot)
        self.settings(allow=[OWNER_RULE])
        self.audit()
        self.assertNotIn("ISR-A004", [f["rule"] for f in self.snap()["findings"]])
        self.assertEqual(self.daily(), "NO_CHANGES")
        self.assertTrue(os.path.isfile(self.snapshot_path()))

    def test_a_quiet_day_writes_nothing(self):   # replay (767b34e: no rules_snapshot.json)
        self.start()
        self.assertTrue(os.path.isfile(self.snapshot_path()))
        st = os.stat(self.snapshot_path())
        with open(self.snapshot_path()) as f:
            before = f.read()
        self.assertEqual(self.daily(), "NO_CHANGES")
        with open(self.snapshot_path()) as f:
            self.assertEqual(f.read(), before)
        self.assertEqual(os.stat(self.snapshot_path()).st_ino, st.st_ino)


class ExportRuleChanges(_Daily):
    """fix round 1 (Codex): the auto-review exports are a source of their own, compared only when read both times."""
    EXPORT_ASK = "Ask first: wire transfers to new payees"

    def export(self, *lines):
        return write_json(os.path.join(os.environ["ISR_BOT_HOME"], "exports", "auto-review.md"), "\n".join(lines) + "\n")

    def test_an_unreadable_export_is_not_its_rules_removed(self):   # replay (staged build: ask_removed for the export's rule)
        self.export(self.EXPORT_ASK)
        self.start()
        p = self.export(self.EXPORT_ASK)
        os.remove(p); os.makedirs(p)   # still there, but not a file ISR Bot can read
        self.settings(allow=ALLOW + ["Tidy the downloads folder"])
        out = self.daily()
        chg = self.changes(out)
        self.assertNotIn("ask_removed", chg["rules"])
        self.assertEqual(chg["rules"]["allow_added"], ["Tidy the downloads folder"])   # the settings file is still compared
        self.assertEqual(chg.get("rules_not_compared"), "auto-review exports unreadable")
        os.rmdir(p); self.export(self.EXPORT_ASK)   # back, the same rules: nothing to say
        self.assertNotIn("rule_changes", self.daily())

    def test_export_changes_are_said_without_a_settings_file(self):   # replay (staged build: NO_CHANGES)
        self.export("Ask first: any purchase over ten dollars")
        self.audit()
        self.assertEqual(self.daily(), "NO_CHANGES")
        self.export("Ask first: any purchase over ten dollars", "Allow automatically: Tidy the downloads folder")
        chg = self.changes(self.daily())
        self.assertEqual(chg["rules"]["allow_added"], ["Tidy the downloads folder"])
        self.assertNotIn("rules_not_compared", chg)
        self.export("Allow automatically: Tidy the downloads folder")
        chg = self.changes(self.daily())
        self.assertEqual(chg["rules"]["ask_removed"], ["any purchase over ten dollars"])

    def test_a_rule_taken_out_of_a_readable_export_is_said(self):   # guard
        self.export(self.EXPORT_ASK)
        self.start()
        self.export("Ask first: any purchase over ten dollars")
        chg = self.changes(self.daily())
        self.assertEqual(chg["rules"]["ask_removed"], ["wire transfers to new payees"])
        self.assertEqual(chg["rules"]["ask_added"], ["any purchase over ten dollars"])
        self.assertNotIn("rules_not_compared", chg)


if __name__ == "__main__":
    unittest.main()
