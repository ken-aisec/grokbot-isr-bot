"""Batch 5 PR B, Codex round 2: the access map says "none" for a field only when this command looked at all of it, fresh.

1 the browser's cookie seed is looked at now, never taken from the last audit's findings (the Bot can write that file);
2 plugins are the folders the scan finds; state/plugins.json (writable by the Bot) sets neither their count nor whose they are;
3 a scan that misses a folder the audit scans, an MCP file Watchtower couldn't read, or a failed `crontab -l` is incomplete, and
  an incomplete field never says there is none;
4 every count is whole before a list is cut: Bots past the 40 listed, a Bot's connectors, routines past the 60 kept;
5 one connector name keeps every product it names;
7 every folder from / down to a map source is opened without following a link, and a linked profile is said, not dropped;
and (Codex's notes) a line from the last audit's findings says it is the last audit's, with the date.
(6, the golden expectations, is in test_golden_expect.)

Tests marked "replay" fail on 3170952 on their assertion (measured with 3170952's watchtower/ sources, this file in place). Every
planted value is FAKE…; the box is a temp folder, never this computer's own."""
import datetime as dt, json, os, re, shutil, sys, unittest
from unittest import mock
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import ROOT, wt
from test_batch5_access_map import AGENT, SETTINGS, w
from test_batch5_brief_access import _Brief

DAY = dt.date.today()
TODAY = f"{DAY.strftime('%b')} {DAY.day}"
VOCAB_LABELS = ("Gmail", "Google Drive", "Google Calendar", "Slack", "Discord", "Microsoft Teams", "Microsoft 365", "GitHub", "Notion",
                "1Password", "Bitwarden", "Telegram", "Dropbox", "Jira", "Linear", "Stripe", "Shopify", "Zapier", "OpenAI", "Claude",
                "Codex", "Grok")
CANT = "This is about {0}. ISR Bot couldn't check this time whether anything on this computer reaches {0}."


class _Small(_Brief):
    def small(self, bots=("Golf",)):
        """A box with Grok Bot's settings and a roster, and nothing else: no browser, no tool connection, no sign-in."""
        w(os.path.join(self.home, "agent-data", "settings.json"), SETTINGS)
        w(self.wt_home("exports", "roster.json"), [{"name": n, "kind": "bot"} for n in bots])

    def said(self, access):
        """rollcall_findings.json with these answers, as a roll-call today keeps them."""
        wt.save_json(wt.state_path("rollcall_findings.json"), {"at": wt.now(), "masked": wt.VERSION, "bots": list(access), "findings": [],
                                                               "access": access})

    def here(self, title):
        return self.brief([(title, "")])[0]["top_stories"][0]["here"]


# ---------------------------------------------------------------- 1: the cookie seed, now
class TheSeedIsLookedAtNow(_Small):
    def seed(self, where=None):
        return w(where or os.path.join(self.home, "sand-data", "cookies.json"),
                 [{"domain": ".mail.google.com", "name": "SID", "value": "FAKEcookieVALUE"}, {"domain": "example.com", "name": "_ga", "value": "x"}])

    def forget_the_seed_finding(self):
        """Delete ISR-S004 from state/last_findings.json, as the Bot could."""
        p = wt.state_path("last_findings.json")
        snap = json.load(open(p))
        for k in ("findings", "suppressed"):
            snap[k] = [f for f in snap.get(k) or [] if f.get("rule") != "ISR-S004"]
        wt.save_json(p, snap)

    def test_deleting_the_cached_finding_hides_no_sign_in(self):   # replay (3170952: "found no shared browser cookies")
        self.small()
        self.seed()
        self.audit_json()
        self.forget_the_seed_finding()
        out = self.access()[1]
        self.assertIn("- Browser: signed in to 1 site, including mail.google.com.", out)
        self.assertNotIn("found no shared browser cookies", out)
        self.assertEqual(self.here("Gmail flaw lets attackers steal session tokens"),
                         "This is about Gmail. Here: the shared browser is signed in to mail.google.com, so every Bot can reach it.")

    def test_a_seed_that_cant_be_read_is_not_no_cookies(self):   # replay (3170952: "found no shared browser cookies")
        self.small()
        os.makedirs(os.path.join(self.home, "sand-data"))
        os.symlink(self.seed(os.path.join(self.tmp, "elsewhere", "cookies.json")), os.path.join(self.home, "sand-data", "cookies.json"))
        self.audit_json()
        self.forget_the_seed_finding()
        out = self.access()[1]
        self.assertIn("- Browser: ISR Bot couldn't check all of it this time (something there couldn't be read).", out)
        self.assertNotIn("found no shared browser cookies", out)
        self.assertNotIn("not signed in to any site", out)

    def test_the_audits_own_map_has_the_whole_seed(self):   # replay (4; 3170952 read the finding's first 8): the audit's own look, whole
        self.small()
        w(os.path.join(self.home, "sand-data", "cookies.json"), [{"domain": f"s{i:02d}.github.com", "name": "user_session", "value": "x"} for i in range(11)])
        self.audit_json()
        b = json.loads(self.map_file())["shared"]["browser"]
        self.assertEqual((b["sites"], b["sensitive_count"], len(b["sensitive"])), (11, 11, 8))
        self.assertNotIn("browser", json.loads(self.map_file())["shared"]["incomplete"])


# ---------------------------------------------------------------- 2: plugins
class PluginsAreWhatTheScanFinds(_Small):
    def plugin(self, where, name):
        d = os.path.join(self.home, where)
        w(os.path.join(d, "plugin.json"), {"name": name})
        return d

    def test_a_planted_catalog_label_makes_no_plugin_grok_bots(self):   # replay (3170952: "1 (1 from Grok Bot, 0 added)")
        self.small()
        d = self.plugin(".cursor/plugins/acme-tools", "acme-tools")
        self.audit_json()
        wt.save_json(wt.state_path("plugins.json"), {"acme-tools": {"since": wt.now(), "status": "catalog", "roots": [d]}})
        self.assertIn("- Plugins: 1 (0 from Grok Bot, 1 added).", self.access()[1])

    def test_one_entry_for_two_folders_is_two_plugins(self):   # replay (3170952: one plugin)
        self.small()
        a, b = self.plugin(".cursor/plugins/a", "x"), self.plugin(".claude/plugins/b", "y")
        self.audit_json()
        wt.save_json(wt.state_path("plugins.json"), {"x": {"since": wt.now(), "status": "known", "roots": [a, b]}})
        self.assertIn("- Plugins: 2 (0 from Grok Bot, 2 added).", self.access()[1])

    def test_two_folders_with_one_name_are_two_plugins_in_the_audits_map(self):   # replay (3170952: the audit's map had 1)
        self.small()
        self.plugin(".cursor/plugins/dup", "dup")
        self.plugin(".claude/plugins/dup-copy", "dup")
        self.audit_json()
        pl = json.loads(self.map_file())["shared"]["plugins"]
        self.assertEqual((pl["grok"], pl["added"]), (0, 2))

    def test_a_plugin_in_a_platform_folder_is_grok_bots(self):   # guard: Watchtower's own platform roots vouch for it
        self.small()
        self.plugin(".grok/bundled/plugins/p", "p")
        self.audit_json()
        self.assertIn("- Plugins: 1 (1 from Grok Bot, 0 added).", self.access()[1])


# ---------------------------------------------------------------- 3: incomplete collection
class IncompleteIsNeverNone(_Small):
    def test_watchtower_installed_elsewhere_still_looks_in_the_workspace(self):   # replay (3170952 looked in /opt: "found no Slack")
        os.environ["WATCHTOWER_HOME"] = os.path.join(self.tmp, "opt", "watchtower")
        self.small()
        w(os.path.join(self.ws, "project", "mcp.json"), {"mcpServers": {"slack": {"command": "npx"}}})
        self.audit_json()
        self.assertEqual(self.here("Slack MCP server flaw lets attackers read every channel"),
                         "This is about Slack. Here: a tool connection named slack, so every Bot can reach it.")

    def test_an_audit_that_left_out_the_workspace_says_so(self):   # replay (3170952: "0 MCP tools", checked)
        self.small()
        code, out, err = self.run_cmd("audit", "--roots", self.home, "--budget", "0")
        self.assertEqual(code, 0, err)
        self.assertIn("MCP tools not fully checked", json.loads(out)["access"])
        sh = json.loads(self.map_file())["shared"]
        self.assertEqual({k: sh["incomplete"].get(k) for k in ("mcp", "plugins", "hooks", "webhooks")}, dict.fromkeys(("mcp", "plugins", "hooks", "webhooks"), "scope"))

    def test_an_unreadable_tool_list_blocks_found_no(self):   # replay (3170952: "found no Dropbox connector, sign-in or webhook")
        self.mapped()   # ~/projects/tools/mcp.json is "{not json"
        self.assertEqual(self.here("Dropbox token leak lets attackers steal shared files"), CANT.format("Dropbox"))

    def test_an_unreadable_tool_list_is_no_count(self):   # replay (3170952: mcp_tools 0)
        self.small()
        w(os.path.join(self.home, "projects", "tools", "mcp.json"), "{not json")
        self.audit_json()
        sh = json.loads(self.access("--json")[1])["shared"]
        self.assertEqual((sh["mcp_tools"], sh["mcp_files"], sh["mcp_unreadable"]), (None, 1, 1))   # one file is there; its tools unknown

    def crontab(self, code, err):
        real = wt.run
        return mock.patch.object(wt, "run", lambda cmd, *a, **k: (code, "", err) if list(cmd[:2]) == ["crontab", "-l"] else real(cmd, *a, **k))

    def test_a_failed_crontab_is_not_zero_jobs(self):   # replay (3170952: scheduled_jobs 0, checked)
        self.small()
        for code, err in ((124, "timed out after 10s"), (127, "[Errno 2] No such file or directory: 'crontab'"), (1, "crontab: permission denied")):
            with self.crontab(code, err):
                self.audit_json()
                d = json.loads(self.access("--json")[1])
            self.assertIsNone(d["shared"]["scheduled_jobs"], code)
            self.assertEqual(json.loads(self.map_file())["shared"].get("incomplete", {}).get("scheduled"), "failed", code)

    def test_no_crontab_is_zero_jobs(self):   # guard
        self.small()
        with self.crontab(1, "no crontab for box"):
            self.audit_json()
            d = json.loads(self.access("--json")[1])
        self.assertEqual(d["shared"]["scheduled_jobs"], 0)


# ---------------------------------------------------------------- 4: whole counts before any cap
class CountsBeforeCaps(_Small):
    def forty_one(self):
        names = [f"Bot{i:02d}" for i in range(41)]
        self.small(names)
        self.said({n: {"said_at": DAY.isoformat(), "connectors": ["Gmail"] if n == "Bot40" else [], "routines": []} for n in names})
        self.audit_json()

    def test_gmail_on_bot_41_is_still_here(self):   # replay (3170952: "found no Gmail")
        self.forty_one()
        self.assertEqual(self.here("Gmail flaw lets attackers steal session tokens"), "This is about Gmail. Here: 1 Bot said it uses a Gmail connector.")
        self.assertIn("- And 1 more Bot past the 40 listed (1 says Gmail).", self.access()[1])

    def test_the_bots_past_the_list_are_in_the_json(self):   # replay (3170952: no count of them)
        self.forty_one()
        d = json.loads(self.access("--json")[1])
        more = d.get("more", {})
        # round 3 (3): `more` counts every Bot the JSON doesn't list, fit()'s cuts too (was (1, {"Gmail": 1}): only Bot40, while
        # fit() had cut 30 more from the list)
        self.assertLess(len(d["bots"]), 40)
        self.assertEqual((more.get("bots"), more.get("connectors_of_bots_not_listed")), (41 - len(d["bots"]), {"Gmail": 1}))

    def test_every_connector_of_a_bot_is_in_the_json(self):   # replay (3170952: 12 of 22)
        self.small()
        self.said({"Golf": {"said_at": DAY.isoformat(), "connectors": list(VOCAB_LABELS), "routines": []}})
        self.audit_json()
        golf = json.loads(self.access("--json")[1])["bots"][0]
        self.assertEqual((golf["connectors"], golf["other_connectors"]), (list(VOCAB_LABELS), 0))

    def test_routine_61_counts(self):   # replay (3170952: 60 routines, none sending)
        self.small()
        quiet = {"trigger": "schedule", "sends_or_posts": False, "asks_first": True}
        self.rollcall({"name": "Golf", "routines": [quiet] * 60 + [{"trigger": "schedule", "sends_or_posts": True, "asks_first": False}]})
        self.audit_json()
        # round 3 (2): the reply has no connectors, so Golf didn't say (was: "- Golf: no connectors; 61 routines, ...")
        self.assertIn("- Golf: didn't say which connectors it uses; 61 routines, 1 sends without asking you.", self.access()[1])
        golf = json.loads(self.access("--json")[1])["bots"][0]
        self.assertEqual((golf["routines"], golf["routines_send_without_asking"]), (61, 1))

    def test_a_cli_sign_in_past_the_twelve_listed_still_reaches(self):   # replay (3170952: only the 12 listed were matched)
        m = wt.access_record({"shared": {"cli_logins": [{"tool": f"tool {i}", "file": f"~/f{i}"} for i in range(12)] + [{"tool": "GitHub CLI login", "file": "~/g"}],
                                         "cli_count": 13, "platform_logins": []}})
        e_ = next(e for e in wt.access_vocab() if e["id"] == "github")
        self.assertTrue(wt.access_touch(e_, m)["cli"])


# ---------------------------------------------------------------- 5: every product in one name
class EveryProductInOneName(_Small):
    def test_gmail_and_slack_is_both(self):   # replay (3170952: Gmail only)
        self.assertEqual(wt.access_connectors(["Gmail and Slack"]), (["Gmail", "Slack"], 0))
        self.assertEqual(wt.access_connectors(["Gmail and Acme CRM"]), (["Gmail"], 1))     # what is left is one other

    def test_a_label_written_out_is_one_product(self):   # replay (3170952 kept one product a name): the longer match wins
        self.assertEqual(wt.access_connectors(["Microsoft Teams", "MS Teams"]), (["Microsoft Teams"], 0))
        self.assertEqual(wt.access_connectors(["Teams and Outlook", "Google Drive, Notion"]), (["Google Drive", "Microsoft Teams", "Microsoft 365", "Notion"], 0))

    def test_the_brief_sees_slack_in_gmail_and_slack(self):   # replay (3170952: "found no Slack")
        self.small()
        self.rollcall({"name": "Golf", "connectors": "Gmail and Slack"})
        self.audit_json()
        self.assertEqual(self.here("Slack MCP server flaw lets attackers read every channel"),
                         "This is about Slack. Here: 1 Bot said it uses a Slack connector (Golf).")


# ---------------------------------------------------------------- 7: no link anywhere on the way
class NoLinkFromTheRootDown(_Small):
    def test_a_proc_root_alias_is_refused(self):   # replay (3170952 opened the README through both)
        readme = os.path.join(os.path.realpath(ROOT), "README.md")
        for p in ("/proc/self/root" + readme, f"/proc/{os.getpid()}/root" + readme):
            fd = wt._ax_open(p, [os.path.dirname(p)])
            if fd is not None:
                os.close(fd)
            self.assertIsNone(fd, p)

    def test_a_linked_base_is_refused(self):   # replay (3170952 never checked the base or its ancestors)
        real = w(os.path.join(self.tmp, "real", "box", "x.json"), {"a": 1})
        os.symlink(os.path.join(self.tmp, "real"), os.path.join(self.tmp, "linked"))
        p = os.path.join(self.tmp, "linked", "box", "x.json")
        self.assertEqual(wt._ax_json_file(real), {"a": 1})
        self.assertIsNone(wt._ax_json_file(p, [os.path.join(self.tmp, "linked", "box")]))

    def test_a_folder_swapped_for_a_link_mid_open_is_not_followed(self):   # replay (3170952 opened the link's target, then refused it)
        d = os.path.dirname(w(os.path.join(self.tmp, "box", "agents", "a", "profile.json"), {"name": "Real"}))
        secret = os.path.dirname(w(os.path.join(self.tmp, "secret", "profile.json"), {"name": "FAKEsecretNAME"}))
        real_os_open, opened, swapped = os.open, [], []

        def swap_then_open(p, *a, **k):
            if os.path.basename(os.fspath(p)) == "profile.json" and not swapped:
                swapped.append(1)
                os.rename(d, d + ".old")
                os.symlink(secret, d)
            fd = real_os_open(p, *a, **k)
            opened.append(os.readlink(f"/proc/self/fd/{fd}"))
            return fd
        with mock.patch("os.open", swap_then_open):
            got = wt._ax_json_file(os.path.join(d, "profile.json"), [self.tmp])
        self.assertTrue(swapped)
        self.assertNotIn(os.path.join(os.path.realpath(secret), "profile.json"), opened)
        self.assertNotEqual(got, {"name": "FAKEsecretNAME"})

    def test_a_linked_profile_is_said(self):   # replay (3170952 left the Bot out without a word)
        self.small(())
        target = w(os.path.join(self.tmp, "elsewhere", "profile.json"), {"name": "Kilo"})
        os.makedirs(os.path.join(self.home, "agent-data", "agents", AGENT))
        os.symlink(target, os.path.join(self.home, "agent-data", "agents", AGENT, "profile.json"))
        self.rollcall({"name": "Golf"})
        self.audit_json()
        out = self.access()[1]
        self.assertIn("- ISR Bot couldn't read 1 Bot profile (a link, or not plain JSON), so a Bot may be missing from this list.", out)
        self.assertNotIn("Kilo", out)

    def test_the_fallback_map_is_read_the_same_way(self):   # replay (3170952 read it through a linked state folder)
        self.small()
        self.audit_json()
        st = wt.state_path()
        shutil.move(st, st + ".real")
        os.symlink(st + ".real", st)
        self.assertIsNone(wt.last_access_map())


# ---------------------------------------------------------------- the last audit's lines say so
class LastAuditLinesSaySo(_Small):
    def test_the_report_marks_the_webhook_as_the_last_audits(self):   # replay (3170952: no date, no "last audit")
        self.mapped()
        sec = self.section(self.report()[0])
        self.assertIn(f"\n- Chat webhooks (from the last audit, {TODAY}): a Slack webhook in \"digest\". Anyone who has that link can post to that channel.\n", sec)

    def test_key_files_from_the_last_audit_say_so(self):   # replay
        m = wt.access_record({"shared": {"key_files": 2, "cached": ["key_files"], "cached_at": "2026-10-18", "from": "now"}})
        self.assertIn("Files with live-looking keys (from the last audit, Oct 18): 2. Every Bot can read them (see the findings).", wt.access_shared_lines(m))

    def test_the_audits_own_lines_need_no_mark(self):   # guard: the audit found them itself
        m = wt.access_record(self.mapped())
        self.assertIn("Chat webhooks: a Slack webhook in \"digest\". Anyone who has that link can post to that channel.", wt.access_shared_lines(m))


if __name__ == "__main__":
    unittest.main()
