"""Batch 5 PR B, Codex round 1: the access map's seven findings, replayed.

1 a roll-call connector keeps no text but a vocabulary label (a key, "password=...", a sentence about a client are counted, never
  kept), and secrets are masked before rollcall_findings.json is written, earlier answers included;
2 nothing in state/access_map.json (the Bot can write it) can understate what Bots reach: each command builds its map from this
  computer, and the saved map is only a fallback whose every shared line is "couldn't check";
3 a list cut for display keeps its whole count, and what it reaches is worked out before the cut;
5 the map follows no link to a source, the file's own or a folder's on the way;
6 with no map the brief's JSON is byte for byte what it was;
7 the cookie seed's "sensitive: none" is no signed-in site.
(4, the golden expectations, is in test_golden_expect.)

Tests marked "replay" fail on 0a72c20 on their assertion (measured with 0a72c20's watchtower/ sources, this file in place). Every
planted value is FAKE…; the box is a temp folder, never this computer's own."""
import html, json, os, re, sys, unittest
from unittest import mock
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import wt
from test_batch5_access_map import _Access, SETTINGS, cookie_jar, w
from test_batch5_brief_access import _Brief

TOKEN = "ghp_FAKE" + "A1b2C3d4" * 4   # a GitHub token's shape (40 characters), not a real one
PRIVATE = ("hunter2", "FAKEA1b2", "Dana Ortiz", "cancer")


def no_private(test, name, text):
    for p in PRIVATE:
        test.assertNotIn(p, text, f"{p!r} in {name}")


class _Outputs(_Brief):
    def outputs(self):
        """Every place the map reaches: the state files, `access` and `access --json`, the report section, the dashboard, the brief."""
        md, page = self.report()
        r, out, brief_page, saved = self.brief([("Gmail flaw lets attackers steal session tokens", "")])
        return {"rollcall_findings.json": open(wt.state_path("rollcall_findings.json")).read(), "access_map.json": self.map_file(),
                "access": self.access()[1], "access --json": self.access("--json")[1], "report": md, "dashboard": page,
                "brief JSON": out, "brief page": brief_page, "last_brief.json": saved}


# ---------------------------------------------------------------- 1: connector text
class ConnectorsKeepNoText(_Outputs):
    REPLY = {"name": "Golf", "connectors": ["Gmail", TOKEN, "password=hunter2", "Client Dana Ortiz has cancer"],
             "memories": {"count": 1, "loosen_permissions": 0, "from_outside_content": 0}}

    def test_a_key_a_password_and_a_sentence_reach_nothing(self):   # replay (0a72c20 kept all three in access.connectors)
        self.build(rollcall=False)
        w(self.wt_home("exports", "roster.json"), [{"name": "Golf", "kind": "bot"}])
        self.rollcall(self.REPLY)
        golf = json.load(open(wt.state_path("rollcall_findings.json")))["access"]["Golf"]
        self.audit_json()
        outs = self.outputs()
        for name, text in outs.items():
            no_private(self, name, text)
        self.assertEqual((golf["connectors"], golf["connectors_other"]), (["Gmail"], 3))
        self.assertIn("- Golf: Gmail and 3 other connectors; 1 memory.", outs["access"])

    def test_an_earlier_answer_carried_over_is_reduced_again(self):   # replay (0a72c20 carried the planted answer over as it was)
        self.build(rollcall=False)
        rnd = wt.open_rollcall_round()
        wt.save_json(wt.state_path("rollcall_findings.json"), {
            "at": wt.now(), "round": rnd, "masked": wt.VERSION, "shape_only": True, "bots": ["Hotel"],
            "findings": [dict(wt.finding("ISR-R013", "t", "medium", ["ASI02"], "rollcall:Hotel", f"key {TOKEN} password=hunter2", "fix"), bot="Hotel")],
            "access": {"Hotel": {"said_at": wt.now()[:10], "connectors": ["Slack", "password=hunter2", "Client Dana Ortiz has cancer"], "routines": []}}})
        self.rollcall(dict(self.REPLY, connectors=["Notion"]))
        rc = open(wt.state_path("rollcall_findings.json")).read()
        no_private(self, "rollcall_findings.json", rc)
        self.assertEqual(json.loads(rc)["access"]["Hotel"]["connectors"], ["Slack"])
        self.assertEqual(json.loads(rc)["access"]["Hotel"]["connectors_other"], 2)

    def test_a_bot_name_or_routine_name_with_a_key_is_masked(self):   # guard: the roll-call's own fields, before they are written
        self.build(rollcall=False)
        self.rollcall({"name": "Ida", "routines": [{"name": f"push {TOKEN}", "trigger": "schedule", "sends_or_posts": True, "asks_first": False}]})
        rc = open(wt.state_path("rollcall_findings.json")).read()
        self.assertIn("rollcall:Ida:routine:push ghp_FA", rc)
        self.assertNotIn(TOKEN, rc)

    def test_none_is_no_connector(self):   # guard
        self.assertEqual(wt.access_connectors(["none", " ", "-", "N/A", "no connectors yet", "Google Calendar", "gmail"]), (["Gmail", "Google Calendar"], 0))


# ---------------------------------------------------------------- 2: a planted map
PLANTED = {"v": 1, "at": None, "shared": {"browser": {"sites": 0, "sensitive": [], "products": []}, "cli_logins": [], "platform_logins": [],
                                         "settings": "found", "auto_allow": [], "runs_programs": "never", "auto_review": True,
                                         "mcp": {"files": 0, "tools": [], "unreadable": 0, "unreadable_files": []},
                                         "plugins": {"grok": 0, "added": 0, "names": []}, "webhooks": [], "scheduled": {"crontab": 0, "systemd": 0},
                                         "hooks": {"platform": 0, "other": 0}, "key_files": 0},
           "bots": [], "bots_more": 0, "bots_no_detail": [], "bots_silent": [], "rollcall": {"at": None, "fresh": False}, "unknown": []}
NEGATIVE = re.compile(r"none found|Never allow|not allowed|no Allow-automatically|not signed in to any site|Plugins: none|found no shared browser")
PLANTED_SAYS = re.compile(r"none found|Never allow|not allowed|no Allow-automatically|not signed in to any site|found no shared browser")


class APlantedMapUnderstatesNothing(_Outputs):
    def plant(self, m=None):
        m = dict(m or PLANTED, at=wt.now())
        wt.save_json(wt.state_path("access_map.json"), m)

    def card(self, page):
        i = page.find("Who can reach what</h2>")
        return html.unescape(page[i:page.index("</div>\n", i)]) if i >= 0 else ""

    def test_each_command_looks_at_this_computer(self):   # replay (0a72c20 showed the planted map: "none found", "Never allow")
        self.build()
        self.audit_json()
        self.plant()
        md, page = self.report()
        out = self.access()[1]
        for text in (out, self.section(md), self.card(page)):
            self.assertIn("Running programs: Bots can run programs without asking you (Execution on Local Computer: Always allow).", text)
            self.assertIn("Tool connections (MCP): 2 tools in 2 files: github and notion (mcp.notion.com).", text)
            self.assertIn("Command-line sign-ins: OpenAI Codex CLI login.", text)
            self.assertIn("Browser: signed in to 2 sites, including github.com and mail.google.com.", text)
            self.assertNotRegex(text, PLANTED_SAYS)   # (no plugins here really: "Plugins: none." is this computer's own answer)
        d = json.loads(self.access("--json")[1])
        self.assertEqual((d["shared"]["runs_programs"], d["shared"]["mcp_files"]), ("without asking", 2))
        r = self.brief([("Gmail flaw lets attackers steal session tokens", "")])[0]
        self.assertIn("the shared browser is signed in to mail.google.com", r["top_stories"][0]["here"])

    def test_when_the_look_fails_the_saved_map_says_nothing_is_none(self):   # replay (0a72c20: "none found", "Never allow", "not found")
        self.build()
        self.audit_json()
        self.plant()
        boom = mock.Mock(side_effect=OSError("FAKE"))
        with mock.patch.object(wt, "access_map_now", boom, create=True):
            out, md_page = self.access()[1], self.report()
            r = self.brief([("Dropbox token leak lets attackers steal shared files", "")])[0]
        for text in (out, self.section(md_page[0]), self.card(md_page[1])):
            self.assertNotRegex(text, NEGATIVE)
            self.assertIn("Tool connections (MCP): ISR Bot couldn't check this time.", text)
            self.assertIn("Command-line sign-ins: ISR Bot couldn't check this time.", text)
            self.assertIn("Allowed without asking: ISR Bot couldn't check this time.", text)
            self.assertNotIn("Running programs", text)
        self.assertEqual(r["top_stories"][0]["here"],
                         "This is about Dropbox. ISR Bot couldn't check this time whether anything on this computer reaches Dropbox.")
        self.assertIn("From the audit at", out)

    def test_missing_fields_are_unknown(self):   # replay (0a72c20 filled what was missing with 0 and "missing": "none found")
        self.build()
        self.audit_json()
        self.plant({"v": 1, "shared": {"settings": "found", "runs_programs": "never"}, "bots": []})
        with mock.patch.object(wt, "access_map_now", mock.Mock(side_effect=OSError("FAKE")), create=True):
            out, js = self.access()[1], self.access("--json")[1]
        self.assertNotRegex(out, NEGATIVE)
        self.assertNotIn("Running programs", out)
        sh = json.loads(js)["shared"]
        for k in ("mcp_files", "mcp_tools", "plugins_added", "key_files", "hooks", "scheduled_jobs", "browser_sites", "settings", "runs_programs"):
            self.assertIsNone(sh.get(k), k)

    def test_the_saved_map_is_the_audits_own(self):   # guard: what an audit saves is what it checked
        self.build()
        self.audit_json()
        m = json.loads(self.map_file())
        self.assertEqual((m["shared"]["from"], m["shared"]["checked"]), ("audit", list(wt.ACCESS_SHARED)))
        self.assertEqual(wt.last_access_map()["shared"]["checked"], [])


# ---------------------------------------------------------------- 3: padding before the cap
class PaddingHidesNothing(_Brief):
    def test_forty_tools_before_slack(self):   # replay (0a72c20 cut Slack off at tools[:40]; the brief said Slack wasn't here)
        servers = {f"tool{i:02d}": {"command": "true"} for i in range(40)}
        servers["slack"] = {"command": "npx"}
        w(os.path.join(self.home, ".cursor", "mcp.json"), {"mcpServers": servers})
        w(os.path.join(self.home, "agent-data", "settings.json"), SETTINGS)
        self.audit_json()
        r = self.brief([("Slack MCP server flaw lets attackers read every channel", "")])[0]
        self.assertEqual(r["top_stories"][0]["here"], "This is about Slack. Here: a Slack tool connection, so every Bot can reach it.")
        mcp = json.loads(self.map_file())["shared"]["mcp"]
        self.assertEqual((mcp.get("count"), len(mcp["tools"])), (41, 40))
        self.assertIn("slack", mcp.get("products", []))
        self.assertIn("Tool connections (MCP): 41 tools in 1 file: tool00, tool01, tool02, tool03, tool04, tool05, tool06, tool07 and 33 more.",
                      self.access()[1])

    def test_a_rule_past_twenty_still_counts(self):   # replay (0a72c20 kept 20 rules and dropped the 21st's area)
        rules = [f"Run the test suite in ~/projects/app{i:02d}" for i in range(20)] + ["Send email to anyone on the team without asking"]
        w(os.path.join(self.home, "agent-data", "settings.json"), dict(SETTINGS, autoReviewInstructions={"allowAutomatically": rules}))
        self.audit_json()
        out = self.access()[1]
        self.assertIn("20 rules let Bots run commands without asking you", out)
        self.assertIn("1 rule lets Bots send things out without asking you", out)

    def test_every_capped_list_keeps_its_count(self):   # replay (0a72c20 had no counts beside its lists)
        m = wt.access_record({"shared": {
            "browser": {"sites": 3, "sensitive": [f"s{i}.github.com" for i in range(20)], "products": []},
            "webhooks": [{"service": "Slack", "skill": f"k{i}"} for i in range(15)] + [{"service": "Discord", "skill": "last"}],
            "cli_logins": [{"tool": f"tool {i}", "file": f"~/f{i}"} for i in range(14)]},
            "bots_silent": [f"Bot{i:02d}" for i in range(45)], "bots": [{"name": f"B{i:02d}"} for i in range(43)]})
        sh = m["shared"]
        self.assertEqual((sh["browser"]["sites"], sh["browser"].get("sensitive_count")), (20, 20))
        self.assertEqual((len(sh["webhooks"]), sh.get("webhook_count"), sh.get("webhook_services")), (12, 16, ["Slack", "Discord"]))
        self.assertEqual((len(sh["cli_logins"]), sh.get("cli_count")), (12, 14))
        self.assertEqual((len(m["bots_silent"]), m["rollcall"].get("silent_more"), len(m["bots"]), m["bots_more"]), (40, 5, 40, 3))
        e_ = next(e for e in wt.access_vocab() if e["id"] == "discord")
        self.assertEqual(wt.access_touch(e_, m)["webhook"], True)   # past the twelve listed, still reached


# ---------------------------------------------------------------- 5: links
class NoLinkIsFollowed(_Access):
    def test_a_linked_source_is_never_opened(self):   # replay (0a72c20 opened ~/.cursor/mcp.json's target, a FAKE credential file)
        self.build(rollcall=False)
        creds = w(os.path.join(self.home, ".aws", "credentials.json"), {"mcpServers": {"FAKEcredSERVER": {"command": "x"}}, "key": "FAKEsecretVALUE"})
        os.remove(os.path.join(self.home, ".cursor", "mcp.json"))
        os.symlink(creds, os.path.join(self.home, ".cursor", "mcp.json"))
        hidden = w(os.path.join(self.tmp, "outside", "notes", "mcp.json"), {"mcpServers": {"FAKEnoteSERVER": {"command": "x"}}})   # no root holds it
        os.makedirs(os.path.join(self.home, "projects", "p"), exist_ok=True)
        os.symlink(os.path.dirname(hidden), os.path.join(self.home, "projects", "p", "linked"))   # a folder on the way is the link
        os.symlink(creds, os.path.join(self.home, "agent-data", "agents", "FAKE"))   # not an agent id: never listed anyway
        self.audit_json()
        snap = self.snap()
        meta = {"access_sources": {"roots": self.roots, "persistence": {}, "plugin_files": [],
                                   "mcp": [os.path.join(self.home, ".cursor", "mcp.json"), os.path.join(self.home, "projects", "p", "linked", "mcp.json")]}}
        opened = []   # what was really opened: each open file's own path, read back from /proc (a link's target, if one was)
        real_open, real_os_open = open, os.open

        def rec_open(p, *a, **k):
            f = real_open(p, *a, **k)
            opened.append(os.readlink(f"/proc/self/fd/{f.fileno()}"))
            return f

        def rec_os_open(p, *a, **k):
            fd = real_os_open(p, *a, **k)
            opened.append(os.readlink(f"/proc/self/fd/{fd}"))
            return fd
        with mock.patch("builtins.open", rec_open), mock.patch("os.open", rec_os_open):
            m = wt.build_access_map(snap, meta)
            code, out, _ = self.run_cmd("access")
        self.assertIn(os.path.realpath(self.wt_home("exports", "roster.json")), opened)   # the recorder sees the map's reads
        self.assertNotIn(os.path.realpath(creds), opened)
        self.assertNotIn(os.path.realpath(hidden), opened)
        self.assertEqual(m["shared"]["mcp"]["unreadable_files"], ["~/.cursor/mcp.json", "~/projects/p/linked/mcp.json"])
        self.assertNotIn("FAKE", json.dumps(m) + out)

    def test_a_linked_settings_file_is_unreadable_not_missing(self):   # guard
        self.build(settings=False, rollcall=False)
        real = w(os.path.join(self.home, "elsewhere.json"), SETTINGS)
        os.symlink(real, os.path.join(self.home, "agent-data", "settings.json"))
        rules, settings, status = wt._ax_auto_allow(wt._ax_bases([self.home]))
        self.assertEqual((rules, settings, status), (None, None, "unreadable"))


# ---------------------------------------------------------------- 6: no map, the brief as it was
class NoMapBriefAsBefore(_Brief):
    def test_five_long_titles_fit_as_before(self):   # replay (0a72c20 added `here` with no map: only four fit in 6 KB)
        items = [(f"Gmail agent flaw number {i} lets attackers steal session tokens: " + "word " * 165, "") for i in range(5)]
        self.assertTrue(all(850 <= len(t) <= 1000 for t, _ in items))
        r, out, page, saved = self.brief(items)
        self.assertIsNone(wt.load_access_map())
        b = json.loads(saved)
        snap = wt.load_json(wt.state_path("last_findings.json"), None)
        top, _ = wt.split_stories(b)
        old = wt.fit({"brief": b["path"], "threat_level": wt.threat_level(b, snap, top)[1], "score_line": wt.score_line(snap),   # 77dedd1's cmd_brief
                      "top_stories": [{"id": s["id"], "tier": s["tier"], "category": s["category_label"], "title": s["title"],
                                       "cves": s.get("cves", []), "source": s["source"]} for s in top],
                      "kev_relevant": [f"{k['cve']} {k['vendor']} {k['product']}" for k in b["kev"] if k["relevant"]][:6],
                      "updates": b["updates"], "doc_changes": [p["name"] for p in b["pages"]],
                      "sources_down": [s["name"] for s in b["sources"] if s["status"] != "ok"],
                      "next_step": "Required: write notes.json with 'means' and 'do' for each top_stories id (see the watchtower-brief skill, step 2), "
                                   "then run wt.py brief --notes <file>. Until then the stories show generic text."}, limit=6000)
        self.assertEqual(len(json.loads(old)["top_stories"]), 5)
        self.assertEqual(out, old + "\n")


# ---------------------------------------------------------------- 7: "sensitive: none"
class SensitiveNone(_Access):
    def test_none_is_no_site(self):   # replay (0a72c20 counted "none" as a signed-in site)
        seed = wt.finding("ISR-S004", "Shared browser cookies visible to every Bot", "medium", ["ASI03"], os.path.join(self.home, "sand-data", "cookies.json"),
                          "12 domains; sensitive: none", "fix")
        m = wt.build_access_map({"findings": [seed]}, {"access_sources": {"roots": self.roots}, "persistence": {}})
        self.assertEqual(m["shared"]["browser"]["sites"], 0)
        self.assertIn("Browser: not signed in to any site ISR Bot can see.", wt.access_shared_lines(m))


if __name__ == "__main__":
    unittest.main()
