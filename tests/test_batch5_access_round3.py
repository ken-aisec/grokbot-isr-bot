"""Batch 5 PR B, Codex round 3: "none" only from a field looked at whole, fresh, this run; anything left out is "couldn't check".

1 a folder the scan couldn't list, left out (a link to a folder, one too deep, a cache or package folder) leaves the fields it
  feeds incomplete, and every "none" line needs the whole field (the unreadable-folder case with no unreadable file too);
2 a connector name too long to keep still gives its products; every connector, Bot and routine counts, however many; an empty
  answer, or one without connectors, is "didn't say", never "no connectors";
3 `access --json` works out the Bots it doesn't list, and their connectors, after fitting, and counts each product whole;
4 a golden must_see entry is met in each of its scenarios, on its own;
5 the system cron folder's jobs are scheduled jobs too;
6 the unreadable-profile line is shown without a recent roll-call too.

Tests marked "replay" fail on 2e84aa8 on their assertion (measured with 2e84aa8's watchtower/ sources and tests/golden_split.py,
this file in place). Every planted value is FAKE…; the box is a temp folder, never this computer's own."""
import datetime as dt, json, os, re, sys, unittest
from unittest import mock
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import ROOT, wt
from test_batch5_access_map import AGENT, w
from test_batch5_access_round2 import CANT, DAY, _Small
import golden_split as gs  # noqa: E402  (the module, never its TestCase)

SLACK_MCP = {"mcpServers": {"slack": {"command": "npx"}}}
SLACK_STORY = "Slack MCP server flaw lets attackers read every channel"
GMAIL_STORY = "Gmail flaw lets attackers steal session tokens"
FOUND_NO = re.compile(r"found no|none found|no connectors|Plugins: none")


class _Round3(_Small):
    def answered(self, **golf):
        """Golf's roll-call answer today, kept as a roll-call keeps it (connectors [] unless given)."""
        self.said({"Golf": dict({"said_at": DAY.isoformat(), "connectors": [], "routines": []}, **golf)})

    def shared(self):
        return [x for x in self.access()[1].splitlines() if x.startswith("- Tool connections (MCP)")]


# ---------------------------------------------------------------- 1: what the scan leaves out
class TheScanSaysWhatItLeftOut(_Round3):
    def test_a_folder_that_cant_be_listed_is_not_none_found(self):   # replay (2e84aa8: "Tool connections (MCP): none found.")
        self.small()
        locked = os.path.join(self.home, "projects", "locked")
        w(os.path.join(locked, "mcp.json"), SLACK_MCP)
        os.chmod(locked, 0)   # (the box's tearDown opens it up again before removing it)
        self.audit_json()
        self.assertEqual(self.shared(), ["- Tool connections (MCP): ISR Bot couldn't check all of it this time (something there couldn't be read)."])
        self.assertNotIn("- Tool connections (MCP): none found.", self.section(self.report()[0]))
        self.assertEqual(json.loads(self.map_file())["shared"]["incomplete"].get("mcp"), "unreadable")

    def test_the_unreadable_reason_alone_never_renders_none(self):   # replay (2e84aa8: the renderer wanted an unreadable file count)
        m = wt.access_record({"shared": {"checked": ["mcp"], "incomplete": {"mcp": "unreadable"},
                                         "mcp": {"files": 0, "count": 0, "tools": [], "unreadable": 0, "unreadable_files": []}}})
        lines = [x for x in wt.access_shared_lines(m) if x.startswith("Tool connections")]
        self.assertEqual(lines, ["Tool connections (MCP): ISR Bot couldn't check all of it this time (something there couldn't be read)."])

    def test_a_tool_list_below_the_depth_limit_is_not_found_no(self):   # replay (2e84aa8: "found no Slack ... here")
        self.small()
        self.answered()
        w(os.path.join(self.home, *"abcdefghi", "mcp.json"), SLACK_MCP)   # nine folders down: past walk's max_depth of 8
        self.audit_json()
        self.assertEqual(self.here(SLACK_STORY), CANT.format("Slack"))
        self.assertEqual(json.loads(self.map_file())["shared"]["incomplete"].get("mcp"), "skipped")
        self.assertEqual(self.shared(), ["- Tool connections (MCP): ISR Bot couldn't check all of it this time (the scan leaves some folders "
                                         "out: links to folders, caches and package folders, and folders too deep)."])

    def test_a_linked_folder_is_not_found_no(self):   # replay (2e84aa8: "found no Slack ... here")
        self.small()
        self.answered()
        w(os.path.join(self.tmp, "elsewhere", "tools", "mcp.json"), SLACK_MCP)
        os.symlink(os.path.join(self.tmp, "elsewhere", "tools"), os.path.join(self.home, "tools"))
        self.audit_json()
        self.assertEqual(self.here(SLACK_STORY), CANT.format("Slack"))
        self.assertEqual(json.loads(self.map_file())["shared"]["incomplete"].get("mcp"), "skipped")

    def test_a_folder_the_scan_never_enters_is_not_found_no(self):   # replay (2e84aa8: "found no Slack ... here")
        self.small()
        self.answered()
        w(os.path.join(self.home, "projects", "app", "node_modules", "slack-tools", "mcp.json"), SLACK_MCP)
        self.audit_json()
        self.assertEqual(self.here(SLACK_STORY), CANT.format("Slack"))
        self.assertNotRegex("\n".join(self.shared()), FOUND_NO)

    def test_the_browser_profile_is_left_out_so_not_found_no(self):   # replay (2e84aa8: "found no Dropbox connector, sign-in or webhook")
        self.mapped()   # test_batch5_brief_access's box: its ~/chrome-profile is a folder the scan never enters
        os.remove(os.path.join(self.home, "projects", "tools", "mcp.json"))
        self.assertEqual(self.here("Dropbox token leak lets attackers steal shared files"), CANT.format("Dropbox"))

    def test_a_box_with_nothing_left_out_still_says_none(self):   # guard: a whole look still answers
        self.small()
        self.answered()
        w(os.path.join(self.home, *"abcdefg", "notes.txt"), "eight folders down is still scanned")
        self.audit_json()
        self.assertEqual(self.shared(), ["- Tool connections (MCP): none found."])
        self.assertTrue(self.here(SLACK_STORY).startswith("This is about Slack. ISR Bot found no Slack connector"))

    def test_the_walk_counts_what_it_leaves_out(self):   # guard: and nothing else
        w(os.path.join(self.home, "a", "f.txt"), "x")
        w(os.path.join(self.home, ".cache", "f.txt"), "x")
        os.symlink(os.path.join(self.home, "a"), os.path.join(self.home, "link"))
        errors, skipped = [], []
        files = sorted(wt.walk([self.home], errors=errors, skipped=skipped))
        self.assertEqual(files, [os.path.join(self.home, "a", "f.txt")])
        self.assertEqual((errors, sorted(skipped)), ([], [os.path.join(self.home, ".cache"), os.path.join(self.home, "link")]))


# ---------------------------------------------------------------- 2: connectors, every one, and "didn't say"
class EveryConnectorAnswer(_Round3):
    def test_a_name_too_long_to_keep_is_still_gmail(self):   # replay (2e84aa8: "Golf: no connectors", "found no Gmail")
        self.small()
        self.rollcall({"name": "Golf", "connectors": ["Gmail account for the operations department"]})
        self.audit_json()
        out = self.access()[1]
        self.assertIn("- Golf: Gmail and 1 other connectors.", out)
        self.assertNotIn("operations department", out + self.map_file() + open(wt.state_path("rollcall_findings.json")).read())
        self.assertEqual(self.here(GMAIL_STORY), "This is about Gmail. Here: 1 Bot said it uses a Gmail connector (Golf).")

    def test_connector_1001_counts(self):   # replay (2e84aa8 read connectors 41 to 1000 only)
        self.small()
        self.rollcall({"name": "Golf", "connectors": [f"Acme {i}" for i in range(1000)] + ["Gmail"]})
        self.audit_json()
        golf = json.loads(self.map_file())["bots"][0]
        self.assertEqual((golf["connectors"], golf["connectors_other"]), (["Gmail"], 1000))
        self.assertEqual(self.here(GMAIL_STORY), "This is about Gmail. Here: 1 Bot said it uses a Gmail connector (Golf).")

    def test_bot_10001_counts(self):   # replay (2e84aa8 read 10000 Bots: "found no Gmail")
        names = [f"B{i:05d}" for i in range(10001)]
        self.small(())
        self.said({n: {"said_at": DAY.isoformat(), "connectors": ["Gmail"] if n == names[-1] else [], "routines": []} for n in names})
        self.audit_json()
        self.assertEqual(self.here(GMAIL_STORY), "This is about Gmail. Here: 1 Bot said it uses a Gmail connector.")
        self.assertIn("- And 9961 more Bots past the 40 listed (1 says Gmail).", self.access()[1])

    def test_routine_10001_counts(self):   # replay (2e84aa8: 10000 routines, none sending)
        self.small()
        self.rollcall({"name": "Golf", "connectors": [], "routines": [{}] * 10000 + [{"sends_or_posts": True}]})
        self.audit_json()
        self.assertIn("- Golf: no connectors; 10001 routines, 1 sends without asking you.", self.access()[1])

    def test_a_kept_routine_10001_counts(self):   # replay (2e84aa8: _ax_said read 10000)
        self.small()
        self.answered(routines=[{"trigger": "schedule"}] * 10000 + [{"trigger": "schedule", "sends_without_asking": True}])
        self.audit_json()
        golf = json.loads(self.access("--json")[1])["bots"][0]
        self.assertEqual((golf["routines"], golf["routines_send_without_asking"]), (10001, 1))

    def test_an_empty_answer_is_didnt_say(self):   # replay (2e84aa8: "Golf: no connectors.", "found no Gmail")
        self.small()
        self.said({"Golf": {}})
        self.audit_json()
        out = self.access()[1]
        self.assertIn("- Golf: didn't say which connectors it uses.", out)
        self.assertNotIn("no connectors", out)
        self.assertEqual(self.here(GMAIL_STORY), CANT.format("Gmail"))

    def test_an_answer_without_connectors_is_didnt_say(self):   # replay (2e84aa8: "Golf: no connectors; 1 memory.")
        self.small()
        self.rollcall({"name": "Golf", "memories": {"count": 1}})
        self.audit_json()
        self.assertIn("- Golf: didn't say which connectors it uses; 1 memory.", self.access()[1])
        self.assertEqual(self.here(GMAIL_STORY), CANT.format("Gmail"))

    def test_an_answer_that_isnt_a_name_is_not_none(self):   # replay (2e84aa8: "Golf: no connectors.")
        self.small()
        self.rollcall({"name": "Golf", "connectors": [{"name": "Gmail"}]})
        self.audit_json()
        self.assertIn("- Golf: ISR Bot couldn't read which connectors it uses.", self.access()[1])
        self.assertEqual(self.here(GMAIL_STORY), CANT.format("Gmail"))

    def test_an_answer_that_isnt_an_object_is_didnt_say(self):   # replay (2e84aa8 left Golf out: "found no Gmail")
        self.small()
        self.said({"Golf": "FAKE planted text"})
        self.audit_json()
        self.assertIn("- Golf: didn't say which connectors it uses.", self.access()[1])
        self.assertEqual(self.here(GMAIL_STORY), CANT.format("Gmail"))

    def test_a_bot_past_the_list_that_didnt_say_is_counted(self):   # replay (2e84aa8: "found no Gmail")
        names = [f"Bot{i:02d}" for i in range(41)]
        self.small(names)
        self.said({n: {"said_at": DAY.isoformat(), "connectors": [], "routines": []} if n != "Bot40" else {} for n in names})
        self.audit_json()
        self.assertIn("- ISR Bot doesn't know every connector of 1 Bot not listed here (an answer without them, or one it couldn't read).",
                      self.access()[1])
        self.assertEqual(self.here(GMAIL_STORY), CANT.format("Gmail"))

    def test_none_said_is_still_no_connectors(self):   # guard
        self.small()
        self.rollcall({"name": "Golf", "connectors": ["none"]})
        self.audit_json()
        self.assertIn("- Golf: no connectors.", self.access()[1])
        self.assertTrue(self.here(GMAIL_STORY).startswith("This is about Gmail. ISR Bot found no Gmail"))


# ---------------------------------------------------------------- 3: the JSON's counts after fitting
class TheJsonCountsWhatItLeavesOut(_Round3):
    def test_gmail_on_the_40th_bot_survives_fitting(self):   # replay (2e84aa8: more.bots 1, Gmail in neither the list nor more)
        names = [f"Bot{i:02d}" for i in range(41)]
        self.small(names)
        self.said({n: {"said_at": DAY.isoformat(), "connectors": ["Gmail"] if n == "Bot39" else ["Slack"] if n == "Bot40" else [], "routines": []}
                   for n in names})
        self.audit_json()
        out = self.access("--json")[1]
        self.assertLessEqual(len(out.encode()), 4096)
        d = json.loads(out)
        listed = [b["name"] for b in d["bots"]]
        self.assertNotIn("Bot39", listed)   # fit() cut it
        self.assertEqual(d["more"]["bots"], 41 - len(listed))
        self.assertEqual(d["truncated"]["bots"], 40 - len(listed))
        self.assertEqual(d["more"]["connectors_of_bots_not_listed"], {"Gmail": 1, "Slack": 1})
        self.assertEqual(d.get("bots_per_connector"), {"Gmail": 1, "Slack": 1})
        self.assertEqual(d.get("products_here"), ["Gmail", "Slack"])
        self.assertIs(d.get("bot_connectors_complete"), True)

    def test_every_product_here_is_counted_whole(self):   # replay (2e84aa8 had no product totals)
        self.small()
        w(os.path.join(self.home, ".cursor", "mcp.json"), {"mcpServers": dict({f"tool{i:02d}": {"command": "npx"} for i in range(60)},
                                                                              slack={"command": "npx"})})
        self.answered()
        self.audit_json()
        d = json.loads(self.access("--json")[1])
        self.assertNotIn("slack", d["mcp_tools"])   # past the 40 kept
        self.assertIn("Slack", d.get("products_here") or [])


# ---------------------------------------------------------------- 5: system cron
class SystemCronIsScheduled(_Round3):
    def test_an_owner_cron_file_is_a_scheduled_job(self):   # replay (2e84aa8: scheduled_jobs 0, checked)
        persist = {"crontab": "", "/etc/cron.d": ["owner-digest"]}
        with mock.patch.object(wt, "SYSTEM_CRON", "/etc/cron.d", create=True):
            m = wt.build_access_map({"findings": []}, {"persistence": persist, "access_sources": {"roots": self.roots, "crontab": "none"}})
        d = json.loads(wt.access_json(m))
        self.assertEqual(d["shared"]["scheduled_jobs"], 1)
        self.assertIn("Scheduled jobs on this computer: 1.", wt.access_shared_lines(m))

    def no_crontab(self):
        real = wt.run
        return mock.patch.object(wt, "run", lambda cmd, *a, **k: (1, "", "no crontab for box") if list(cmd[:2]) == ["crontab", "-l"] else real(cmd, *a, **k))

    def test_access_counts_the_system_cron_folder(self):   # replay (2e84aa8: scheduled_jobs 0)
        self.small()
        w(os.path.join(wt.SYSTEM_CRON, "owner-digest"), "0 7 * * * box /home/box/digest.sh\n")
        w(os.path.join(wt.SYSTEM_CRON, ".placeholder"), "")
        with self.no_crontab():
            self.audit_json()
            d = json.loads(self.access("--json")[1])
        self.assertEqual(d["shared"]["scheduled_jobs"], 1)
        self.assertEqual(json.loads(self.map_file())["shared"]["scheduled"], {"crontab": 0, "system": 1, "systemd": 0})

    def test_a_system_cron_folder_that_cant_be_read_is_no_count(self):   # replay (2e84aa8: scheduled_jobs 0)
        self.small()
        w(os.path.join(self.tmp, "elsewhere", "cron.d", "owner-digest"), "x\n")
        os.makedirs(os.path.dirname(wt.SYSTEM_CRON))
        os.symlink(os.path.join(self.tmp, "elsewhere", "cron.d"), wt.SYSTEM_CRON)   # _ax_listdir never reads through a link
        with self.no_crontab():
            self.audit_json()
            d = json.loads(self.access("--json")[1])
        self.assertIsNone(d["shared"]["scheduled_jobs"])
        self.assertEqual(d["incomplete"].get("scheduled"), "unreadable")


# ---------------------------------------------------------------- 6: the unreadable profile, always said
class TheProfileLineIsAlwaysSaid(_Round3):
    def test_without_a_recent_roll_call(self):   # replay (2e84aa8: only the no-roll-call line)
        m = wt.access_record({"rollcall": {"fresh": False, "profiles_unreadable": 1}})
        lines = wt.access_bot_lines(m)
        self.assertEqual(lines[-1], "ISR Bot couldn't read 1 Bot profile (a link, or not plain JSON), so a Bot may be missing from this list.")
        self.assertTrue(lines[0].startswith("No Bot has answered a roll-call in the last 35 days"), lines)

    def test_on_a_box(self):   # replay
        self.small(())
        target = w(os.path.join(self.tmp, "elsewhere", "profile.json"), {"name": "Kilo"})
        os.makedirs(os.path.join(self.home, "agent-data", "agents", AGENT))
        os.symlink(target, os.path.join(self.home, "agent-data", "agents", AGENT, "profile.json"))
        self.audit_json()
        self.assertIn("- ISR Bot couldn't read 1 Bot profile (a link, or not plain JSON), so a Bot may be missing from this list.", self.access()[1])


# ---------------------------------------------------------------- 4: golden must_see, per scenario
SIDS = ("box-empty_account-cli", "box-odd_layout-cli")
KEYS = ("tree workspace/watchtower/state/access_map.json", "tree workspace/watchtower/reports/2026-W43.md", "tree workspace/watchtower/reports/dashboard.html",
        "003 audit :stdout", "004 report :stdout")


def items_for(entries, sid):
    """(pre, post) items for a scenario, built from the item-a entries it has: post has each entry's output, exactly."""
    pre, post = {"001 status :stdout": "ok\n"}, {"001 status :stdout": "ok\n"}
    for e in entries:
        if not e["_s"].search(sid):
            continue
        key = next(k for k in KEYS if e["_k"].search(k))
        assert key not in post, (sid, key)   # one entry per output of a scenario
        if e.get("_exact"):
            post[key] = "\n".join(e["_exact"]["head"]) + "\n" + json.dumps(dict(e["_exact"]["doc"], at="2026-10-19T06:51:40+00:00"), indent=2)
        else:
            pre[key] = "\n".join(["P0"] + [x[1:] for x in e["_block"] if x.startswith("-")] + ["P9"]) + "\n"
            post[key] = "\n".join(["P0"] + [x[1:] for x in e["_block"] if x.startswith("+")] + ["P9"]) + "\n"
            assert gs.diff_lines(pre[key], post[key]) == e["_block"], (sid, key)
    return pre, post


class MustSeeIsPerScenario(unittest.TestCase):
    def harness(self, entries, items):
        """The golden check over SIDS, each scenario's (pre, post) items from `items`."""
        class Harness(gs.GoldenSplit):
            report, failed, MODE, pre, post = [], False, "full", "<pre tree>", "<post tree>"
            ITEMS = ["a"]
        Harness.sandbox = True
        Harness.expect = entries
        h = Harness("test_1_tiers")
        h.place = lambda tree: None
        h.run_sandboxed = lambda sid, plan, tag: {"items": dict(items[sid][1] if tag == "post" else items[sid][0])}
        h.timing = lambda: None
        with mock.patch.dict(os.environ, {"WT_GOLDEN_ONLY": "^(" + "|".join(SIDS) + ")$"}):
            try:
                h.test_1_tiers()
            except AssertionError as e:
                return "failed: " + str(e), "\n".join(type(h).report)
        return "passed", "\n".join(type(h).report)

    def test_one_scenario_cant_meet_another_ones_entry(self):   # replay (2e84aa8: passed)
        e = {"item": "a", "scenario_rx": "^(box-empty_account-cli|box-odd_layout-cli)$", "key_rx": "^003 audit :stdout$", "block": ['+ "access": "x",'],
             "must_see": True, "why": "the access line"}
        entries = gs.parse_expect({"entries": [e]}, ["a"])
        pre = {"003 audit :stdout": "{\n}\n"}
        good = (pre, {"003 audit :stdout": '{\n "access": "x",\n}\n'})
        self.assertEqual(self.harness(entries, {s: good for s in SIDS})[0], "passed")
        out, rep = self.harness(entries, {"box-empty_account-cli": good, "box-odd_layout-cli": (pre, pre)})
        self.assertTrue(out.startswith("failed: 1 problems"), rep)
        self.assertIn("must_see entry 0 matched nothing in box-odd_layout-cli", rep)

    def test_a_pattern_is_met_in_any_one_of_its_scenarios(self):   # guard: PR A's ^box- entries (not every box re-masks a copy)
        e = {"item": "a", "scenario_rx": "^box-", "key_rx": "^003 audit :stdout$", "block": ['+ "access": "x",'], "must_see": True, "why": "x"}
        entries = gs.parse_expect({"entries": [e]}, ["a"])
        pre = {"003 audit :stdout": "{\n}\n"}
        good = (pre, {"003 audit :stdout": '{\n "access": "x",\n}\n'})
        self.assertEqual(self.harness(entries, {"box-empty_account-cli": good, "box-odd_layout-cli": (pre, pre)})[0], "passed")
        out, rep = self.harness(entries, {s: (pre, pre) for s in SIDS})
        self.assertIn("must_see entry 0 matched nothing in box-empty_account-cli", rep)

    def test_a_scenario_without_its_map_and_section_fails(self):   # replay (2e84aa8: zero unexpected lines, zero unmet)
        with open(os.path.join(ROOT, "tests", "golden_expect", "batch5.json")) as f:
            entries = gs.parse_expect(json.load(f), ["a"])
        healthy = {s: items_for(entries, s) for s in SIDS}
        self.assertEqual(self.harness(entries, healthy)[0], "passed")
        pre, post = healthy["box-odd_layout-cli"]
        dropped = dict(post)
        for k in ("tree workspace/watchtower/state/access_map.json", "tree workspace/watchtower/reports/2026-W43.md"):
            if k in pre:
                dropped[k] = pre[k]
            else:
                dropped.pop(k)
        out, rep = self.harness(entries, dict(healthy, **{"box-odd_layout-cli": (pre, dropped)}))
        self.assertTrue(out.startswith("failed: 2 problems"), rep)
        self.assertEqual(len(set(re.findall(r"must_see entry (\d+) matched nothing in box-odd_layout-cli", rep))), 2, rep)   # the map, the section
        self.assertNotIn("matched nothing in box-empty_account-cli", rep)


if __name__ == "__main__":
    unittest.main()
