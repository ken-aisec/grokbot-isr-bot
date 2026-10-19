"""Batch 5, item 0: the golden check's expect mode (tests/golden_split.py, scripts/golden-check.sh --expect FILE --items A,B).

Batch 5 changes behavior on purpose, so the golden check accepts a difference between pre and post only when an entry of an
enabled item in the expect file names its lines; anything else, and a must_see entry that matched nothing, fails it. Without
--expect it is exactly the split check (step 0's byte comparison included). Like test_golden_harness, these drive the harness
with stubs: no sandbox, no tree run, no git archive."""
import os, shutil, subprocess, sys, tempfile, unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import golden_split as gs  # noqa: E402  (the module, never its TestCase)

PRE = {"001 audit :rc": "0", "001 audit :stdout": '{\n "masked": 3,\n "status": "ok"\n}\n', "001 audit :stderr": ""}
POST = dict(PRE, **{"001 audit :stdout": '{\n "masked": 4,\n "status": "ok"\n}\n'})


def entry(**kw):
    e = {"item": "c", "scenario_rx": "^tierA$", "key_rx": r"audit :stdout$", "lines_rx": [r'^[-+] "masked": [34],$'],
         "must_see": False, "why": "MASK_VERSION 3 -> 4"}
    e.update(kw)
    return e


class _Expect(unittest.TestCase):
    def harness(self, entries, items, post=POST):
        class Harness(gs.GoldenSplit):
            report, failed, MODE, pre, post = [], False, "quick", "<pre tree>", "<post tree>"
            ITEMS = list(items)
        Harness.sandbox = True
        Harness.expect = gs.parse_expect({"entries": entries}, items)
        h = Harness("test_1_tiers")
        h.place = lambda tree: None
        h.run_sandboxed = lambda sid, plan, tag: {"items": dict(post if tag == "post" else PRE)}
        h.timing = lambda: None
        return h

    def outcome(self, h):
        with mock.patch.dict(os.environ, {"WT_GOLDEN_ONLY": "^tierA$"}):
            try:
                h.test_1_tiers()
            except AssertionError as e:
                return "failed: " + str(e)
        return "passed"


class ExpectedDifferences(_Expect):
    def test_an_unlisted_difference_fails(self):
        h = self.harness([], [])
        self.assertTrue(self.outcome(h).startswith("failed: 1 problems"))
        self.assertTrue(any('-"masked":3,' in l.replace(" ", "") for l in type(h).report), type(h).report)
        self.assertFalse([l for l in type(h).report if l.startswith("RESULT")])

    def test_a_listed_difference_passes_and_is_counted(self):
        h = self.harness([entry()], ["c"])
        self.assertEqual(self.outcome(h), "passed", type(h).report)
        rep = "\n".join(type(h).report)
        self.assertIn("c 2 lines by 1 entries", rep)
        self.assertIn("RESULT: post == pre on every tier run except the expected differences of c", rep)

    def test_a_listed_line_in_another_item_or_scenario_is_not_expected(self):
        for e in (entry(key_rx="report :stdout$"), entry(scenario_rx="^box-")):
            h = self.harness([e], ["c"])
            self.assertTrue(self.outcome(h).startswith("failed: 1 problems"), e)

    def test_one_unlisted_line_among_listed_ones_fails(self):
        post = dict(POST, **{"001 audit :stdout": '{\n "masked": 4,\n "status": "Act now"\n}\n'})
        h = self.harness([entry()], ["c"], post=post)
        self.assertTrue(self.outcome(h).startswith("failed: 1 problems"))
        self.assertIn('"status": "Act now"', "\n".join(type(h).report))

    def test_an_unmet_must_see_fails(self):
        h = self.harness([entry(must_see=True)], ["c"], post=PRE)
        out = self.outcome(h)
        self.assertTrue(out.startswith("failed: 1 problems"), out)
        self.assertIn("must_see entry 0 matched nothing", "\n".join(type(h).report))

    def test_a_must_see_whose_scenario_did_not_run_is_not_a_problem(self):
        h = self.harness([entry(), entry(scenario_rx="^box-platform_refresh", must_see=True)], ["c"])
        self.assertEqual(self.outcome(h), "passed", type(h).report)

    def test_entries_of_items_not_enabled_are_ignored(self):
        h = self.harness([entry(item="d1", must_see=True)], ["c"])
        self.assertTrue(self.outcome(h).startswith("failed: 1 problems"))
        self.assertNotIn("must_see", "\n".join(type(h).report))

    def test_a_new_item_is_a_line_of_its_own(self):
        post = dict(PRE, **{"tree workspace/watchtower/state/new.json": "file 0600\n{}"})
        self.assertEqual(gs.diff_lines(None, "file 0600\n{}"), [gs.NEW_ITEM, "+file 0600", "+{}"])
        self.assertEqual(gs.diff_lines("a\n", None), [gs.GONE_ITEM, "-a"])
        self.assertEqual(gs.diff_lines("a\n", "a"), ["~line ends differ"])
        e = entry(key_rx=r"^tree workspace/watchtower/state/new\.json$", lines_rx=[r"^\+<new item>$", r"^\+file 0600$", r"^\+\{\}$"])
        h = self.harness([e], ["c"], post=post)
        self.assertEqual(self.outcome(h), "passed", type(h).report)


class NarrowPatterns(unittest.TestCase):
    def test_catch_all_line_patterns_are_refused(self):
        for rx in (".*", ".+", "", "   ", "^.*$", "^[-+]", "[+-].*", r"^\+", "^-", "(?s).", "x|"):
            with self.assertRaises(ValueError, msg=rx):
                gs.parse_expect({"entries": [entry(lines_rx=[r'^[-+] "masked"', rx])]}, ["c"])

    def test_refused_in_a_disabled_item_too(self):
        with self.assertRaises(ValueError):
            gs.parse_expect({"entries": [entry(item="b", lines_rx=[".*"])]}, ["c"])

    def test_malformed_entries_are_refused(self):
        for bad in ({"entries": "x"}, [], {"entries": [dict(entry(), extra=1)]}, {"entries": [entry(why=" ")]},
                    {"entries": [entry(lines_rx=[])]}, {"entries": [entry(must_see="yes")]}, {"entries": [entry(key_rx="(")]}):
            with self.assertRaises(ValueError, msg=repr(bad)):
                gs.parse_expect(bad, ["c"])

    def test_the_shipped_file_parses_with_every_item(self):
        import json
        with open(os.path.join(ROOT, "tests", "golden_expect", "batch5.json")) as f:
            doc = json.load(f)
        items = sorted({e["item"] for e in doc["entries"]})
        self.assertEqual(len(gs.parse_expect(doc, items)), len(doc["entries"]))


class AccessMapExpectations(unittest.TestCase):
    """PR B, Codex round 1 (4): the shipped item-a entries take the access map, the report section and the card exactly; a leak, a
    value out of its set, a count that moved or an added line fails. Replays: on 0a72c20 (key and line patterns) each tampered item
    passed the check."""
    SID = "box-empty_account-cli"
    # PR B, Codex round 2 (6): the map and section as this box really writes them now (the map gained incomplete, cached,
    # cached_at, scope, cli_products and the roll-call's counts; the section's four limitation lines, which the old line patterns
    # let a test leave out, are back in). Only these fixtures changed, no assertion. Round 3: the map has the roll-call's
    # connectors_unknown_more and scheduled.system (fixtures only again).
    MAP = {"at": "<TS>", "bots": [], "bots_more": 0, "bots_no_detail": [], "bots_silent": [],
           "rollcall": {"at": None, "connectors_more": {}, "connectors_unknown_more": 0, "fresh": False, "no_detail_more": 0, "profiles_unreadable": 0,
                        "silent_more": 0},
           "shared": {"auto_allow": [], "auto_allow_areas": dict.fromkeys(("deletes", "everything", "installs", "other", "pays", "permissions", "runs code", "sends"), 0),
                      "auto_review": None, "browser": None, "cached": [], "cached_at": None,
                      "checked": ["browser", "cli_logins", "settings", "mcp", "plugins", "webhooks", "scheduled", "hooks", "key_files"],
                      "cli_count": 0, "cli_logins": [], "cli_products": [], "from": "audit", "hooks": {"other": 0, "platform": 0},
                      "incomplete": {"key_files": "depth", "scheduled": "failed"}, "key_files": 0,
                      "mcp": {"count": 0, "files": 0, "products": [], "tools": [], "unreadable": 0, "unreadable_files": []},
                      "platform_logins": [], "plugins": {"added": 0, "grok": 0, "names": []}, "runs_programs": "unknown",
                      "scheduled": {"crontab": 0, "system": 0, "systemd": 0}, "scope": ["/home/box", "/workspace"], "settings": "missing",
                      "webhook_count": 0, "webhook_services": [], "webhooks": []},
           "unknown": ["connectors", "routines_on_box", "secrets_content", "approvals"], "v": 1}
    SECTION = ["", "## Who can reach what", "", "All your Bots share this computer, so every Bot can use everything in the first list.", "",
               "Shared by all Bots", "- Browser: Watchtower found no shared browser cookies to check.", "- Command-line sign-ins: none found.",
               "- Allowed without asking: Watchtower couldn't find Grok Bot's approval settings, so it can't say what Bots may do without asking.",
               "- Tool connections (MCP): none found.", "- Plugins: none.", "",
               "Each Bot (what each Bot said in the roll-call; Watchtower can't check it)",
               "- No Bot has answered a roll-call in the last 35 days, so Watchtower doesn't know which connectors each Bot uses. Ask Watchtower to run a roll-call.",
               "", "What Watchtower can't see", "- Grok Bot's approval settings: Watchtower couldn't find them on this computer.",
               "- Which connectors a Bot uses, except what it said in the roll-call. The Grok Bot app keeps that list, not this computer.",
               "- Routines and when they run: the Grok Bot app keeps them, not this computer.",
               "- What each sign-in or connector is allowed to do at its service (its permissions there).",
               "- What's inside memories, messages or saved passwords. Watchtower never reads them."]

    # the same box's map as 0a72c20 wrote it: its patterns took it, and took it tampered too (each tampering is tried on both)
    OLD_MAP = {"at": "<TS>", "bots": [], "bots_more": 0, "bots_no_detail": [], "bots_silent": [], "rollcall": {"at": None, "fresh": False},
               "shared": {"auto_allow": [], "auto_review": None, "browser": None, "cli_logins": [], "hooks": {"other": 0, "platform": 0}, "key_files": 0,
                          "mcp": {"files": 0, "tools": [], "unreadable": 0, "unreadable_files": []}, "platform_logins": [],
                          "plugins": {"added": 0, "grok": 0, "names": []}, "runs_programs": "unknown", "scheduled": {"crontab": 0, "systemd": 0},
                          "settings": "missing", "webhooks": []},
               "unknown": ["connectors", "routines_on_box", "secrets_content", "approvals"], "v": 1}

    def setUp(self):
        import json
        with open(os.path.join(ROOT, "tests", "golden_expect", "batch5.json")) as f:
            self.entries = gs.parse_expect(json.load(f), ["a"])

    def bad(self, key, pre, post):
        return gs.unexpected_lines(self.SID, key, pre, post, self.entries, {})

    def map_bad(self, change=None, m=None):
        import copy, json
        m = copy.deepcopy(self.MAP if m is None else m)
        if change:
            change(m)
        return self.bad("tree workspace/watchtower/state/access_map.json", None, "file 0644\n" + json.dumps(m, indent=2, sort_keys=True))

    def both_fail(self, change):
        self.assertTrue(self.map_bad(change, self.OLD_MAP), "the 0a72c20-shaped map, tampered")
        self.assertTrue(self.map_bad(change), "this map, tampered")

    def test_the_map_as_these_boxes_write_it_is_expected(self):   # guard
        self.assertEqual(self.map_bad(), [])

    def test_private_prose_in_plugin_names_fails(self):   # replay
        self.both_fail(lambda m: m["shared"]["plugins"].update(names=["Client Dana Ortiz has cancer"]))

    def test_a_value_outside_its_set_fails(self):   # replay
        self.both_fail(lambda m: m["shared"].update(runs_programs="FAKE anything at all"))
        self.both_fail(lambda m: m["shared"].update(settings=True))   # the right key, the wrong type

    def test_a_moved_count_a_moved_key_or_a_missing_one_fails(self):   # replay
        self.both_fail(lambda m: m["shared"]["mcp"].update(files=1))
        self.both_fail(lambda m: m["shared"].update(sites=0))            # a known key, at another place
        self.both_fail(lambda m: m["shared"]["mcp"].pop("tools"))        # a missing key
        self.assertTrue(self.map_bad(lambda m: m["shared"].pop("checked")))             # unchecked: never what an audit writes
        self.assertTrue(self.map_bad(lambda m: m["shared"].update(checked=["browser"])))

    @staticmethod
    def report_pair(section):
        """(pre, post) report text around the section as a report has it: the findings table after it is longer than Top fixes
        before it, so the diff adds the section with its first empty line, as in the golden boxes (PR B, Codex round 2, 6: the
        section is one exact block now, so its diff lines matter; was: pre "# Watchtower\\n\\n## All open findings\\n")."""
        top, rest = ["# Watchtower", "", "## Top fixes", "Nothing to fix this week."], ["", "## All open findings", "", "Confirmed: x.", "", "| a |", "| b |"]
        return "\n".join(top + rest) + "\n", "\n".join(top + section + rest) + "\n"

    def test_an_added_report_line_fails(self):   # replay
        key, (pre, post) = "tree workspace/watchtower/reports/2026-W43.md", self.report_pair(self.SECTION)
        self.assertEqual(self.bad(key, pre, post), [])
        leak = post.replace("- Plugins: none.", "- Plugins: none.\n- Browser: FAKE_PRIVATE_MESSAGE")
        self.assertEqual(self.bad(key, pre, leak), ["+- Browser: FAKE_PRIVATE_MESSAGE"])
        self.assertTrue(self.bad(key, pre, post.replace("Plugins: none.", "Plugins: 9 (0 from Grok Bot, 9 added).")))

    def test_an_added_card_item_fails(self):   # replay
        import html
        key = "tree workspace/watchtower/reports/dashboard.html"
        items = lambda xs: "".join(f"<li>{html.escape(x[2:])}</li>" for x in xs)
        card = ("<h2 style='font-size:16px'>Who can reach what</h2><div class='card'><p class='mut'>" + html.escape(self.SECTION[3]) + "</p>"
                "<p><b>Shared by all Bots</b></p><ul>" + items(self.SECTION[6:11]) + "</ul><p><b>" + html.escape(self.SECTION[12]) + "</b></p><ul>"
                + items(self.SECTION[13:14]) + "</ul><p><b>What Watchtower can&#x27;t see</b></p><ul>"
                + items(self.SECTION[16:21]) + "</ul></div>")   # round 2: SECTION has the five lines now (was four listed here + SECTION[16])
        self.assertEqual(self.bad(key, "<p>a</p>\n", card + "\n<p>a</p>\n"), [])
        self.assertTrue(self.bad(key, "<p>a</p>\n", card.replace("<li>Plugins: none.</li>", "<li>Plugins: none.</li><li>Browser: FAKE_PRIVATE_MESSAGE</li>") + "\n<p>a</p>\n"))


class AccessMapRound2Negatives(unittest.TestCase):
    """PR B, Codex round 2 (6): each scenario's map is pinned value for value and each report section is one exact block, so the
    mutations Codex found accepted now fail. Each is tried on the output as 3170952 wrote it (R1_*) first, then as this branch
    writes it: replays, since on 3170952 (its matcher and batch5.json) the R1_ ones passed."""
    MAP, SECTION, report_pair = AccessMapExpectations.MAP, AccessMapExpectations.SECTION, staticmethod(AccessMapExpectations.report_pair)
    setUp, bad = AccessMapExpectations.setUp, AccessMapExpectations.bad
    SID = AccessMapExpectations.SID
    R1_MAP = {"at": "<TS>", "bots": [], "bots_more": 0, "bots_no_detail": [], "bots_silent": [],
              "rollcall": {"at": None, "fresh": False, "no_detail_more": 0, "silent_more": 0},
              "shared": {"auto_allow": [], "auto_allow_areas": dict.fromkeys(("deletes", "everything", "installs", "other", "pays", "permissions", "runs code", "sends"), 0),
                         "auto_review": None, "browser": None,
                         "checked": ["browser", "cli_logins", "settings", "mcp", "plugins", "webhooks", "scheduled", "hooks", "key_files"],
                         "cli_count": 0, "cli_logins": [], "from": "audit", "hooks": {"other": 0, "platform": 0}, "key_files": 0,
                         "mcp": {"count": 0, "files": 0, "products": [], "tools": [], "unreadable": 0, "unreadable_files": []},
                         "platform_logins": [], "plugins": {"added": 0, "grok": 0, "names": []}, "runs_programs": "unknown",
                         "scheduled": {"crontab": 0, "systemd": 0}, "settings": "missing", "webhook_count": 0, "webhook_services": [], "webhooks": []},
              "unknown": ["connectors", "routines_on_box", "secrets_content", "approvals"], "v": 1}
    R1_SECTION = AccessMapExpectations.SECTION[:16] + AccessMapExpectations.SECTION[20:]   # 3170952's fixture: one limitation line
    SEEN = {"products": [], "sensitive": [], "sensitive_count": 0, "sites": 0}   # the busy and platform-refresh boxes' cookie seed

    def maps(self, sid):
        """(this branch's map, 3170952's) for a scenario."""
        import copy
        new, old = copy.deepcopy(self.MAP), copy.deepcopy(self.R1_MAP)
        if sid == "box-platform_refresh-cli":
            for m in (new, old):
                m["shared"]["browser"] = dict(self.SEEN)
            new["shared"]["plugins"] = {"added": 3, "grok": 0, "names": ["figma-notes", "notion-workspace", "vercel-docs"]}
            # round 3 (1): this box has folders the scan leaves out (fixture only)
            new["shared"]["incomplete"] = dict(dict.fromkeys(("hooks", "mcp", "plugins", "webhooks"), "skipped"), key_files="depth", scheduled="failed")
            old["shared"]["plugins"] = {"added": 0, "grok": 3, "names": []}
        if sid == "box-emoji_names-cli":
            new["bots_silent"] = old["bots_silent"] = ["Ïris 🤖", "Танго"]
        return new, old

    def tampered_fails(self, sid, change):
        """This branch's map for the scenario is expected as written, and not once tampered."""
        import json
        key, m = "tree workspace/watchtower/state/access_map.json", self.maps(sid)[0]
        self.assertEqual(gs.unexpected_lines(sid, key, None, "file 0644\n" + json.dumps(m, indent=2, sort_keys=True), self.entries, {}), [], sid)
        change(m)
        self.assertTrue(gs.unexpected_lines(sid, key, None, "file 0644\n" + json.dumps(m, indent=2, sort_keys=True), self.entries, {}), sid)

    def r1_tampered_fails(self, sid, change):
        """3170952's map, tampered: its matcher took it; this one must not (it isn't any scenario's map, tampered or not)."""
        import json
        m = self.maps(sid)[1]
        change(m)
        self.assertTrue(gs.unexpected_lines(sid, "tree workspace/watchtower/state/access_map.json", None,
                                            "file 0644\n" + json.dumps(m, indent=2, sort_keys=True), self.entries, {}))

    def test_three_plugins_where_none_are_fails(self):   # replay
        self.r1_tampered_fails("box-empty_account-cli", lambda m: m["shared"]["plugins"].update(grok=3))
        self.tampered_fails("box-empty_account-cli", lambda m: m["shared"]["plugins"].update(added=3, names=["a", "b", "c"]))

    def test_zero_or_one_plugin_where_three_are_fails(self):   # replay
        for n in (0, 1):
            self.r1_tampered_fails("box-platform_refresh-cli", lambda m: m["shared"]["plugins"].update(grok=n))
            self.tampered_fails("box-platform_refresh-cli", lambda m: m["shared"]["plugins"].update(added=n, names=["figma-notes"][:n]))

    def test_an_empty_silent_roster_fails(self):   # replay
        self.r1_tampered_fails("box-emoji_names-cli", lambda m: m.update(bots_silent=[]))
        self.tampered_fails("box-emoji_names-cli", lambda m: m.update(bots_silent=[]))

    def section_fails(self, change):
        key = "tree workspace/watchtower/reports/2026-W43.md"
        for name, section in (("3170952's section", self.R1_SECTION), ("this branch's section", self.SECTION)):
            pre, post = self.report_pair(change(list(section)))
            self.assertTrue(self.bad(key, pre, post), name)

    def test_the_whole_section_is_expected(self):   # guard: untouched, it passes
        self.assertEqual(self.bad("tree workspace/watchtower/reports/2026-W43.md", *self.report_pair(self.SECTION)), [])

    def test_an_omitted_mcp_line_fails(self):   # replay
        self.section_fails(lambda s: [x for x in s if not x.startswith("- Tool connections (MCP)")])

    def test_an_omitted_limitation_line_fails(self):   # replay
        self.section_fails(lambda s: [x for x in s if not x.startswith("- What each sign-in or connector")] if len(s) > 17 else
                           [x for x in s if not x.startswith("- What's inside")])

    def test_a_duplicated_contradictory_plugin_line_fails(self):   # replay
        self.section_fails(lambda s: [y for x in s for y in ([x, "- Plugins: 3 (3 from Grok Bot, 0 added)."] if x == "- Plugins: none." else [x])])

    def test_one_scenario_one_map(self):   # guard: no scenario has two maps to choose from
        import json
        with open(os.path.join(ROOT, "tests", "golden_expect", "batch5.json")) as f:
            entries = [e for e in json.load(f)["entries"] if e["item"] == "a" and "access_map" in e["key_rx"]]
        self.assertTrue(entries and all("json_exact" in e for e in entries))
        for sid in ("box-empty_account-cli", "box-platform_refresh-cli", "box-emoji_names-driver", "crash", "extended", "tierC"):
            self.assertEqual(sum(1 for e in entries if gs.re.search(e["scenario_rx"], sid)), 1, sid)


class JsonShape(unittest.TestCase):
    """The json_shape schema is strict and refuses what it can't apply."""
    def test_malformed_schemas_are_refused(self):
        for bad in ({}, {"enum": []}, {"object": {"a": {}}}, {"list": {"of": {"enum": [1]}}}, {"int": [3, 1]}, {"text": ".*"},
                    {"enum": [1], "int": [0, 1]}, {"any": []}, {"enum": [{"a": 1}]}):
            e = entry(key_rx="map$", json_shape={"head": [], "doc": bad})
            del e["lines_rx"]
            with self.assertRaises(ValueError, msg=repr(bad)):
                gs.parse_expect({"entries": [e]}, ["c"])

    def test_values_fit_exactly(self):
        s = {"object": {"n": {"int": [0, 3]}, "xs": {"list": {"of": {"enum": ["a", None]}, "max": 2}}, "b": {"enum": [False]}}}
        self.assertTrue(gs.json_shape_ok(s, {"n": 3, "xs": ["a", None], "b": False}))
        for v in ({"n": 4, "xs": [], "b": False}, {"n": True, "xs": [], "b": False}, {"n": 1, "xs": ["a", "a", "a"], "b": False},
                  {"n": 1, "xs": ["b"], "b": False}, {"n": 1, "xs": [], "b": 0}, {"n": 1, "xs": [], "b": False, "c": 1}, {"n": 1, "xs": []}):
            self.assertFalse(gs.json_shape_ok(s, v), v)

    def test_only_a_new_item_with_that_head_is_taken(self):
        shape = {"head": ["file 0644"], "doc": {"object": {"v": {"enum": [1]}}}}
        self.assertTrue(gs.json_new_shape(None, 'file 0644\n{"v": 1}', shape))
        self.assertFalse(gs.json_new_shape('file 0644\n{"v": 1}', 'file 0644\n{"v": 1}', shape))   # not new
        self.assertFalse(gs.json_new_shape(None, 'file 0600\n{"v": 1}', shape))
        self.assertFalse(gs.json_new_shape(None, 'file 0644\n{"v": 1, "v": 1}', shape))   # strict JSON


class ExactKinds(unittest.TestCase):
    """PR B, Codex round 2 (6): `block` takes one exact run of diff lines, once; `json_exact` one exact document."""
    def entries(self, **alt):
        e = entry(key_rx=r"^r$", **alt)
        del e["lines_rx"]
        return gs.parse_expect({"entries": [e]}, ["c"])

    def test_a_block_is_taken_whole_and_once(self):
        es = self.entries(block=["+a", "+b"])
        self.assertEqual(gs.unexpected_lines("tierA", "r", "x\n", "x\na\nb\n", es, {}), [])
        self.assertEqual(gs.unexpected_lines("tierA", "r", "x\n", "x\na\n", es, {}), ["+a"])                 # a line left out
        self.assertEqual(gs.unexpected_lines("tierA", "r", "x\n", "x\na\nb\nb\n", es, {}), ["+b"])          # a second copy
        self.assertEqual(gs.unexpected_lines("tierA", "r", "x\n", "x\nb\na\n", es, {}), ["+b", "+a"])      # the order

    def test_json_exact_is_every_value_with_its_type_and_order(self):
        es = self.entries(json_exact={"head": ["file 0644"], "doc": {"a": 1, "b": [True]}})
        self.assertEqual(gs.unexpected_lines("tierA", "r", None, 'file 0644\n{"a": 1, "b": [true]}', es, {}), [])
        for bad in ('{"a": 2, "b": [true]}', '{"b": [true], "a": 1}', '{"a": 1, "b": [1]}', '{"a": 1, "b": [true], "c": 0}'):
            self.assertTrue(gs.unexpected_lines("tierA", "r", None, "file 0644\n" + bad, es, {}), bad)

    def test_json_exact_takes_any_time_written_and_nothing_else_for_it(self):
        es = self.entries(json_exact={"head": ["file 0644"], "doc": {"at": "<TS>", "v": 1}})
        for at in ("<TS>", "2026-10-18T12:00:00+00:00", "2026-10-19T06:51:40.123Z"):
            self.assertEqual(gs.unexpected_lines("tierA", "r", None, f'file 0644\n{{"at": "{at}", "v": 1}}', es, {}), [], at)
        for at in ('"FAKE private text"', '"2026-10-18"', "null", "1"):
            self.assertTrue(gs.unexpected_lines("tierA", "r", None, f'file 0644\n{{"at": {at}, "v": 1}}', es, {}), at)

    def test_malformed_exact_entries_are_refused(self):
        for alt in ({"block": []}, {"block": ["no sign"]}, {"block": "+a"}, {"json_exact": {"head": []}}, {"json_exact": {"head": [], "doc": []}}):
            with self.assertRaises(ValueError, msg=repr(alt)):
                self.entries(**alt)


class StepZero(unittest.TestCase):
    """Without --expect the byte comparison runs exactly as for the split; with it, only compile and loader checks."""
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wt-golden-expect-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        os.makedirs(os.path.join(self.tmp, "watchtower", "wt_parts"))
        with open(os.path.join(self.tmp, "watchtower", "wt.py"), "wb") as f:
            f.write(b"x = 1\n")

    def step0(self, pre_bytes, expect):
        class Harness(gs.GoldenSplit):
            report, failed, MODE, PRE, untracked = [], False, "quick", "151e40c", []
            ITEMS = []
        Harness.post = self.tmp
        Harness.expect = expect
        h = Harness("test_0_reassembly")
        show = lambda *a, **k: b"151e40c\n" if a[0] == "rev-parse" else pre_bytes
        with mock.patch.object(gs, "git", show):
            try:
                h.test_0_reassembly()
            except AssertionError as e:
                return "failed: " + str(e), type(h).report
        return "passed", type(h).report

    def test_no_expect_mode_still_compares_bytes(self):
        out, rep = self.step0(b"x = 2\n", None)
        self.assertTrue(out.startswith("failed: step 0: the reassembled wt.py differs"), out)
        out, rep = self.step0(b"x = 1\n", None)
        self.assertEqual(out, "passed")
        self.assertIn("byte-equal", rep[-1])

    def test_expect_mode_checks_compile_and_the_loader_block(self):
        out, rep = self.step0(b"x = 2\n" + gs.LOADER_BEGIN, [])
        self.assertEqual(out, "passed")
        self.assertIn("step 0: behavior-change mode, byte check not applicable", rep[-1])
        out, rep = self.step0(b"x = 2\n", [])
        self.assertIn("no wt_parts loader block", out)
        with open(os.path.join(self.tmp, "watchtower", "wt.py"), "wb") as f:
            f.write(b"x = (\n")
        out, rep = self.step0(gs.LOADER_BEGIN, [])
        self.assertIn("does not compile", out)


class Script(unittest.TestCase):
    """scripts/golden-check.sh from a copy with stub git and python3 (as test_golden_harness.H3)."""
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wt-golden-expect-sh-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        for d in ("scripts", "bin"):
            os.makedirs(os.path.join(self.tmp, d))
        self.script = os.path.join(self.tmp, "scripts", "golden-check.sh")
        shutil.copy2(os.path.join(ROOT, "scripts", "golden-check.sh"), self.script)
        with open(os.path.join(self.tmp, "x.json"), "w") as f:
            f.write('{"entries": []}')
        for name, body in (("git", "exit 0\n"), ("python3", 'echo "STUB pre=$WT_GOLDEN_PRE tiers=$WT_GOLDEN_TIERS only=$WT_GOLDEN_ONLY '
                                                            'expect=$WT_GOLDEN_EXPECT items=$WT_GOLDEN_ITEMS"\n')):
            p = os.path.join(self.tmp, "bin", name)
            with open(p, "w") as f:
                f.write("#!/bin/sh\n" + body)
            os.chmod(p, 0o755)

    def check(self, *argv):
        env = {"PATH": os.path.join(self.tmp, "bin") + ":/usr/bin:/bin", "LC_ALL": "C.UTF-8"}
        return subprocess.run([shutil.which("bash") or "/bin/bash", self.script, *argv], capture_output=True, text=True, env=env,
                              cwd=self.tmp, timeout=60)

    def test_expect_and_items_are_passed_on(self):
        p = self.check("151e40c", "quick", "--expect", "x.json", "--items", "c,d1")
        self.assertEqual((p.returncode, p.stdout.strip()), (0, "STUB pre=151e40c tiers=quick only= expect=x.json items=c,d1"), p.stderr)
        p = self.check("--expect", "x.json", "--items", "", "151e40c", "full", "^tierA$")
        self.assertEqual(p.stdout.strip(), "STUB pre=151e40c tiers=full only=^tierA$ expect=x.json items=", p.stderr)

    def test_without_expect_nothing_changes(self):
        p = self.check("151e40c", "quick")
        self.assertEqual(p.stdout.strip(), "STUB pre=151e40c tiers=quick only= expect= items=", p.stderr)

    def test_usage_errors(self):
        for argv, why in ((("151e40c", "--items", "c"), "--items needs --expect"), (("151e40c", "--expect", "nosuch.json"), "no expect file"),
                          (("151e40c", "--expect"), "--expect needs a file"), (("--expect", "x.json"), "no baseline ref given")):
            p = self.check(*argv)
            self.assertEqual((p.returncode, p.stdout), (2, ""), argv)
            self.assertIn(why, p.stderr)


if __name__ == "__main__":
    unittest.main()
