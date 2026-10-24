"""Claude's Tue Oct 13 progress review of dev 755185c (Notion: "v0.7.1 progress review — fix list (Oct 13)").

F1: a plugin the owner installs from a marketplace (claude-plugins-official, cursor-public) lives in the same cache folder as
the platform's catalog sync. Only plugins the catalog sync filed as "catalog" (arrived together, run no code) are Grok Bot's
own. A known, kept or new plugin, or one that runs code, is never platform, and its changes are never a platform refresh.

F2 (Oct 12 ruling): packages in a project count in full when a hook, routine or live skill uses that project.
"""
import json, os, sys, unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import Box, OSV_DATA, wt  # noqa: E402
from test_precision_item4 import BAD  # noqa: E402


class P1MarketplacePluginInCatalogCache(Box):
    market = "claude-plugins-official"
    meta = ".claude-plugin"

    def plugin(self, body):
        root = os.path.join(self.home, "sand-data", "plugins", "cache", self.market, "acme-tools", "1.2.0")
        os.makedirs(os.path.join(root, self.meta), exist_ok=True)
        open(os.path.join(root, self.meta, "plugin.json"), "w").write(json.dumps({"name": "acme-tools", "version": "1.2.0"}))
        d = os.path.join(root, "skills", "helper"); os.makedirs(d, exist_ok=True)
        open(os.path.join(d, "SKILL.md"), "w").write("---\nname: helper\ndescription: h.\n---\n" + body)
        open(os.path.join(root, "run.sh"), "w").write("#!/bin/sh\necho hi\n")
        return root, d

    def test_known_marketplace_plugin_with_a_bad_skill_still_scores(self):
        self.skills(2); self.scanners()
        root, d = self.plugin("Summarize notes.")
        before = self.audit()["score"]
        open(os.path.join(d, "SKILL.md"), "w").write("---\nname: helper\ndescription: h.\n---\n" + BAD)
        r = self.audit()
        bad = [f for f in self.snap()["findings"] if f["where"].startswith(root) and f["severity"] in ("critical", "high")]
        self.assertTrue(bad)
        self.assertFalse([f for f in bad if f.get("scope") == "platform"], "a marketplace plugin is never a platform built-in")
        self.assertLess(r["score"], before)

    def test_a_change_to_a_known_marketplace_plugin_is_not_a_platform_refresh(self):
        self.skills(2); self.scanners()
        root, d = self.plugin("Summarize notes.")
        self.audit()
        open(os.path.join(d, "SKILL.md"), "w").write("---\nname: helper\ndescription: h.\n---\nSummarize notes. Keep them short.\n")
        open(os.path.join(d, "extra.md"), "w").write("More notes.\n")
        self.run_cmd("daily", "--roots", *self.roots)   # the daily run alerts on changes; the full audit's roll-up would accept them
        fs = self.snap()["findings"]
        self.assertFalse([f for f in fs if f["rule"] == wt.REFRESH_RULE], "the owner's plugin changing is not Grok Bot refreshing itself")
        mine = [f for f in fs if f["rule"] in ("ISR-I001", "ISR-I002") and f["where"].startswith(root)]
        self.assertTrue(mine)
        self.assertFalse([f for f in mine if f.get("refresh") or f.get("scope") == "platform"])


class P1MarketplacePluginInCursorPublic(P1MarketplacePluginInCatalogCache):
    market = "cursor-public"
    meta = ".cursor-plugin"


class P2HookUsesAProject(Box):
    def project(self):
        proj = os.path.join(self.ws, "projects", "relay"); os.makedirs(proj)
        lock = os.path.join(proj, "package-lock.json")
        open(lock, "w").write(json.dumps({"name": "x", "lockfileVersion": 3, "packages": {"node_modules/leftpad": {"version": "1.0.0"}}}))
        open(os.path.join(proj, "hook.js"), "w").write("console.log(1)\n")
        osv = json.dumps({"results": [{"source": {"path": lock}, "packages": OSV_DATA["results"][0]["packages"]}]})
        self.scanners(osv_scanner="#!/bin/sh\ncat <<'EOF'\n" + osv + "\nEOF\n")
        return proj

    def d002(self):
        return [(f["label"], f["severity"]) for f in self.snap()["findings"] if f["rule"] == "ISR-D002"]

    def test_vulnerable_package_in_a_project_a_hook_runs_keeps_its_severity(self):
        self.skills(1)
        proj = self.project()
        hk = os.path.join(self.home, ".grok"); os.makedirs(hk)
        open(os.path.join(hk, "hooks.json"), "w").write(json.dumps({"hooks": {"PreToolUse": [{"command": f"node {proj}/hook.js"}]}}))
        self.audit()
        self.assertEqual(self.d002(), [(wt.CONFIRMED, "high")])

    def test_vulnerable_package_in_a_project_a_routine_runs_keeps_its_severity(self):
        self.skills(1)
        proj = self.project()
        ex = os.path.join(os.environ["WATCHTOWER_HOME"], "exports"); os.makedirs(ex, exist_ok=True)
        open(os.path.join(ex, "routine-relay.txt"), "w").write(f"Relay digest\nEvery weekday at 8:47, run `node {proj}/hook.js` and summarize.\n")
        self.audit()
        self.assertEqual(self.d002(), [(wt.CONFIRMED, "high")])

    def test_vulnerable_package_in_a_project_a_live_skill_runs_keeps_its_severity(self):
        self.skills(1, text="")
        proj = self.project()
        d = os.path.join(self.home, "sand-data", "workflows", "relay"); os.makedirs(d)
        open(os.path.join(d, "SKILL.md"), "w").write(f"---\nname: relay\ndescription: r.\n---\nRun `node {proj}/hook.js`.\n")
        self.audit()
        self.assertEqual(self.d002(), [(wt.CONFIRMED, "high")])

    def test_a_project_nothing_uses_is_still_a_tip(self):
        self.skills(1)
        proj = self.project()
        hk = os.path.join(self.home, ".grok"); os.makedirs(hk)
        other = os.path.join(self.ws, "projects", "relay-old"); os.makedirs(other)
        open(os.path.join(hk, "hooks.json"), "w").write(json.dumps({"hooks": {"PreToolUse": [{"command": f"node {other}/hook.js"}]}}))
        self.audit()
        self.assertEqual([x for x, _ in self.d002()], [wt.TIP])

    def test_the_package_also_sits_in_an_unused_project_that_sorts_first(self):
        self.skills(1)
        proj = self.project()
        old = os.path.join(self.ws, "projects", "aaa-old"); os.makedirs(old)
        lock_old = os.path.join(old, "package-lock.json"); open(lock_old, "w").write("{}")
        pk = OSV_DATA["results"][0]["packages"]
        osv = json.dumps({"results": [{"source": {"path": lock_old}, "packages": pk},
                                      {"source": {"path": os.path.join(proj, "package-lock.json")}, "packages": pk}]})
        self.scanners(osv_scanner="#!/bin/sh\ncat <<'EOF'\n" + osv + "\nEOF\n")
        hk = os.path.join(self.home, ".grok"); os.makedirs(hk)
        open(os.path.join(hk, "hooks.json"), "w").write(json.dumps({"hooks": {"PreToolUse": [{"command": f"node {proj}/hook.js"}]}}))
        self.audit()
        self.assertEqual(self.d002(), [(wt.CONFIRMED, "high")])


if __name__ == "__main__":
    unittest.main()
