"""Hardening batch 3, roadmap row 8 (Oct 16 review R3: platform folders).

A lone file planted in ~/.grok/bundled became a low WT-I002, folded into the "Platform refresh" Tip and was re-baselined at the
next full audit without a word. Grok Bot updates its own folders many files at a time; a planted skill is usually one or two
files. Now fewer than 3 fresh changes under one platform folder in one check are a lone change: each new or changed file is a
high alert until the owner says "fix it", and it stays one (by path) until it is approved or gone.

builtin() and is_vendor() also matched substrings (/plugins/, /managed-skills/...), so a user's own skill under
workflows/x/managed-skills/ had its high "changed" alert rolled away as a built-in update. Those checks are now prefixes of
the real vendor folders, with the user's own folders excluded.
"""
import json, os, sys, unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import Box, wt  # noqa: E402
from test_watchtower import fake_key  # noqa: E402
import test_dq042_vendor_skills as dq042  # noqa: E402

CLEAN = "---\nname: {n}\ndescription: Helps with {n}.\n---\nSummarize the notes for the user. Ask before saving.\n"


def put(p, t):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as f:
        f.write(t)


def add(p, t):
    with open(p, "a") as f:
        f.write(t)


class _Platform(Box):
    REL = ".grok/bundled/skills"

    def setUp(self):
        super().setUp()
        self.root = os.path.join(self.home, self.REL)
        for n in ("alpha", "beta", "gamma"):
            put(self.md(n), CLEAN.format(n=n))
        self.skills(1)                                                          # one of the owner's own

    def md(self, n):
        return os.path.join(self.root, n, "SKILL.md")

    def start(self, **fakes):
        self.scanners(**fakes)
        self.audit()                                                            # the first audit takes the baseline
        self.assertEqual(wt.load_baseline()[1], "ok")

    def daily(self):
        return self.run_cmd("daily", "--roots", *self.roots)[1].strip()

    def at(self, rule, path):
        return [f for f in self.snap()["findings"] if f["rule"] == rule and f["where"] == path]


class _LoneNewFile:
    def test_1_a_lone_new_file_is_a_high_alert(self):
        self.start()
        p = os.path.join(self.root, "helper", "SKILL.md")
        put(p, CLEAN.format(n="helper"))
        self.assertNotEqual(self.daily(), "NO_CHANGES")
        x = self.at("WT-I002", p)
        self.assertEqual(len(x), 1)
        self.assertEqual((x[0]["severity"], x[0]["label"], x[0].get("lone")), ("high", wt.CONFIRMED, True))
        self.assertTrue(wt.counts(x[0]))
        self.assertIn("on its own", x[0]["title"])
        self.assertFalse([f for f in self.snap()["findings"] if f["rule"] == "WT-I008"])
        self.audit()                                                            # a full audit doesn't roll it into the baseline
        self.assertEqual(len(self.at("WT-I002", p)), 1)
        self.assertNotIn(p, wt.load_baseline()[0])
        out = json.loads(self.run_cmd("fix", "--roots", *self.roots)[1])
        self.assertIn("helper", [s.get("name") for s in out.get("changed_skills", [])])   # offered for "fix it" (re-scan, re-approve)
        self.run_cmd("fix", "--revet", "--only", "helper", "--roots", *self.roots)
        self.assertIn(p, wt.load_baseline()[0])
        self.audit()
        self.assertEqual(self.at("WT-I002", p), [])


class BundledLoneNewFile(_LoneNewFile, _Platform):
    REL = ".grok/bundled/skills"


class ManagedLoneNewFile(_LoneNewFile, _Platform):
    REL = "agent-data/managed-skills"


class LoneEdits(_Platform):
    def test_2a_one_edit_on_its_own_is_a_high_alert(self):
        self.start()
        add(self.md("alpha"), "One more line.\n")
        self.assertNotEqual(self.daily(), "NO_CHANGES")
        x = self.at("WT-I001", self.md("alpha"))
        self.assertEqual([(f["severity"], f.get("lone")) for f in x], [("high", True)])
        self.assertTrue(wt.counts(x[0]))

    def test_2b_two_edits_are_still_lone(self):
        self.start()
        add(self.md("alpha"), "One more line.\n"); add(self.md("beta"), "One more line.\n")
        self.audit()
        for n in ("alpha", "beta"):
            self.assertEqual([(f["severity"], f.get("lone")) for f in self.at("WT-I001", self.md(n))], [("high", True)], n)


class RoutineUpdate(_Platform):
    def test_3_contrast_a_routine_update_is_one_platform_line(self):
        """DQ-042 guard, not a replay: a routine update is one Platform line, not an alert. It no longer passes on base: since
        Codex round 1 the update waits for the owner's yes in the fix (base rolled it in at the next full audit)."""
        self.start()
        add(self.md("alpha"), "Updated.\n"); add(self.md("beta"), "Updated.\n")
        put(os.path.join(self.root, "gamma", "references", "guide.md"), "# Guide\nMore detail.\n")
        self.assertEqual(self.daily(), "NO_CHANGES")
        fs = self.snap()["findings"]
        self.assertEqual(len([f for f in fs if f["rule"] == "WT-I008"]), 1)
        self.assertFalse([f for f in fs if f["severity"] in ("critical", "high") and self.root in f["where"]])
        # Codex, batch 3 round 1 (planned assertion change): an audit no longer approves it on its own; it stays the one Tip,
        # out of the baseline, until the owner's yes in the fix. Then nothing is left, as before.
        self.audit()
        self.assertEqual(len([f for f in self.snap()["findings"] if f["rule"] == "WT-I008"]), 1)
        self.assertNotEqual(wt.load_baseline()[0].get(self.md("alpha")), wt.sha256_file(self.md("alpha")))
        out = json.loads(self.run_cmd("fix", "--roots", *self.roots)[1])
        self.assertEqual(out["platform_update"]["files"], 3)
        self.run_cmd("fix", "--apply", "--owner-said-yes", "--roots", *self.roots)
        self.audit()
        self.assertFalse([f for f in self.snap()["findings"] if f["rule"] in ("WT-I001", "WT-I002", "WT-I008")])

    def test_4_contrast_a_partly_rolled_update_stays_quiet(self):
        """Contrast (passes on base too; on this branch the carried-bundle memory is what keeps it quiet): a 4-file update where
        one skill is flagged by the engines in wording-only terms (DQ-042). The full audit rolls the other three; the flagged
        one stays out of the baseline, and the next daily must not turn it into a lone high."""
        learn = os.path.join(self.root, "learn", "SKILL.md")
        put(learn, dq042.LEARN_V1)
        self.start(skillspector=dq042.skillspector(dq042.LEARN_ISSUES), husk=dq042.husk(dq042.LEARN_HUSK))
        put(learn, dq042.LEARN_V2)
        put(os.path.join(self.root, "learn", "references", "lessons.md"), "# Lessons\n")
        add(self.md("alpha"), "Updated.\n"); add(self.md("beta"), "Updated.\n")
        self.audit()
        base = wt.load_baseline()[0]
        self.assertIn(self.md("alpha"), base)
        self.assertNotEqual(base.get(learn), wt.sha256_file(learn))           # the flagged skill wasn't rolled
        self.assertEqual(self.daily(), "NO_CHANGES")
        self.assertFalse([f for f in self.snap()["findings"] if f.get("lone")])


class StickyLone(_Platform):
    def test_5_a_later_update_never_folds_a_plant_into_its_tip(self):
        self.start()
        p = os.path.join(self.root, "helper", "SKILL.md")
        put(p, CLEAN.format(n="helper"))
        self.daily()
        self.assertEqual([f["severity"] for f in self.at("WT-I002", p)], ["high"])
        for n in ("alpha", "beta", "gamma"):                                    # day 2: a real 5-file refresh, which also edits the plant
            add(self.md(n), "Updated.\n")
        put(os.path.join(self.root, "alpha", "references", "a.md"), "# A\n")
        put(os.path.join(self.root, "beta", "references", "b.md"), "# B\n")
        add(p, "Edited with the refresh.\n")
        out = self.daily()
        x = self.at("WT-I002", p)
        self.assertEqual([(f["severity"], f.get("lone")) for f in x], [("high", True)])
        fixed = [] if out == "NO_CHANGES" else json.loads(out).get("fixed", [])   # the plant's alert is the same open one
        self.assertFalse([f for f in fixed if f["where"] == p])
        tip = [f for f in self.snap()["findings"] if f["rule"] == "WT-I008"]
        self.assertEqual(len(tip), 1)
        self.assertIn("5 of Grok Bot's own files changed", tip[0]["title"])


class SubstringBypass(Box):
    def test_7_a_user_folder_named_like_a_vendor_folder_still_alerts(self):
        wf = os.path.join(self.home, "sand-data", "workflows")
        a = os.path.join(wf, "x", "managed-skills", "SKILL.md")
        b = os.path.join(wf, "y", "plugins", "z", "SKILL.md")
        put(a, CLEAN.format(n="x")); put(b, CLEAN.format(n="z"))
        self.scanners()
        self.audit()
        add(a, "One more line.\n"); add(b, "One more line.\n")
        r = self.audit()
        self.assertFalse([n for n in r["notes"] if "accepted automatically" in n], r["notes"])
        changed = {f["where"] for f in self.snap()["findings"] if f["rule"] == "WT-I001" and f["severity"] == "high"}
        self.assertEqual(changed, {a, b})
        for p in (a, b):
            self.assertFalse(wt.builtin({"where": p}))
            self.assertFalse(wt.is_vendor(p))


class OutsideTheHomeFolders(Box):
    def test_8_a_plugins_folder_in_a_project_gets_full_rules(self):
        p = os.path.join(self.ws, "proj", "plugins", "x", "SKILL.md")
        put(p, CLEAN.format(n="x"))
        self.assertFalse(wt.is_vendor(p))
        self.assertFalse(wt.builtin({"where": p}))
        self.scanners()
        self.audit()
        add(p, "One more line.\n")
        self.audit()
        self.assertEqual([f["severity"] for f in self.snap()["findings"] if f["rule"] == "WT-I001" and f["where"] == p], ["high"])

    def test_8_a_key_in_a_project_named_like_grok_bots_config_counts(self):
        p = os.path.join(self.ws, "p", "sand-data", "gateway.json")
        put(p, '{\n "url": "https://gw.internal.example",\n "token": "ghp_' + fake_key(36) + '"\n}\n')
        self.assertFalse(wt.platform_file({"where": p + ":3"}))
        self.audit()
        s = [f for f in self.snap()["findings"] if f["rule"] in ("WT-S001", "WT-S002") and f["where"].startswith(p)]
        self.assertTrue(s)
        # Its full severity, like a key-shaped string anywhere else (unverified, so Worth a look), never "the platform's own token"
        self.assertEqual((s[0].get("severity_was", s[0]["severity"]), s[0]["title"]), ("critical", "Secret stored in a file on the shared computer"), s[0])
        self.assertNotEqual(s[0].get("scope"), "platform")
        self.assertTrue(wt.counts(s[0]))

    def test_8_contrast_grok_bots_own_config_is_still_its_own(self):
        """Contrast: passes on base too."""
        p = os.path.join(self.home, "sand-data", "gateway.json")
        put(p, '{\n "url": "https://gw.internal.example",\n "token": "Ya2u' + "Q7xLp3ZtV9" * 4 + '"\n}\n')
        f = wt.finding("WT-S001", "x", "critical", ["ASI03"], p + ":3", "e", "f")
        self.assertTrue(wt.platform_file(f))
        self.assertFalse(wt.counts(f))
        self.assertTrue(wt.platform_file({"where": "/home/box/sand-data/teach-queue-key.json:3"}))


class VendorRoots(Box):
    def check(self, path, want):
        fn = getattr(wt, "vendor_root_path", None)
        self.assertTrue(callable(fn))
        self.assertEqual(bool(fn(path)), want, path)
        self.assertEqual(bool(wt.builtin({"where": path})), want, path)

    def test_9_real_vendor_folders(self):
        for rel in ("sand-data/plugins/acme/skills/a/SKILL.md", ".agents/skills/a", ".grok/bundled/skills/a/SKILL.md",
                    "agent-data/managed-skills/a/SKILL.md:3", ".codex/skills/a/SKILL.md", ".claude/plugins/x/SKILL.md"):
            self.check(os.path.join(self.home, rel), True)
        self.check("/home/box/sand-data/plugins/cache/cursor-public/vercel/abc/skills/env/SKILL.md", True)

    def test_9_lookalikes_and_links_are_not(self):
        put(os.path.join(self.home, ".grok", "bundled-evil", "skills", "a", "SKILL.md"), "x")
        self.check(os.path.join(self.home, ".grok", "bundled-evil", "skills", "a", "SKILL.md"), False)
        outside = os.path.join(self.tmp, "elsewhere", "a")
        put(os.path.join(outside, "SKILL.md"), "x")
        bundled = os.path.join(self.home, ".grok", "bundled", "skills")
        os.makedirs(bundled, exist_ok=True)
        os.symlink(outside, os.path.join(bundled, "sneaky"))                    # a link in a vendor folder that leads out
        self.check(os.path.join(bundled, "sneaky", "SKILL.md"), False)
        put(os.path.join(bundled, "real", "SKILL.md"), "x")
        os.symlink(os.path.join(bundled, "real"), os.path.join(self.tmp, "elsewhere", "in"))   # a link elsewhere that leads in
        self.check(os.path.join(self.tmp, "elsewhere", "in", "SKILL.md"), False)
        self.check(os.path.join(self.home, "sand-data", "workflows", "x", "plugins", "y", "SKILL.md"), False)   # a user folder named plugins
        self.check(os.path.join(self.home, "sand-data", "workflows", "x", ".grok", "bundled", "s", "SKILL.md"), False)
        self.check(os.path.join(self.home, "sand-data", "plugins"), False)       # the root itself is not inside it
        self.check("/workspace/proj/plugins/x/SKILL.md", False)


if __name__ == "__main__":
    unittest.main()
