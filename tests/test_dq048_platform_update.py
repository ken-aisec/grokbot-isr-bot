"""DQ-048 (2026-10-23, Watchtower daily watch): a vendor platform update dropped the installed v0.7.3's daily score 85 -> 21.

The real run (`isr.py daily`, v0.7.3, 6:02 AM ET): 62 high ISR-I001/ISR-I002 `platform_unverified` files, all routine vendor
updates: Grok Bot's managed skills under sand-data/ and agent-data/managed-skills/skills/* (e.g. sign-in/SKILL.md sha256
329d4f59c94d -> 29439432e18b, routines/SKILL.md 9da244f643c6 -> 31dc58ae4565) and agent-data/managed-skills/cache.json,
.grok/bundled/skills/learn/* and .grok/bundled/manifest.json, Codex's .codex/skills/.system/openai-docs/*; the same day the
cursor-public catalog folder moved d1453c11... -> 9b93e81f... and pstack went 0.15.29 -> 0.15.30.

Replay only (test-only, v0.7.4): the same paths and shape through the b8i4 middle path. Each file was already on disk (in the
baseline) and its update is clean, so the run gets the one quiet Platform refresh line, no counted high and no score drop. The old bytes are on the
platform list (the real box's score was 85, none of these held). The
file bodies are stand-ins at the real relative paths (only "clean update at a path that already exists" matters). The empty-new
trim and the missing why_it_dropped seen in that run are logged as the next batch (dq-proposed), not tested here.
"""
import json, os, sys, unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import wt  # noqa: E402
from test_item8_provenance import CLEAN, add, put  # noqa: E402
from test_b8i4_middle_path import _Middle  # noqa: E402
import profiles  # noqa: E402
import test_dq047_catalog_move as dq047  # noqa: E402

OLD = "d1453c11d1dde9714d4c313c97d3a68432265c7f"   # the catalog folder after DQ-047's move (Oct 22)
NEW = "9b93e81f"                                   # the Oct 23 folder (the queue gives the prefix)
MANAGED = ("sign-in", "routines")


class DQ048VendorPlatformUpdate(_Middle):
    def files(self):
        h = self.home
        ms = [os.path.join(h, d, "managed-skills", "skills", s, "SKILL.md") for d in ("sand-data", "agent-data") for s in MANAGED]
        return {
            "managed": ms,
            "managed_cache": os.path.join(h, "agent-data", "managed-skills", "cache.json"),
            "learn": [os.path.join(h, ".grok", "bundled", "skills", "learn", n) for n in ("SKILL.md", "reference.md")],
            "bundled_manifest": os.path.join(h, ".grok", "bundled", "manifest.json"),
            "openai_docs": [os.path.join(h, ".codex", "skills", ".system", "openai-docs", n) for n in ("SKILL.md", "LICENSE.txt")],
        }

    def flat(self, fs):
        return [p for v in fs.values() for p in (v if isinstance(v, list) else [v])]

    def catalog(self, folder, ver):
        root = os.path.join(self.home, "sand-data", "plugins", "cache", "cursor-public", "pstack", folder)
        put(os.path.join(root, "plugin.json"), dq047.PSTACK_PLUGIN_JSON.replace('"0.15.29"', f'"{ver}"'))
        put(os.path.join(root, ".cursor-plugin", "plugin.json"), dq047.PSTACK_CURSOR_PLUGIN_JSON.replace('"0.15.29"', f'"{ver}"'))
        for s in dq047.PSTACK_SKILLS:
            put(os.path.join(root, "skills", s, "SKILL.md"), f"---\nname: {s}\ndescription: pstack {s}.\n---\nPlan first. Ask before changing files.\n")
        return root

    def test_the_dq048_vendor_update_is_the_quiet_refresh_line(self):
        fs = self.files()
        for p in fs["managed"]:
            put(p, CLEAN.format(n=os.path.basename(os.path.dirname(p))))
        put(fs["managed_cache"], '{"version": 7, "skills": {"sign-in": {"name": "sign-in", "body": "Sign the user in."}}}\n')
        for p in fs["learn"] + fs["openai_docs"]:
            put(p, CLEAN.format(n=os.path.basename(os.path.dirname(p))) if p.endswith("SKILL.md") else "Notes for this skill.\n")
        put(fs["bundled_manifest"], '{"version": "1.0.0", "skills": ["learn"]}\n')
        profiles.vendor_release(self, *self.flat(fs))    # the old bytes are on the platform list, as on the real box (score 85)
        old = self.catalog(OLD, "0.15.29")               # the catalog copies stay open lows, as after DQ-047 (never accepted)
        self.start()
        self.audit()
        before = self.snap()
        high0 = self.snap_counts()["high"]
        for p in self.flat(fs):                           # before the update: none held, none a counted high
            self.assertEqual(self.counted_high(p), [], p)
            self.assertNotIn(p, self.unverified(), p)

        # the overnight vendor update
        for p in fs["managed"] + fs["learn"] + fs["openai_docs"]:
            add(p, "Updated by the vendor.\n")
        put(fs["managed_cache"], '{"version": 8, "skills": {"sign-in": {"name": "sign-in", "body": "Sign the user in again."}}}\n')
        put(fs["bundled_manifest"], '{"version": "1.0.1", "skills": ["learn"]}\n')
        os.rename(old, os.path.join(os.path.dirname(old), NEW))
        self.catalog(NEW, "0.15.30")

        out = self.daily()
        after = self.snap()
        daily_out = None if out == "NO_CHANGES" else json.loads(out)
        every = self.flat(fs)
        for p in every:
            self.assertEqual(self.counted_high(p), [], p)
            self.assertNotIn(p, self.unverified(), p)
        self.assertEqual(self.snap_counts()["high"], high0, [(f["rule"], f["where"]) for f in after["findings"] if f["severity"] == "high" and wt.counts(f)])
        if daily_out is not None:
            self.assertEqual((daily_out.get("platform_unverified") or {}).get("open", 0), 0, daily_out.get("platform_unverified"))
        self.assertGreaterEqual(after["score"], before["score"], (before["score"], after["score"]))
        tip = self.tip()
        self.assertEqual(len(tip), 1, [f["title"] for f in after["findings"]])
        self.assertEqual(tip[0]["severity"], "info")
        self.assertIn("Grok Bot's own files changed", tip[0]["title"])
        self.assertIn("Codex's", tip[0]["title"])
        named = set(tip[0].get("files", []))
        for p in fs["learn"] + fs["openai_docs"] + [fs["bundled_manifest"]] + fs["managed"][:len(MANAGED)]:
            self.assertIn(self.rel(p), named, p)


if __name__ == "__main__":
    unittest.main()
