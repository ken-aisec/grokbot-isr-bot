"""b8i4, F1 (Claude review Oct 23): .claude/plugins/synced/<bucket>/ holds every plugin synced to the account, the ones the owner
installs from marketplaces included; the release list names only cowork-plugin-management. There the middle path is only for an
update of a path the release list names (a `<bucket>` line or an exact line): a new plugin, a new file in one, or a path only the
baseline has stays the counted high it was in v0.7.3. Other platform folders are unchanged.

Each test marked R in its docstring fails on 4872a9b (watchtower/ stashed) at an assertion; G is a guard that passes there and
here.
"""
import os, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_boxes  # noqa: E402
import isr  # noqa: E402
from test_item8_provenance import CLEAN, put, add  # noqa
from test_b8i4_middle_path import _Middle  # noqa
from test_item8_provenance import sha  # noqa: E402
from test_b8i4_fix_round1 import A_PAIR, B_PAIR  # noqa: E402
import profiles  # noqa: E402


class SyncedMarketplacePluginNeverQuiet(_Middle):
    """R (Claude review Oct 23): .claude/plugins/synced also holds plugins the owner installs from marketplaces. A plugin the
    release list doesn't name is never a quiet 'Claude's own files' refresh: new, or updated."""

    def plug(self, name="someplug"):
        return os.path.join(self.home, ".claude", "plugins", "synced", "a1_b2", name, "skills", "x", "SKILL.md")

    def test_new_marketplace_plugin_is_counted(self):
        self.start()
        p = self.plug()
        put(p, CLEAN.format(n="x"))
        self.assertNotEqual(self.daily(), "NO_CHANGES")
        self.audit()
        self.assertIn(p, self.unverified())
        self.assertNotIn(p, isr.load_baseline()[0])
        self.assertFalse(any(self.rel(p) in (t.get("files") or []) for t in self.tip()))

    def test_new_file_in_marketplace_plugin_after_update_is_counted(self):
        self.start()
        p = self.plug()
        put(p, CLEAN.format(n="x"))
        self.audit(); self.audit()
        q = os.path.join(os.path.dirname(p), "extra.md")
        add(p, "See extra.md.\n"); put(q, "More notes.\n")
        self.audit()
        self.assertIn(p, self.unverified())
        self.assertIn(q, self.unverified())

    def test_baseline_only_marketplace_plugin_update_is_counted(self):
        """R: a marketplace plugin that got into the baseline (an older run rolled it, or the Bot wrote the line) and is then
        updated cleanly: daily isn't quiet, the audit holds it as a counted high outside the Platform refresh line, and the
        baseline keeps its old bytes (4872a9b: the baseline-only "update" made it quiet and rolled it in)."""
        self.start()
        p = self.plug()
        put(p, CLEAN.format(n="x"))
        v1 = sha(p)
        isr.save_baseline(dict(isr.load_baseline()[0], **{p: v1}))
        add(p, "Version 2.\n")
        self.assertNotEqual(self.daily(), "NO_CHANGES")
        self.audit()
        self.assertEqual(len(self.counted_high(p)), 1)
        self.assertIn(p, self.unverified())
        self.assertEqual(isr.load_baseline()[0][p], v1)
        self.assertFalse(any(self.rel(p) in (t.get("files") or []) for t in self.tip()))


class SyncedReleaseListedStaysQuiet(_Middle):
    def test_listed_cowork_file_update_in_any_bucket_is_quiet(self):
        """G: cowork-plugin-management's SKILL.md in two buckets, both listed by one `<bucket>` line: a clean update of each is
        the quiet Platform refresh line, and the next full audit rolls both in."""
        synced = os.path.join(self.home, ".claude", "plugins", "synced")
        rel = os.path.join("cowork-plugin-management", "skills", "manage", "SKILL.md")
        a, b = os.path.join(synced, A_PAIR, rel), os.path.join(synced, B_PAIR, rel)
        put(a, CLEAN.format(n="manage")); put(b, CLEAN.format(n="manage"))
        profiles.vendor_release(self, (os.path.join(synced, "<bucket>", rel), CLEAN.format(n="manage")))
        self.start()
        add(a, "One more line.\n"); add(b, "One more line.\n")
        self.assertEqual(self.daily(), "NO_CHANGES")
        self.quiet(a, b)
        self.audit()
        self.assertEqual((isr.load_baseline()[0][a], isr.load_baseline()[0][b]), (sha(a), sha(b)))


class ManagedSkillsStayPlatform(_Middle):
    def pair(self):
        s = os.path.join(self.home, "sand-data", "managed-skills", "x", "SKILL.md")
        g = os.path.join(self.home, "agent-data", "managed-skills", "x", "SKILL.md")
        put(s, CLEAN.format(n="x")); put(g, CLEAN.format(n="x"))
        return s, g

    def test_listed_managed_skill_update_is_quiet(self):
        """G: a clean update of a listed managed skill at sand-data and agent-data managed-skills is the quiet line."""
        s, g = self.pair()
        profiles.vendor_release(self, s, g)
        self.start()
        add(s, "One more line.\n"); add(g, "One more line.\n")
        self.assertEqual(self.daily(), "NO_CHANGES")
        self.quiet(s)
        self.assertEqual((self.counted_high(g), g in self.unverified()), ([], False))

    def test_new_then_baseline_only_managed_skill_update_is_quiet(self):
        """G: an unlisted new managed skill in an update run is quiet and rolls in; its next clean update (a path only the
        baseline has) is quiet too: the synced rule doesn't reach managed-skills."""
        self.start()
        s, g = self.pair()
        self.assertEqual(self.daily(), "NO_CHANGES")
        self.audit()
        self.assertEqual((isr.load_baseline()[0].get(s), isr.load_baseline()[0].get(g)), (sha(s), sha(g)))
        add(s, "Version 2.\n"); add(g, "Version 2.\n")
        self.assertEqual(self.daily(), "NO_CHANGES")
        self.quiet(s)
        self.assertEqual((self.counted_high(g), g in self.unverified()), ([], False))


if __name__ == "__main__":
    unittest.main()
