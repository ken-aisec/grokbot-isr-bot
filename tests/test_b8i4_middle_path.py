"""b8i4 (v0.7.4 item 4): the platform-file middle path.

The Oct 18 rule (a platform file is trusted only by its path and sha256 in rules/platform-release.lock) made every routine
Grok Bot, Codex or Claude update a counted high per file, on every box, every day: versions differ per user, so the shipped
lock can't be the only source of trust. Decision, Oct 22: a clean update at a path that already exists (on the release list
or in the baseline), or a clean new platform skill folder, gets the quiet "Platform refresh" line and rolls into the baseline
on the next full audit. Anything risky stays a counted high: a file Watchtower's rules flag, one over 1 MB or unreadable, one
two scanners name a dangerous behavior in (or whose scanner answer is out of date), a loose file, a link in or out, a colon
in its path, an unusable release list, a new file in a skill folder nobody updated this run.

Each test marked R in its docstring fails on f7c28e6 (watchtower/ and the lock stashed) at an assertion; G is a guard that
passes there and here.
"""
import hashlib, json, os, sys, unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import Box, wt  # noqa: E402
from test_item8_provenance import CLEAN, FLAGGED, SWAP_ENGINE, _Platform, add, put, sha  # noqa: E402
import profiles  # noqa: E402
import test_dq042_vendor_skills as dq042  # noqa: E402


class _Middle(_Platform):
    def rel(self, p):
        return os.path.relpath(p, self.home)

    def unverified(self):
        return sorted(f["where"] for f in self.snap()["findings"] if f.get("unverified_platform"))

    def high_count(self):
        return self.snap_counts()["high"]

    def snap_counts(self):
        return {s: sum(1 for f in self.snap()["findings"] if f["severity"] == s and wt.counts(f)) for s in ("critical", "high")}

    def quiet(self, *paths):
        """Each path has no counted high and no held finding, and the one Platform refresh line names it."""
        tip = self.tip()
        self.assertEqual(len(tip), 1, [f["title"] for f in self.snap()["findings"]])
        for p in paths:
            self.assertEqual(self.counted_high(p), [], p)
            self.assertNotIn(p, self.unverified(), p)
            self.assertIn(self.rel(p), tip[0].get("files", []), p)
        return tip[0]


class CleanUpdates(_Middle):
    def test_clean_update_at_listed_path_is_quiet(self):
        """R: on f7c28e6 alpha's routine update is a counted high and daily isn't quiet."""
        self.start()
        add(self.md("alpha"), "One more line.\n")
        self.assertEqual(self.daily(), "NO_CHANGES")
        tip = self.quiet(self.md("alpha"))
        self.assertIn("1 of Grok Bot's own files changed", tip["title"])
        self.assertEqual(self.unverified(), [])

    def test_quiet_update_rolls_in_on_full_audit(self):
        """R: on f7c28e6 the baseline keeps alpha's old bytes."""
        self.start()
        add(self.md("alpha"), "One more line.\n")
        self.daily()
        self.audit()
        self.assertEqual(wt.load_baseline()[0][self.md("alpha")], sha(self.md("alpha")))
        self.audit()
        self.assertEqual(self.at(self.md("alpha")), [])
        self.assertFalse(self.tip())

    def test_baseline_only_path_update_is_quiet(self):
        """R: a path only the baseline has (a clean new skill folder that rolled in) updates quietly, twice."""
        self.start()
        p = self.md("helper")
        put(p, CLEAN.format(n="helper"))
        self.audit()
        self.assertEqual(wt.load_baseline()[0].get(p), sha(p))
        for v in ("Version 2.\n", "Version 3.\n"):
            add(p, v)
            self.assertEqual(self.daily(), "NO_CHANGES", v)
            self.quiet(p)
            self.audit()
            self.assertEqual(wt.load_baseline()[0].get(p), sha(p), v)

    def test_first_run_clean_file_at_listed_path_raises_nothing(self):
        """R: a new box whose alpha is a newer version than the release list's: no counted high, not in the first baseline, and the
        second full audit rolls it in (on f7c28e6 it is a counted high on every run)."""
        add(self.md("alpha"), "A newer version than the release list's.\n")
        self.start()
        self.assertEqual(self.counted_high(self.md("alpha")), [])
        self.assertNotIn(self.md("alpha"), self.unverified())
        self.assertNotIn(self.md("alpha"), wt.load_baseline()[0])
        self.audit()
        self.assertEqual(wt.load_baseline()[0].get(self.md("alpha")), sha(self.md("alpha")))

    def test_tip_names_vendor_per_root(self):
        """R: one Platform refresh line with each vendor's count, and both paths in `files`."""
        img = os.path.join(self.home, ".codex", "skills", ".system", "imagegen", "SKILL.md")
        put(img, CLEAN.format(n="imagegen"))
        profiles.vendor_release(self, img)
        self.start()
        add(self.md("alpha"), "One more line.\n"); add(img, "One more line.\n")
        self.assertEqual(self.daily(), "NO_CHANGES")
        tip = self.quiet(self.md("alpha"), img)
        self.assertIn("1 of Grok Bot's own files changed, 1 of Codex's", tip["title"])
        self.assertIn("Codex", tip["fix"])

    def test_new_file_in_skill_with_same_run_update_is_quiet(self):
        """R: a new file in alpha's folder, in the same run as a clean update of alpha's SKILL.md (decision D1)."""
        self.start()
        extra = os.path.join(self.root, "alpha", "extra.md")
        add(self.md("alpha"), "See extra.md.\n")
        put(extra, "More notes for alpha.\n")
        self.assertEqual(self.daily(), "NO_CHANGES")
        self.quiet(self.md("alpha"), extra)

    def test_daily_lists_only_held_files(self):
        """R: daily's platform_unverified lists the loose plant, not alpha's clean update."""
        self.start()
        plant = self.loose()
        put(plant, CLEAN.format(n="helper"))
        add(self.md("alpha"), "One more line.\n")
        out = json.loads(self.daily())
        self.assertEqual([f["where"] for f in out["platform_unverified"]["files"]], [plant])
        self.assertEqual(out["platform_unverified"]["open"], 1)

    def test_unscanned_types_are_scanned_first(self):
        """R: a .xsd file (no text extension, so the skill scan only fingerprints it) is read and checked before it is quiet."""
        x = os.path.join(self.root, "alpha", "schema.xsd")
        put(x, "<schema/>\n")
        profiles.vendor_release(self, x)
        self.start()
        put(x, "<schema><element name='notes'/></schema>\n")
        self.assertEqual(self.daily(), "NO_CHANGES")
        self.quiet(x)


class NewSkillFolders(_Middle):
    def test_new_clean_skill_folder_is_quiet(self):
        """R: a clean new skill folder in a platform folder is one Platform refresh line, and the full audit rolls both files in."""
        self.start()
        md, ref = self.md("helper"), os.path.join(self.root, "helper", "ref.md")
        put(md, CLEAN.format(n="helper")); put(ref, "Notes for the helper.\n")
        self.assertEqual(self.daily(), "NO_CHANGES")
        tip = self.quiet(md, ref)
        self.assertIn("helper", tip["title"])
        self.audit()
        base = wt.load_baseline()[0]
        self.assertEqual((base.get(md), base.get(ref)), (sha(md), sha(ref)))

    def test_new_skill_folder_with_one_flagged_file_is_all_high(self):
        """G: one flagged file holds the whole new folder."""
        self.start()
        md, ref = self.md("helper"), os.path.join(self.root, "helper", "ref.md")
        put(md, CLEAN.format(n="helper")); put(ref, FLAGGED.format(n="helper"))
        self.audit()
        for p in (md, ref):
            self.assertEqual(len(self.counted_high(p)), 1, p)
        base = wt.load_baseline()[0]
        self.assertNotIn(md, base); self.assertNotIn(ref, base)

    def test_new_file_in_skill_alone_is_high(self):
        """G: a new file in an existing skill folder that wasn't updated this run (decision D1)."""
        self.start()
        extra = os.path.join(self.root, "alpha", "extra.md")
        put(extra, "More notes for alpha.\n")
        self.assertNotEqual(self.daily(), "NO_CHANGES")
        x = self.counted_high(extra)
        self.assertEqual([f["rule"] for f in x], ["ISR-I002"])

    def test_loose_new_file_is_high(self):
        """G: a file in a platform folder outside any skill folder, at no existing path."""
        self.start()
        p = self.loose()
        put(p, CLEAN.format(n="helper"))
        self.assertNotEqual(self.daily(), "NO_CHANGES")
        self.assertEqual(len(self.counted_high(p)), 1)
        self.audit()
        self.assertNotIn(p, wt.load_baseline()[0])

    def test_first_run_loose_file_is_high(self):
        """G: a loose file on a new box."""
        p = self.loose()
        put(p, CLEAN.format(n="helper"))
        self.start()
        self.assertEqual(len(self.counted_high(p)), 1)
        self.assertNotIn(p, wt.load_baseline()[0])


class StillHigh(_Middle):
    def test_flagged_update_is_counted_high(self):
        """G: an update Watchtower's rules flag."""
        self.start()
        v1 = sha(self.md("alpha"))
        put(self.md("alpha"), FLAGGED.format(n="alpha"))
        out = json.loads(self.daily())
        self.assertIn(self.md("alpha"), [f["where"] for f in out["platform_unverified"]["files"]])
        x = self.counted_high(self.md("alpha"))
        self.assertEqual([f["rule"] for f in x], ["ISR-I001"])
        self.assertEqual(x[0]["title"], "One of Grok Bot's own files changed, and the new version isn't on Grok Bot's release list")
        self.audit()
        self.assertEqual(wt.load_baseline()[0][self.md("alpha")], v1)
        self.assertNotIn(self.rel(self.md("alpha")), (self.tip() or [{}])[0].get("files", []))

    def test_lock_path_with_other_bytes_flagged_is_high(self):
        """G: a path on the release list with flagged bytes it doesn't list."""
        p = self.md("helper")
        profiles.vendor_release(self, (p, CLEAN.format(n="helper")))
        self.start()
        put(p, FLAGGED.format(n="helper"))
        self.audit()
        self.assertEqual(len(self.counted_high(p)), 1)
        self.assertNotIn(p, wt.load_baseline()[0])

    def test_dangerous_engine_kind_holds_update(self):
        """G: two scanners name a dangerous behavior (the harness fakes: "Exfil: Upload" and "obfuscated loader") in alpha's folder."""
        self.start()
        v1 = sha(self.md("alpha"))
        add(self.md("alpha"), "Release notes: EVIL HUSK.\n")
        self.audit()
        x = [f for f in self.snap()["findings"] if f["rule"] == "ISR-X003" and f["where"] == os.path.dirname(self.md("alpha"))]
        self.assertEqual(len(x), 1)
        self.assertEqual(len(self.counted_high(self.md("alpha"))), 1)
        self.assertEqual(wt.load_baseline()[0][self.md("alpha")], v1)

    def test_kinds_incomplete_holds_update(self):
        """G: an engine answer that is out of date (kinds_incomplete) never lets an update through."""
        d = os.path.join(self.root, "learn")
        md = os.path.join(d, "SKILL.md")
        put(md, dq042.LEARN_V1)
        profiles.vendor_release(self, md)
        self.start(skillspector=dq042.skillspector(dq042.FIFTH_ISSUES[:4]), husk=dq042.husk(dq042.LEARN_HUSK))
        put(md, dq042.LEARN_V2)
        self.daily()
        p = wt.state_path("engine_cache.json")
        cache = wt.load_json(p, {})
        cache[d]["ss"].pop("kinds", None)                                       # an answer from before DQ-042 read every kind
        wt.save_json(p, cache)
        self.audit("--budget", "0")
        x = [f for f in self.snap()["findings"] if f["rule"] == "ISR-X003" and f["where"] == d]
        self.assertEqual([f.get("kinds_incomplete") for f in x], [True])
        self.assertEqual(len(self.counted_high(md)), 1)
        self.assertEqual(wt.load_baseline()[0][md], hashlib.sha256(dq042.LEARN_V1.encode()).hexdigest())

    def test_unusable_lock_disables_quiet_path(self):
        """G: one bad line makes the release list unusable, and with it the quiet path (decision D4)."""
        self.start()
        add(self.md("alpha"), "One more line.\n")
        with open(self.platform_lock, "a") as f:
            f.write(f"{'0' * 64}  .grok/bundled/skills/x:3/SKILL.md\n")
        r = self.audit()
        self.assertEqual(len(self.counted_high(self.md("alpha"))), 1)
        self.assertTrue([n for n in r["notes"] if "release list" in n and "can't be used" in n], r["notes"])
        self.assertFalse([f for f in self.tip() if self.rel(self.md("alpha")) in f.get("files", [])])

    def test_links_in_and_out_stay_high(self):
        """G: a skill folder in a platform folder that links out, and an owner's folder (or one elsewhere) that links into one.
        A link in is fingerprinted under its own name only when it is asked for as a root (the walks keep one name per real
        path, the platform's): `--roots` with it is how a Bot would get it read."""
        self.start()
        out = os.path.join(self.home, "x", "helper")
        put(os.path.join(out, "SKILL.md"), CLEAN.format(n="helper"))
        os.symlink(out, os.path.join(self.root, "helper"))
        inside = os.path.join(self.root, "inner")
        put(os.path.join(inside, "SKILL.md"), CLEAN.format(n="inner"))
        aliases = [os.path.join(self.home, "sand-data", "workflows", "inner"), os.path.join(self.tmp, "elsewhere", "inner")]
        for a in aliases:
            os.makedirs(os.path.dirname(a), exist_ok=True)
            os.symlink(inside, a)
        self.roots = self.roots + aliases
        self.audit()
        for p in [self.md("helper")] + [os.path.join(a, "SKILL.md") for a in aliases]:
            self.assertEqual(len(self.counted_high(p)), 1, p)
            self.assertNotIn(p, wt.load_baseline()[0], p)
            self.assertFalse(wt.platform_skill_path(p, line=False), p)

    def test_a_file_link_inside_the_root_stays_high(self):
        """G: a listed file replaced by a link to another platform file (clean bytes, real path in the same root) is never quiet."""
        self.start()
        v1 = sha(self.md("alpha"))
        os.remove(self.md("alpha"))
        os.symlink(self.md("beta"), self.md("alpha"))
        self.audit()
        self.assertEqual(len(self.counted_high(self.md("alpha"))), 1)
        self.assertEqual(wt.load_baseline()[0][self.md("alpha")], v1)

    def test_colon_folder_stays_high(self):
        """G: a path with a colon is never quiet."""
        self.start()
        p = os.path.join(self.root, "x:3", "SKILL.md")
        put(p, CLEAN.format(n="x"))
        self.audit()
        self.assertEqual(len(self.counted_high(p)), 1)
        self.assertNotIn(p, wt.load_baseline()[0])

    def test_lookalike_roots_get_no_platform_quiet(self):
        """G: ~/.grok/bundled-evil and an owner's workflows/x/managed-skills are no platform folder. The owner's folder is the
        owner's change (a counted high); bundled-evil is no place the platform loads from, so it is not scanned at all."""
        evil = os.path.join(self.home, ".grok", "bundled-evil", "skills", "a", "SKILL.md")
        mine = os.path.join(self.home, "sand-data", "workflows", "x", "managed-skills", "SKILL.md")
        put(evil, CLEAN.format(n="a")); put(mine, CLEAN.format(n="x"))
        self.start()
        add(evil, "One more line.\n"); add(mine, "One more line.\n")
        self.audit()
        x = [f for f in self.at(mine) if f["rule"] == "ISR-I001"]
        self.assertEqual([(f["title"], f["severity"], wt.counts(f)) for f in x], [("Reviewed skill or plugin changed", "high", True)])
        for p in (evil, mine):
            self.assertFalse(wt.platform_skill_path(p, line=False), p)
            self.assertFalse([f for f in self.at(p) if f.get("platform_update")], p)
            self.assertFalse([f for f in self.tip() if self.rel(p) in f.get("files", []) or self.rel(p) in f["evidence"]], p)

    def test_over_1mb_stays_high(self):
        """G: a file over 1 MB isn't read whole, so it is never quiet."""
        big = os.path.join(self.root, "alpha", "big.md")
        put(big, "A line.\n")
        profiles.vendor_release(self, big)
        self.start()
        add(self.md("alpha"), "One more line.\n")
        put(big, "A line.\n" * 140_000)
        self.audit()
        self.assertEqual(len(self.counted_high(big)), 1)
        self.assertNotEqual(wt.load_baseline()[0].get(big), sha(big))

    def test_rolled_bytes_are_the_scanned_bytes(self):
        """G: an engine that rewrites the file while it scans never gets the new bytes rolled into the baseline."""
        self.start()
        md = self.md("alpha")
        v1 = sha(md)
        add(md, "One more line.\n")
        v2 = sha(md)
        swapped = FLAGGED.format(n="alpha")
        self.scanners(skillspector=SWAP_ENGINE % (md, swapped))
        self.audit()
        self.assertIn(wt.load_baseline()[0].get(md), (v1, v2))
        self.assertNotEqual(wt.load_baseline()[0].get(md), hashlib.sha256(swapped.encode()).hexdigest())

    def test_approve_platform_still_refused(self):
        """G: `fix --approve-platform` is refused and changes nothing (decision D10)."""
        self.start()
        plant = self.loose()
        put(plant, CLEAN.format(n="helper"))
        self.audit()
        before = wt.load_baseline()[0]
        out = self.approve("0" * 20)
        self.assertIn("NOT APPROVED", out)
        self.assertIn("Nothing was changed", out)
        self.assertEqual(wt.load_baseline()[0], before)
        self.assertFalse(os.path.lexists(wt.state_path(wt.OLD_PLATFORM_APPROVALS)))

    def test_unscanned_types_are_scanned_first_flagged(self):
        """G: the same .xsd file with flagged text stays a counted high."""
        x = os.path.join(self.root, "alpha", "schema.xsd")
        put(x, "<schema/>\n")
        profiles.vendor_release(self, x)
        self.start()
        put(x, FLAGGED.format(n="alpha"))
        self.assertNotEqual(self.daily(), "NO_CHANGES")
        self.assertEqual(len(self.counted_high(x)), 1)


class WordingOnlyVote(_Middle):
    def test_wording_only_vote_stays_quiet_and_rolls(self):
        """R: the DQ-042 learn update at a listed, baselined path, not on the release list: two engines agree only on wording, so
        it is the quiet line (the vote a Platform line) and the full audit rolls it in."""
        d = os.path.join(self.root, "learn")
        md = os.path.join(d, "SKILL.md")
        put(md, dq042.LEARN_V1)
        profiles.vendor_release(self, md)                                       # v1 is the vendor's; v2 isn't listed
        self.start(skillspector=dq042.skillspector(dq042.LEARN_ISSUES), husk=dq042.husk(dq042.LEARN_HUSK))
        put(md, dq042.LEARN_V2)
        self.assertEqual(self.daily(), "NO_CHANGES")
        tip = self.quiet(md)
        self.assertIn("learn", tip["title"])
        x = [f for f in self.snap()["findings"] if f["rule"] == "ISR-X003" and f["where"] == d]
        self.assertEqual([(f["severity"], f["label"]) for f in x], [("info", wt.PLATFORM)])
        self.audit()
        self.assertEqual(wt.load_baseline()[0][md], sha(md))
        self.assertFalse([f for f in self.at(md) if f["rule"] in ("ISR-I001", "ISR-I002")])


class KeptVoteInDaily(_Middle):
    def test_kept_vote_in_daily_holds_update(self):
        """R: in daily, a scanner line kept from the last run (it may lack a kind: kinds_incomplete) holds a quiet update in its
        folder until a full audit scans it again (hold_on_kept_votes); f7c28e6 never rolls the first update in."""
        d = os.path.join(self.root, "learn")
        md = os.path.join(d, "SKILL.md")
        put(md, dq042.LEARN_V1)
        profiles.vendor_release(self, md)
        self.start(skillspector=dq042.skillspector(dq042.LEARN_ISSUES), husk=dq042.husk(dq042.LEARN_HUSK))
        put(md, dq042.LEARN_V2)
        self.audit()                                                            # quiet, rolled in; the vote is a Platform line
        self.assertEqual(wt.load_baseline()[0][md], sha(md))
        add(md, "One more line.\n")
        self.scanners(skillspector=None, husk=None)                             # no engine answers in daily: last run's line is kept
        self.daily()
        x = [f for f in self.snap()["findings"] if f["rule"] == "ISR-X003" and f["where"] == d]
        self.assertEqual([f.get("kinds_incomplete") for f in x], [True])
        held = self.counted_high(md)
        self.assertEqual(len(held), 1)
        self.assertTrue(held[0]["fix"].startswith("The scanners' answer for its folder is from an earlier run"))


class ManagedMirror(_Middle):
    def pair(self, a, b):
        s = os.path.join(self.home, "sand-data", "managed-skills", "x", "SKILL.md")
        g = os.path.join(self.home, "agent-data", "managed-skills", "x", "SKILL.md")
        put(s, a); put(g, b)
        return s, g

    def test_managed_mirror_is_one_finding(self):
        """R: the same flagged file at sand-data and agent-data managed-skills is one counted high that names both paths."""
        self.start()
        before = self.audit()["open_by_severity"]["high"]
        s, g = self.pair(FLAGGED.format(n="x"), FLAGGED.format(n="x"))
        r = self.audit()
        x = [f for f in self.snap()["findings"] if f["rule"] == "ISR-I002" and f.get("unverified_platform")]
        self.assertEqual([f["where"] for f in x], [s])
        self.assertEqual(x[0].get("also_at"), [g])
        self.assertIn(f"The same file (same sha256) is also at {g}.", x[0]["fix"])
        self.assertEqual(r["open_by_severity"]["high"] - before, 1)

    def test_managed_mirror_different_bytes_is_two(self):
        """G: different bytes at the two places are two findings."""
        self.start()
        s, g = self.pair(FLAGGED.format(n="x"), FLAGGED.format(n="y"))
        self.audit()
        x = [f for f in self.snap()["findings"] if f["rule"] == "ISR-I002" and f.get("unverified_platform")]
        self.assertEqual(sorted(f["where"] for f in x), sorted([s, g]))


if __name__ == "__main__":
    unittest.main()
