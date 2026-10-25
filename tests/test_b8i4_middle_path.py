"""b8i4 (v0.7.4 item 4): the platform-file middle path.

The Oct 18 rule (a platform file is trusted only by its path and sha256 in rules/platform-release.lock) made every routine
Grok Bot, Codex or Claude update a counted high per file, on every box, every day: versions differ per user, so the shipped
lock can't be the only source of trust. Decision, Oct 22: a clean update at a path that already exists (on the release list
or in the baseline), or a clean new platform skill folder, gets the quiet "Platform refresh" line and rolls into the baseline
on the next full audit. Anything risky stays a counted high: a file ISR Bot's rules flag, one over 1 MB or unreadable, one
two scanners name a dangerous behavior in (or whose scanner answer is out of date), a loose file, a link in or out, a colon
in its path, an unusable release list, a new file in a skill folder nobody updated this run.

Each test marked R in its docstring fails on f7c28e6 (the engine sources and the lock stashed) at an assertion; G is a guard that
passes there and here.
"""
import hashlib, json, os, sys, unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import Box  # noqa: E402
import isr  # noqa: E402
from test_item8_provenance import CLEAN, FLAGGED, NOTHING, SWAP_ENGINE, _Platform, add, put, sha  # noqa: E402
import profiles  # noqa: E402
import test_dq042_vendor_skills as dq042  # noqa: E402


class _Middle(_Platform):
    def setUp(self):
        super().setUp()

    def rel(self, p):
        return os.path.relpath(p, self.home)

    def unverified(self):
        return sorted(f["where"] for f in self.snap()["findings"] if f.get("unverified_platform"))

    def high_count(self):
        return self.snap_counts()["high"]

    def snap_counts(self):
        return {s: sum(1 for f in self.snap()["findings"] if f["severity"] == s and isr.counts(f)) for s in ("critical", "high")}

    def quiet(self, *paths):
        """Each path has no counted high and no held finding, and the one Platform refresh line names it.
        v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only. So no Platform
        refresh line, no drift row and no baseline line for any of them."""
        self.assertEqual(self.tip(), [], [f["title"] for f in self.snap()["findings"]])
        for p in paths:
            self.assertEqual(self.counted_high(p), [], p)
            self.assertEqual(self.drift(p), [], p)
            self.assertNotIn(p, self.unverified(), p)
            self.assertNotIn(p, isr.load_baseline()[0], p)


class CleanUpdates(_Middle):
    def test_clean_update_at_listed_path_is_quiet(self):
        """R: on f7c28e6 alpha's routine update is a counted high and daily isn't quiet.
        v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        self.start()
        add(self.md("alpha"), "One more line.\n")
        self.assertEqual(self.daily(), "NO_CHANGES")
        self.quiet(self.md("alpha"))
        self.assertFalse(os.path.lexists(isr.state_path("platform_held.json")))
        self.assertEqual(self.unverified(), [])

    def test_quiet_update_rolls_in_on_full_audit(self):
        """R: on f7c28e6 the baseline keeps alpha's old bytes.
        v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        self.start()
        add(self.md("alpha"), "One more line.\n")
        self.daily()
        self.audit()
        self.assertNotIn(self.md("alpha"), isr.load_baseline()[0])
        self.audit()
        self.assertEqual(self.at(self.md("alpha")), [])
        self.assertFalse(self.tip())

    def test_baseline_only_path_update_is_quiet(self):
        """R: a path only the baseline has (a clean new skill folder that rolled in) updates quietly, twice.
        v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        self.start()
        p = self.md("helper")
        put(p, CLEAN.format(n="helper"))
        self.audit()
        self.assertNotIn(p, isr.load_baseline()[0])
        for v in ("Version 2.\n", "Version 3.\n"):
            add(p, v)
            self.assertEqual(self.daily(), "NO_CHANGES", v)
            self.quiet(p)
            self.audit()
            self.assertNotIn(p, isr.load_baseline()[0], v)

    def test_first_run_clean_file_at_listed_path_raises_nothing(self):
        """R: a new box whose alpha is a newer version than the release list's: no counted high, not in the first baseline, and the
        second full audit rolls it in (on f7c28e6 it is a counted high on every run).
        v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        add(self.md("alpha"), "A newer version than the release list's.\n")
        self.start()
        self.assertEqual(self.counted_high(self.md("alpha")), [])
        self.assertNotIn(self.md("alpha"), self.unverified())
        self.assertNotIn(self.md("alpha"), isr.load_baseline()[0])
        self.audit()
        self.assertEqual(self.drift(self.md("alpha")), [])

    def test_tip_names_vendor_per_root(self):
        """R: one Platform refresh line with each vendor's count, and both paths in `files`.
        v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        img = os.path.join(self.home, ".codex", "skills", ".system", "imagegen", "SKILL.md")
        put(img, CLEAN.format(n="imagegen"))
        profiles.vendor_release(self, img)
        self.start()
        add(self.md("alpha"), "One more line.\n"); add(img, "One more line.\n")
        self.assertEqual(self.daily(), "NO_CHANGES")
        self.quiet(self.md("alpha"), img)
        self.assertFalse([f for f in self.vs() if f["rule"] == "ISR-I008"])
        self.assertFalse(os.path.lexists(isr.state_path("platform_held.json")))

    def test_new_file_in_skill_with_same_run_update_is_quiet(self):
        """R: a new file in alpha's folder, in the same run as a clean update of alpha's SKILL.md (decision D1)."""
        self.start()
        extra = os.path.join(self.root, "alpha", "extra.md")
        add(self.md("alpha"), "See extra.md.\n")
        put(extra, "More notes for alpha.\n")
        self.assertEqual(self.daily(), "NO_CHANGES")
        self.quiet(self.md("alpha"), extra)

    def test_daily_lists_only_held_files(self):
        """R: daily's platform_unverified lists the loose plant, not alpha's clean update.
        v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        self.start()
        plant = self.loose()
        put(plant, CLEAN.format(n="helper"))
        add(self.md("alpha"), "One more line.\n")
        u = self.user("helper")
        put(u, CLEAN.format(n="helper"))
        out = json.loads(self.daily())
        self.assertEqual([(f["where"], f["severity"]) for f in out["new"] if f["rule"] == "ISR-I002"], [(u, "low")])
        self.assertNotIn("platform_unverified", out)
        self.assertEqual(self.drift(plant) + self.drift(self.md("alpha")), [])

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
        """R: a clean new skill folder in a platform folder is one Platform refresh line, and the full audit rolls both files in.
        v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        self.start()
        md, ref = self.md("helper"), os.path.join(self.root, "helper", "ref.md")
        put(md, CLEAN.format(n="helper")); put(ref, "Notes for the helper.\n")
        self.assertEqual(self.daily(), "NO_CHANGES")
        self.quiet(md, ref)
        self.assertFalse([f for f in self.vs() if f["rule"].startswith("ISR-I")])
        self.audit()
        base = isr.load_baseline()[0]
        self.assertEqual((base.get(md), base.get(ref)), (None, None))

    def test_new_skill_folder_with_one_flagged_file_is_all_high(self):
        """G: one flagged file holds the whole new folder.
        v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        self.start()
        md, ref = self.md("helper"), os.path.join(self.root, "helper", "ref.md")
        um, ur = self.user("helper"), self.user("helper", "ref.md")
        put(md, CLEAN.format(n="helper")); put(ref, FLAGGED.format(n="helper"))
        put(um, CLEAN.format(n="helper")); put(ur, FLAGGED.format(n="helper"))
        self.audit()
        for p in (md, ref):
            self.assertEqual(self.drift(p), [], p)
        for p in (um, ur):
            self.assertEqual(self.ints(p), [("ISR-I002", "low")], p)
        self.assertTrue(self.vend(ref))
        base = isr.load_baseline()[0]
        self.assertNotIn(md, base); self.assertNotIn(ref, base)
        self.assertNotIn(um, base); self.assertNotIn(ur, base)

    def test_new_file_in_skill_alone_is_high(self):
        """G: a new file in an existing skill folder that wasn't updated this run (decision D1).
        v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        self.start()
        extra = os.path.join(self.root, "alpha", "extra.md")
        put(extra, "More notes for alpha.\n")
        self.assertEqual(self.daily(), "NO_CHANGES")
        ux = self.user("skill000", "extra.md")
        put(ux, "More notes for skill000.\n")
        self.assertNotEqual(self.daily(), "NO_CHANGES")
        self.assertEqual(self.ints(ux), [("ISR-I002", "low")])
        self.assertEqual(self.drift(extra), [])

    def test_loose_new_file_is_high(self):
        """G: a file in a platform folder outside any skill folder, at no existing path.
        v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        self.start()
        p = self.loose()
        put(p, CLEAN.format(n="helper"))
        self.assertEqual(self.daily(), "NO_CHANGES")
        u = self.user("helper")
        put(u, CLEAN.format(n="helper"))
        self.assertNotEqual(self.daily(), "NO_CHANGES")
        self.assertEqual(self.ints(u), [("ISR-I002", "low")])
        self.assertEqual(self.drift(p), [])
        self.audit()
        self.assertNotIn(p, isr.load_baseline()[0])
        self.assertNotIn(u, isr.load_baseline()[0])

    def test_first_run_loose_file_is_high(self):
        """G: a loose file on a new box.
        v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        p = self.loose()
        put(p, CLEAN.format(n="helper"))
        self.start()
        self.assertEqual(self.drift(p), [])
        self.assertNotIn(p, isr.load_baseline()[0])
        self.assertIn(self.own, isr.load_baseline()[0])


class StillHigh(_Middle):
    def test_flagged_update_is_counted_high(self):
        """G: an update ISR Bot's rules flag.
        v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        self.start()
        u = self.own
        u1 = sha(u)
        put(self.md("alpha"), FLAGGED.format(n="alpha"))
        put(u, FLAGGED.format(n="skill000"))
        out = json.loads(self.daily())
        self.assertIn(u, [f["where"].split(":")[0] for f in out["new"]])
        self.assertNotIn("platform_unverified", out)
        x = self.counted_high(u)
        self.assertEqual([f["rule"] for f in x], ["ISR-I001"])
        self.assertEqual(x[0]["title"], "Reviewed skill or plugin changed")
        self.audit()
        base = isr.load_baseline()[0]
        self.assertEqual(base[u], u1)
        self.assertNotIn(self.md("alpha"), base)
        self.assertEqual(self.drift(self.md("alpha")), [])
        self.assertTrue(self.vend(self.md("alpha")))
        self.assertFalse(self.tip())

    def test_lock_path_with_other_bytes_flagged_is_high(self):
        """G: a path on the release list with flagged bytes it doesn't list.
        v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        p = self.md("helper")
        profiles.vendor_release(self, (p, CLEAN.format(n="helper")))
        self.start()
        u = self.own
        u1 = sha(u)
        put(p, FLAGGED.format(n="helper"))
        put(u, FLAGGED.format(n="skill000"))
        self.audit()
        self.assertEqual(len(self.counted_high(u)), 1)
        self.assertEqual(self.drift(p), [])
        self.assertTrue(self.vend(p))
        self.assertNotIn(p, isr.load_baseline()[0])
        self.assertEqual(isr.load_baseline()[0][u], u1)

    def test_dangerous_engine_kind_holds_update(self):
        """G: two scanners name a dangerous behavior (the harness fakes: "Exfil: Upload" and "obfuscated loader") in alpha's folder.
        v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        self.start()
        u = self.own
        u1 = sha(u)
        add(self.md("alpha"), "Release notes: EVIL HUSK.\n")
        add(u, "Release notes: EVIL HUSK.\n")
        self.audit()
        x = [f for f in self.vs() if f["rule"] == "ISR-X003" and f["where"] == os.path.dirname(self.md("alpha"))]
        self.assertEqual(len(x), 1)
        self.assertEqual(len([f for f in self.fs() if f["rule"] == "ISR-X003" and f["where"] == os.path.dirname(u)]), 1)
        self.assertEqual(len(self.counted_high(u)), 1)
        self.assertEqual(self.drift(self.md("alpha")), [])
        self.assertEqual(isr.load_baseline()[0][u], u1)
        self.assertNotIn(self.md("alpha"), isr.load_baseline()[0])

    def test_kinds_incomplete_holds_update(self):
        """G: an engine answer that is out of date (kinds_incomplete) never lets an update through.
        v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        d = os.path.join(self.root, "learn")
        md = os.path.join(d, "SKILL.md")
        put(md, dq042.LEARN_V1)
        profiles.vendor_release(self, md)
        self.start(skillspector=dq042.skillspector(dq042.FIFTH_ISSUES[:4]), husk=dq042.husk(dq042.LEARN_HUSK))
        u = self.own
        u1 = sha(u)
        put(md, dq042.LEARN_V2)
        add(u, "One more line.\n")
        self.daily()
        p = isr.state_path("engine_cache.json")
        cache = isr.load_json(p, {})
        cache[d]["ss"].pop("kinds", None)                                       # an answer from before DQ-042 read every kind
        isr.save_json(p, cache)
        self.audit("--budget", "0")
        x = [f for f in self.vs() if f["rule"] == "ISR-X003" and f["where"] == d]
        self.assertEqual([f.get("kinds_incomplete") for f in x], [True])
        self.assertEqual(self.drift(md), [])
        self.assertEqual(len(self.counted_high(u)), 1)
        self.assertNotIn(md, isr.load_baseline()[0])
        self.assertEqual(isr.load_baseline()[0][u], u1)

    def test_unusable_lock_disables_quiet_path(self):
        """G: one bad line makes the release list unusable, and with it the quiet path (decision D4).
        v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only. The audit reads
        no release list, so nothing about it is said."""
        self.start()
        add(self.md("alpha"), "One more line.\n")
        add(self.own, "One more line.\n")
        with open(self.platform_lock, "a") as f:
            f.write(f"{'0' * 64}  .grok/bundled/skills/x:3/SKILL.md\n")
        r = self.audit()
        self.assertEqual([f["title"] for f in self.counted_high(self.own)], ["Reviewed skill or plugin changed"])
        self.assertEqual(self.drift(self.md("alpha")), [])
        self.assertFalse([n for n in r["notes"] if "release list" in n], r["notes"])
        self.assertFalse([f for f in self.tip() if self.rel(self.md("alpha")) in f.get("files", [])])

    def test_links_in_and_out_stay_high(self):
        """G: a skill folder in a platform folder that links out, and an owner's folder (or one elsewhere) that links into one.
        A link in is fingerprinted under its own name only when it is asked for as a root (the walks keep one name per real
        path, the platform's): `--roots` with it is how a Bot would get it read.
        v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only. The link out
        leads to the owner's folder, so it is the owner's file (a new one: low). The link-in names are written in the owner's places,
        so by the two-sided rule (a link between a user place and a vendor place is user) they are the owner's new files too."""
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
        helper = self.md("helper")
        self.assertEqual(self.ints(helper), [("ISR-I002", "low")])
        for p in [os.path.join(a, "SKILL.md") for a in aliases]:
            self.assertEqual(self.ints(p), [("ISR-I002", "low")], p)
        for p in [helper] + [os.path.join(a, "SKILL.md") for a in aliases]:
            self.assertNotIn(p, isr.load_baseline()[0], p)
            self.assertFalse(isr.platform_skill_path(p, line=False), p)

    def test_a_file_link_inside_the_root_stays_high(self):
        """G: a listed file replaced by a link to another platform file (clean bytes, real path in the same root) is never quiet.
        v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only. The control's link
        leads outside the scanned folders, so the walk (one name per real path) keeps the owner's name for it."""
        u0, u2 = self.own, os.path.join(self.tmp, "outside", "mine2", "SKILL.md")
        put(u2, CLEAN.format(n="mine2"))
        self.start()
        u1 = sha(u0)
        os.remove(self.md("alpha"))
        os.symlink(self.md("beta"), self.md("alpha"))
        os.remove(u0)
        os.symlink(u2, u0)
        self.audit()
        self.assertEqual(len(self.counted_high(u0)), 1)
        self.assertEqual(self.drift(self.md("alpha")), [])
        self.assertEqual(isr.load_baseline()[0][u0], u1)
        self.assertNotIn(self.md("alpha"), isr.load_baseline()[0])

    def test_colon_folder_stays_high(self):
        """G: a path with a colon is never quiet.
        v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        self.start()
        p = os.path.join(self.root, "x:3", "SKILL.md")
        uc = self.user("x:3")
        put(p, CLEAN.format(n="x"))
        put(uc, CLEAN.format(n="x"))
        self.audit()
        at = lambda q, fs: [f for f in fs if f["where"] == q or f["where"].startswith(q + ":")]   # the folder name has a colon
        self.assertEqual([(f["rule"], f["severity"]) for f in at(uc, self.fs()) if f["rule"] in ("ISR-I001", "ISR-I002")],
                         [("ISR-I002", "low")])
        self.assertEqual([f for f in at(p, self.fs() + self.vs()) if f["rule"] in ("ISR-I001", "ISR-I002", "ISR-I003", "ISR-I011")], [])
        self.assertNotIn(p, isr.load_baseline()[0])
        self.assertNotIn(uc, isr.load_baseline()[0])

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
        self.assertEqual([(f["title"], f["severity"], isr.counts(f)) for f in x], [("Reviewed skill or plugin changed", "high", True)])
        for p in (evil, mine):
            self.assertFalse(isr.platform_skill_path(p, line=False), p)
            self.assertFalse([f for f in self.at(p) if f.get("platform_update")], p)
            self.assertFalse([f for f in self.tip() if self.rel(p) in f.get("files", []) or self.rel(p) in f["evidence"]], p)

    def test_over_1mb_stays_high(self):
        """G: a file over 1 MB isn't read whole, so it is never quiet.
        v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        big = os.path.join(self.root, "alpha", "big.md")
        ub = self.user("skill000", "big.md")
        put(big, "A line.\n"); put(ub, "A line.\n")
        profiles.vendor_release(self, big)
        self.start()
        add(self.md("alpha"), "One more line.\n")
        put(big, "A line.\n" * 140_000)
        put(ub, "A line.\n" * 140_000)
        self.audit()
        self.assertEqual(len(self.counted_high(ub)), 1)
        self.assertEqual(self.drift(big), [])
        self.assertNotEqual(isr.load_baseline()[0].get(ub), sha(ub))
        self.assertNotIn(big, isr.load_baseline()[0])

    def test_rolled_bytes_are_the_scanned_bytes(self):
        """G: an engine that rewrites the file while it scans never gets the new bytes rolled into the baseline.
        v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only. The swap is on
        the owner's file."""
        self.start()
        md, u0 = self.md("alpha"), self.own
        u1 = sha(u0)
        add(md, "One more line.\n")
        add(u0, "One more line.\n")
        u2 = sha(u0)
        swapped = FLAGGED.format(n="skill000")
        self.scanners(skillspector=SWAP_ENGINE % (u0, swapped))
        self.audit()
        self.assertIn(isr.load_baseline()[0].get(u0), (u1, u2))
        self.assertNotIn(md, isr.load_baseline()[0])
        self.assertNotEqual(isr.load_baseline()[0].get(u0), hashlib.sha256(swapped.encode()).hexdigest())

    def test_approve_platform_still_refused(self):
        """G: `fix --approve-platform` is refused and changes nothing (decision D10).
        v0.8.1 (decision, Oct 24): vendor folders are never scored, so there is nothing to approve."""
        self.start()
        plant = self.loose()
        put(plant, CLEAN.format(n="helper"))
        self.audit()
        before = isr.load_baseline()[0]
        out = self.approve("0" * 20)
        self.assertIn("NOT APPROVED", out)
        self.assertIn(NOTHING, out)
        self.assertIn("Nothing was changed", out)
        self.assertNotIn(plant, isr.load_baseline()[0])
        self.assertEqual(isr.load_baseline()[0], before)
        self.assertFalse(os.path.lexists(isr.state_path("platform_approved.json")))

    def test_unscanned_types_are_scanned_first_flagged(self):
        """G: the same .xsd file with flagged text stays a counted high.
        v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        x = os.path.join(self.root, "alpha", "schema.xsd")
        ux = self.user("skill000", "schema.xsd")
        put(x, "<schema/>\n"); put(ux, "<schema/>\n")
        profiles.vendor_release(self, x)
        self.start()
        put(x, FLAGGED.format(n="alpha"))
        self.assertEqual(self.daily(), "NO_CHANGES")
        put(ux, FLAGGED.format(n="skill000"))
        self.assertNotEqual(self.daily(), "NO_CHANGES")
        self.assertEqual(len(self.counted_high(ux)), 1)
        self.assertEqual(self.drift(x), [])


class WordingOnlyVote(_Middle):
    def test_wording_only_vote_stays_quiet_and_rolls(self):
        """R: the DQ-042 learn update at a listed, baselined path, not on the release list: two engines agree only on wording, so
        it is the quiet line (the vote a Platform line) and the full audit rolls it in.
        v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        d = os.path.join(self.root, "learn")
        md = os.path.join(d, "SKILL.md")
        put(md, dq042.LEARN_V1)
        profiles.vendor_release(self, md)                                       # v1 is the vendor's; v2 isn't listed
        self.start(skillspector=dq042.skillspector(dq042.LEARN_ISSUES), husk=dq042.husk(dq042.LEARN_HUSK))
        put(md, dq042.LEARN_V2)
        self.assertEqual(self.daily(), "NO_CHANGES")
        self.quiet(md)
        self.assertFalse(os.path.lexists(isr.state_path("platform_held.json")))
        x = [f for f in self.vs() if f["rule"] == "ISR-X003" and f["where"] == d]
        self.assertEqual([f["rule"] for f in x], ["ISR-X003"])
        self.audit()
        self.assertNotIn(md, isr.load_baseline()[0])
        self.assertFalse([f for f in self.at(md) if f["rule"] in ("ISR-I001", "ISR-I002")])


class KeptVoteInDaily(_Middle):
    def test_kept_vote_in_daily_holds_update(self):
        """R: in daily, a scanner line kept from the last run (it may lack a kind: kinds_incomplete) holds a quiet update in its
        folder until a full audit scans it again (hold_on_kept_votes); f7c28e6 never rolls the first update in.
        v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only. The kept vote is
        carried with the vendor records."""
        d = os.path.join(self.root, "learn")
        md = os.path.join(d, "SKILL.md")
        put(md, dq042.LEARN_V1)
        profiles.vendor_release(self, md)
        self.start(skillspector=dq042.skillspector(dq042.LEARN_ISSUES), husk=dq042.husk(dq042.LEARN_HUSK))
        put(md, dq042.LEARN_V2)
        self.audit()                                                            # quiet, rolled in; the vote is a Platform line
        self.assertNotIn(md, isr.load_baseline()[0])
        add(md, "One more line.\n")
        add(self.own, "One more line.\n")
        self.scanners(skillspector=None, husk=None)                             # no engine answers in daily: last run's line is kept
        self.daily()
        x = [f for f in self.vs() if f["rule"] == "ISR-X003" and f["where"] == d]
        self.assertEqual([f.get("kinds_incomplete") for f in x], [True])
        held = self.counted_high(self.own)
        self.assertEqual(len(held), 1)
        self.assertEqual(self.drift(md), [])
        self.assertEqual(held[0]["title"], "Reviewed skill or plugin changed")


class ManagedMirror(_Middle):
    def pair(self, a, b):
        s = os.path.join(self.home, "sand-data", "managed-skills", "x", "SKILL.md")
        g = os.path.join(self.home, "agent-data", "managed-skills", "x", "SKILL.md")
        put(s, a); put(g, b)
        return s, g

    def test_managed_mirror_is_one_finding(self):
        """R: the same flagged file at sand-data and agent-data managed-skills is one counted high that names both paths.
        v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only. Both places are
        platform notes, with no drift row and no count."""
        self.start()
        before = self.audit()["open_by_severity"]["high"]
        s, g = self.pair(FLAGGED.format(n="x"), FLAGGED.format(n="x"))
        r = self.audit()
        self.assertEqual([p for p in (s, g) if self.vend(p)], [s, g])
        self.assertFalse([f for f in self.vs() if f.get("also_at")])
        self.assertEqual(self.drift(s) + self.drift(g), [])
        self.assertEqual(r["open_by_severity"]["high"] - before, 0)

    def test_managed_mirror_different_bytes_is_two(self):
        """G: different bytes at the two places are two findings.
        v0.8.1 (decision, Oct 24): vendor folders are never scored; drift is tracked for the owner's files only."""
        self.start()
        s, g = self.pair(FLAGGED.format(n="x"), FLAGGED.format(n="y"))
        self.audit()
        self.assertEqual(sorted(p for p in (s, g) if self.vend(p)), sorted([s, g]))
        self.assertEqual(self.drift(s) + self.drift(g), [])


if __name__ == "__main__":
    unittest.main()
