"""PR #9 (Ken: few false alarms): the platform's own sync bookkeeping is not a provenance subject.

On 7e853c4 every file in the five platform folders was held to rules/platform-release.lock, so the files the platform rewrites
at every sync with no release (managed-skills/cache.json, 554 KB on Ken's box; Claude's plugin sync markers and bucket
bookkeeping) were a counted high after each sync, and the lock listed seven of them. wt.py's PLATFORM_CHURN names them exactly,
the walk skips them (no WT-I002/WT-I001 high, no WT-I011 count, no baseline line), and the lock's fill command skips the same
pattern. Anything else stays a provenance subject: a link named like one, a lookalike in a skill or plugin folder, an exec bit.

Each test fails on 7e853c4 (watchtower/wt.py and rules/platform-release.lock stashed) by reaching an assertion unless its
docstring says it is a contrast.
"""
import os, re, shlex, subprocess, sys, unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import Box, wt  # noqa: E402
from test_item8_provenance import CLEAN, LEAKS, put  # noqa: E402
from test_watchtower import fake_key  # noqa: E402
import profiles  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOCK = os.path.join(ROOT, "rules", "platform-release.lock")
BUCKET = "11111111-2222-3333-4444-555555555555_66666666-7777-8888-9999-000000000000"
BUCKET2 = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee_ffffffff-0000-1111-2222-333333333333"
SYNCED = ".claude/plugins/synced"
CHURN = ("sand-data/managed-skills/cache.json", "agent-data/managed-skills/cache.json", f"{SYNCED}/.bucket-{BUCKET}",
         f"{SYNCED}/{BUCKET}/manifest.json", f"{SYNCED}/{BUCKET}/build.meta.json", f"{SYNCED}/{BUCKET}/.marketplaces.json")
# The seven lines 7e853c4's lock had for these (Ken's box, Oct 18)
KEN_BUCKET = "cf8c9421-4d56-4812-8a8e-a30e1e852fc5_5c03d306-6f6b-4cd3-bddc-c65efeae7180"
REMOVED = ("sand-data/managed-skills/cache.json", "agent-data/managed-skills/cache.json", f"{SYNCED}/.bucket-{KEN_BUCKET}",
           f"{SYNCED}/{KEN_BUCKET}/manifest.json", f"{SYNCED}/{KEN_BUCKET}/cowork-plugin-management.meta.json",
           f"{SYNCED}/{KEN_BUCKET}/.marketplaces.json", f"{SYNCED}/{KEN_BUCKET}/build-with-ai.meta.json")


def read_lock():
    with open(LOCK, encoding="utf-8") as f:
        return f.read()


def fill_command(text):
    """The fill command in the lock's header: the lines after "To fill it", without their leading "#"."""
    lines = text.splitlines()
    i = next(n for n, l in enumerate(lines) if l.startswith("# To fill it"))
    out = []
    for l in lines[i + 1:]:
        if not l.startswith("#   "):
            break
        out.append(l[1:])
    return "\n".join(out)


def header_regex(text):
    m = re.search(r"-regex \\\n#\s+'([^']+)'", text)
    return m.group(1) if m else None


class _Churn(Box):
    def setUp(self):
        super().setUp()
        self.h = lambda rel: os.path.join(self.home, rel)
        self.pdf = self.h("sand-data/managed-skills/pdf/SKILL.md")
        self.prime = self.h(f"{SYNCED}/{BUCKET}/build/skills/prime/SKILL.md")
        put(self.pdf, CLEAN.format(n="pdf"))
        put(self.prime, CLEAN.format(n="prime"))
        profiles.vendor_release(self, self.pdf, self.prime)                    # the vendor's own, as its release lists them
        self.churn = [self.h(r) for r in CHURN]
        self.sync(1)

    def sync(self, n):
        """What a sync does: rewrite its bookkeeping (the marker stays empty)."""
        for p in self.churn:
            put(p, "" if "/.bucket-" in p else '{"synced": %d}\n' % n)

    def start(self):
        self.scanners()
        self.audit()
        self.assertEqual(wt.load_baseline()[1], "ok")

    def daily(self):
        return self.run_cmd("daily", "--roots", *self.roots)[1].strip()

    def at(self, path):
        return [f for f in self.snap()["findings"] if f["where"] == path]

    def counted_high(self, path):
        return [f for f in self.at(path) if f["rule"] in ("WT-I001", "WT-I002") and f["severity"] == "high" and wt.counts(f)]

    def unverified(self):
        return sorted(f["where"] for f in self.snap()["findings"] if f.get("unverified_platform"))


class FillCommand(Box):
    """(a) and (b): the header's fill command, run as written on a fake home, leaves out exactly what PLATFORM_CHURN skips."""

    def tree(self):
        files = {
            "sand-data/managed-skills/cache.json": False, "agent-data/managed-skills/cache.json": False,
            f"{SYNCED}/.bucket-{BUCKET}": False, f"{SYNCED}/{BUCKET}/manifest.json": False,
            f"{SYNCED}/{BUCKET}/build.meta.json": False, f"{SYNCED}/{BUCKET}/.marketplaces.json": False,
            # kept: release content, scripts, lookalikes below a bucket's top level or in a folder that isn't a bucket
            ".grok/bundled/manifest.json": True, ".grok/bundled/skills/pptx/SKILL.md": True,
            ".codex/skills/.system/.codex-system-skills.marker": True, "sand-data/managed-skills/pdf/SKILL.md": True,
            "sand-data/managed-skills/pdf/cache.json": True, "sand-data/managed-skills/sync.py": True,
            f"{SYNCED}/{BUCKET}/build/skills/prime/SKILL.md": True, f"{SYNCED}/{BUCKET}/build/foo.meta.json": True,
            f"{SYNCED}/{BUCKET}/build/manifest.json": True, f"{SYNCED}/{BUCKET}/run.sh": True,
            f"{SYNCED}/{BUCKET}/manifest.json.sh": True, f"{SYNCED}/notabucket/manifest.json": True,
            f"{SYNCED}/.bucket-{BUCKET}.sh": True, ".grok/bundled/cache.json": True,
        }
        for rel in files:
            put(os.path.join(self.home, rel), "x\n")
        exe = f"{SYNCED}/{BUCKET2}/manifest.json"
        put(os.path.join(self.home, exe), "#!/bin/sh\n")
        os.chmod(os.path.join(self.home, exe), 0o755)                           # an exec bit is never skipped
        files[exe] = True
        return files

    def test_a_the_fill_command_leaves_out_the_bookkeeping_and_keeps_the_rest(self):
        files = self.tree()
        out = os.path.join(self.tmp, "filled.lock")
        cmd = fill_command(read_lock()).replace("<checkout>/rules/platform-release.lock", shlex.quote(out))
        self.assertIn("find ", cmd)
        r = subprocess.run(["bash", "-c", cmd], env=dict(os.environ, HOME=self.home), capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(out) as f:
            listed = {l.split("  ", 1)[1] for l in f.read().splitlines() if l}
        self.assertEqual(listed, {rel for rel, keep in files.items() if keep})
        for rel, keep in files.items():                                         # the same answer as wt.py's rule, file by file
            self.assertEqual(wt.platform_churn_file(os.path.join(self.home, rel)), not keep, rel)

    def test_b_the_header_rule_is_platform_churn(self):
        text = read_lock()
        rx = header_regex(text)
        self.assertIsNotNone(rx, "no -regex in the fill command")
        self.assertIn("PLATFORM_CHURN", text)
        self.assertIn("! -perm /111", fill_command(text))
        self.assertEqual(rx, wt.PLATFORM_CHURN.pattern)
        for rel in CHURN + REMOVED:
            self.assertTrue(re.fullmatch(rx, rel) and wt.platform_churn(rel), rel)
        for rel in (".grok/bundled/manifest.json", "sand-data/managed-skills/pdf/cache.json", f"{SYNCED}/{BUCKET}/build/x.meta.json",
                    f"{SYNCED}/notabucket/manifest.json", f"{SYNCED}/.bucket-{BUCKET}/x", "sand-data/managed-skills/cache.json.py",
                    f"{SYNCED}/{BUCKET}/SKILL.md", "x/sand-data/managed-skills/cache.json"):
            self.assertFalse(re.fullmatch(rx, rel) or wt.platform_churn(rel), rel)


class SyncIsQuiet(_Churn):
    """(c): a sync that rewrites only its bookkeeping raises nothing; a changed listed SKILL.md or a script beside it still does."""

    def test_c_a_sync_rewriting_its_bookkeeping_is_quiet(self):
        self.start()
        self.sync(2)
        self.assertEqual(self.daily(), "NO_CHANGES")
        self.assertEqual(self.unverified(), [])

    def test_c_a_changed_skill_and_a_script_beside_the_bookkeeping_still_alert(self):
        self.start()
        self.sync(2)
        put(self.pdf, CLEAN.format(n="pdf") + "Version 2.\n")                  # not on the release list
        script = self.h("sand-data/managed-skills/sync.py")
        put(script, "print('hi')\n")
        run = self.h(f"{SYNCED}/{BUCKET}/run.sh")
        put(run, "echo hi\n")
        self.assertNotEqual(self.daily(), "NO_CHANGES")
        self.assertEqual(self.unverified(), sorted([self.pdf, script, run]))
        for p in (self.pdf, script, run):
            self.assertEqual(len(self.counted_high(p)), 1, p)
        for p in self.churn:
            self.assertEqual(self.at(p), [], p)

    def test_c_bookkeeping_is_not_counted_in_the_walk_limit(self):
        saved = wt.PLATFORM_WALK_MAX_FILES
        wt.PLATFORM_WALK_MAX_FILES = 2                                          # pdf and prime; the six bookkeeping files don't count
        try:
            self.start()
            self.assertFalse([f for f in self.snap()["findings"] if f["rule"] == "WT-I011"])
            self.assertEqual(self.unverified(), [])
        finally:
            wt.PLATFORM_WALK_MAX_FILES = saved

    def test_c_an_older_baselines_bookkeeping_lines_raise_nothing(self):
        self.start()
        base = wt.load_baseline()[0]
        base.update({p: "0" * 64 for p in self.churn})                          # as a baseline written before the rule held them
        wt.save_json(wt.state_path("baseline.json"), base)
        self.audit()
        for p in self.churn:
            self.assertEqual(self.at(p), [], p)
        self.assertEqual(self.unverified(), [])

    def test_c_the_owners_yes_holds_nothing_back_for_bookkeeping(self):
        self.start()
        self.sync(2)
        out = self.run_cmd("baseline", "--roots", *self.roots, "--owner-said-yes")[1]
        self.assertNotIn("Not approved by this", out)
        self.assertFalse(set(self.churn) & set(wt.load_baseline()[0]))

    def test_c_contrast_a_key_in_the_bookkeeping_is_still_found(self):
        """Contrast: passes on 7e853c4 too; the content checks on these files are unchanged."""
        cache = self.churn[0]
        put(cache, '{"token": "ghp_' + fake_key(36) + '"}\n')
        self.scanners(gitleaks=LEAKS % [cache])
        self.audit()
        s = [f for f in self.snap()["findings"] if f["rule"] == "WT-S002" and f["where"] == cache + ":1"]
        self.assertEqual(len(s), 1)
        self.assertTrue(wt.counts(s[0]))


class Lookalikes(_Churn):
    """(d): only the exact names at the exact places, as written and where they lead, are bookkeeping. Each test also checks a
    real bookkeeping file in the same audit is quiet (that is the part that fails on 7e853c4)."""

    def quiet_beside(self, loud):
        self.assertNotEqual(self.daily(), "NO_CHANGES")
        self.assertEqual(len(self.counted_high(loud)), 1, loud)
        self.assertEqual(self.unverified(), [loud])
        self.assertFalse(wt.platform_churn_file(loud))

    def test_d_a_link_named_cache_json_leading_to_a_skill_file_is_not_bookkeeping(self):
        self.start()
        link = self.churn[0]
        os.remove(link)
        os.symlink(self.pdf, link)
        self.quiet_beside(link)

    def test_d_a_link_named_cache_json_leading_to_the_other_cache_is_not_bookkeeping(self):
        self.start()
        link = self.churn[0]
        os.remove(link)
        os.symlink(self.churn[1], link)
        self.quiet_beside(link)

    def test_d_a_meta_json_inside_a_plugin_folder_is_not_bookkeeping(self):
        self.start()
        meta = self.h(f"{SYNCED}/{BUCKET}/build/foo.meta.json")
        put(meta, "{}\n")
        self.quiet_beside(meta)

    def test_d_a_bookkeeping_name_with_an_exec_bit_is_not_bookkeeping(self):
        self.start()
        m = self.h(f"{SYNCED}/{BUCKET}/manifest.json")
        os.chmod(m, 0o755)
        self.quiet_beside(m)

    def test_d_a_cache_json_beside_a_skill_md_is_not_bookkeeping(self):
        md = self.h("agent-data/managed-skills/SKILL.md")
        put(md, CLEAN.format(n="root"))
        profiles.vendor_release(self, md)
        self.start()
        self.sync(2)
        self.assertEqual(len(self.counted_high(self.churn[1])), 1)
        self.assertEqual(self.unverified(), [self.churn[1]])
        self.assertFalse(wt.platform_churn_file(self.churn[1]))

    def test_d_a_bucket_folder_linked_from_outside_the_home_folder_is_not_bookkeeping(self):
        outside = os.path.join(self.tmp, "elsewhere", BUCKET)
        os.makedirs(outside)
        put(os.path.join(outside, "manifest.json"), "{}\n")
        self.start()
        bucket = self.h(f"{SYNCED}/{BUCKET}")
        os.rename(bucket, os.path.join(self.tmp, "old-bucket"))
        os.symlink(outside, bucket)
        self.audit()
        m = os.path.join(bucket, "manifest.json")
        self.assertEqual(self.at(self.churn[0]), [])
        self.assertEqual(len(self.counted_high(m)), 1)
        self.assertFalse(wt.platform_churn_file(m))


class Lock(unittest.TestCase):
    """(e): the release list Watchtower ships lists no bookkeeping, and its count line is the real count."""

    def entries(self):
        return [l.split("  ", 1)[1] for l in read_lock().splitlines() if l.strip() and not l.lstrip().startswith("#")]

    def test_e_the_shipped_lock_lists_no_bookkeeping(self):
        rels = self.entries()
        self.assertTrue(rels)
        self.assertFalse(set(REMOVED) & set(rels))
        self.assertEqual([r for r in rels if wt.platform_churn(r)], [])
        self.assertIn(".grok/bundled/manifest.json", rels)                     # release content stays listed

    def test_e_the_count_line_is_the_real_count(self):
        m = re.search(r"leaving (\d+)\.", read_lock())
        self.assertIsNotNone(m, "no count line")
        self.assertEqual(int(m.group(1)), len(self.entries()))
        self.assertEqual(len(self.entries()), 623 - len(REMOVED))

    def test_e_the_header_names_the_exception_not_an_impossible_rule(self):
        text = read_lock()
        self.assertNotIn("can only come from a computer no Bot has run on yet", text)
        self.assertIn("accepted exception", text)
        self.assertNotIn("ships with no entries", open(os.path.join(ROOT, "watchtower", "wt.py"), encoding="utf-8").read())


class Labels(unittest.TestCase):
    def test_contrasts_are_marked(self):
        """Contrast: passes on 7e853c4 too (a check on this file's own labels)."""
        import inspect
        for name, obj in list(globals().items()):
            if isinstance(obj, type) and issubclass(obj, unittest.TestCase):
                for m in [m for m in dir(obj) if m.startswith("test_") and "_contrast" in m]:
                    self.assertIn("Contrast", inspect.getdoc(getattr(obj, m)) or "", f"{name}.{m}")


if __name__ == "__main__":
    unittest.main()
