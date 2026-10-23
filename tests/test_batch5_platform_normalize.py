"""Batch 5, item d3: the platform's own metadata JSON (.grok/bundled/manifest.json and the like) that its sync rewrites.

d3a: an unverified metadata JSON is still a counted high, with honest wording: the platform rewrites it, don't delete it, it clears
when a Watchtower release lists the version. d3b (decision 3, Oct 18): rules/platform-normalize.json names fields the sync
rewrites; the release list holds the digest of the file without them. The shipped spec is EMPTY, so nothing changes until a spike
proves which fields are unused; these tests use a spec of their own. A file read strictly (no duplicate keys, NaN, BOM, link or
oversize) with only those fields changed is a Platform refresh Tip; any other change stays a counted WT-I001.

"replay" tests fail on 151e40c on their assertion; "guard" tests keep real changes counted.

b8i4 (decision D2, Oct 22): metadata JSON follows the middle path, so a change Watchtower's rules find nothing in, at a path
that already exists, is the quiet Platform refresh line now, though it isn't verified against the released version (it is
not in VERIFIED_METADATA, so the line never says it was compared). Only a change the middle path holds (over 1 MB here) stays
counted; the held wording is checked on the finding a held version gets. Fix round 1 (Codex 1): a new skill folder on a
first run is no middle-path candidate, so the skill-file wording test reads its counted high again, as on f7c28e6."""
import hashlib, json, os, sys, unittest
from unittest import mock
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import Box, ROOT, wt
import profiles

REL = ".grok/bundled/manifest.json"
V1 = {"generated_at": "2026-10-01T08:00:00Z", "generation": 7,
      "skills": [{"name": "pptx", "installation_preference": "available"}, {"name": "learn", "installation_preference": "available"}]}


def text(doc):
    return json.dumps(doc, indent=2) + "\n"


def canonical(doc, drop=("generated_at",)):
    """The canonical form, written independently of wt.canonical_platform_json: the named top-level fields dropped, compact JSON."""
    return hashlib.sha256(json.dumps({k: v for k, v in doc.items() if k not in drop}, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


class _Meta(Box):
    def setUp(self):
        super().setUp()
        self.p = os.path.join(self.home, REL)
        os.makedirs(os.path.dirname(self.p), exist_ok=True)
        os.makedirs(os.path.join(self.home, ".grok", "bundled", "skills", "pptx"), exist_ok=True)
        pptx = os.path.join(self.home, ".grok", "bundled", "skills", "pptx", "SKILL.md")
        with open(pptx, "w") as f:
            f.write("---\nname: pptx\ndescription: decks\n---\nMake decks.\n")
        profiles.vendor_release(self, pptx)

    def write(self, data):
        if os.path.lexists(self.p):
            os.remove(self.p)
        with open(self.p, "wb") as f:
            f.write(data if isinstance(data, bytes) else data.encode())

    def spec(self, entries):
        p = os.path.join(self.tmp, "platform-normalize.json")
        with open(p, "w") as f:
            json.dump({"about": "test", "entries": entries}, f)
        had, old = hasattr(wt, "PLATFORM_NORMALIZE"), getattr(wt, "PLATFORM_NORMALIZE", None)   # 151e40c has none: it reads no spec
        wt.PLATFORM_NORMALIZE = p
        self.addCleanup(lambda: setattr(wt, "PLATFORM_NORMALIZE", old) if had else delattr(wt, "PLATFORM_NORMALIZE"))

    def mine(self):
        return [f for f in self.snap()["findings"] if f["where"].split(":")[0] == self.p]

    def counted(self):
        return [f for f in self.mine() if wt.counts(f)]


# ---------------------------------------------------------------- d3a: the wording
class MetadataWording(_Meta):
    def test_a_changed_metadata_file_says_what_it_is(self):   # replay (151e40c: "Don't use this skill … remove it")
        self.write(text(V1))
        profiles.vendor_release(self, self.p)
        self.skills(1); self.audit(); self.run_cmd("baseline", "--roots", *self.roots, "--owner-said-yes")
        was = wt.sha256_file(self.p)
        self.write(text(dict(V1, generated_at="2026-10-18T08:00:00Z")))
        self.audit()
        i1 = [f for f in self.mine() if f["rule"] == "WT-I001"]
        self.assertEqual([(f["severity"], wt.counts(f)) for f in i1 if wt.counts(f)], [])   # b8i4: the middle path's quiet line
        self.assertNotIn(self.p, wt.VERIFIED_METADATA)                         # not compared with the released version
        held = wt.unverified_platform_finding(self.p, wt.sha256_file(self.p), was)   # the wording a held version gets
        self.assertEqual(held["title"], "ISR Bot's release list doesn't have Grok Bot's changed list of what it loads yet")
        self.assertIn("Don't delete it (Grok Bot needs it)", held["fix"])
        self.assertIn("tell ISR Bot support", held["fix"])
        self.assertNotIn("remove it", held["fix"])
        self.assertEqual(self.snap()["status"], wt.ALL_GOOD)

    def test_a_new_metadata_file_too(self):   # replay (151e40c: "A new file appeared …")
        self.skills(1)
        self.write(text(V1))
        self.audit()
        i2 = [f for f in self.mine() if f["rule"] == "WT-I002"]
        self.assertEqual([(f["severity"], wt.counts(f)) for f in i2], [("high", True)])
        self.assertTrue(i2[0]["title"].startswith("ISR Bot's release list doesn't have Grok Bot's new list of what it loads"))

    def test_a_skill_file_keeps_its_wording(self):   # guard
        self.skills(1)
        q = os.path.join(self.home, ".grok", "bundled", "skills", "learn", "SKILL.md")
        os.makedirs(os.path.dirname(q))
        with open(q, "w") as f:
            f.write("---\nname: learn\n---\nLearn.\n")
        self.audit()
        i2 = [f for f in self.snap()["findings"] if f["where"] == q and f["rule"] == "WT-I002"]
        self.assertIn("treat it like a file someone added", i2[0]["fix"])


# ---------------------------------------------------------------- d3b: the normalization machinery
class Normalized(_Meta):
    SPEC = [{"path": REL, "fields": [{"key": ["generated_at"], "type": "iso8601"}]}]

    def baseline_with(self, doc):
        self.spec(self.SPEC)
        self.write(text(doc))
        with open(self.platform_lock, "a") as f:
            f.write(f"canonical {canonical(doc)}  {REL}\n")   # what a release lists: the digest of the canonical form (batch 6 fix round 1: on a line that says so)
        self.skills(1); self.audit(); self.run_cmd("baseline", "--roots", *self.roots, "--owner-said-yes")
        self.assertEqual(self.counted(), [])

    def test_a_timestamp_only_sync_is_a_tip(self):   # replay (151e40c: a counted high WT-I001)
        self.baseline_with(V1)
        self.write(text(dict(V1, generated_at="2026-10-18T09:30:00.123Z")))
        self.assertEqual(self.run_cmd("daily", "--roots", *self.roots)[1].strip(), "NO_CHANGES")
        tip = [f for f in self.snap()["findings"] if f["rule"] == "WT-I008"]
        self.assertEqual([(f["label"], f["severity"]) for f in tip], [(wt.TIP, "info")])
        self.assertIn("Platform refresh: 1 of Grok Bot's own files changed", tip[0]["title"])
        r = json.loads(self.run_cmd("audit", "--roots", *self.roots)[1])   # the full audit accepts it like any listed platform update
        self.assertEqual(self.counted(), [])
        self.assertFalse([f for f in self.mine() if f.get("unverified_platform")])
        self.assertEqual(r["status"], wt.ALL_GOOD)

    def assert_counted(self, data, why):
        self.write(data)
        self.audit()
        self.assertEqual([(f["rule"], f["severity"]) for f in self.counted()], [("WT-I001", "high")], why)

    def assert_quiet_unverified(self, data, why):
        """b8i4: not normalized (so never verified), and the middle path lets it through: no counted finding, not compared."""
        self.write(data)
        self.audit()
        self.assertEqual([(f["rule"], f["severity"]) for f in self.counted()], [], why)
        self.assertNotIn(self.p, wt.VERIFIED_METADATA, why)

    def test_any_other_change_stays_counted(self):   # guard
        changes = {"installation_preference available -> required": dict(V1, skills=[dict(V1["skills"][0], installation_preference="required"), V1["skills"][1]]),
                   "an added skill": dict(V1, skills=V1["skills"] + [{"name": "evil", "installation_preference": "required"}]),
                   "a changed name": dict(V1, skills=[dict(V1["skills"][0], name="pptx2"), V1["skills"][1]]),
                   "a changed generation": dict(V1, generation=8),
                   "the timestamp holding an object": dict(V1, generated_at={"skills": ["evil"]}),
                   "the timestamp not a timestamp": dict(V1, generated_at="see https://evil.example")}
        self.baseline_with(V1)
        for why, doc in changes.items():
            self.assert_quiet_unverified(text(doc), why)

    def test_files_that_are_not_strict_json_stay_counted(self):   # guard
        self.baseline_with(V1)
        body = text(dict(V1, generated_at="2026-10-18T09:30:00Z"))
        for why, data in (("a duplicate key", body.replace('"generation": 7,', '"generation": 7, "generation": 9,')),
                          ("NaN", body.replace('"generation": 7', '"generation": NaN'))):
            self.assert_quiet_unverified(data, why)
        for why, data in (("a byte-order mark", b"\xef\xbb\xbf" + body.encode()),            # the middle path holds these too:
                          ("over 1 MB", body[:-2] + ', "pad": "' + "x" * (1024 * 1024) + '"}\n')):   # rules flag the BOM; too big
            self.assert_counted(data, why)

    def test_a_link_stays_counted(self):   # guard
        self.baseline_with(V1)
        real = os.path.join(self.tmp, "elsewhere.json")
        with open(real, "w") as f:
            f.write(text(dict(V1, generated_at="2026-10-18T09:30:00Z")))
        os.remove(self.p)
        os.symlink(real, self.p)
        self.audit()
        self.assertTrue(self.counted())

    def test_a_spec_that_isnt_the_released_one_is_ignored(self):   # guard
        self.baseline_with(V1)
        self.write(text(dict(V1, generated_at="2026-10-18T09:30:00Z")))
        real = wt.release_digest
        vars(wt)["_PLATFORM_NORMALIZE_CACHE"].clear()
        with mock.patch.object(wt, "release_digest", lambda rel: "0" * 64 if rel == wt.PLATFORM_NORMALIZE_REL else real(rel)):
            self.audit()
        vars(wt)["_PLATFORM_NORMALIZE_CACHE"].clear()
        self.assertEqual([(f["rule"], f["severity"]) for f in self.counted()], [])   # b8i4: the middle path's quiet line
        self.assertNotIn(self.p, wt.VERIFIED_METADATA)                         # the spec was ignored: nothing was verified
        self.assertTrue([n for n in self.snap()["notes"] if wt.PLATFORM_NORMALIZE_REL in n and "MANIFEST.sha256" in n])

    def test_the_shipped_spec_is_empty(self):   # guard: no behavior change until the spike's data lands
        with open(os.path.join(ROOT, "rules", "platform-normalize.json")) as f:
            self.assertEqual(json.load(f)["entries"], [])
        with open(os.path.join(ROOT, "MANIFEST.sha256")) as f:
            self.assertIn("  rules/platform-normalize.json", f.read())


class ShapeScript(unittest.TestCase):
    def test_it_prints_key_paths_and_types_never_values(self):   # guard
        import subprocess, tempfile
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "manifest.json")
            with open(p, "w") as f:
                json.dump(dict(V1, secret="FAKEvalue123"), f)
            out = subprocess.run([sys.executable, "-I", os.path.join(ROOT, "scripts", "platform-json-shape.py"), p], capture_output=True,
                                 text=True, timeout=60).stdout
            self.assertIn('.\"generated_at\"\tstring\t', out)
            self.assertIn('.\"skills\"[1].\"installation_preference\"\tstring\t', out)
            self.assertNotIn("FAKEvalue123", out)
            self.assertNotIn("2026-10-01", out)
            with open(p, "w") as f:
                f.write('{"a": 1, "a": 2}')
            out = subprocess.run([sys.executable, "-I", os.path.join(ROOT, "scripts", "platform-json-shape.py"), p], capture_output=True,
                                 text=True, timeout=60)
            self.assertEqual(out.returncode, 1)
            self.assertIn("not strict JSON: duplicate key", out.stdout)


if __name__ == "__main__":
    unittest.main()
