"""b8i5, generic release: no tracked file carries an owner, Bot or box name or a real reply host.

The denylist holds only sha256 digests, so this file never ships the strings it guards against, and a failure names the file,
line, kind and a digest prefix, never the matched text. Candidates per file: words (as written and lowercased), hosts and
their dot-suffixes, hyphen/dot/underscore compounds (every run of 2 or more parts), 2- and 3-grams of the lowercased word
stream, UUIDs and uuid_uuid buckets.
"""
import hashlib, json, os, re, secrets, subprocess, sys, tempfile, unittest, uuid
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import ROOT, wt

DENY = frozenset({
    "0715f7c809a4caa3d73fcf425cc676ccadaad250e340652dad0446b8fe98f845",
    "b3cd90b170e623ff13c227330f5a3e0de0d3148801119ebcc4472b9e099dca36",
    "e85f3d74bf753f2b8b23e1b3999144e468fa67dbc115ceb4361d2fa9ab486e8b",
    "d492559b465c0312a7b30ba904f06cc9cfa11b76195aa17d65669b87461c211a",
    "2cfc93553c4517ee112b601db0fb96e60139d93cb7eab699c22d20e39e6d2983",
    "f91a10777707e0e0ec417ad7646556431a29b5357937b4b5b495b96bfa0e963b",
    "ebcd9aca2aa31a8f31dcad71302c37378d717d591af684900cdb1e3d9bcbdbbe",
    "71c095b134e2d3b1af4bbc53166b42e0c25ef286fde0622a06f5f5cd68fe2bab",
    "4a84f5ba2ed4b8ca11e32e181217b496c09b27b0a2ad2d9f552b8f6fc2f10872",
    "9bebadf8653f1e2895c27f35df536e8ac63465711df76ddb7879ef39b78e757d",
    "8899ecd1626db63dd12b9c57879efda72a1a78a21b498e943c07229dedc09ea7",
    "cd3d89d800ee2b34148939d52ae16923bbf96c3480ff28d0179e8375279bde5f",
    "f1c4225545215ad9e81db4d2f119b6c72aeb0c9886a45af79098fe1049772b20",
    "75fd13fb102277fde9d3b2ef44e62ad196660660682e1bf152f19e6966abf5a5",
    "820ee1d5fcdd6572988e2ef108cec3652f5aa94cc01c950162f447c835c96df0",
    "ee4b266f483008b12c3bb335811171efba12a460633187415eda8964d03fb3b0",
    "785ccca178178ce128bf10c6f00a688aa7419094c4bfc13cebcf13b4fb4754b9",
    "1cb12b334f1ba8511d70128eabe69ac51835c32144b59f1a8bc93e47b6b366ce",
})
# Item 4 adds the digests of the two sync bucket ids here, with the lock rewrite that drops them.
SYNC_BUCKET_UUIDS_TODO_ITEM4 = ()
# Item 4 (on hold) rewrites these; remove when it lands (test_item4_exemptions_still_needed fails then).
ITEM4_PENDING = frozenset({"rules/platform-release.lock", "rules/platform-normalize.json", "rules/platform-reviewed.json",
                           "tests/test_item8_churn.py"})
CHANGELOG_CUT = re.compile(r"^## 0\.7\.3$")   # CHANGELOG.md from this header down is history (owner decision, b8i5)
NO_CUT = "no-0.7.3-header"

WORD = re.compile(r"[A-Za-z0-9]+")
HOST = re.compile(r"[a-z0-9.-]+\.[a-z]{2,}")
COMPOUND = re.compile(r"[a-z0-9]+(?:[-._][a-z0-9]+)+")
_U = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
UUID = re.compile(_U)
BUCKET = re.compile(_U + "_" + _U)
SPLIT = re.compile(r"([-._])")
_digest = {}


def sha(s):
    d = _digest.get(s)
    if d is None:
        d = _digest[s] = hashlib.sha256(s.encode("utf-8")).hexdigest()
    return d


def candidates(text):
    """Yield (line, kind, candidate) for every shape the denylist can match."""
    stream = []
    for n, line in enumerate(text.splitlines(), 1):
        low = line.lower()
        for w in WORD.findall(line):
            yield n, "word", w
            yield n, "word", w.lower()
            stream.append((w.lower(), n))
        for h in HOST.findall(low):
            parts = h.split(".")
            for i in range(len(parts) - 1):
                yield n, "host", ".".join(parts[i:])
        for c in COMPOUND.findall(low):
            bits = SPLIT.split(c)            # part, sep, part, sep, ...
            k = len(bits) // 2 + 1
            for i in range(k):
                for j in range(i + 2, k + 1):
                    yield n, "compound", "".join(bits[2 * i:2 * j - 1])
        for u in UUID.findall(low):
            yield n, "uuid", u
        for b in BUCKET.findall(low):
            yield n, "bucket", b
    for i in range(len(stream)):
        for size in (2, 3):
            if i + size <= len(stream):
                yield stream[i][1], f"{size}-gram", " ".join(w for w, _ in stream[i:i + size])


def scan_text(text, deny, path="-"):
    hits = set()
    for n, kind, c in candidates(text):
        d = sha(c)
        if d in deny:
            hits.add((path, n, kind, d[:12]))
    return sorted(hits)


def scan(root, files, deny):
    """[(path, line, kind, digest[:12])] for every denylisted candidate in `files` (paths relative to `root`)."""
    hits = []
    for rel in files:
        try:
            with open(os.path.join(root, rel), "rb") as f:
                raw = f.read()
        except (FileNotFoundError, IsADirectoryError):
            continue
        if b"\0" in raw:
            continue
        text = raw.decode("utf-8", errors="replace")
        if rel == "CHANGELOG.md":
            lines = text.splitlines()
            cut = next((i for i, l in enumerate(lines) if CHANGELOG_CUT.match(l)), None)
            if cut is None:
                hits.append((rel, 0, NO_CUT, "-"))   # and nothing is exempt
            else:
                text = "\n".join(lines[:cut])
        hits.extend(scan_text(text, deny, rel))
    return hits


def tracked(root):
    if os.path.isdir(os.path.join(root, ".git")):
        out = subprocess.run(["git", "ls-files", "-z"], cwd=root, capture_output=True, check=True).stdout
        return [p for p in out.decode("utf-8", errors="replace").split("\0") if p]
    files = []
    for d, dirs, names in os.walk(root):
        dirs[:] = [x for x in dirs if x != ".git"]
        files += [os.path.relpath(os.path.join(d, x), root).replace(os.sep, "/") for x in names]
    return sorted(files)


def tree(files):
    root = tempfile.mkdtemp(prefix="wt-generic-")
    for rel, body in files.items():
        os.makedirs(os.path.dirname(os.path.join(root, rel)) or root, exist_ok=True)
        with open(os.path.join(root, rel), "w") as f:
            f.write(body)
    return root


def tok(prefix):
    return prefix + secrets.token_hex(6)


class Denylist(unittest.TestCase):
    def test_no_tracked_file_has_a_denylisted_string(self):
        files = [p for p in tracked(ROOT) if p not in ITEM4_PENDING]
        hits = scan(ROOT, files, DENY)
        if hits:
            self.fail(f"{len(hits)} hit(s) in {len({h[0] for h in hits})} file(s):\n" +
                      "\n".join(f"{p}:{n}: {k} {d}" for p, n, k, d in hits))

    def test_matcher_finds_every_shape(self):
        cap, low = tok("Zq"), tok("zw")
        host = tok("r") + ".invalid"
        comp = tok("c") + "-" + tok("k")
        g3 = [tok("pa"), tok("pb"), tok("pc")]
        u, b1, b2 = str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())
        bucket = f"{b1}_{b2}"
        expect = {cap: ("a.md", 2, "word"), low: ("a.md", 3, "word"), host: ("a.md", 4, "host"),
                  comp: ("b/c.txt", 1, "compound"), " ".join(g3): ("b/c.txt", 3, "3-gram"),
                  u: ("b/c.txt", 5, "uuid"), bucket: ("b/c.txt", 6, "bucket")}
        root = tree({"a.md": f"nothing here\nSee {cap}, today.\nmixed {low.upper()[:4]}{low[4:]} case\n"
                             f"post to https://{host}/api/x only\n",
                     "b/c.txt": f"ls x-{comp}.meta.json\nfiller\nthen {g3[0]}  {g3[1].upper()}\n{g3[2]} end\n"
                                f"id {u} here\nbucket {bucket}.json\n",
                     "bin.dat": f"{cap}\0"})
        deny = frozenset(sha(t) for t in expect)
        hits = scan(root, ["a.md", "b/c.txt", "bin.dat"], deny)
        for t, (path, line, kind) in expect.items():
            mine = [h for h in hits if h[3] == sha(t)[:12]]
            self.assertEqual({(p, n) for p, n, _, _ in mine}, {(path, line)}, kind)
            self.assertIn(kind, {k for _, _, k, _ in mine})
        self.assertEqual({h[0] for h in hits}, {"a.md", "b/c.txt"})   # the NUL file is skipped
        for h in hits:
            self.assertNotIn(cap, repr(h)); self.assertNotIn(host, repr(h))   # a hit never shows the text

    def test_matcher_misses_lookalikes(self):
        cap = tok("Kq")
        comp = tok("ca") + "-" + tok("cb")
        host = tok("h") + ".invalid"
        deny = frozenset(sha(t) for t in (cap, comp, host))
        root = tree({"x.py": f"user {cap.lower()}-aisec\n{cap.upper()}_BUCKET = 1\n{cap}ed and {cap}s\n"
                             f"just {cap.lower()} here\n{comp}x and y{comp}\nhttps://x{host}/\n",
                     "y.md": "a forged entry; def forge()\nforge forged FORGE\n"})
        self.assertEqual(scan(root, ["x.py"], deny), [])
        self.assertEqual(scan(root, ["y.md"], DENY), [])

    def test_changelog_cut(self):
        above, below = tok("Ab"), tok("Be")
        deny = frozenset({sha(above), sha(below)})
        root = tree({"CHANGELOG.md": f"# Changelog\n\n## Unreleased\n- {above} did it\n\n## 0.7.3\n- {below} did it\n"})
        self.assertEqual([h[:3] for h in scan(root, ["CHANGELOG.md"], deny)], [("CHANGELOG.md", 4, "word")])
        root = tree({"CHANGELOG.md": f"# Changelog\n\n## 0.7.3 (renamed)\n- {below} did it\n"})
        hits = scan(root, ["CHANGELOG.md"], deny)
        self.assertIn(("CHANGELOG.md", 0, NO_CUT, "-"), hits)
        self.assertIn(sha(below)[:12], {h[3] for h in hits})   # with no header nothing is exempt

    def test_item4_exemptions_still_needed(self):
        for rel in sorted(ITEM4_PENDING):
            self.assertTrue(os.path.isfile(os.path.join(ROOT, rel)), rel)
            self.assertTrue(scan(ROOT, [rel], DENY), f"{rel} is clean now: drop it from ITEM4_PENDING")

    def test_digests_well_formed(self):
        self.assertEqual(len(DENY), 18)
        for d in DENY:
            self.assertRegex(d, r"^[0-9a-f]{64}$")
        self.assertEqual(SYNC_BUCKET_UUIDS_TODO_ITEM4, ())


class PlatformRefusal(unittest.TestCase):
    def test_platform_refusal_states_the_policy_without_a_name(self):
        s = wt.PLATFORM_YES_REFUSED
        self.assertEqual(scan_text(s, DENY), [])
        self.assertIn("(Watchtower policy: only a release that lists a platform file clears it)", s)
        self.assertIn("NOT APPROVED", s)
        self.assertIn("Nothing was changed", s)


ROUTINES = os.path.join(ROOT, "routines")
APPLIES = re.compile(r"\b(apply|applies|applied|delete[sd]?|remove[sd]?|clean(s|ed)? up)\b", re.I)
PREVIEW = ("a preview", "Apply nothing in this run", "Read-only")


class RoutineDescriptions(unittest.TestCase):
    def descriptions(self):
        p = os.path.join(ROUTINES, "descriptions.json")
        self.assertTrue(os.path.isfile(p), "routines/descriptions.json is missing")
        with open(p) as f:
            return json.load(f)

    def test_every_routine_has_exactly_one_description(self):
        stems = sorted(f[:-3] for f in os.listdir(ROUTINES) if f.endswith(".md"))
        ds = self.descriptions()
        slugs = [d["slug"] for d in ds]
        self.assertEqual(sorted(slugs), sorted(f"watchtower-{s}" for s in stems))
        self.assertEqual(len(slugs), len(set(slugs)))
        for d in ds:
            self.assertEqual(sorted(d), ["description", "name", "slug"])
            self.assertTrue(d["name"].strip() and d["description"].strip(), d["slug"])

    def test_the_names_are_the_ones_uninstall_removes(self):
        self.assertEqual(sorted(d["name"] for d in self.descriptions()), sorted(wt.ROUTINE_NAMES))
        self.assertEqual(len(wt.ROUTINE_NAMES), 4)

    def test_all_four_names_and_descriptions_exact(self):
        self.assertEqual(sorted((d["slug"], d["name"], d["description"]) for d in self.descriptions()), sorted([
            ("watchtower-daily-watch", "Watchtower daily watch",
             "Every morning, check for skill changes, decoy reads and new risks; alert only when something changed."),
            ("watchtower-weekly-audit", "Watchtower weekly audit",
             "Every Sunday, run the full audit, threat brief and weekly report into this chat."),
            ("watchtower-weekly-tidy", "Watchtower weekly tidy",
             "Every Sunday, preview the safe cleanup (changes nothing) and ask before applying anything."),
            ("watchtower-monthly-rollcall", "Watchtower monthly roll-call",   # the name uninstall removes (wt.ROUTINE_NAMES)
             "On the 1st, post a reminder that a roll-call is due; it runs only after the owner says yes."),
        ]))

    def test_a_preview_routine_is_never_described_as_doing_it(self):
        self.assertTrue(APPLIES.search("apply the safe cleanup"))   # the old template text
        seen = 0
        for d in self.descriptions():
            with open(os.path.join(ROUTINES, d["slug"][len("watchtower-"):] + ".md")) as f:
                body = f.read()
            if any(p in body for p in PREVIEW):
                seen += 1
                self.assertIsNone(APPLIES.search(d["description"]), d["slug"])
        self.assertGreaterEqual(seen, 3)   # daily watch, weekly audit, weekly tidy


if __name__ == "__main__":
    unittest.main()
