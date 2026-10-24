"""b8i5, generic release: no tracked file carries an owner, Bot or box name or a real reply host.

The denylist holds only sha256 digests, so this file never ships the strings it guards against, and a failure names the file
(a denylisted path component masked to its digest prefix), the line and a digest prefix, never the matched text. Keyed
entries are the digest of the string casefolded with everything but [a-z0-9] dropped, so they match in any case, across
separators, split over adjacent string literals or lines, and behind escapes. Exact-form entries (digest of the string as
first stored) match words (as written and lowercased), hosts and their dot-suffixes, hyphen/dot/underscore compounds (every
run of 2 or more parts), 2- and 3-grams of the lowercased word stream, UUIDs and uuid_uuid buckets. Both are read in the text
as it is and with escapes read and adjacent string literals joined. Every path component is scanned too. The files are what
`git ls-files` lists, decoded as text (UTF-16 with a BOM, else UTF-8, else latin-1); only the formats in BINARY are skipped.
"""
import codecs, functools, hashlib, json, os, re, secrets, shutil, subprocess, sys, tempfile, unicodedata, unittest, uuid
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import ROOT
import isr  # noqa: E402

KEYED = frozenset({   # sha256 of key(s): casefolded, only [a-z0-9] kept (fix round 1)
    "78e0b1fdb55ecbc60a8da0168ce87daa0e7ba2b44ffa0cf61a8f0a6c5b423d7a",
    "9533327a239046b9fb62ee9b412bcd93a098721f6b4f72095b2612e4eedea38e",
    "cd3d89d800ee2b34148939d52ae16923bbf96c3480ff28d0179e8375279bde5f",
    "f84bd215ffb21b0f126aca76726556472aa877b68defdceb2afc6bdc4320a217",
    "1b87290375a0f18d14c57aef5a17d1481a4df80af6a6550cd6bdf733542b1dac",
})
EXACT_ONLY = frozenset({   # exact-form only, case-folded digest pending owner (the text is in no tracked file)
    "0715f7c809a4caa3d73fcf425cc676ccadaad250e340652dad0446b8fe98f845",
    "e85f3d74bf753f2b8b23e1b3999144e468fa67dbc115ceb4361d2fa9ab486e8b",
    "d492559b465c0312a7b30ba904f06cc9cfa11b76195aa17d65669b87461c211a",
    "ebcd9aca2aa31a8f31dcad71302c37378d717d591af684900cdb1e3d9bcbdbbe",
    "71c095b134e2d3b1af4bbc53166b42e0c25ef286fde0622a06f5f5cd68fe2bab",
    "4a84f5ba2ed4b8ca11e32e181217b496c09b27b0a2ad2d9f552b8f6fc2f10872",
    "9bebadf8653f1e2895c27f35df536e8ac63465711df76ddb7879ef39b78e757d",
    "f1c4225545215ad9e81db4d2f119b6c72aeb0c9886a45af79098fe1049772b20",
    "75fd13fb102277fde9d3b2ef44e62ad196660660682e1bf152f19e6966abf5a5",
    "ee4b266f483008b12c3bb335811171efba12a460633187415eda8964d03fb3b0",
    "785ccca178178ce128bf10c6f00a688aa7419094c4bfc13cebcf13b4fb4754b9",
    "1cb12b334f1ba8511d70128eabe69ac51835c32144b59f1a8bc93e47b6b366ce",
    # Exact form kept on purpose (owner decision pending): its keyed digest, 71b41d6dd48d..., is a common lowercase word
    # that test_matcher_misses_lookalikes keeps clean (b8i5).
    "8899ecd1626db63dd12b9c57879efda72a1a78a21b498e943c07229dedc09ea7",
})
# b8i4: the maintainer's sync bucket, exact form (each id, and the <id>_<id> pair), as the lock rewrite dropped it
SYNC_BUCKET_UUIDS_TODO_ITEM4 = ("a6af8a9727de5c1f720a52c73a151c50a1241c700c0f119199b085bb1046be47",
                                "803ca00ca78c653c21c5f450aafe97adf24468831e99d9d17f64d310d3bcc4aa",
                                "1eeb23c119624deef03f937efe2d90d6c8a3a8cdeb789880dcebfaba9fa75d31")
DENY = KEYED | EXACT_ONLY | frozenset(SYNC_BUCKET_UUIDS_TODO_ITEM4)
# The public repo account in the release URLs (owner decision, fix round 1): sha256 of the whole compound exactly as written.
# Only that exact compound is blanked before scanning; any other spelling, casing or longer compound still hits.
ALLOW = frozenset({"363a7d48f615cc538634ee46c83655545f415c1ab50de82afb8629e036e00b47"})
# Item 4 could not edit these two rules files, and the lock still names a vendor skill path (.grok/bundled/skills/...) whose
# words join into a keyed entry (decision D9: the owner decides any ALLOW); remove each when it is clean
# (test_item4_exemptions_still_needed fails then).
ITEM4_PENDING = frozenset({"rules/platform-release.lock", "rules/platform-normalize.json", "rules/platform-reviewed.json"})
CHANGELOG_CUT = re.compile(r"^## 0\.7\.3$")   # CHANGELOG.md from this header down is history (owner decision, b8i5)
NO_CUT = "no-0.7.3-header"
BINARY = (".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".bmp", ".zip", ".gz", ".tgz", ".bz2", ".xz", ".pdf",
          ".woff", ".woff2", ".ttf", ".otf")   # the only files whose contents are not scanned (their paths are)

# --- matcher ---
WORD = re.compile(r"[A-Za-z0-9]+")
HOST = re.compile(r"[a-z0-9.-]+\.[a-z]{2,}")
COMPOUND = re.compile(r"[a-z0-9]+(?:[-._][a-z0-9]+)+")
ACCOUNT = re.compile(r"[A-Za-z0-9]+(?:[-._][A-Za-z0-9]+)+")   # what ALLOW can name: a whole compound
_U = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
UUID = re.compile(_U)
BUCKET = re.compile(_U + "_" + _U)
SPLIT = re.compile(r"([-._])")
RUN_CAP = 48   # characters in a joined run of words; the longest keyed entry is 11
_BREAKS = "\n\r\x0b\x0c\x1c-\x1e\x85\N{LINE SEPARATOR}\N{PARAGRAPH SEPARATOR}"   # what splitlines splits on
GLUE = re.compile(r"\\(?:x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|N\{[^}" + _BREAKS + r"]*\}|[0-7]{1,3}|[^"
                  + _BREAKS + r"])|[\"'][ \t]*\+?[ \t]*[\"']")


@functools.lru_cache(maxsize=1 << 16)
def sha(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def key(s):
    return re.sub(r"[^a-z0-9]", "", s.casefold())


def deny_of(*strings):
    """Keyed digests, as KEYED stores them (the tests inject these for runtime-built tokens)."""
    return frozenset(sha(key(s)) for s in strings)


def _unglue(m):
    s = m.group()
    if s[0] != "\\":
        return ""                                   # "ab" "cd" and 'ab' + 'cd' read as "abcd"
    e = s[1:]
    try:
        if e[0] in "xuU":
            c = chr(int(e[1:], 16))
        elif e[0] == "N" and len(e) > 1:
            c = unicodedata.lookup(e[2:-1])
        elif e[0] in "01234567":
            c = chr(int(e, 8))
        else:
            c = " "                                 # \n, \t, \\ and the rest separate words
    except (ValueError, KeyError, OverflowError):
        c = " "
    return c if WORD.fullmatch(c) else " "


def unglued(text):
    """The text with escapes read (an escaped letter or digit kept, any other escape a space) and adjacent string literals
    on a line joined; line breaks are kept, so line numbers hold. One left-to-right pass."""
    return GLUE.sub(_unglue, text)


def unallowed(text, allow):
    """The text with every whole compound whose digest is in `allow` blanked out (same length, no line break)."""
    if not allow:
        return text
    return ACCOUNT.sub(lambda m: " " * len(m.group()) if sha(m.group()) in allow else m.group(), text)


def candidates(text):
    """Yield (line, kind, candidate) for every shape the denylist can match."""
    words, at = [], []
    for n, line in enumerate(text.splitlines(), 1):
        low = line.lower()
        for w in WORD.findall(line):
            yield n, "word", w
            yield n, "word", w.lower()
            words.append(w)
            at.append(n)
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
    lows = [w.lower() for w in words]
    for i in range(len(words)):
        for size in (2, 3):
            if i + size <= len(words):
                yield at[i], f"{size}-gram", " ".join(lows[i:i + size])
        run = words[i]                       # adjacent words joined, across any separator or line break
        for j in range(i + 1, len(words)):
            if len(run) + len(words[j]) > RUN_CAP:
                break
            run += words[j]
            folded = run.casefold()
            yield at[i], "run", folded
            if folded != run:
                yield at[i], "run", run


def scan_text(text, deny, path="-", allow=ALLOW):
    text = unallowed(text, allow)
    hits = set()
    for t in {text, unglued(text)}:
        for n, kind, c in candidates(t):
            d = sha(c)
            if d in deny:
                hits.add((path, n, kind, d[:12]))
    return sorted(hits)


def shown(rel, deny, allow=ALLOW):
    """(rel with each denylisted component replaced by [digest prefix], one "path" hit per denylisted component)."""
    parts, found = [], []
    for c in rel.split("/"):
        ds = sorted({h[3] for h in scan_text(c, deny, allow=allow)})
        parts.append(f"[{ds[0]}]" if ds else c)
        found += ds
    path = "/".join(parts)
    return path, [(path, 0, "path", d) for d in found]


def decode(raw):
    """Any file as text: UTF-16 with a BOM, else UTF-8, else latin-1. A NUL stays a character (a word separator)."""
    if raw[:2] in (codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE):
        return raw.decode("utf-16", errors="replace")
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def scan(root, files, deny, allow=ALLOW):
    """[(path, line, kind, digest[:12])] for every denylisted candidate in `files` (paths relative to `root`) and their
    paths (line 0); `path` has each denylisted component masked."""
    hits = []
    for rel in files:
        path, found = shown(rel, deny, allow)
        hits += found
        if rel.lower().endswith(BINARY):
            continue
        try:
            with open(os.path.join(root, rel), "rb") as f:
                raw = f.read()
        except (FileNotFoundError, IsADirectoryError):
            continue
        text = decode(raw)
        if rel == "CHANGELOG.md":
            lines = text.splitlines()
            cut = next((i for i, l in enumerate(lines) if CHANGELOG_CUT.match(l)), None)
            if cut is None:
                hits.append((path, 0, NO_CUT, "-"))   # and nothing is exempt
            else:
                text = "\n".join(lines[:cut])
        hits.extend(scan_text(text, deny, path, allow))
    return hits


def report(hits):
    """The failure text: path (denylisted components masked), line and digest prefix; never the matched text."""
    return "\n".join(f"{p}:{n}: {d if d != '-' else k}" for p, n, k, d in hits)


def same_safely(tc, got, want, deny=DENY):
    """assertEqual that can't print a denylisted string: one in either value fails first, by digest prefix only."""
    for name, value in (("found", got), ("expected", want)):
        hits = scan_text(json.dumps(value), deny)
        tc.assertFalse(hits, f"denylisted text in the {name} value")
    tc.assertEqual(got, want)


def tracked(root):
    """The tracked files, from `git ls-files` only (it reads a linked worktree's .git file too); never a directory walk."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    try:
        p = subprocess.run(["git", "ls-files", "-z"], cwd=root, env=env, capture_output=True)
    except FileNotFoundError:
        raise unittest.SkipTest("git is not installed: the release scan reads the tracked files from `git ls-files` only")
    if p.returncode and not os.path.lexists(os.path.join(root, ".git")):
        raise unittest.SkipTest("not a git checkout: the release scan reads the tracked files from `git ls-files` only")
    if p.returncode:
        raise AssertionError(f"`git ls-files` failed with exit {p.returncode} in a git checkout")
    return [os.fsdecode(x) for x in p.stdout.split(b"\0") if x]
# --- end of matcher ---


def tree(files):
    root = tempfile.mkdtemp(prefix="isr-bot-generic-")
    for rel, body in files.items():
        os.makedirs(os.path.dirname(os.path.join(root, rel)) or root, exist_ok=True)
        with open(os.path.join(root, rel), "wb" if isinstance(body, bytes) else "w") as f:
            f.write(body)
    return root


def tok(prefix):
    return prefix + secrets.token_hex(6)


def prefix(s):
    return next(iter(deny_of(s)))[:12]


class Denylist(unittest.TestCase):
    def test_no_tracked_file_has_a_denylisted_string(self):
        files = [p for p in tracked(ROOT) if p not in ITEM4_PENDING]
        hits = scan(ROOT, files, DENY)
        if hits:
            self.fail(f"{len(hits)} hit(s) in {len({h[0] for h in hits})} file(s):\n" + report(hits))

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
                     "bin.png": f"{cap}\0"})
        deny = frozenset(sha(t) for t in expect)   # exact-form entries
        hits = scan(root, ["a.md", "b/c.txt", "bin.png"], deny)
        for t, (path, line, kind) in expect.items():
            mine = [h for h in hits if h[3] == sha(t)[:12]]
            self.assertEqual({(p, n) for p, n, _, _ in mine}, {(path, line)}, kind)
            self.assertIn(kind, {k for _, _, k, _ in mine})
        self.assertEqual({h[0] for h in hits}, {"a.md", "b/c.txt"})   # the .png (a BINARY format) is skipped
        for h in hits:
            self.assertNotIn(cap, repr(h)); self.assertNotIn(host, repr(h))   # a hit never shows the text

    def test_matcher_misses_lookalikes(self):
        cap = tok("Kq")
        comp = tok("ca") + "-" + tok("cb")
        host = tok("h") + ".invalid"
        deny = deny_of(cap, comp, host)
        root = tree({"x.py": f"{cap}ed and {cap}s\n{comp}x and y{comp}\nhttps://x{host}/\n"
                             f"pre{cap} and {cap[:5]}x{cap[5:]}\n",
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
        self.assertEqual(len(DENY), 21)
        for d in DENY:
            self.assertRegex(d, r"^[0-9a-f]{64}$")
        self.assertEqual(len(set(SYNC_BUCKET_UUIDS_TODO_ITEM4)), 3)
        for d in SYNC_BUCKET_UUIDS_TODO_ITEM4:
            self.assertRegex(d, r"^[0-9a-f]{64}$")

    def test_keyed_exact_and_allow_sets(self):
        self.assertEqual((len(KEYED), len(EXACT_ONLY), len(ALLOW)), (5, 13, 1))
        self.assertEqual(KEYED & EXACT_ONLY, frozenset())
        self.assertEqual(ALLOW & DENY, frozenset())
        for d in ALLOW:
            self.assertRegex(d, r"^[0-9a-f]{64}$")

    def test_binary_formats_skipped_are_these(self):
        self.assertEqual(BINARY, (".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".bmp", ".zip", ".gz", ".tgz", ".bz2",
                                  ".xz", ".pdf", ".woff", ".woff2", ".ttf", ".otf"))

    def test_only_the_exact_account_name_is_allowed(self):
        name, suffix = tok("nm"), tok("as")
        account = f"{name}-{suffix}"
        variants = [account.upper(), f"{name.capitalize()}-{suffix}", f"{name}_{suffix}", f"{name} {suffix}",
                    f"{name}.{suffix}", name, name.upper(), f"{account}-x", f"x.{account}", f'"{name}" "-{suffix}"',
                    f"{name}\\x2d{suffix}"]
        text = f"https://example.invalid/{account}/repo\n" + "\n".join(variants) + "\n"
        hits = scan_text(text, deny_of(name), allow=frozenset({sha(account)}))
        self.assertEqual({h[1] for h in hits}, set(range(2, len(variants) + 2)))
        self.assertEqual({h[1] for h in scan_text(text, deny_of(name), allow=frozenset())}, set(range(1, len(variants) + 2)))


class FixRound1(unittest.TestCase):
    """Codex round 1 on 7f2a892: one replay per finding (each fails there at its assertion)."""

    def test_1_case_variants_of_a_keyed_name_hit(self):
        cap = tok("Kq")
        text = (f"user {cap.lower()}-aisec\n{cap.upper()}_BUCKET = 1\njust {cap.lower()} here\n"   # lookalikes before
                f"{cap.upper()}\n{cap.swapcase()}\n{cap}\n")
        self.assertEqual({h[1] for h in scan_text(text, deny_of(cap))}, {1, 2, 3, 4, 5, 6})

    def test_2_split_literals_and_escapes_hit(self):
        cap, comp = tok("Sp"), tok("ca") + "-" + tok("cb")
        g = [tok("ga"), tok("gb")]
        text = "\n".join([f'x = ("{cap[:5]}" "{cap[5:]}")', f"y = \"{cap[:3]}\" + '{cap[3:]}'", f'z = ("{cap[:4]}"',
                          f'     "{cap[4:]}")', f'"{g[0]}\\n{g[1]}"', f'"{g[0]}\\t{g[1]}"', f'"{comp[:7]}" "{comp[7:]}"',
                          f'"\\x{ord(cap[0]):02x}{cap[1:]}"']) + "\n"
        hits = scan_text(text, deny_of(cap, " ".join(g), comp))
        for t, lines in ((cap, {1, 2, 3, 8}), (" ".join(g), {5, 6}), (comp, {7})):
            self.assertEqual({h[1] for h in hits if h[3] == prefix(t)}, lines)

    def test_3_path_components_are_scanned_and_masked(self):
        cap = tok("Pa")
        a, b = f"docs/{cap}.md", f"notes/{cap.lower()}/x.md"
        root = tree({a: "nothing to see\n", b: f"see {cap}\n"})
        hits = scan(root, [a, b], deny_of(cap))
        d = prefix(cap)
        self.assertIn((f"docs/[{d}]", 0, "path", d), hits)
        self.assertIn((f"notes/[{d}]/x.md", 0, "path", d), hits)
        self.assertIn(f"notes/[{d}]/x.md", {h[0] for h in hits if h[1] == 1})
        self.assertNotIn(cap.lower(), repr(hits).lower())

    def test_4_tracked_files_come_from_git_in_a_worktree_with_a_git_file(self):
        if shutil.which("git") is None:
            self.skipTest("git is not installed")
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        repo = tempfile.mkdtemp(prefix="isr-bot-generic-git-")
        subprocess.run(["git", "init", "-q", repo], env=env, check=True, capture_output=True)
        work = tree({"tracked.md": "a\n", "untracked.md": "b\n", ".git": f"gitdir: {os.path.join(repo, '.git')}\n"})
        subprocess.run(["git", "add", "tracked.md"], cwd=work, env=env, check=True, capture_output=True)
        self.assertEqual(tracked(work), ["tracked.md"])

    def test_4_no_checkout_is_a_skip_not_a_walk(self):
        if shutil.which("git") is None:
            self.skipTest("git is not installed")
        with self.assertRaises(unittest.SkipTest):
            tracked(tree({"a.md": "x\n"}))

    def test_5_the_failure_report_never_shows_the_text(self):
        cap = tok("Rp")
        rel = f"{cap}/notes.md"
        hits = scan(tree({rel: f"by {cap}\n"}), [rel], deny_of(cap))
        msg = report(hits)
        self.assertTrue(hits)
        self.assertNotIn(cap.lower(), msg.lower())
        self.assertIn(prefix(cap), msg)

    def test_6_nul_utf16_and_latin1_files_are_scanned(self):
        cap = tok("Nu")
        line = f"x {cap}\n"
        files = {"a.txt": (cap + "\0").encode(), "b.md": line.encode("utf-16"),
                 "c.md": codecs.BOM_UTF16_BE + line.encode("utf-16-be"), "d.cfg": ("caf\xe9 " + line).encode("latin-1"),
                 "e.dat": line.encode("utf-16-le"), "f.png": line.encode()}
        hits = scan(tree(files), sorted(files), deny_of(cap))
        self.assertEqual({h[0] for h in hits}, {"a.txt", "b.md", "c.md", "d.cfg", "e.dat"})


class PlatformRefusal(unittest.TestCase):
    def test_platform_refusal_states_the_policy_without_a_name(self):
        s = isr.PLATFORM_YES_REFUSED
        self.assertEqual(scan_text(s, DENY), [])
        self.assertIn("(ISR Bot policy: the owner's yes never approves a platform file)", s)
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
        self.assertEqual(sorted(d["name"] for d in self.descriptions()), sorted(isr.ROUTINE_NAMES))
        self.assertEqual(len(isr.ROUTINE_NAMES), 4)

    def test_all_four_names_and_descriptions_exact(self):
        same_safely(self, sorted((d["slug"], d["name"], d["description"]) for d in self.descriptions()), sorted([
            ("watchtower-daily-watch", "ISR Bot daily watch",
             "Every morning, check for skill changes, decoy reads and new risks; report what changed and anything that "
             "still needs attention, such as open unverified findings or checks that didn't complete."),
            ("watchtower-weekly-audit", "ISR Bot weekly audit",
             "Every Sunday, run the full audit, threat brief and weekly report into this chat."),
            ("watchtower-weekly-tidy", "ISR Bot weekly tidy",
             "Every Sunday, preview the safe cleanup (changes nothing) and ask before applying anything."),
            ("watchtower-monthly-rollcall", "ISR Bot monthly roll-call",   # the name uninstall removes (isr.ROUTINE_NAMES)
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

    def test_5_a_description_mismatch_never_prints_denylisted_text(self):   # Codex round 1, finding 4 (replay)
        t = tok("Dz")
        got = sorted((d["slug"], d["name"], d["description"]) for d in self.descriptions())
        bad = [(got[0][0], got[0][1], f"{t} reads your keys")] + got[1:]
        with self.assertRaises(AssertionError) as cm:
            same_safely(self, bad, got, deny_of(t))
        self.assertNotIn(t.lower(), str(cm.exception).lower())

    def test_7_the_daily_description_does_not_promise_silence(self):   # Codex round 1, finding 7 (replay)
        d = {x["slug"]: x["description"] for x in self.descriptions()}["watchtower-daily-watch"]
        self.assertIsNone(re.search(r"\b(only|silent|silence|quiet|nothing)\b", d, re.I), "the daily description")
        for part in ("what changed", "still needs attention", "unverified", "checks that didn't complete"):
            self.assertIn(part, d)


if __name__ == "__main__":
    unittest.main()
