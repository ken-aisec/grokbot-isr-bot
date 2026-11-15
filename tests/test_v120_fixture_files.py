"""1.2.0: ISR Bot's own shipped test and doc files are recognized by content (plan fixture-recognition, sections 3 to 5).

The Nov 15 live audit listed 42 medium key hits: 12 ISR-S001 and 2 ISR-S002 in each of three copies of this repo (docs/KNOWN-LIMITS.md
and 11 tests). Their values are example keys and key-block headers that exist to prove such values still alert, so no value test
can drop them. A file whose exact bytes are one ISR Bot shipped under tests/ or docs/ (rules/fixture_files.json, sha256 only, read
from the running engine's own rules/) is now noted, not scored. One byte more or less and every hit fires as before.

Planted values are built here at run time and never echoed (assertions name rules, counts and paths only). gitleaks is the
column-accurate stand-in of test_v082_secrets; FF1 also runs with the real gitleaks when it is on PATH (skipped otherwise).
TruffleHog is left out (no answers: a key keeps its rule's severity). FF1 (both) and FF8 fail on 5c86099 at their assertion
(no recognizer, no registry), FF8 and FF10 on cd85c7e (its registry kept only files with an ISR-T011 or URI hit); the others
guard what must not change."""
import base64, hashlib, json, os, re, shlex, shutil, string, subprocess, sys, unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import Box  # noqa: E402
from test_isr_bot import REAL_GITLEAKS  # noqa: E402
from test_v120_decoy_sweeps import value_of  # noqa: E402
import test_v082_secrets as v82  # noqa: E402  (module access: its test classes don't run twice)
import isr  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SECRETS = ("ISR-S001", "ISR-S002")
# plan section 1: the files the Nov 15 live audit flagged, in each of the three copies
FLAGGED = ["docs/KNOWN-LIMITS.md"] + [f"tests/{n}.py" for n in (
    "test_batch4_codex_review1", "test_batch4_codex_review2", "test_batch6_example_keys", "test_batch6b_codex_r1",
    "test_batch6b_codex_r2", "test_batch6b_codex_r3", "test_batch7a_must_fix", "test_batch7d_part2", "test_hardening_batch4",
    "test_isr_bot", "test_v111_fixtures")]
# the three copies the live audit saw, and the commit each was checked out at
COPIES = (("rev4-src", "5c86099"), ("rev4-base", "6820632"), ("rev4-main", "7da4c44"))
T011 = next(r for r in isr.load_rules()["rules"] if r["id"] == isr.SECRET_RULE)["rx"]


# a scheme://user:pass@ credential (the gitleaks stand-in reports these; the registry lists every shipped file, hit or not)
URI_RX = re.compile(r"\b[A-Za-z][A-Za-z0-9+.-]*://[^\s/:@'\"]+:[^\s/@'\"]+@")


def has_hit(data):
    text = data.decode("utf-8", "replace")
    return bool(T011.search(text) or URI_RX.search(text))


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read_bytes(p):
    with open(p, "rb") as f:
        return f.read()


def _chars(seed, n, alphabet=string.ascii_letters + string.digits):
    out, i = [], 0
    while len(out) < n:
        out += [alphabet[b % len(alphabet)] for b in hashlib.sha256(f"ff|{seed}|{i}".encode()).digest()]
        i += 1
    return "".join(out[:n])


def gh_like(seed):
    """A GitHub-token-shaped value that is not an ISR Bot fixture (made now, never committed)."""
    return "ghp_" + _chars(seed, 36)


def pem_block(seed):
    """A private key block with a key-shaped body (made now)."""
    body = base64.b64encode(b"".join(hashlib.sha256(f"pem|{seed}|{i}".encode()).digest() for i in range(6))).decode()
    kind = "RSA " + "PRIVATE KEY"
    return f"-----BEGIN {kind}-----\n" + "\n".join(body[i:i + 64] for i in range(0, len(body), 64)) + f"\n-----END {kind}-----\n"


def uri_cred(seed):
    return "https://" + "deploy" + ":" + _chars(seed, 24, string.hexdigits[:16]) + "@files.example.com/x"


def kept_hits(text):
    """How many ISR-T011 hits ISR Bot counts in `text` (an ISR Bot fixture value is none)."""
    return sum(1 for m in T011.finditer(text) if isr.keep_secret_hit(m.group(0)))


def files_of(f):
    """Every file a key finding is about: its where, its grouped files and its hits'."""
    out = {f["where"].split(":")[0]} | set(f.get("affected_files") or [])
    out |= {h.get("file") for k in ("member_hits", "secret_hits") for h in f.get(k) or [] if isinstance(h, dict)}
    return {x for x in out if isinstance(x, str)}


def under(p, top):
    return p == top or p.startswith(top.rstrip("/") + "/")


class _FF(Box):
    def setUp(self):
        super().setUp()
        self.hits = []
        self.skills(1)
        self.metas = []
        real = isr.audit

        def spy(*a, **k):   # the run's meta (fixture_files), as audit() returns it
            out = real(*a, **k)
            self.metas.append(out[1])
            return out
        p = mock.patch.object(isr, "audit", side_effect=spy); p.start(); self.addCleanup(p.stop)

    def put(self, p, data):
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(data if isinstance(data, bytes) else data.encode())
        return p

    def copy(self, rel, dest):
        """One of the repo's own files, byte for byte."""
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.copyfile(os.path.join(ROOT, rel), dest)
        return dest

    def leak(self, p, value, rule):
        self.hits += v82.leaks(p, value, rule)

    def leak_all(self, p):
        """The gitleaks stand-in reports every key hit and URI credential in p, on every line that holds it."""
        text = read_bytes(p).decode("utf-8", "replace")
        for v in sorted({m.group(0) for m in T011.finditer(text)}):
            self.leak(p, v, "private-key" if v.startswith("-----") else "generic-api-key")
        for v in sorted({m.group(0) for m in URI_RX.finditer(text)}):
            self.leak(p, v, "generic-api-key")

    def run_audit(self, gitleaks=None):
        report = os.path.join(self.tmp, "leaks.json")
        with open(report, "w") as f:
            json.dump(self.hits, f)
        self.scanners(gitleaks=gitleaks or v82.GITLEAKS.replace("REPORT", repr(report)), trufflehog=None)
        return self.audit()

    def keys(self, top):
        """The key findings (ISR-S001, ISR-S002) about any file at or under `top`."""
        return [f for f in self.snap()["findings"] if f["rule"] in SECRETS and any(under(x, top) for x in files_of(f))]

    def rules_at(self, p):
        return sorted({r for f in self.keys(p) for r in [f["rule"]] + list(f.get("also_rules") or [])})

    def fixture_files(self):
        return self.metas[-1]["fixture_files"]

    def no_registry(self):
        return mock.patch.object(isr, "FIXTURE_REGISTRY", os.path.join(self.tmp, "no-such-registry.json"))


class FF1FlaggedCopiesGoToZero(_FF):
    def place(self, name):
        return os.path.join(self.ws, "copies", name)

    def assert_zero(self, copies, gitleaks=None, stand_in=True):
        if stand_in:
            for p in copies:
                self.leak_all(p)
            self.assertTrue(self.hits)
        with self.no_registry():   # contrast: as 5c86099 sees them, every copy is a key finding and gitleaks reports them
            self.run_audit(gitleaks)
        self.assertEqual(self.fixture_files(), [])
        seen = {x for name, _ in COPIES for f in self.keys(self.place(name)) for x in files_of(f)}
        self.assertEqual(sorted(p for p in copies if p not in seen), [])
        self.assertTrue(any("ISR-S002" in self.rules_at(self.place(name)) for name, _ in COPIES))
        self.run_audit(gitleaks)
        for name, _ in COPIES:
            self.assertEqual([(f["rule"], f["where"]) for f in self.keys(self.place(name))], [], name)
        self.assertEqual(sorted(p for p in self.fixture_files() if p in copies), sorted(copies))
        self.assertEqual(len(copies), 36)
        # the report says them in one line (the snapshot carries fixture_files once baseline.py copies it: misses.md)
        snap = dict(self.snap(), fixture_files=self.fixture_files())
        self.assertIn("\n36 ISR Bot test/doc files recognized by content; not scored.\n", isr.render_md(snap, [], "2026-W46"))
        self.assertNotIn("recognized by content", isr.render_md(dict(snap, fixture_files=[]), [], "2026-W46"))

    def test_ff1_the_twelve_files_at_three_paths_give_no_key_finding(self):   # replay: fails on 5c86099 (36 S001, S002)
        copies = [self.copy(rel, os.path.join(self.place(name), rel)) for name, _ in COPIES for rel in FLAGGED]
        self.assert_zero(copies)

    def test_ff1_replay_the_live_shape_each_copy_at_its_own_commit(self):   # replay: fails on 5c86099
        copies = []
        for name, commit in COPIES:
            for rel in FLAGGED:
                try:
                    data = subprocess.run(["git", "-C", ROOT, "cat-file", "blob", f"{commit}:{rel}"], capture_output=True, check=True).stdout
                except (OSError, subprocess.CalledProcessError):
                    self.skipTest(f"this checkout has no git history with {commit}")
                copies.append(self.put(os.path.join(self.place(name), rel), data))
        self.assert_zero(copies)

    @unittest.skipUnless(os.access(REAL_GITLEAKS, os.X_OK), "gitleaks is not installed")
    def test_ff1_with_the_real_gitleaks(self):   # replay, when the real gitleaks is installed (it is run, never changed or copied)
        copies = [self.copy(rel, os.path.join(self.place(name), rel)) for name, _ in COPIES for rel in FLAGGED]
        self.assert_zero(copies, gitleaks="#!/bin/sh\nexec " + shlex.quote(REAL_GITLEAKS) + ' "$@"\n', stand_in=False)
        self.assertIn("gitleaks", isr.load_json(isr.state_path("engines_used.json"), {}).get("engines", []))   # it ran


class FF2NonFixtureFileStillFires(_FF):
    def shape(self, p):
        return sorted((f["rule"], f["title"], f.get("severity_was") or f["severity"], f["evidence"], f.get("also_rules") or [])
                      for f in self.keys(p))

    def test_ff2_a_new_notes_file_with_a_key_a_key_block_and_a_url_credential(self):   # guard
        gh, pem, uri = gh_like(21), pem_block(22), uri_cred(23)
        p = self.put(os.path.join(self.ws, "notes", "notes.md"), f"# notes\ntoken {gh}\n\n{pem}\nmirror {uri}\n")
        self.leak(p, gh, "github-pat")
        self.leak(p, pem.split("\n")[0], "private-key")
        self.leak(p, uri, "generic-api-key")
        with self.no_registry():
            self.run_audit()
        before = self.shape(p)
        self.run_audit()
        self.assertEqual(self.shape(p), before)                          # as without the registry: same rules, titles, severities
        self.assertEqual(self.rules_at(p), list(SECRETS))
        s1 = [f for f in self.keys(p) if f["rule"] == "ISR-S001"]
        self.assertEqual([(f["title"], isr.counts(f)) for f in s1], [("Secret stored in a file on the shared computer", True)])
        self.assertIn("(2 in file)", s1[0]["evidence"])
        self.assertNotIn(p, self.fixture_files())


def pem_line_flip(text):
    """`text` with one byte changed on a line holding a key-block header, outside the header (None when no such line)."""
    for m in T011.finditer(text):
        if not m.group(0).startswith("-----"):
            continue
        a, b = text.rfind("\n", 0, m.start()) + 1, text.find("\n", m.end())
        b = len(text) if b < 0 else b
        for i in list(range(a, m.start())) + list(range(m.end(), b)):
            if text[i].isalnum():
                return text[:i] + ("x" if text[i] != "x" else "y") + text[i + 1:]
    return None


class FF3EditedFixtureStillFires(_FF):
    REL = "tests/test_v111_fixtures.py"

    def base(self):
        data = read_bytes(os.path.join(ROOT, self.REL))
        self.assertIn(sha(data), isr.load_fixture_registry())
        return data.decode("utf-8")

    def assert_fires(self, p, n):
        got = [f for f in self.keys(p) if f["rule"] == "ISR-S001"]
        self.assertEqual(len(got), 1, [(f["rule"], f["where"]) for f in self.keys(p)])
        self.assertIn(f"({n} in file)", got[0]["evidence"])              # every hit counted, as before
        self.assertNotIn(p, self.fixture_files())

    def test_ff3_one_real_looking_key_appended(self):   # guard
        text, gh = self.base(), gh_like(31)
        p = self.put(os.path.join(self.ws, "app", "test_v111_fixtures.py"), text + f"\nTOKEN = '{gh}'\n")
        self.leak(p, gh, "github-pat")
        self.run_audit()
        self.assert_fires(p, kept_hits(text) + 1)
        self.assertEqual(self.rules_at(p), list(SECRETS))

    def test_ff3_one_byte_changed_on_the_key_block_line(self):   # guard
        text = self.base()
        flipped = pem_line_flip(text)
        self.assertIsNotNone(flipped)
        self.assertEqual(len(flipped), len(text))
        p = self.put(os.path.join(self.ws, "app", "test_v111_fixtures.py"), flipped)
        self.run_audit()
        self.assert_fires(p, kept_hits(text))


class FF4NoMarkerOrNeighbourTrick(_FF):
    REL = "tests/test_v111_fixtures.py"

    def test_ff4_a_real_key_after_a_copied_header_line(self):   # guard
        text, gh = read_bytes(os.path.join(ROOT, self.REL)).decode("utf-8"), gh_like(41)
        line = next(l for l in text.splitlines() if T011.search(l) and T011.search(l).group(0).startswith("-----"))
        p = self.put(os.path.join(self.ws, "app", "keys.txt"), line + "\n" + f"GH_TOKEN={gh}\n")
        self.run_audit()
        got = [f for f in self.keys(p) if f["rule"] == "ISR-S001"]
        self.assertEqual(len(got), 1)
        self.assertIn("(2 in file)", got[0]["evidence"])
        self.assertNotIn(p, self.fixture_files())

    def test_ff4_a_whole_fixture_file_plus_a_real_key(self):   # guard
        text, gh = read_bytes(os.path.join(ROOT, self.REL)).decode("utf-8"), gh_like(42)
        p = self.put(os.path.join(self.ws, "app", "test_v111_fixtures.py"), f"GH_TOKEN = '{gh}'\n" + text)
        self.run_audit()
        got = [f for f in self.keys(p) if f["rule"] == "ISR-S001"]
        self.assertEqual(len(got), 1)
        self.assertIn(f"({kept_hits(text) + 1} in file)", got[0]["evidence"])
        self.assertNotIn(p, self.fixture_files())


class FF5OnlyTheEnginesRegistry(_FF):
    def test_ff5_a_scanned_copy_cannot_list_its_own_files(self):   # guard
        self.assertEqual(os.path.realpath(isr.FIXTURE_REGISTRY), os.path.join(os.path.realpath(ROOT), "rules", "fixture_files.json"))
        clone = os.path.join(self.ws, "clone")
        keys = self.put(os.path.join(clone, "tests", "keys.md"), f"token {gh_like(51)}\n")
        reg = self.put(os.path.join(clone, "rules", "fixture_files.json"), json.dumps({"version": 1, "sha256": [sha(read_bytes(keys))]}))
        self.put(os.path.join(clone, "MANIFEST.sha256"), f"{sha(read_bytes(reg))}  rules/fixture_files.json\n{sha(read_bytes(keys))}  tests/keys.md\n")
        self.run_audit()
        self.assertEqual([f["rule"] for f in self.keys(keys)], ["ISR-S001"])
        self.assertNotIn(keys, self.fixture_files())
        self.assertFalse(isr.is_fixture_file(keys))

    def test_ff5_a_link_to_a_fixture_file_is_not_recognized(self):   # guard
        target = self.copy("tests/test_v111_fixtures.py", os.path.join(self.tmp, "outside", "test_v111_fixtures.py"))
        link = os.path.join(self.ws, "linked", "test_v111_fixtures.py")
        os.makedirs(os.path.dirname(link))
        os.symlink(target, link)
        self.run_audit()
        self.assertNotIn(link, self.fixture_files())
        self.assertEqual([f["rule"] for f in self.keys(link)], ["ISR-S001"])   # read through the link, and scored
        self.assertFalse(isr.is_fixture_file(link))
        self.assertTrue(isr.is_fixture_file(target))                     # the file itself is one


class FF6FailClosed(_FF):
    def test_ff6_missing_corrupt_or_empty_registry_suppresses_nothing(self):   # guard
        p = self.copy("docs/KNOWN-LIMITS.md", os.path.join(self.ws, "repo", "docs", "KNOWN-LIMITS.md"))
        good = sha(read_bytes(p))
        self.assertIn(good, isr.load_fixture_registry())
        bad = {"missing": None, "corrupt": "{not json", "empty": {"version": 1, "sha256": []}, "list": [good],
               "other version": {"version": 2, "sha256": [good]}, "a bad entry": {"version": 1, "sha256": [good, "not-hex"]},
               "not a list": {"version": 1, "sha256": good}}
        for name, body in bad.items():
            with self.subTest(registry=name):
                reg = os.path.join(self.tmp, "reg", name.replace(" ", "-") + ".json")
                if body is not None:
                    self.put(reg, body if isinstance(body, str) else json.dumps(body))
                with mock.patch.object(isr, "FIXTURE_REGISTRY", reg):
                    self.assertEqual(isr.load_fixture_registry(), frozenset())
                    self.run_audit()                                     # the audit still runs (code 0, asserted by audit())
                self.assertEqual(self.fixture_files(), [])
                self.assertEqual([f["rule"] for f in self.keys(p) if f["rule"] == "ISR-S001"], ["ISR-S001"])


class FF7DecoysUnchanged(_FF):
    def test_ff7_a_decoy_value_in_a_copy_of_a_fixture_file_is_still_its_k_finding(self):   # guard
        code, o, e = self.run_cmd("canary", "plant")
        self.assertEqual(code, 0, e)
        reg = isr.load_json(isr.state_path("canaries.json"), {})
        top = os.path.realpath(self.tmp) + os.sep
        self.assertEqual([n for n, v in reg.items() if not os.path.realpath(v["path"]).startswith(top)], [])   # the box's own decoys
        value = "rk_live_" + value_of(reg["api-env"]["path"]) * 2   # in memory only
        text = read_bytes(os.path.join(ROOT, "tests", "test_v111_fixtures.py")).decode("utf-8")
        p = self.put(os.path.join(self.ws, "app", "test_v111_fixtures.py"), text + f"\nkey: {value}\n")
        same = self.copy("tests/test_v111_fixtures.py", os.path.join(self.ws, "app2", "test_v111_fixtures.py"))
        self.run_audit()
        self.assertEqual([(f["rule"], f["severity"]) for f in self.snap()["findings"] if f["where"] == p and f["rule"].startswith("ISR-K")],
                         [("ISR-K003", "critical")])
        self.assertNotIn(p, self.fixture_files())
        self.assertEqual([f["rule"] for f in self.keys(p)], ["ISR-S001"])
        self.assertIn(same, self.fixture_files())                         # the unchanged copy beside it is recognized


class FF8RegistryIsFresh(unittest.TestCase):
    def test_ff8_every_tracked_test_and_doc_file_with_a_hit_is_listed(self):   # replay: fails on 5c86099 (no registry)
        try:
            out = subprocess.run(["git", "-C", ROOT, "ls-files", "-z", "--", "tests", "docs"], capture_output=True, check=True).stdout
        except (OSError, subprocess.CalledProcessError):
            self.skipTest("not a git checkout")
        rels = [r for r in out.decode().split("\0") if r]
        if not rels:
            self.skipTest("not a git checkout")
        with open(os.path.join(ROOT, "rules", "fixture_files.json"), encoding="utf-8") as f:
            listed = json.load(f)
        self.assertEqual(sorted(listed), ["sha256", "version"])
        self.assertEqual(listed["sha256"], sorted(set(listed["sha256"])))   # sorted, once each (the script's output)
        reg = isr.load_fixture_registry()
        self.assertEqual(reg, frozenset(listed["sha256"]))
        stale, n = [], 0
        for rel in rels:
            p = os.path.join(ROOT, rel)
            if os.path.islink(p) or not os.path.isfile(p):
                continue
            data = read_bytes(p)
            n += has_hit(data)
            if sha(data) not in reg:   # every shipped file, hit or not: gitleaks has rules ISR-T011 doesn't (FF10)
                stale.append(rel)
        self.assertGreaterEqual(n, len(FLAGGED))
        self.assertEqual(stale, [], "run `make manifest` (scripts/make-fixture-registry.sh, then make-manifest.sh)")


def one_byte_off(text, avoid):
    """`text` with one letter changed on its first line that holds none of `avoid` (same length)."""
    a = 0
    for line in text.split("\n"):
        if not any(v in line for v in avoid):
            i = next((a + j for j, c in enumerate(line) if c.isalpha()), None)
            if i is not None:
                return text[:i] + ("x" if text[i] != "x" else "y") + text[i + 1:]
        a += len(line) + 1
    return None


class FF10OtherGitleaksRulesOnAShippedFile(_FF):
    """Real gitleaks hits shipped tests with rules ISR-T011 doesn't have (curl-auth-user, generic-api-key). The registry once
    kept only files with an ISR-T011 or URI hit, so a byte copy of such a file still gave a tests-folder ISR-S002."""
    REL = "tests/test_batch4_codex_review3.py"
    RELS = ("tests/test_batch4_codex_review3.py", "tests/test_batch4_codex_review4.py")
    # obviously fake values the file holds: a curl --user pair and an API_TOKEN value (built here so this line trips nothing)
    VALUES = (("admin:" + "FAKE" + "user1", "curl-auth-user"), ("FAKE" + "scanner" + "ERROR", "generic-api-key"))

    def gitleaks_s002(self, p):
        return [f["rule"] for f in self.keys(p) if f["rule"] == "ISR-S002" or "ISR-S002" in (f.get("also_rules") or [])]

    def test_ff10_a_copy_with_only_curl_or_generic_hits_is_recognized_and_one_byte_off_fires(self):   # replay: fails on cd85c7e
        data = read_bytes(os.path.join(ROOT, self.REL))
        self.assertFalse(has_hit(data))                                  # no ISR-T011 or URI hit: the old filter left it out
        self.assertIn(sha(data), isr.load_fixture_registry())
        text = data.decode("utf-8")
        self.assertTrue(all(v in text for v, _ in self.VALUES))
        same = self.copy(self.REL, os.path.join(self.ws, "shipped", "tests", os.path.basename(self.REL)))
        off = self.put(os.path.join(self.ws, "edited", "tests", os.path.basename(self.REL)), one_byte_off(text, [v for v, _ in self.VALUES]))
        self.assertEqual(len(read_bytes(off)), len(data))
        self.assertNotEqual(sha(read_bytes(off)), sha(data))
        for p in (same, off):
            for v, rule in self.VALUES:
                self.leak(p, v, rule)
        self.assertEqual(sorted({h["RuleID"] for h in self.hits if h["File"] == same}), sorted(r for _, r in self.VALUES))
        with self.no_registry():                                         # contrast: both copies are gitleaks findings
            self.run_audit()
        self.assertEqual((self.gitleaks_s002(same), self.gitleaks_s002(off)), (["ISR-S002"], ["ISR-S002"]))
        self.run_audit()
        self.assertEqual(self.keys(same), [])
        self.assertIn(same, self.fixture_files())
        self.assertEqual(self.gitleaks_s002(off), ["ISR-S002"])          # one byte off: fires as before
        self.assertNotIn(off, self.fixture_files())

    @unittest.skipUnless(os.access(REAL_GITLEAKS, os.X_OK), "gitleaks is not installed")
    def test_ff10_with_the_real_gitleaks(self):   # replay, when the real gitleaks is installed (it is run, never changed or copied)
        gl = "#!/bin/sh\nexec " + shlex.quote(REAL_GITLEAKS) + ' "$@"\n'
        same = [self.copy(rel, os.path.join(self.ws, "shipped", rel)) for rel in self.RELS]
        off = [self.put(os.path.join(self.ws, "edited", rel), one_byte_off(read_bytes(os.path.join(ROOT, rel)).decode("utf-8"), ["curl", "TOKEN", "=", ":"]))
               for rel in self.RELS]
        for rel in self.RELS:
            self.assertFalse(has_hit(read_bytes(os.path.join(ROOT, rel))))
        with self.no_registry():                                         # contrast: real gitleaks reports every copy
            self.run_audit(gl)
        self.assertEqual([p for p in same + off if not self.gitleaks_s002(p)], [])
        self.run_audit(gl)
        self.assertEqual([(f["rule"], f["where"]) for f in self.keys(os.path.join(self.ws, "shipped"))], [])
        self.assertEqual(sorted(p for p in self.fixture_files() if p in same), sorted(same))
        self.assertEqual([p for p in off if not self.gitleaks_s002(p)], [])   # one byte off: fires as before
        self.assertEqual([p for p in off if p in self.fixture_files()], [])


class FF9Cost(_FF):
    def test_ff9_each_hit_file_is_read_once_and_files_without_a_hit_never(self):   # guard
        fx = self.copy("tests/test_batch7a_must_fix.py", os.path.join(self.ws, "repo", "tests", "test_batch7a_must_fix.py"))
        other = self.put(os.path.join(self.ws, "app", "env.txt"), f"GH_TOKEN={gh_like(91)}\n")
        plain = [self.put(os.path.join(self.ws, "notes", f"n{i}.md"), f"Meeting notes {i}.\n") for i in range(5)]
        self.leak_all(fx)
        self.leak(other, gh_like(91), "github-pat")
        self.assertGreater(len([h for h in self.hits if h["File"] == fx]), 1)   # gitleaks asks about it more than once too
        read, real = [], isr._fixture_digest

        def counted(path, size):
            read.append(path)
            return real(path, size)
        with mock.patch.object(isr, "_fixture_digest", side_effect=counted):
            self.run_audit()
        self.assertEqual(sorted(read), sorted([fx, other]))              # once each, though both scanners asked
        self.assertEqual([p for p in plain if p in read], [])
        self.assertEqual(self.fixture_files(), [fx])


class FF11ReportLineFromTheSnapshot(_FF):
    """misses.md item 1: `isr.py report` reads the saved snapshot, so baseline.py must carry fixture_files into it."""

    def weekly_md(self):
        code, o, e = self.run_cmd("report")
        self.assertEqual(code, 0, e)
        week = isr.dt.date.today().isocalendar()
        return read_bytes(os.path.join(isr.home(), "reports", f"{week[0]}-W{week[1]:02d}.md")).decode("utf-8")

    def test_ff11_audit_then_report_says_the_recognized_files(self):   # replay: fails on cd85c7e (the snapshot had no fixture_files)
        fx = [self.copy(rel, os.path.join(self.ws, "repo", rel)) for rel in ("docs/KNOWN-LIMITS.md", "tests/test_v111_fixtures.py")]
        with self.no_registry():                                         # contrast: nothing recognized, no line
            self.run_audit()
        self.assertNotIn("fixture_files", self.snap())
        self.assertNotIn("recognized by content", self.weekly_md())
        self.run_audit()
        self.assertEqual(self.snap().get("fixture_files"), sorted(fx))   # the saved snapshot carries them (paths only)
        self.assertIn("\n2 ISR Bot test/doc files recognized by content; not scored.\n", self.weekly_md())


if __name__ == "__main__":
    unittest.main()
