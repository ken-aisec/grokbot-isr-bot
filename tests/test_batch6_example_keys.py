"""Batch 6 PR2, B5 (DQ-043/044): example-looking keys are listed low, and a real key is critical wherever it sits.

One content check (secret_kind) for Watchtower's own rule (WT-T011, WT-S001) and every gitleaks hit, on the secret value only:
FAKE or placeholder text, an environment-variable reference, a key block whose structure isn't a key, and (gitleaks
generic-api-key) a file's checksum by its line's format look like examples. gitleaks runs with --redact; its secret is found
again in the file from its Match, judged in memory and never stored. Fix round 2 (Codex 3, 4; Ken's rule): anyone can write a
real key in those forms, so an example-looking hit is never left out: it is a low finding, "Looks like an example or checksum
value - check it", never Confirmed, never offered for revoking or clearing, kept apart from the per-file and folder grouping of
real hits, every file and line named. The tests/, fixtures/ and *.test.* path skips, the line rule that hid a whole line next
to a $VAR and FIXTURE_PATH (a file name lowering a key to low) are gone (Ken: no name-based skips); .pem files are read as text.
Fix round 3 (Codex 1, 2, 3; test_batch6b_codex_r3): an example-looking hit lowers nothing. It keeps its rule's severity, title,
counting, grouping and Confirmed rules, and only its fix gets "This looks like an example or checksum value (…); if it is real,
rotate it."; a key block that can't be read, is short or starts like a key is a key. The assertions changed here are listed in
CHANGELOG.

The gitleaks used here is a stand-in that reports the hits each test names, applying Watchtower's gitleaks config (its path and
line allowlists) the way gitleaks does, with Match redacted and gitleaks' Entropy. Fake keys contain FAKE or are documentation
placeholders; every real-shaped key (tokens, DER, OpenSSH) is generated when the test runs and never committed.

Tests marked "replay" fail on 5dcd0a2 on their assertion (measured with 5dcd0a2's watchtower/ sources, this file in place); the
ones marked "guard" pass there too."""
import base64, gzip, json, os, re, secrets, string, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import Box, SCANNERS, wt

ALNUM = string.ascii_letters + string.digits
EXAMPLE = "Looks like an example or checksum value - check it"   # round 2's wt.EXAMPLE_TITLE; fix round 3: no finding has it
NOTE = "This looks like an example or checksum value"   # fix round 3: the note an example-looking hit gets in its fix
PLACEHOLDER_WORDS = re.compile(r"(?i)(example|sample|placeholder|your|dummy|fake|test|xxxx|0000|1234|abcd)")

FAKE_GITLEAKS = r"""#!/usr/bin/env python3
import json, math, os, re, sys
a = sys.argv[1:]
if a and a[0] == "version":
    print("8.30.1"); sys.exit(0)
src, cfg, out = a[a.index("--source") + 1], a[a.index("--config") + 1], a[a.index("--report-path") + 1]
blocks = []
for b in open(cfg).read().split("[[allowlists]]")[1:]:
    t = re.search(r'regexTarget = "(\w+)"', b)
    r = re.search(r"targetRules = \[(.*?)\]", b)
    p = re.search(r"paths = \[(.*?)\n\]", b, re.S)
    g = re.search(r"regexes = \[(.*?)\]\s*$", b, re.S)
    blocks.append({"target": t.group(1) if t else "secret", "rules": re.findall(r'"([\w-]+)"', r.group(1)) if r else [],
                   "paths": [re.compile(x) for x in re.findall(r"'''(.*?)'''", p.group(1))] if p else [],
                   "regexes": [re.compile(x) for x in re.findall(r"'''(.*?)'''", g.group(1))] if g else []})
def entropy(s):
    c = {}
    for ch in s:
        c[ch] = c.get(ch, 0) + 1
    return -sum(k / len(s) * math.log2(k / len(s)) for k in c.values())
def column(data, i, end=False):
    # gitleaks' columns, in bytes: from 1 on the first line, from 2 on the lines after (it counts the line break before)
    nl = data.rfind(b"\n", 0, i - 1 if end else i)
    return (i if end else i + 1) if nl < 0 else (i - nl if end else i - nl + 1)
report, later = [], []
cands = json.load(open(CANDS))
files = [os.path.join(d, n) for d, _, ns in os.walk(src) for n in ns]
for f in files:   # by content, as gitleaks reads: a hit named for this file, or for a file of the same name (a private copy)
    data = open(f, "rb").read()
    for h in cands:
        if h["file"] != f and (os.path.basename(h["file"]) != os.path.basename(f) or h["file"] in files):
            continue
        i = data.find(h["match"].encode())
        if i < 0 or data.count(b"\n", 0, i) + 1 != h["line"]:
            continue
        j = i + len(h["match"].encode())
        line = data.decode().split("\n")[h["line"] - 1]
        target = {"line": line, "secret": h["secret"], "match": h["match"]}
        if any((not b["rules"] or h["rule"] in b["rules"]) and (any(x.search(f) for x in b["paths"])
               or any(x.search(target[b["target"]]) for x in b["regexes"])) for b in blocks):
            continue
        sc, ec = h.get("cols") or (column(data, i), column(data, j, True))   # "cols": what a later piece of a long file counts
        report.append({"File": f, "StartLine": h["line"], "EndLine": h["line"] + h["match"].count("\n"), "RuleID": h["rule"],
                       "StartColumn": sc, "EndColumn": ec,
                       "Match": h["match"].replace(h["secret"], "REDACTED"), "Secret": "REDACTED", "Entropy": entropy(h["secret"])})
        if h.get("then") is not None and h["file"] == f:
            later.append((f, h["then"]))
json.dump(report, open(out, "w"))
for f, text in later:
    open(f, "w").write(text)
"""


def token(prefix, n):
    """A real-shaped random token, made now: no placeholder word in it (fix round 1: the words checked here, as wt.PLACEHOLDER,
    which is gone, did; such a token is real for every version)."""
    while True:
        k = prefix + "".join(secrets.choice(ALNUM) for _ in range(n))
        if not PLACEHOLDER_WORDS.search(k):
            return k


def der_len(n):
    return bytes([n]) if n < 0x80 else b"\x81" + bytes([n]) if n < 256 else b"\x82" + n.to_bytes(2, "big")


def der(tag, body):
    return bytes([tag]) + der_len(len(body)) + body


def der_int(b):
    return der(0x02, b"\x00" + b if b[0] & 0x80 else b)


def rsa_der():
    r = secrets.token_bytes
    return der(0x30, der_int(b"\x00") + der_int(b"\xc1" + r(255)) + der_int(b"\x01\x00\x01") + b"".join(der_int(b"\x41" + r(n)) for n in (255, 127, 127, 127, 127, 127)))


def pem(label, raw, headers=""):
    b = base64.b64encode(raw).decode()
    return f"-----BEGIN {label}PRIVATE KEY-----\n{headers}" + "\n".join(b[i:i + 64] for i in range(0, len(b), 64)) + f"\n-----END {label}PRIVATE KEY-----\n"


def real_pems():
    """Real-shaped key blocks, generated now: PKCS#1 RSA, PKCS#8, OpenSSH, encrypted PKCS#8, an old encrypted PEM."""
    r = secrets.token_bytes
    p8 = der(0x30, der_int(b"\x00") + der(0x30, der(0x06, bytes.fromhex("2a864886f70d010101")) + b"\x05\x00") + der(0x04, rsa_der()))
    enc8 = der(0x30, der(0x30, der(0x06, bytes.fromhex("2a864886f70d01050d")) + der(0x30, r(40))) + der(0x04, r(640)))
    return {"rsa": pem("RSA ", rsa_der()), "pkcs8": pem("", p8), "openssh": pem("OPENSSH ", b"openssh-key-v1\x00" + r(400)),
            "enc8": pem("ENCRYPTED ", enc8),
            "legacy": pem("RSA ", r(640), "Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC," + r(16).hex().upper() + "\n\n")}


def fake_pems():
    """Key blocks that aren't keys: text in the body, random bytes that aren't DER, a body too short to be one."""
    junk = b"\x99" + secrets.token_bytes(299)
    return {"words": "-----BEGIN RSA PRIVATE KEY-----\nThis is a FAKE key for the docs; paste yours here.\n-----END RSA PRIVATE KEY-----\n",
            "random": pem("RSA ", junk), "short": pem("", secrets.token_bytes(16)),
            "random8": pem("", b"\x30\x82\x01\x00" + secrets.token_bytes(60))}


class _Keys(Box):
    def setUp(self):
        super().setUp()
        self.cands = []
        self.skill = os.path.join(self.home, "sand-data", "workflows", "setup-dev-tools")
        self.put("sand-data/workflows/setup-dev-tools/SKILL.md", "---\nname: setup-dev-tools\ndescription: Sets up the tools.\n---\n"
                 "Install the tools the project uses. Ask before saving.\n")

    def put(self, rel, text):
        p = os.path.join(self.home, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(text)
        return p

    def leak(self, path, match, secret=None, rule="generic-api-key", then=None, cols=None, line=None):
        """gitleaks reports `match` (its secret `secret`, the whole match when not given) where it is in the file (`line`: on
        that line, for a match not in the file yet; `cols`: the columns it reports instead of the match's own)."""
        text = open(path).read()
        i = text.find(match)
        self.cands.append({"file": path, "line": line or text.count("\n", 0, i) + 1, "rule": rule, "match": match,
                           "secret": match if secret is None else secret, "then": then, "cols": cols})

    def scan(self):
        cf =os.path.join(self.tmp, "cands.json")
        json.dump(self.cands, open(cf, "w"))
        self.scanners(gitleaks=FAKE_GITLEAKS.replace("CANDS", repr(cf)), trufflehog=None)
        r = self.audit()
        return self.snap()["findings"], r["notes"]

    def keys(self, findings, under):
        return [f for f in findings if f["rule"] in ("WT-S001", "WT-S002", "WT-T011", "WT-T011x") and f["where"].startswith(under)]


class ExampleKeysAreNotSecrets(_Keys):
    def fakes(self):
        return {"gh.md": ("token: ghp_FAKE" + "x9" * 16, "ghp_FAKE" + "x9" * 16, "github-pat"),
                "stripe.md": ("STRIPE_KEY=sk_live_FAKE" + "Ab3" * 7, "sk_live_FAKE" + "Ab3" * 7, "stripe-access-token"),
                "aws.md": ("aws key AKIAFAKE" + "Q7" * 6, "AKIAFAKE" + "Q7" * 6, "aws-access-token"),
                "conf.md": ('api_key = "your-api-key-here"', "your-api-key-here", "generic-api-key")}

    def noted_only(self, got, severity=None):
        """True when every finding in `got` carries the example note and keeps its own title (fix round 3: never EXAMPLE, never
        lowered), at `severity` (raw) when given."""
        return bool(got) and all(NOTE in f["fix"] and f["title"] != EXAMPLE
                                 and (severity is None or (f.get("severity_was") or f["severity"]) == severity) for f in got)

    def test_fake_keys_in_a_live_skills_examples_are_noted(self):   # replay (5dcd0a2: critical "secrets in 4 files under examples")
        # fix round 3 (Codex 1): scored as any hit (four files in one folder are one critical folder finding, as on 5dcd0a2),
        # each finding noted
        paths = []
        for name, (line, secret, rule) in self.fakes().items():
            p = self.put(f"sand-data/workflows/setup-dev-tools/examples/{name}", f"# Example\n\n{line}\n")
            self.leak(p, line.split(" ")[-1].split("=")[-1] if rule != "generic-api-key" else line, secret, rule)
            paths.append(p)
        fs, notes = self.scan()
        got = self.keys(fs, self.skill)
        self.assertTrue(self.noted_only(got, "critical"), got)
        self.assertEqual([(f["where"], f["title"]) for f in got if f["rule"] == "WT-S002"],
                         [(os.path.join(self.skill, "examples"), "gitleaks: secrets in 4 files under examples")])
        self.assertIn("gitleaks: 4 hit(s) look like example or checksum values; each is scored as any other hit and noted, to check "
                      "(anyone can write a real key that way).", self.snap()["notes"])

    def test_key_blocks_that_arent_keys_are_noted(self):   # replay (5dcd0a2: WT-T011 critical on each BEGIN line, and gitleaks)
        # fix round 3 (Codex 3): a body that can't be read (words), is short, or starts like a key (0x30) is a key; only random
        # bytes starting no key are an example, noted. Four files in one folder: one folder finding, as for real hits
        want = {"words": "WT-T011", "random": "WT-T011x", "short": "WT-T011", "random8": "WT-T011"}
        for name, block in fake_pems().items():
            p = self.put(f"sand-data/workflows/setup-dev-tools/references/{name}.md", "Your key file looks like this:\n\n" + block)
            self.leak(p, block.rstrip("\n"), rule="private-key")
        fs, notes = self.scan()
        got = [f for f in self.keys(fs, self.skill) if f["rule"] == "WT-S002"]
        self.assertEqual([(f["title"], f.get("severity_was") or f["severity"]) for f in got],
                         [("gitleaks: secrets in 4 files under references", "critical")])
        self.assertNotIn(NOTE, got[0]["fix"])   # three of its four hits are keys
        for name, block in fake_pems().items():
            t11 = [f for f in wt.scan_text("Key:\n" + block, "/s/SKILL.md", wt.load_rules()) if f["rule"] in ("WT-T011", "WT-T011x")]
            self.assertEqual([(f["rule"], f["title"], f["severity"]) for f in t11], [(want[name], "Secret or key in text", "critical")], name)
            self.assertEqual(NOTE in t11[0]["fix"], name == "random", name)

    def test_environment_references_in_a_ci_log(self):   # replay (5dcd0a2: S002 critical, and the log was on the scrub list)
        lines = {"GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}": "${{ secrets.GITHUB_TOKEN }}", "export API_TOKEN=$GITHUB_TOKEN": "$GITHUB_TOKEN",
                 "token: ***": "***", "NPM_TOKEN=%NPM_TOKEN%": "%NPM_TOKEN%", "apiKey: process.env.API_KEY": "process.env.API_KEY",
                 'auth_token = "${DEPLOY_TOKEN}"': "${DEPLOY_TOKEN}"}
        p = self.put("projects/app/ci/build.log", "Run actions/checkout@v4\n" + "\n".join(lines) + "\nDone.\n")
        for line, secret in lines.items():
            self.leak(p, line, secret)
        fs, notes = self.scan()
        got = self.keys(fs, p)
        self.assertTrue(self.noted_only(got, "medium"), got)   # fix round 3: the generic rule's own severity, noted
        self.assertEqual([f["evidence"] for f in got], ["6 hit(s): generic-api-key"])
        self.assertNotIn(p, wt.scrub_targets_from_findings())

    def test_a_checksum_list_is_noted(self):   # replay (5dcd0a2: S002 for each line)
        # fix round 1 (Codex 3): a checksum by its line's own format (sha256sum's "<hex>  <path>", pip's --hash=sha256:), no
        # longer a name -> hex map: a name never makes a value a checksum (test_batch6b_codex_r1 has that one counted)
        h1, h2 = secrets.token_hex(32), secrets.token_hex(32)
        p = self.put("projects/app/release/SHA256SUMS", "%s  skills/auth/tokens.md\n" % h1)
        q = self.put("projects/app/requirements.txt", "requests==2.32.3 --hash=sha256:%s\n" % h2)
        self.leak(p, "%s  skills/auth/tokens.md" % h1, h1)
        self.leak(q, "--hash=sha256:%s" % h2, h2)
        fs, _ = self.scan()
        self.assertTrue(self.noted_only(self.keys(fs, p), "medium"), self.keys(fs, p))   # fix round 3: never lowered, noted
        self.assertTrue(self.noted_only(self.keys(fs, q), "medium"), self.keys(fs, q))

    def test_fakes_group_and_count_as_any_hit(self):   # fix round 3 (Codex 1): round 2's test_fakes_never_make_a_folder_group
        d = "sand-data/workflows/setup-dev-tools/examples"
        for i in range(5):
            line = "token: ghp_FAKE%d" % i + "y8" * 15 + "z"
            self.leak(self.put(f"{d}/fake{i}.md", line + "\n"), line[7:], rule="github-pat")
        real = token("ghp_", 36)
        rp = self.put(f"{d}/real.md", "token: " + real + "\n")
        self.leak(rp, real, rule="github-pat")
        fs, _ = self.scan()
        s2 = [f for f in self.keys(fs, self.skill) if f["rule"] == "WT-S002"]
        self.assertEqual([(f["where"], f["title"], f.get("severity_was") or f["severity"]) for f in s2],
                         [(os.path.join(self.home, d), "gitleaks: secrets in 6 files under examples", "critical")])   # as 5dcd0a2
        self.assertNotIn(NOTE, s2[0]["fix"])   # a real one among them: no note

    def test_fake_akia_is_noted_and_a_real_one_critical(self):   # replay of fix round 2 (de3b328 left the fake out)
        rules = wt.load_rules()   # fix round 3 (Codex 1): WT-T011's own title and severity, noted
        got = [f for f in wt.scan_text("Use AKIAFAKE" + "Q7" * 6 + " to call it.", "/s/SKILL.md", rules) if f["rule"].startswith("WT-T011")]
        self.assertEqual([(f["rule"], f["title"], f["severity"]) for f in got], [("WT-T011x", "Secret or key in text", "critical")])
        self.assertIn(NOTE, got[0]["fix"])
        self.assertIn("WT-T011", {f["rule"] for f in wt.scan_text("Use " + token("AKIA", 0) + "".join(secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZ234567") for _ in range(16)) + " to call it.", "/s/SKILL.md", rules)})


class RealKeysAreReportedAnywhere(_Keys):
    def test_a_real_key_in_tests_is_reported(self):   # replay (5dcd0a2: gitleaks' tests/ path skip hid both)
        gh, sk = token("ghp_", 36), token("sk_live_", 24)
        p = self.put("projects/app/tests/test_api.py", f'GH = "{gh}"\nSTRIPE = "{sk}"\n')
        self.leak(p, gh, rule="github-pat")
        self.leak(p, sk, rule="stripe-access-token")
        fs, _ = self.scan()
        self.assertTrue([f for f in self.keys(fs, p) if f["rule"] == "WT-S002"], self.keys(fs, p))

    def test_under_fixtures_and_in_a_test_file(self):   # replay (5dcd0a2: the fixtures/ and *.test.ts skips hid them)
        for rel in ("projects/app/fixtures/keys.json", "projects/app/src/client.test.ts", "projects/app/__tests__/k.js"):
            sk = token("sk_live_", 24)
            self.leak(self.put(rel, f'const key = "{sk}";\n'), sk, rule="stripe-access-token")
        fs, _ = self.scan()
        for rel in ("projects/app/fixtures/keys.json", "projects/app/src/client.test.ts", "projects/app/__tests__/k.js"):
            p = os.path.join(self.home, rel)
            self.assertTrue([f for f in self.keys(fs, p) if f["rule"] == "WT-S002"], rel)

    def test_real_key_blocks_in_a_live_skill_are_critical(self):   # guard (critical on 5dcd0a2 too)
        for name, block in real_pems().items():
            p = self.put(f"sand-data/workflows/setup-dev-tools/examples/{name}.md", "Deploy key:\n" + block)
            self.leak(p, block.rstrip("\n"), rule="private-key")
        fs, notes = self.scan()
        got = self.keys(fs, self.skill)
        self.assertTrue(got)
        self.assertEqual({f.get("severity_was") or f["severity"] for f in got if f["rule"] == "WT-S002"}, {"critical"})
        self.assertFalse(any("were example values" in n for n in notes), notes)
        for name, block in real_pems().items():
            self.assertIn("WT-T011", {f["rule"] for f in wt.scan_text("Key:\n" + block, "/s/SKILL.md", wt.load_rules())}, name)

    def test_a_fake_word_inside_a_real_key_block_is_still_a_key(self):   # guard
        b = pem("RSA ", rsa_der())
        body = b.split("\n")
        body[3] = body[3][:20] + "FAKE" + body[3][24:]
        block = "\n".join(body)
        self.assertIn("WT-T011", {f["rule"] for f in wt.scan_text("Key:\n" + block, "/s/SKILL.md", wt.load_rules())})
        p = self.put("sand-data/workflows/setup-dev-tools/examples/k.md", "Key:\n" + block)
        self.leak(p, block.rstrip("\n"), rule="private-key")
        fs, _ = self.scan()
        self.assertTrue([f for f in self.keys(fs, p) if f["rule"] == "WT-S002"])

    def test_a_pem_file_is_read(self):   # replay (5dcd0a2 never read .pem files: no WT-S001)
        p = self.put("projects/app/deploy/server.pem", pem("RSA ", rsa_der()))
        fs, _ = self.scan()
        self.assertEqual([f["rule"] for f in self.keys(fs, p)], ["WT-S001"])

    def test_a_real_key_on_the_line_of_a_var(self):   # replay (5dcd0a2: the line rule hid the whole line)
        real = token("", 32)
        p = self.put("projects/app/deploy.sh", f"curl -H token=$GITHUB_TOKEN api_key={real} https://api.example\n")
        self.leak(p, f"api_key={real}", real)
        fs, _ = self.scan()
        self.assertTrue([f for f in self.keys(fs, p) if f["rule"] == "WT-S002"])

    def test_a_real_key_beside_a_fake_key_block_line(self):   # guard: a key block judges only gitleaks' private-key hit
        real = token("", 32)
        p = self.put("projects/app/notes.md", f"-----BEGIN RSA PRIVATE KEY----- api_key={real}\n-----END RSA PRIVATE KEY-----\n")
        self.leak(p, f"api_key={real}", real)
        fs, notes = self.scan()
        self.assertTrue([f for f in self.keys(fs, p) if f["rule"] == "WT-S002"], self.keys(fs, p))
        self.assertFalse(any("were example values" in n for n in notes), notes)

    def test_a_hit_in_a_file_changed_after_gitleaks_is_kept(self):   # guard: never judged on other bytes
        r1, r2 = token("", 32), token("", 32)
        p1 = self.put("projects/app/a.env", f"API_KEY={r1}\n")
        p2 = self.put("projects/app/b.env", f"API_KEY={r2}\n")
        self.leak(p1, f"API_KEY={r1}", r1, then="nothing here now\n")
        self.leak(p2, f"API_KEY={r2}", r2, then="API_KEY=FAKEexampleKEYforDOCS\n")   # the value swapped for an example one
        fs, notes = self.scan()
        for p in (p1, p2):
            self.assertTrue([f for f in self.keys(fs, p) if f["rule"] == "WT-S002"], p)
        self.assertFalse(any("were example values" in n for n in notes), notes)

    def test_no_secret_value_is_stored(self):   # guard: the secrets gitleaks found again are judged and dropped
        gh, real = token("ghp_", 36), token("", 32)
        p = self.put("projects/app/tests/conf.py", f'GH = "{gh}"\napi_key = "{real}"\n')
        self.leak(p, gh, rule="github-pat")
        self.leak(p, f'api_key = "{real}"', real)
        blocks = real_pems()
        q = self.put("projects/app/tests/k.md", "Key:\n" + blocks["rsa"])
        self.leak(q, blocks["rsa"].rstrip("\n"), rule="private-key")
        self.scan()
        self.run_cmd("report")
        body = blocks["rsa"].split("\n")[2]
        for dp, _, fns in os.walk(os.environ["WATCHTOWER_HOME"]):
            if os.path.join("scanners", "bin") in dp:
                continue
            for fn in fns:
                fp = os.path.join(dp, fn)
                data = open(fp, "rb").read()
                if fn.endswith(".gz"):
                    data = gzip.decompress(data)
                for s in (gh[6:30], real[4:28], body[10:40]):
                    self.assertNotIn(s.encode(), data, fp)


if __name__ == "__main__":
    unittest.main()
