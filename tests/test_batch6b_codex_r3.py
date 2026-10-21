"""Batch 6 PR2, Codex round 3 (7 high on b621cf4): replays and guards. Ken's rule, final round: pick the safe option every time.

1, 2: an example-looking or checksum-framed secret lowers nothing. It keeps its rule's severity, title, counting and
Confirmed/Worth-a-look rules, backs up and is backed up like any other hit, and is dismissed only as any other is; the check only
adds a note to its fix ("This looks like an example or checksum value (…); if it is real, rotate it.") and keeps it out of the
fix plan's automatic clearing and revoke links. WT-T011x stays only so a placeholder never raises WT-T011 itself (the pre-batch
test_placeholder_keys_ignored); every table reads it as WT-T011. 3: key structures are read before any size (SEC1 on any curve,
with or without its public point); a short or unreadable block is a key. 4, 5: one armor reading for masking and the example
check: a BEGIN marker with a label of any length, an END only as a whole line with the same label (never a Comment: header), and
a block with no such END hidden to the end of the text. 6: escaped line breaks read one backslash run at a time. 7: a file's line
starts found once for all its gitleaks hits.

Every real-shaped key here is generated when the test runs and never committed (P-224 and P-160 SEC1 keys are built as DER from
random scalars: Python's standard library makes no EC keys); fake ones contain FAKE. Tests marked "replay" fail on b621cf4 on
their assertion (measured with b621cf4's watchtower/ sources, this file in place); "guard" ones pass there too, unless marked
"new" (they call something b621cf4 doesn't have, or its behaviour is new)."""
import base64, gzip, json, os, secrets, shutil, subprocess, sys, tempfile, time, unittest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import Box, ROOT, wt
from test_batch6_example_keys import _Keys, der, der_int, pem, public_key_packet, rsa_der, token
from test_batch6b_codex_r2 import ed25519_pkcs8, raw_sev

NOTE = "This looks like an example or checksum value"   # wt.EXAMPLE_NOTE's start, written out so a replay fails on its assertion
SKILL = "---\nname: setup-dev-tools\ndescription: Sets up the tools.\n---\nInstall the tools the project uses. Ask before saving.\n"
P224_N = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D", 16)
P160_N = int("0100000000000000000001F4C8F927AED3CA752257", 16)   # secp160r1
P224_OID, P160_OID = bytes.fromhex("2b81040021"), bytes.fromhex("2b81040008")
P256_OID = bytes.fromhex("2a8648ce3d030107")


def sec1(n, oid, size, point=None):
    """A SEC1 ECPrivateKey made now: version 1, a random scalar in [1, n-1] as `size` bytes, the curve's OID, and the public
    point only when given (it is optional)."""
    d = secrets.randbelow(n - 1) + 1
    body = der_int(b"\x01") + der(0x04, d.to_bytes(size, "big")) + der(0xA0, der(0x06, oid))
    return der(0x30, body + (der(0xA1, der(0x03, b"\x00" + point)) if point else b""))


def crc24(data):
    crc = 0xB704CE
    for b in data:
        crc ^= b << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
    return crc & 0xFFFFFF


def pgp_secret_block(comment):
    """An OpenPGP RSA secret-key packet made now (old format, tag 5: version 4, a creation time, RSA, n and e, no S2K, d, p, q,
    u and its checksum), armored with `comment` as a header line and its CRC-24 line."""
    mpi = lambda nbytes: (nbytes * 8).to_bytes(2, "big") + bytes([0x80 | secrets.randbelow(128)]) + secrets.token_bytes(nbytes - 1)
    secret = mpi(256) + mpi(128) + mpi(128) + mpi(128)
    body = (b"\x04" + int(time.time()).to_bytes(4, "big") + b"\x01" + mpi(256) + b"\x00\x11\x01\x00\x01" + b"\x00" + secret
            + (sum(secret) % 65536).to_bytes(2, "big"))
    pkt = b"\x95" + len(body).to_bytes(2, "big") + body
    b64 = base64.b64encode(pkt).decode()
    crc = base64.b64encode(crc24(pkt).to_bytes(3, "big")).decode()
    return ("-----BEGIN PGP PRIVATE KEY BLOCK-----\n" + comment + "\n\n" + "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
            + "\n=" + crc + "\n-----END PGP PRIVATE KEY BLOCK-----\n"), [b64[i:i + 24] for i in range(0, len(b64) - 23, 24)]


def bits_of(raw):
    b = base64.b64encode(raw).decode()
    return [b[i:i + 16] for i in range(0, len(b) - 15, 16)]


def t011(text):
    return [f for f in wt.scan_text(text, "/s/SKILL.md", wt.load_rules()) if f["rule"].startswith("WT-T011")]


def approved_copy(test, name, text):
    """The approved copy save_approved keeps of a skill with one more file, `name`, holding `text`."""
    d = os.path.join(test.home, "sand-data", "workflows", "deploy-keys")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "SKILL.md"), "w") as f:
        f.write("---\nname: deploy-keys\ndescription: Deploys.\n---\nUse the keys.\n")
    with open(os.path.join(d, name), "w") as f:
        f.write(text)
    wt.save_approved(d)
    with gzip.open(wt.approved_path(d), "rt", encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------- 1, 2: example-looking hits lower nothing
class ExamplesLowerNothing(_Keys):
    def s002(self, fs, p):
        return [f for f in self.keys(fs, p) if f["rule"] == "WT-S002"]

    def ordinary(self, line, secret):
        p = self.put("projects/app/settings.conf", line + "\n")
        self.leak(p, line, secret)
        fs, notes = self.scan()
        got = self.s002(fs, p)
        self.assertEqual([(f["title"], raw_sev(f)) for f in got], [("gitleaks: secrets in file", "medium")], got)   # generic: medium
        self.assertIn(NOTE, got[0]["fix"])
        return got[0], notes

    def test_fake_then_64_hex_keeps_the_rules_severity(self):   # replay 1 (b621cf4: an example, low)
        hx = secrets.token_hex(32)
        self.ordinary(f'api_key="FAKE{hx}"', "FAKE" + hx)

    def test_checksum_framing_keeps_the_rules_severity(self):   # replay 2 (b621cf4: a checksum, low)
        hx = secrets.token_hex(32)
        f, notes = self.ordinary(f"api_key sha256:{hx}", hx)
        self.assertIn("(a file's checksum)", f["fix"])
        self.assertIn("gitleaks: 1 hit(s) look like example or checksum values; each is scored as any other hit and noted, to check "
                      "(anyone can write a real key that way).", self.snap()["notes"])

    def drift_backed(self, line, secret):
        """`line` in a live skill, scanned, its gitleaks finding given a planted dismissal (what a Bot can write), then the skill
        changed: the finding must count, backed up by the change, the planted record notwithstanding."""
        p = self.put("sand-data/workflows/setup-dev-tools/SKILL.md", SKILL + line + "\n")
        self.leak(p, line, secret)
        fs, _ = self.scan()
        first = self.s002(fs, p)
        self.assertEqual(len(first), 1, first)
        with open(wt.state_path(wt.DISMISS_LOG), "a") as fh:
            fh.write(json.dumps({"at": wt.now(), "key": first[0]["key"], "action": "dismissed", "reason": "FAKE planted"}) + "\n")
        with open(p, "a") as fh:
            fh.write("Keep the notes short.\n")
        fs, _ = self.scan()
        got = self.s002(fs, p)
        self.assertEqual([(f["class"], raw_sev(f)) for f in got], [("corroborated", "medium")], got)
        self.assertTrue(wt.counts(got[0]))

    def test_a_planted_dismissal_never_removes_a_drift_backed_fake(self):   # replay 1 (b621cf4: never backed up, then dismissed)
        hx = secrets.token_hex(32)
        self.drift_backed(f'api_key="FAKE{hx}"', "FAKE" + hx)

    def test_a_planted_dismissal_never_removes_a_drift_backed_checksum(self):   # replay 2 (b621cf4: the same)
        hx = secrets.token_hex(32)
        self.drift_backed(f"api_key sha256:{hx}", hx)

    def test_a_fake_counts_in_its_files_finding(self):   # replay 1 (b621cf4: a separate low finding, the real one alone counted)
        hx = secrets.token_hex(32)
        real = token("", 32)
        p = self.put("projects/app/a.env", f'API_KEY="FAKE{hx}"\nOTHER_KEY="{real}"\n')
        self.leak(p, f'API_KEY="FAKE{hx}"', "FAKE" + hx)
        self.leak(p, f'OTHER_KEY="{real}"', real)
        fs, _ = self.scan()
        got = self.s002(fs, p)
        self.assertEqual([(f["evidence"], raw_sev(f)) for f in got], [("2 hit(s): generic-api-key", "medium")], got)
        self.assertNotIn(NOTE, got[0]["fix"])   # one real-looking hit: no note

    def test_an_example_is_offered_to_check_never_to_clear_or_revoke(self):   # guard (new)
        p = self.put("projects/app/logs/session.log", '{"text": "token: ghp_FAKE' + "z7" * 16 + '"}\n')   # a log: on the scrub list if real
        self.leak(p, "ghp_FAKE" + "z7" * 16, rule="github-pat")
        fs, _ = self.scan()
        mine = self.s002(fs, p)
        self.assertEqual([raw_sev(f) for f in mine], ["critical"])
        self.assertNotIn(p, wt.scrub_targets_from_findings())
        self.assertEqual(wt.revoke_targets([dict(mine[0], severity="critical")]), [])
        self.assertEqual(wt.plain(mine[0])["title"], "Keys that look like examples or checksums")
        self.assertNotIn("fix it", wt.plain(mine[0])["how"])
        dead = wt.apply_key_status(mine, {p: [{"status": "dead", "detector": "Github", "line": 1}]}, ran=True)[0]
        self.assertEqual((dead["title"], wt.fix_class(dead)), (wt.KEY_DEAD, "only_you"))   # not the fix's automatic clearing
        self.assertIn(NOTE, dead["fix"])

    def test_a_live_key_loses_its_note(self):   # guard (new): the provider's answer decides
        f = wt.annotate_example(wt.finding("WT-S002", "gitleaks: secrets in file", "critical", [], "/w/k.md:3", "1 hit(s): github-pat", "x",
                                           source="gitleaks"), "FAKE or placeholder text")
        out = wt.apply_key_status([f], {"/w/k.md": [{"status": "live", "detector": "Github", "line": 3}]}, ran=True)[0]
        self.assertEqual((out["severity"], out["title"], "example" in out), ("critical", wt.KEY_LIVE, False))
        self.assertNotIn(NOTE, out["fix"])


class ExamplesInWatchtowersRules(unittest.TestCase):
    def test_t011_examples_keep_t011s_severity(self):   # replay 1 (b621cf4: WT-T011x low, "Looks like an example")
        for v in ("ghp_FAKE" + "x9" * 16, "AKIAFAKE" + "Q7" * 6, "sk-proj-EXAMPLEKEY1234567890abcdefgh"):
            got = t011(f"Use {v} here.\n")
            self.assertEqual([(f["rule"], f["title"], f["severity"]) for f in got], [("WT-T011x", "Secret or key in text", "critical")], v)
            self.assertIn(NOTE, got[0]["fix"])

    def test_an_example_backs_up_and_is_backed_up(self):   # replay 1 (b621cf4: an example backed nothing and nothing backed it)
        ex = [f for f in t011("Use ghp_FAKE" + "x9" * 16 + " here.\n")][0]
        ex = dict(ex, where="/w/a.md:2")
        other = wt.finding("WT-S002", "gitleaks: secrets in file", "critical", ["ASI03"], "/w/a.md:2", "1 hit(s): github-pat", "f", source="gitleaks")
        self.assertEqual([f["class"] for f in wt.label_findings([ex, other])], ["corroborated", "corroborated"])

    def test_t011x_is_t011_to_every_table(self):   # guard (new)
        ex = dict(t011("Use ghp_FAKE" + "x9" * 16 + " here.\n")[0], where="/w/a.md:2")
        real = wt.finding("WT-T011", "Secret or key in text", "critical", ["AST04"], "/w/a.md:5", "ghp_…", "f")
        self.assertEqual(wt.kinds_of(ex), {"credential"})
        self.assertTrue(wt.same_rule(ex, real))
        self.assertEqual([f["class"] for f in wt.label_findings([ex, real])], ["pattern", "pattern"])   # one rule: no second vote
        self.assertEqual(wt.vet_verdict(wt.label_findings([ex])), "Do not install")

    def test_a_placeholder_never_raises_t011_itself(self):   # guard: the pre-batch test_placeholder_keys_ignored's line
        for k in ("sk-ant-api03-your-key-here-xxxxxxxxxxxxxxxx", "ghp_" + "a" * 36, "sk-proj-EXAMPLEKEY1234567890abcdefgh"):
            self.assertEqual({f["rule"] for f in t011(f"key={k}")}, {"WT-T011x"}, k)

    def test_nothing_is_dropped_on_a_reference(self):   # guard: a $VAR is noted, never left out (Ken: may be dropped; kept, safe)
        self.assertEqual(wt.secret_kind("${API_TOKEN}"), ("example", "an environment variable name"))


# ---------------------------------------------------------------- 3: key structures before any size
class KeyStructures(unittest.TestCase):
    def test_compact_ec_keys_are_real(self):   # replay 3 (b621cf4: under 64 base64 characters, so an example, WT-T011x low)
        for name, raw in (("P-224", sec1(P224_N, P224_OID, 28)), ("P-160", sec1(P160_N, P160_OID, 21))):
            block = pem("EC ", raw)
            self.assertLess(len(base64.b64encode(raw).rstrip(b"=")), 64, name)
            self.assertEqual([(f["rule"], f["severity"]) for f in t011("Key:\n" + block)], [("WT-T011", "critical")], name)
            self.assertEqual(wt.secret_kind(block.split("\n")[0], tail=block[block.index("\n"):])[0], "real", name)

    def test_openssl_reads_the_p224_key(self):   # guard: the replay's key is a valid key (when openssl is here to say)
        exe = shutil.which("openssl")
        if not exe:
            self.skipTest("openssl not installed")
        d = tempfile.mkdtemp()
        try:
            p = os.path.join(d, "k.pem")
            with open(p, "w") as f:
                f.write(pem("EC ", sec1(P224_N, P224_OID, 28)))
            r = subprocess.run([exe, "pkey", "-in", p, "-check", "-noout"], capture_output=True, text=True, timeout=30)
            self.assertEqual(r.returncode, 0, r.stderr[-300:])
        finally:
            shutil.rmtree(d)

    def test_each_structure_is_named(self):   # guard (new)
        r = secrets.token_bytes
        point = b"\x04" + r(64)
        p8 = der(0x30, der_int(b"\x00") + der(0x30, der(0x06, bytes.fromhex("2a864886f70d010101")) + b"\x05\x00") + der(0x04, rsa_der()))
        enc8 = der(0x30, der(0x30, der(0x06, bytes.fromhex("2a864886f70d01050d")) + der(0x30, r(40))) + der(0x04, r(640)))
        dsa = der(0x30, der_int(b"\x00") + b"".join(der_int(b"\x41" + r(n)) for n in (127, 19, 127, 127, 19)))
        for raw, want in ((sec1(P224_N, P224_OID, 28), "sec1"), (sec1(P160_N, P160_OID, 21), "sec1"),
                          (sec1(P224_N, P256_OID, 32, point), "sec1"), (rsa_der(), "pkcs1"), (p8, "pkcs8"), (ed25519_pkcs8(), "pkcs8"),
                          (enc8, "encrypted-pkcs8"), (dsa, "dsa"), (b"\x30\x03\x02\x01", None), (r(64), None)):
            self.assertEqual(wt.der_key_structure(raw), want, raw[:8].hex())

    def test_short_or_unreadable_blocks_stay_real(self):   # guard (new: b621cf4 called short ones examples)
        for block in (pem("", secrets.token_bytes(16)), pem("", b"\x99" + secrets.token_bytes(40)),
                      "-----BEGIN PRIVATE KEY-----\nyour-key-here\n-----END PRIVATE KEY-----\n"):
            self.assertEqual(wt.secret_kind(block.split("\n")[0], tail=block[block.index("\n"):])[0], "real", block[:60])

    def test_a_long_body_that_is_no_key_is_still_noted(self):   # guard (new: b621cf4 lowered it): what B5 still says, as a note only
        block = pem("RSA ", public_key_packet(300))   # batch 7a fix round 1: a whole public-key packet
        got = t011("Key:\n" + block)
        self.assertEqual([(f["rule"], f["severity"]) for f in got], [("WT-T011x", "critical")])
        self.assertIn("(a key block that isn't a real key)", got[0]["fix"])


# ---------------------------------------------------------------- 4, 5: one armor reading, END only as a whole line
class ArmorBoundaries(Box):
    def test_a_comment_end_never_ends_a_pgp_block(self):   # replay 4 (b621cf4: masked and judged only to the comment)
        for comment in ("Comment: -----END PRIVATE KEY-----", "Comment: -----END PGP PRIVATE KEY BLOCK-----"):
            block, bits = pgp_secret_block(comment)
            doc = approved_copy(self, "notes.md", "My key:\n\n" + block + "\nKeep it safe.\n")
            kept = doc["files"]["notes.md"]
            self.assertEqual(doc["masked"], wt.MASK_VERSION)
            for bit in bits:
                self.assertNotIn(bit, kept, comment)
            self.assertTrue(kept.endswith("-----END PGP PRIVATE KEY BLOCK-----\n\nKeep it safe.\n"), kept[-120:])
            self.assertEqual(wt.secret_kind(block.split("\n")[0], tail=block[block.index("\n"):])[0], "real", comment)

    def test_a_label_of_any_length_is_masked(self):   # replay 5 (b621cf4: a 65-character label kept the whole body)
        raw = ed25519_pkcs8()
        label = "X" * 65 + " "
        block = pem(label, raw)
        b64 = base64.b64encode(raw).decode()
        doc = approved_copy(self, "server.pem", block)
        self.assertNotIn(b64, doc["files"]["server.pem"])
        for bit in bits_of(raw):
            self.assertNotIn(bit, doc["files"]["server.pem"])
            self.assertNotIn(bit, wt.mask_secrets("Key:\n" + block))
        self.assertEqual([(f["rule"], f["severity"]) for f in t011("Key:\n" + block)], [("WT-T011", "critical")])

    def test_an_end_with_another_label_hides_to_the_end(self):   # guard (new)
        raw = rsa_der()
        text = pem("RSA ", raw).replace("-----END RSA PRIVATE KEY-----", "-----END EC PRIVATE KEY-----") + "after\n"
        out = wt.mask_secrets(text)
        self.assertNotIn("after", out)
        for bit in bits_of(raw):
            self.assertNotIn(bit, out)
        self.assertEqual(wt.secret_kind(text.split("\n")[0], tail=text[text.index("\n"):])[0], "real")

    def test_a_whole_line_end_is_found_in_each_framing(self):   # guard: what follows a block stays
        raw = ed25519_pkcs8()
        b = base64.b64encode(raw).decode()
        for text in ("before\n" + pem("", raw) + "after\n",
                     "# before\n" + "".join("# " + l + "\n" for l in pem("", raw).rstrip("\n").split("\n")) + "# after\n",
                     json.dumps({"key": pem("", raw), "after": "visible"}),
                     'K = ("-----BEGIN PRIVATE KEY-----\\n"\n     "' + b + '\\n"\n     "-----END PRIVATE KEY-----\\n")\nafter = 1\n',
                     'K = """-----BEGIN PRIVATE KEY-----\n' + b + '\n-----END PRIVATE KEY-----"""\nafter = 1\n'):
            out = wt.mask_secrets(text)
            self.assertNotIn(b[:24], out, text[:40])
            self.assertIn("after", out, text[:40])
            self.assertEqual(wt.mask_secrets(out), out)

    def test_a_header_line_never_ends_a_block_escaped_either(self):   # guard (new)
        block, bits = pgp_secret_block("Comment: -----END PGP PRIVATE KEY BLOCK-----")
        out = wt.mask_secrets(json.dumps({"k": block}))
        for bit in bits:
            self.assertNotIn(bit, out)

    def test_many_begin_and_end_lines_stay_linear(self):   # guard (new)
        t = time.perf_counter()
        wt.mask_secrets("-----BEGIN " + "X" * 50_000 + " PRIVATE KEY-----\n" + "-----END PRIVATE KEY-----\n" * 4000)
        wt.mask_secrets("-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n" * 4000)
        wt.mask_secrets(("-----BEGIN A PRIVATE KEY-----\nComment: -----END A PRIVATE KEY-----\n") * 4000)
        self.assertLess(time.perf_counter() - t, 3.0)


# ---------------------------------------------------------------- 6, 7: linear time
CHILD_BACKSLASH = ("import sys, time\nsys.path.insert(0, {wt_dir!r})\nimport wt\nrules = wt.load_rules()\n"
                   "text = ('-----BEGIN PRIVATE KEY-----\\n' + '\\\\' * 16000 + '\\n-----END PRIVATE KEY-----\\n') * 16\n"
                   "assert len(text) > 256000\nt = time.perf_counter()\nfs = wt.scan_text(text, '/s/SKILL.md', rules)\n"
                   "print(len([f for f in fs if f['rule'] == 'WT-T011']), time.perf_counter() - t)\n")
CHILD_HITS = ("import os, sys, time, secrets, string\nsys.path.insert(0, {wt_dir!r})\nimport wt\n"
              "p = sys.argv[1]\nalnum = string.ascii_letters + string.digits\nlines, leaks = [], []\n"
              "for i in range(16000):\n"
              "    s = ''.join(secrets.choice(alnum) for _ in range(41))\n"
              "    m = 'k%05d=' % i + s\n    lines.append(m)\n"
              "    first = i == 0\n"
              "    leaks.append({{'File': p, 'StartLine': i + 1, 'EndLine': i + 1, 'StartColumn': 1 if first else 2,\n"
              "                  'EndColumn': len(m) if first else len(m) + 1, 'Match': 'k%05d=REDACTED' % i, 'Secret': 'REDACTED',\n"
              "                  'RuleID': 'generic-api-key', 'Entropy': wt.shannon_entropy(s)}})\n"
              "open(p, 'w').write('\\n'.join(lines) + '\\n')\nsince = os.stat(p).st_ctime_ns + 1\n"
              "assert os.path.getsize(p) > 780000\ndatas = {{}}\nt = time.perf_counter()\n"
              "out = [wt.gitleaks_example(l, datas, since) for l in leaks]\n"
              "print(sum(1 for x in out if x == ''), time.perf_counter() - t)\n")
CHILD_ONE_LINE = ("import sys, time\nsys.path.insert(0, {wt_dir!r})\nimport wt\n"
                  "hx = 'ab12' * 16\nline = ' '.join('sha256:' + hx for _ in range(1380))\ndata = (line + '\\n').encode()\n"
                  "assert len(data) < wt.GITLEAKS_FRAGMENT\nbuf = wt.FileBytes(data)\nt = time.perf_counter()\nn = 0\n"
                  "for i in range(1380):\n"
                  "    s = i * 72 + 7\n"
                  "    lk = {{'StartLine': 1, 'EndLine': 1, 'StartColumn': s + 1, 'EndColumn': s + 64, 'Match': 'REDACTED',\n"
                  "          'Entropy': wt.shannon_entropy(hx)}}\n"
                  "    got = wt.gitleaks_hit(lk, buf)\n"
                  "    n += got is not None and wt.secret_kind(got[0], line=got[1], at=got[2])[1] == \"a file's checksum\"\n"
                  "print(n, time.perf_counter() - t)\n")


class LinearTime(unittest.TestCase):
    def child(self, src, *args, bound=3.0, limit=60):
        try:
            r = subprocess.run([sys.executable, "-c", src.format(wt_dir=os.path.join(ROOT, "watchtower")), *args], capture_output=True,
                               text=True, timeout=limit)
        except subprocess.TimeoutExpired:
            self.fail(f"took more than {limit} seconds")
        self.assertEqual(r.returncode, 0, r.stderr[-400:])
        n, took = r.stdout.split()
        self.assertLess(float(took), bound)
        return int(n)

    def test_16_blocks_of_16000_backslashes(self):   # replay 6 (b621cf4: about a minute, each backslash a new attempt)
        self.assertEqual(self.child(CHILD_BACKSLASH), 16)   # each block is real (its body isn't base64), none lost

    def test_16000_hits_in_one_784_kb_file(self):   # replay 7 (b621cf4: tens of seconds, each hit indexing the whole file)
        d = tempfile.mkdtemp()
        try:
            self.assertEqual(self.child(CHILD_HITS, os.path.join(d, "big.env")), 16000)   # none an example; read once
        finally:
            shutil.rmtree(d)

    def test_1380_checksums_on_one_line(self):   # guard (new): a line read once, each value at its place
        self.assertEqual(self.child(CHILD_ONE_LINE, bound=1.0), 1380)


class EscapedBreaks(unittest.TestCase):
    def test_runs_are_read_once_and_as_before(self):   # guard (new)
        self.assertEqual(list(wt.split_escaped_breaks("a\\nb\\\\nc\\\\d\\te\nf")), ["a", "b", "c\\\\d", "e", "f"])
        raw = ed25519_pkcs8()
        text = json.dumps({"k": pem("", raw)})
        i = text.index("-----BEGIN")
        self.assertEqual(wt.secret_kind(text[i:i + 27], tail=text[i + 27:])[0], "real")
        junk = base64.b64encode(public_key_packet(120)).decode()   # batch 7a fix round 1: a whole public-key packet
        text = json.dumps({"k": "-----BEGIN PRIVATE KEY-----\n" + junk + "\n-----END PRIVATE KEY-----\n"})
        i = text.index("-----BEGIN")
        self.assertEqual(wt.secret_kind(text[i:i + 27], tail=text[i + 27:])[0], "example")


if __name__ == "__main__":
    unittest.main()
