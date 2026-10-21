"""Batch 7a: batch 6 PR2's four must-fix highs (Codex round 4 on 7060724, docs/KNOWN-LIMITS.md before this batch). Ken's
rule: when unsure, mask more or call it real, never less.

1: a JSON-serialized PGP armor whose comment headers hold a literal \\n-----END …----- and a whole inner BEGIN/END pair kept the
full private key body through mask_secrets and save_approved: the literal backslash-n was read as a line break. The END is now
read at the BEGIN's escape level, and a block hides to the furthest END either reading could take (MASK_VERSION 9). 2: blocks
sharing one whitespace tail trimmed it once per block (quadratic). 3: an OpenPGP marker (or other ignored) packet in front of a
secret key gave it the "isn't a real key" note. 4: a long saved connector answer was read in quadratic time.

Every real-shaped key is generated when the test runs and never committed; fake ones say FAKE. No key value is printed. Tests
marked "replay" fail on a3e535e at their assertion (measured with a3e535e's watchtower/ and MANIFEST.sha256, this file in
place); "guard" ones pass there too, unless marked "new" (they call something a3e535e doesn't have, or its behaviour is new).
Timing runs in a child process with a 60-second limit. A failure reports how many pieces of a key it found, never the text."""
import base64, bisect, json, os, random, secrets, shutil, subprocess, sys, tempfile, time, unittest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import Box, ROOT, wt
from test_batch6_example_keys import _Keys, fake_text_body, pem, public_key_packet
from test_batch6b_codex_r2 import ed25519_pkcs8
from test_batch6b_codex_r3 import approved_copy, bits_of, crc24, pgp_secret_block, t011

NOTE = "This looks like an example or checksum value"   # wt.EXAMPLE_NOTE's start, written out so a replay fails on its assertion
CODEX_COMMENTS = ("Comment: \\n-----END PGP PRIVATE KEY BLOCK-----\n"      # \\n: a literal backslash and n inside the header
                  "Comment: -----BEGIN PRIVATE KEY-----\\nFAKE\\n-----END PRIVATE KEY-----")
GPG = shutil.which("gpg")


def serialized(text, depth):
    """`text` JSON-serialized `depth` times, kept as a value in a JSON file with another value after it."""
    for _ in range(depth - 1):
        text = json.dumps(text)
    return json.dumps({"key": text, "after": "visible"})


def armor_packet(block):
    """The packet bytes an armor made by pgp_secret_block holds (its body lines, between the blank line and the CRC line)."""
    lines = block.split("\n")
    i = lines.index("")
    body = lines[i + 1:next(k for k in range(i + 1, len(lines)) if lines[k].startswith("="))]
    return base64.b64decode("".join(body))


def pgp_armor(raw):
    """raw as a PGP PRIVATE KEY BLOCK armor: 64-character lines and the CRC-24 line."""
    b = base64.b64encode(raw).decode()
    crc = base64.b64encode(crc24(raw).to_bytes(3, "big")).decode()
    return ("-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n" + "\n".join(b[i:i + 64] for i in range(0, len(b), 64)) + "\n=" + crc
            + "\n-----END PGP PRIVATE KEY BLOCK-----\n")


def mpi(nbytes):
    return (nbytes * 8).to_bytes(2, "big") + bytes([0x80 | secrets.randbelow(128)]) + secrets.token_bytes(nbytes - 1)


def secret_packet():
    """An OpenPGP RSA secret-key packet made now (pgp_secret_block's)."""
    return armor_packet(pgp_secret_block("Comment: made now")[0])


def public_packet():
    """An OpenPGP RSA public-key packet made now (old format, tag 6: version 4, a creation time, RSA, n and e)."""
    body = b"\x04" + int(time.time()).to_bytes(4, "big") + b"\x01" + mpi(256) + b"\x00\x11\x01\x00\x01"
    return b"\x99" + len(body).to_bytes(2, "big") + body


def public_subkey():
    """public_packet's fields as a public-subkey packet (old format, tag 14)."""
    return b"\xb9" + public_packet()[1:]


def old_packet(tag, body):
    """An old-format packet with a two-byte length."""
    return bytes([0x81 | tag << 2]) + len(body).to_bytes(2, "big") + body


IGNORED = {"marker": b"\xa8\x03PGP",                                   # old format, tag 10 (RFC 4880 5.8)
           "padding": b"\xd5\x10" + b"\x00" * 16,                       # new format, tag 21
           "trust": b"\xb0\x02\x00\x00",                                # old format, tag 12
           "tag 61": b"\xfd\x04FAKE"}                                    # new format, private or experimental


def loose_spans(s):
    """a3e535e's pem_spans (the loose reading alone), written out from its armor_blocks: what masking hid before this batch."""
    begins, ends, n = wt._armor_markers(s, "BEGIN"), wt._armor_markers(s, "END"), len(s)
    index = {}
    for a, b, label in ends:
        p = wt._armor_prefix(s, a)
        if p is not None and wt._end_after_ok(s, b, False):
            index.setdefault((label, "line", p), []).append((a, b))
        if wt._escaped_edge_before(s, a) and wt._end_after_ok(s, b, True):
            index.setdefault((label, "escaped"), []).append((a, b))
    out = []
    for k, (a, b, label) in enumerate(begins):
        nxt = begins[k + 1][0] if k + 1 < len(begins) else None
        j = b
        while j < n and s[j] in " \t":
            j += 1
        if j < n and s[j] in "\r\n":
            p = wt._armor_prefix(s, a)
            keys = [(label, "line", "")] + ([(label, "line", p)] if p else [])
        else:
            keys = [(label, "escaped")]
        before, after = [], []
        for key in keys:
            lst = index.get(key, ())
            lo = bisect.bisect_left(lst, (b,))
            hi = bisect.bisect_left(lst, (nxt,)) if nxt is not None else len(lst)
            if hi > lo:
                before.append(lst[hi - 1])
            elif lo < len(lst):
                after.append(lst[lo])
        e = max(before) if before else (min(after) if after else None)
        x = wt._PEM_EDGE.match(s, b).end()
        y = n if e is None else e[0]
        while y > x and (s[y - 1] in " \t\r\n" or (s[y - 2:y - 1] == "\\" and s[y - 1] in "nrt")):
            y -= 2 if s[y - 1] in "nrt" and s[y - 2:y - 1] == "\\" else 1
        if y > x:
            out.append((x, y))
    return out


def run_child(test, src, limit=60):
    """Runs `src` (formatted with wt_dir) in a child Python and returns its printed words; fails past `limit` seconds."""
    try:
        r = subprocess.run([sys.executable, "-c", src.format(wt_dir=os.path.join(ROOT, "watchtower"))], capture_output=True,
                           text=True, timeout=limit)
    except subprocess.TimeoutExpired:
        test.fail(f"took more than {limit} seconds")
    test.assertEqual(r.returncode, 0, r.stderr[-400:])
    return r.stdout.split()


# ---------------------------------------------------------------- 1: serialized armor comments
def kept(bits, out):
    """How many pieces of a key made now are in `out`: a count, so a failure never prints a key's text."""
    return sum(b in out for b in bits)


class SerializedArmor(Box):   # assertions on masked text report counts and yes/no only, never the text
    def assert_hidden(self, text, bits, label):
        out = wt.mask_secrets(text)
        self.assertEqual(kept(bits, out), 0, label)   # nothing of the real body
        self.assertTrue(wt.mask_secrets(out) == out, f"masking again changed it: {label}")
        doc = approved_copy(self, "release.json", text)
        self.assertEqual(doc["masked"], 10, label)   # batch 7d: MASK_VERSION 10 (was 9)
        self.assertEqual(kept(bits, doc["files"]["release.json"]), 0, label)
        return out

    def test_codex_case_serialized_once_and_twice(self):   # replay (a3e535e: every body line kept, masked 8)
        block, bits = pgp_secret_block(CODEX_COMMENTS)
        for depth in (1, 2):   # the comment's inner BEGIN has no END at its level, so it hides to the end of the text (Ken)
            self.assert_hidden(serialized(block, depth), bits, depth)

    def test_fake_end_then_a_literal_break(self):   # replay (a3e535e: the block ended at the fake END, the body after it kept)
        block, bits = pgp_secret_block("Comment: made now")
        for after in ("", "'"):
            fake = "-----END PGP PRIVATE KEY BLOCK-----" + after + "\\n-----BEGIN PRIVATE KEY-----\\nFAKE\\n-----END PRIVATE KEY-----"
            text = block.replace("Comment: made now", fake)
            for depth in (1, 2):
                self.assert_hidden(serialized(text, depth), bits, (after, depth))

    def test_gpg_reads_the_codex_armor(self):   # guard: the replay's armor is a key GnuPG reads (when gpg is here to say)
        if not GPG:
            self.skipTest("gpg not installed")
        block, _ = pgp_secret_block(CODEX_COMMENTS)
        d = tempfile.mkdtemp()
        try:
            r = subprocess.run([GPG, "--homedir", d, "--batch", "--dearmor"], input=block.encode(), capture_output=True, timeout=30)
        finally:
            shutil.rmtree(d, ignore_errors=True)
        self.assertEqual(r.returncode, 0, r.stderr[-300:])
        self.assertTrue(r.stdout == armor_packet(block), "gpg dearmored other bytes")

    def test_two_keys_of_one_label_in_one_json(self):   # guard: each ends at its own END, the text between them stays
        k1, k2 = ed25519_pkcs8(), ed25519_pkcs8()
        text = json.dumps({"a": pem("", k1), "between": "visible-between", "b": pem("", k2), "after": "visible-after"})
        out = wt.mask_secrets(text)
        self.assertEqual(kept(bits_of(k1) + bits_of(k2), out), 0)
        self.assertTrue("visible-between" in out and "visible-after" in out, "the text between or after was hidden")
        self.assertEqual([wt.pem_kind(text, i) for i in (text.index("-----BEGIN"), text.rindex("-----BEGIN"))], ["real", "real"])

    def test_a_notebooks_literal_block(self):   # guard: \"-----END …-----\\n\" in a notebook's code cell ends the block
        raw = ed25519_pkcs8()
        b = base64.b64encode(raw).decode()
        src = ['key = ("-----BEGIN PRIVATE KEY-----\\n"', '       "' + b + '\\n"', '       "-----END PRIVATE KEY-----\\n")',
               'print("after-cell")']
        text = json.dumps({"cells": [{"cell_type": "code", "source": [ln + "\n" for ln in src]}]}, indent=1)
        self.assertTrue('\\"-----END PRIVATE KEY-----' in text, "the END isn't written as a notebook writes it")
        out = wt.mask_secrets(text)
        self.assertEqual(kept(bits_of(raw), out), 0)
        # batch 7d (A): the block is at the notebook's second escape level (Python in a JSON string), whose \n isn't
        # established, so the rest of the text is hidden (was: assertTrue("after-cell" in out))
        self.assertFalse("after-cell" in out, "the cell after the key was kept")
        self.assertTrue(wt.mask_secrets(out) == out, "masking again changed it")

    def test_a_block_hidden_past_its_strict_end_is_real(self):   # guard (new)
        junk = base64.b64encode(public_key_packet(120)).decode()   # a whole public-key packet: an example alone
        plain = "-----BEGIN PRIVATE KEY-----\n" + junk + "\n-----END PRIVATE KEY-----\n"
        text = json.dumps({"k": plain})
        self.assertEqual(wt.pem_kind(text, text.index("-----BEGIN")), "real")   # batch 7d (B): was "example"
        fake = json.dumps({"k": plain.replace(junk, base64.b64encode(fake_text_body(120)).decode())})
        self.assertEqual(wt.pem_kind(fake, fake.index("-----BEGIN")), "example")   # batch 7d: a FAKE-text body alone
        (_, _, _, es, _, _, hide), = wt.armor_blocks(fake)
        self.assertEqual(hide, es)
        fake = json.dumps({"k": plain.replace(junk, base64.b64encode(fake_text_body(120)).decode()) + "FAKE \\n-----END PRIVATE KEY-----\n"})
        self.assertEqual(wt.pem_kind(fake, fake.index("-----BEGIN")), "real")   # the same, past its strict end
        text = json.dumps({"k": plain + "FAKE \\n-----END PRIVATE KEY-----\n"})   # a later END only the loose reading takes
        (_, _, _, es, _, _, hide), = wt.armor_blocks(text)
        self.assertIsNotNone(es)
        self.assertGreater(hide, es)
        self.assertEqual(wt.pem_kind(text, text.index("-----BEGIN")), "real")
        self.assertNotIn("FAKE", wt.mask_secrets(text))

    def test_no_strict_end_hides_to_the_end_of_the_text(self):   # guard (new): Ken's choice, the stricter one
        block, bits = pgp_secret_block("Comment: made now")
        text = json.dumps({"k": block.replace("\n-----END PGP", "\\n-----END PGP"), "after": "visible"})   # only a literal END
        (_, _, _, es, _, _, hide), = wt.armor_blocks(text)
        self.assertEqual((es, hide), (None, None))
        out = wt.mask_secrets(text)
        self.assertEqual(kept(bits, out), 0)
        self.assertFalse("visible" in out, "the text after the block was kept")
        self.assertEqual(wt.pem_kind(text, text.index("-----BEGIN")), "real")

    # fix round 1 (Codex 1): a quoted END in a header line, in a Python string written with \n escapes
    QUOTED_COMMENT = 'Comment: x + "-----END PGP PRIVATE KEY BLOCK-----'

    def python_source(self, armor):
        return 'KEY = """' + armor.replace("\\", "\\\\").replace("\n", "\\n") + '"""\nprint(len(KEY))\n'

    def trailing(self, block):
        """block with text after its own (last) END marker, the comment's left as it is."""
        end = "-----END PGP PRIVATE KEY BLOCK-----\n"
        i = block.rindex(end)
        return block[:i] + end[:-1] + " trailing\n" + block[i + len(end):]

    def test_a_quoted_comment_end_before_an_end_with_text_after_it(self):   # replay (2ccbab1: every body line kept, masked 9)
        block, bits = pgp_secret_block(self.QUOTED_COMMENT)
        src = self.python_source(self.trailing(block))
        self.assertEqual(src.count("-----END PGP PRIVATE KEY BLOCK-----\\n"), 1)   # the comment's END, as Codex wrote it
        self.assert_hidden(src, bits, "quoted comment END")

    def test_gpg_reads_the_quoted_comment_armor(self):   # guard: GnuPG reads that armor, its END's trailing text and all
        if not GPG:
            self.skipTest("gpg not installed")
        block, _ = pgp_secret_block(self.QUOTED_COMMENT)
        armor = self.trailing(block)
        d = tempfile.mkdtemp()
        try:
            r = subprocess.run([GPG, "--homedir", d, "--batch", "--dearmor"], input=armor.encode(), capture_output=True, timeout=30)
        finally:
            shutil.rmtree(d, ignore_errors=True)
        self.assertEqual(r.returncode, 0, r.stderr[-300:])
        self.assertTrue(r.stdout == armor_packet(block), "gpg dearmored other bytes")

    def test_a_header_line_never_gives_the_end(self):   # replay (2ccbab1: the comment's END was the block's END)
        block, _ = pgp_secret_block(self.QUOTED_COMMENT + "\nComment: -----BEGIN PRIVATE KEY-----\\nFAKE\\n-----END PRIVATE KEY-----")
        src = self.python_source(block)
        blk = wt.armor_blocks(src)[0]
        # batch 7d (A): Python source isn't a JSON document, so it hides to the end (was: blk[6] == the END too)
        self.assertEqual((blk[3], blk[6]), (src.rindex("-----END PGP"), None))
        for code in ('K = ("-----BEGIN PRIVATE KEY-----\\n"\n     "QUJD\\n" + "-----END PRIVATE KEY-----\\n")\n',
                     'K = "-----BEGIN PRIVATE KEY-----\\nQUJD\\n" + "-----END PRIVATE KEY-----"\n'):   # code before a quoted END
            self.assertEqual(wt.armor_blocks(code)[0][3], code.index("-----END"), code)

    def test_a_later_unresolved_end_hides_to_the_end(self):   # replay (2ccbab1: hidden to the first END, the rest kept)
        junk = base64.b64encode(public_key_packet(120)).decode()
        text = ("-----BEGIN PRIVATE KEY-----\n" + junk + "\n-----END PRIVATE KEY-----\nFAKE more\n"
                "-----END PRIVATE KEY----- trailing\nafter\n")
        (_, _, _, es, _, _, hide), = wt.armor_blocks(text)
        self.assertEqual((es, hide), (text.index("-----END"), None))
        out = wt.mask_secrets(text)
        self.assertFalse("FAKE" in out or "after" in out, "text after the first END was kept")
        self.assertEqual(wt.pem_kind(text, 0), "real")
        two = text.replace("FAKE more\n", "") + "-----BEGIN PRIVATE KEY-----\n" + junk + "\n-----END PRIVATE KEY-----\nlast\n"
        self.assertEqual([b[6] is None for b in wt.armor_blocks(two)], [True, False])   # bounded by the label's next BEGIN

    # fix round 2 (Codex 1): a source line continued onto the END's line, and a footer assembled from adjacent literals
    def footless(self):
        """(armor with a placeholder header and no END line, its body pieces)."""
        block, bits = pgp_secret_block("Comment: PLACEHOLDER")
        return block[:block.rindex("-----END PGP")], bits

    def continued_sources(self):
        armor, bits = self.footless()
        escaped = self.python_source(armor).replace("Comment: PLACEHOLDER", 'Comment: x \\\n"-----END PGP PRIVATE KEY BLOCK-----')
        lines = 'KEY = """' + armor.replace("Comment: PLACEHOLDER", "Comment: x \\\n-----END PGP PRIVATE KEY BLOCK-----") + '"""\n'
        return {"escaped": escaped, "real lines": lines, "real lines in JSON": json.dumps({"src": lines})}, bits

    def test_a_continued_line_before_an_end(self):   # replay (037c0e1: every body line kept, at each level)
        sources, bits = self.continued_sources()
        for name, src in sources.items():
            with self.subTest(name):   # each level on its own
                self.assertTrue("\\\n" in src or "\\\\\\n" in src, name)
                self.assert_hidden(src, bits, name)
                self.assertEqual(wt.pem_kind(src, src.index("-----BEGIN")), "real", name)

    def test_gpg_reads_the_continued_armor(self):   # guard: what Python makes of the continued source is a key GnuPG reads
        if not GPG:
            self.skipTest("gpg not installed")
        armor, _ = self.footless()
        block, _ = pgp_secret_block("Comment: PLACEHOLDER")
        value = armor.replace("Comment: PLACEHOLDER", 'Comment: x "-----END PGP PRIVATE KEY BLOCK-----')   # the joined line
        d = tempfile.mkdtemp()
        try:
            r = subprocess.run([GPG, "--homedir", d, "--batch", "--dearmor"], input=value.encode(), capture_output=True, timeout=30)
        finally:
            shutil.rmtree(d, ignore_errors=True)
        self.assertEqual(r.returncode, 0, r.stderr[-300:])
        self.assertTrue(r.stdout == armor_packet(armor + "-----END PGP PRIVATE KEY BLOCK-----\n"), "gpg dearmored other bytes")

    def test_a_footer_from_adjacent_literals(self):   # replay (037c0e1: the comment's END was taken, the body kept)
        armor, bits = self.footless()
        lines = armor.replace("Comment: PLACEHOLDER", "Comment: x \x00-----END PGP PRIVATE KEY BLOCK-----").rstrip("\n").split("\n")
        lits = []
        for ln in lines:
            lits += ['"' + p + '"' for p in ln.split("\x00")[:-1]] + ['"' + ln.split("\x00")[-1] + '\\n"']
        src = "KEY = (" + "\n       ".join(lits + ['"-----END PGP " "PRIVATE KEY BLOCK-----\\n"']) + ")\nprint(len(KEY))\n"
        self.assertEqual(src.count("-----END PGP PRIVATE KEY BLOCK-----"), 1)   # only the comment's: the real footer is split
        self.assert_hidden(src, bits, "adjacent literals")

    # fix round 3 (Codex 1): a raw literal's \n is text, not a line break
    def raw_literal_source(self):
        """A Python source building the armor from literals, its header line ending in r"Comment: x \\n" (a backslash and n, in
        Python's value) next to a quoted END; the real footer left out. (source, body pieces)"""
        armor, bits = self.footless()
        lits = []
        for ln in armor.rstrip("\n").split("\n"):
            lits += (['r"Comment: x \\n"', '"-----END PGP PRIVATE KEY BLOCK-----\\n"'] if ln == "Comment: PLACEHOLDER"
                     else ['"' + ln + '\\n"'])
        return "KEY = (" + "\n       ".join(lits) + ")\nprint(len(KEY))\n", bits

    def test_a_raw_literal_before_a_quoted_end(self):   # replay (2ddc143: every body line kept, at each level)
        src, bits = self.raw_literal_source()
        for depth in (0, 1, 2):
            with self.subTest(depth=depth):
                self.assert_hidden(src if depth == 0 else serialized(src, depth), bits, depth)

    def test_gpg_reads_the_raw_literal_armor(self):   # guard: what Python makes of that source is a key GnuPG reads
        if not GPG:
            self.skipTest("gpg not installed")
        armor, _ = self.footless()
        value = armor.replace("Comment: PLACEHOLDER", "Comment: x \\n-----END PGP PRIVATE KEY BLOCK-----")
        d = tempfile.mkdtemp()
        try:
            r = subprocess.run([GPG, "--homedir", d, "--batch", "--dearmor"], input=value.encode(), capture_output=True, timeout=30)
        finally:
            shutil.rmtree(d, ignore_errors=True)
        self.assertEqual(r.returncode, 0, r.stderr[-300:])
        self.assertTrue(r.stdout == armor_packet(armor + "-----END PGP PRIVATE KEY BLOCK-----\n"), "gpg dearmored other bytes")

    def test_literals_whose_escapes_are_unsure_give_no_end(self):   # replay (2ddc143: each END was taken)
        for name, code in (("single quotes", "K = ('-----BEGIN PRIVATE KEY-----\\n'\n     'QUJD\\n'\n     '-----END PRIVATE KEY-----\\n')\n"),
                           ("backticks", "K = `-----BEGIN PRIVATE KEY-----\\n` +\n    `QUJD\\n` +\n    `-----END PRIVATE KEY-----\\n`\n"),
                           ("raw prefix", 'K = (r"-----BEGIN PRIVATE KEY-----\\n"\n     "QUJD\\n"\n     "-----END PRIVATE KEY-----\\n")\n'),
                           ("C# verbatim", 'K = @"-----BEGIN PRIVATE KEY-----\\n" +\n    "QUJD\\n" +\n    "-----END PRIVATE KEY-----\\n";\n')):
            with self.subTest(name):
                (_, _, _, es, _, _, hide), = wt.armor_blocks(code)
                self.assertIsNone(hide, name)
                self.assertEqual(wt.pem_kind(code, code.index("-----BEGIN")), "real", name)

    def test_ordinary_code_built_blocks_still_end(self):   # guard: JSON lists of lines, notebooks and code keep what follows
        raw = ed25519_pkcs8()
        p = pem("", raw)
        b = base64.b64encode(raw).decode()
        for name, text in (("JSON lines", json.dumps({"lines": [ln + "\n" for ln in p.rstrip("\n").split("\n")], "after": "visible"})),
                           ("code", 'K = ("-----BEGIN PRIVATE KEY-----\\n"\n     "' + b + '\\n"\n     "-----END PRIVATE KEY-----\\n")\nvisible = 1\n'),
                           ("notebook", json.dumps({"cells": [{"source": ['key = ("-----BEGIN PRIVATE KEY-----\\n"\n',
                                                                          '       "' + b + '\\n"\n',
                                                                          '       "-----END PRIVATE KEY-----\\n")\n',
                                                                          'print("visible")']}]}, indent=1))):
            out = wt.mask_secrets(text)
            self.assertEqual(kept(bits_of(raw), out), 0, name)
            (_, _, _, es, _, _, hide), = wt.armor_blocks(text)
            if name == "JSON lines":
                self.assertTrue("visible" in out, f"the text after the block was hidden: {name}")
                self.assertTrue(es is not None and hide == es, name)
            else:   # batch 7d (A): code and a notebook's code cell aren't established escapes: hidden to the end (was: as JSON lines)
                self.assertFalse("visible" in out, f"the text after the block was kept: {name}")
                self.assertTrue(es is not None and hide is None, name)

    def test_the_known_false_alarm_hides_the_rest(self):   # guard (new): KNOWN-LIMITS, open false alarms (batch 7a)
        raw = ed25519_pkcs8()
        block = pem("", raw).rstrip("\n")
        for text in ('K = """\n' + block + '"""\nafter = 1\n', json.dumps({"k": "intro\n" + block, "after": 1})):
            out = wt.mask_secrets(text)   # an END whose closing quote isn't the BEGIN's: no END the strict reading takes
            self.assertEqual(kept(bits_of(raw), out), 0, text[:12])
            self.assertFalse("after" in out, f"the rest was kept: {text[:12]}")
            self.assertEqual(wt.pem_kind(text, text.index("-----BEGIN")), "real", text[:12])

    def test_seeded_fuzz_hides_at_least_what_the_loose_reading_hid(self):   # guard (new)
        parts = ["-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----", "-----BEGIN PGP PRIVATE KEY BLOCK-----",
                 "-----END PGP PRIVATE KEY BLOCK-----", "\n", "\\n", "\\\\n", "\\\\\\n", "\\\\\\\\n", "\r\n", '"', "'", '\\"', "`",
                 " ", "\t", "Comment: ", "# ", "+", ",", "(", ")", "MIIBVQIBADANBgkqhkiG9w0BAQEF", "FAKE", "x"]
        rng = random.Random(7)
        for case in range(4000):
            s = "".join(rng.choice(parts) for _ in range(rng.randint(1, 40)))
            new, old = bytearray(len(s)), bytearray(len(s))
            for spans, cover in ((wt.pem_spans(s), new), (loose_spans(s), old)):
                for a, b in spans:
                    cover[a:b] = b"\x01" * (b - a)
            self.assertFalse(any(o and not w for o, w in zip(old, new)), (case, s))

    def test_long_runs_and_many_comment_ends_stay_linear(self):   # guard
        took, n = run_child(self, CHILD_RUNS)
        self.assertLess(float(took), 3.0)
        self.assertEqual(int(n), 0)


CHILD_RUNS = ("import json, sys, time\nsys.path.insert(0, {wt_dir!r})\nimport wt\n"
              "runs = ('-----BEGIN PRIVATE KEY-----' + '\\\\' * 16000 + 'n-----END PRIVATE KEY-----' + '\\\\' * 16000 + 'n') * 16\n"
              "comments = json.dumps('-----BEGIN PGP PRIVATE KEY BLOCK-----\\n' + 'Comment: \\\\n-----END PGP PRIVATE KEY BLOCK-----\\n' * 4000\n"
              "                      + '\\nFAKEbody\\n-----END PGP PRIVATE KEY BLOCK-----\\n')\n"
              "t = time.perf_counter()\nouts = [wt.mask_secrets(x) for x in (runs, comments)]\n"
              "print(time.perf_counter() - t, outs[1].count('FAKEbody'))\n")


# ---------------------------------------------------------------- 2: a shared whitespace tail
CHILD_TAIL = ("import sys, time\nsys.path.insert(0, {wt_dir!r})\nimport wt\n"
              "def run(n):\n"
              "    text = '-----BEGIN PRIVATE KEY-----\\n' * n + 'x' + '\\n' * (20 * n) + '-----END PRIVATE KEY-----\\n'\n"
              "    t = time.perf_counter()\n    out = wt.mask_secrets(text)\n    return time.perf_counter() - t, 'x' in out\n"
              "small, big = run(500), run(4000)\nprint(small[0], big[0], small[1] or big[1])\n")


class SharedTail(unittest.TestCase):
    def test_4000_blocks_sharing_one_tail(self):   # replay (a3e535e: 19 s against 0.3 s for 500)
        small, big, kept = run_child(self, CHILD_TAIL)
        self.assertLess(float(big), max(1.0, 16 * float(small)))
        self.assertEqual(kept, "False")   # x is hidden


# ---------------------------------------------------------------- 3: ignored packets before a secret key
class IgnoredPackets(_Keys):
    def packets(self):
        sk = secret_packet()
        out = {name: pkt + sk for name, pkt in IGNORED.items()}
        out["public then secret"] = public_packet() + sk
        return out

    def test_a_secret_key_behind_an_ignored_packet_is_real(self):   # replay (a3e535e: WT-T011x, "isn't a real key")
        for name, raw in self.packets().items():
            # WT-T011's pattern names labels ending in PRIVATE KEY; the verdict reads the body alone, so the same packets in a
            # PRIVATE KEY block are what it judges, and the PGP armor is what secret_kind judges
            got = t011("Key:\n" + pem("", raw))
            self.assertEqual([(f["rule"], f["severity"]) for f in got], [("WT-T011", "critical")], name)
            self.assertNotIn(NOTE, got[0]["fix"], name)
            block = pgp_armor(raw)
            self.assertEqual(wt.secret_kind(block.split("\n")[0], tail=block[block.index("\n"):])[0], "real", name)

    def test_through_gitleaks_it_is_a_key_left_in_a_file(self):   # replay (a3e535e: "Keys that look like examples or checksums")
        block = pgp_armor(IGNORED["marker"] + secret_packet())
        p = self.put("projects/app/release.asc", block)
        self.leak(p, block.rstrip("\n"), rule="private-key")
        fs, _ = self.scan()
        got = [f for f in self.keys(fs, p) if f["rule"] == "WT-S002"]
        self.assertEqual(len(got), 1, got)
        self.assertNotIn(NOTE, got[0]["fix"])
        self.assertEqual(wt.plain(got[0])["title"], "Keys left in files")

    def test_public_packets_only_are_still_noted(self):   # guard: a public key labelled PRIVATE is what the note is for
        # fix round 2: a public key, a public subkey and a marker (a user ID's free bytes prove nothing: test_unread_payloads_…)
        # batch 7d (B): no longer noted: a public key's fields may hold a private key's bytes ("example" -> "real"); a FAKE-text
        # body is what the note is for now
        for raw in (public_packet(), public_packet() + public_subkey() + IGNORED["marker"],
                    public_key_packet(300)):   # fix round 1: a whole packet (a cut one is a key, test_a_cut_public_packet_…)
            block = pgp_armor(raw)
            self.assertEqual(wt.secret_kind(block.split("\n")[0], tail=block[block.index("\n"):])[0], "real", raw[:3].hex())
        block = pgp_armor(fake_text_body(300))
        self.assertEqual(wt.secret_kind(block.split("\n")[0], tail=block[block.index("\n"):])[0], "example")

    def test_gpg_reads_the_secret_key_behind_the_marker(self):   # guard: the replay's packets are what GnuPG reads
        if not GPG:
            self.skipTest("gpg not installed")
        d = tempfile.mkdtemp()
        try:
            r = subprocess.run([GPG, "--homedir", d, "--batch", "--list-packets"], input=pgp_armor(IGNORED["marker"] + secret_packet()).encode(),
                               capture_output=True, timeout=30)
        finally:
            shutil.rmtree(d, ignore_errors=True)
        self.assertIn(b"marker packet", r.stdout)
        self.assertIn(b"secret key packet", r.stdout)

    def test_packet_readings(self):   # guard (new)
        sk, pk, m = secret_packet(), public_packet(), IGNORED["marker"]
        for raw, want in ((sk, "secret"), (m + sk, "secret"), (pk + sk, "secret"), (pk, "public"), (m + pk + m, "public"),
                          (b"\x99\xff\xff" + b"\x00" * 64, None),        # a public packet cut short (fix round 1: was "public")
                          (pk + b"\x00", None),                           # bytes after the packets that aren't one
                          (pk + b"\x80\x01\x00", None),                   # reserved tag 0
                          (b"\xc6\xe0" + b"\x00" * 64, None),             # a partial length
                          (b"\x9b" + b"\x00" * 64, None),                 # an indeterminate length
                          (pk + b"\xa4\x01\x00", None),                   # another tag (9, encrypted data)
                          (m * 64 + pk, None), (m * 63 + pk, "public"),   # more packets than the cap
                          (m * 4, None)):                                 # nothing public
            self.assertEqual(wt.pgp_packets(raw), want, raw[:4].hex())

    def test_a_cut_public_packet_before_a_secret_key_is_real(self):   # replay (2ccbab1: "public", an example with the note)
        raw = b"\x99\xff\xff" + secret_packet()   # a public header declaring 65,535 bytes, then the secret-key packet
        self.assertIsNone(wt.pgp_packets(raw))
        got = t011("Key:\n" + pem("", raw))
        self.assertEqual([(f["rule"], f["severity"]) for f in got], [("WT-T011", "critical")])
        self.assertNotIn(NOTE, got[0]["fix"])
        block = pgp_armor(raw)
        self.assertEqual(wt.secret_kind(block.split("\n")[0], tail=block[block.index("\n"):])[0], "real")

    def test_a_public_envelope_around_a_secret_key_is_real(self):   # replay (037c0e1: "public", an example with the note)
        fields = b"\x04" + int(time.time()).to_bytes(4, "big") + b"\x01" + mpi(128) + b"\x00\x11\x01\x00\x01"
        raw = old_packet(6, fields + secret_packet())   # its declared length is exact; the secret packet rides in its payload
        self.assertIsNone(wt.pgp_packets(raw))
        got = t011("Key:\n" + pem("", raw))
        self.assertEqual([(f["rule"], f["severity"]) for f in got], [("WT-T011", "critical")])
        self.assertNotIn(NOTE, got[0]["fix"])
        block = pgp_armor(raw)
        self.assertEqual(wt.secret_kind(block.split("\n")[0], tail=block[block.index("\n"):])[0], "real")

    def test_public_key_structures_are_read_exactly(self):   # guard (new)
        t = int(time.time()).to_bytes(4, "big")
        p256 = b"\x08" + bytes.fromhex("2a8648ce3d030107")
        ecdsa = b"\x04" + t + b"\x13" + p256 + b"\x02\x03\x04" + secrets.token_bytes(64)            # v4 ECDSA P-256: OID, point
        ecdh = b"\x04" + t + b"\x12" + p256 + b"\x02\x03\x04" + secrets.token_bytes(64) + b"\x03\x01\x08\x07"   # and KDF
        ed6 = b"\x06" + t + b"\x1b" + (32).to_bytes(4, "big") + secrets.token_bytes(32)              # v6 Ed25519
        for raw in (public_key_packet(120), public_key_packet(300), old_packet(6, ecdsa), old_packet(14, ecdh), old_packet(6, ed6),
                    public_packet() + public_subkey()):
            self.assertEqual(wt.pgp_packets(raw), "public", raw[:4].hex())
        rsa = public_packet()[3:]
        for raw in (old_packet(6, rsa + b"\x00"),                     # a byte left over
                    old_packet(6, rsa[:-1]),                          # a field cut short
                    old_packet(6, b"\x03" + rsa[1:]),                 # version 3
                    old_packet(6, rsa[:5] + b"\x63" + rsa[6:]),       # algorithm 99
                    old_packet(6, b"\x06" + t + b"\x1b" + (33).to_bytes(4, "big") + secrets.token_bytes(33)),   # v6 length off
                    old_packet(6, b"\x04" + t + b"\x13\x00" + b"\x02\x03\x04" + secrets.token_bytes(64))):    # an empty OID
            self.assertIsNone(wt.pgp_packets(raw), raw[:8].hex())

    # fix round 3 (Codex 2): every field of an accepted public key read exactly
    P256, P384 = bytes.fromhex("2a8648ce3d030107"), bytes.fromhex("2b81040022")
    CV25519, ED25519 = bytes.fromhex("2b060104019755010501"), bytes.fromhex("2b06010401da470f01")

    @staticmethod
    def point(prefix, size):
        return (prefix.bit_length() + 8 * size).to_bytes(2, "big") + bytes([prefix]) + secrets.token_bytes(size)

    @staticmethod
    def key(alg, *fields, version=4):
        body = b"".join(fields)
        count = (len(body).to_bytes(4, "big") if version != 4 else b"")
        return old_packet(6, bytes([version]) + int(time.time()).to_bytes(4, "big") + bytes([alg]) + count + body)

    def oid(self, o):
        return bytes([len(o)]) + o

    def test_malformed_public_fields_are_real(self):   # replay (2ddc143: "public", an example with the note)
        P, kdf = self.oid(self.P256), b"\x03\x01\x08\x07"
        n = mpi(256)
        cases = {"a KDF carrying a private key": self.key(18, P, self.point(4, 64), bytes([51]) + b"\x01\x08\x07" + ed25519_pkcs8()),
                 "a KDF then bytes left over": self.key(18, P, self.point(4, 64), kdf + b"\x00" * 8),
                 "a 4-byte KDF": self.key(18, P, self.point(4, 64), b"\x04\x01\x08\x07\x00"),
                 "an unknown KDF hash": self.key(18, P, self.point(4, 64), b"\x03\x01\x63\x07"),
                 "an unknown KDF cipher": self.key(18, P, self.point(4, 64), b"\x03\x01\x08\x63"),
                 "a KDF reserved byte": self.key(18, P, self.point(4, 64), b"\x03\x02\x08\x07"),
                 "an unknown curve": self.key(19, self.oid(bytes.fromhex("2a8648ce3d030199")), self.point(4, 64)),
                 "a short point": self.key(19, P, self.point(4, 63)),
                 "a compressed point": self.key(19, P, self.point(2, 32)),
                 "a P-256 point on P-384": self.key(19, self.oid(self.P384), self.point(4, 64)),
                 "ECDSA on Curve25519": self.key(19, self.oid(self.CV25519), self.point(0x40, 32), mpi(48)),
                 "an RSA modulus with a leading zero byte": self.key(1, (2048).to_bytes(2, "big") + b"\x00" + n[3:], b"\x00\x11\x01\x00\x01"),
                 "an RSA bit count its first byte doesn't match": self.key(1, (2048).to_bytes(2, "big") + b"\x01" + n[3:], b"\x00\x11\x01\x00\x01"),
                 "legacy EdDSA in a version 6 key": self.key(22, self.oid(self.ED25519), self.point(0x40, 32), mpi(40), version=6)}
        for name, raw in cases.items():
            with self.subTest(name):
                self.assertIsNone(wt.pgp_packets(raw), name)
                got = t011("Key:\n" + pem("", raw))
                self.assertEqual([(f["rule"], f["severity"]) for f in got], [("WT-T011", "critical")], name)
                self.assertFalse(NOTE in got[0]["fix"], f"noted as an example: {name}")
                block = pgp_armor(raw)
                self.assertEqual(wt.secret_kind(block.split("\n")[0], tail=block[block.index("\n"):])[0], "real", name)

    def test_valid_curve_and_group_keys_are_public(self):   # guard (new)
        dsa = self.key(17, mpi(256), mpi(32), mpi(256), mpi(256))
        cases = {"ECDH P-256": self.key(18, self.oid(self.P256), self.point(4, 64), b"\x03\x01\x08\x07"),
                 "ECDH P-384": self.key(18, self.oid(self.P384), self.point(4, 96), b"\x03\x01\x09\x08"),
                 "ECDH Curve25519": self.key(18, self.oid(self.CV25519), self.point(0x40, 32), b"\x03\x01\x08\x07"),
                 "ECDSA P-521": self.key(19, self.oid(bytes.fromhex("2b81040023")), self.point(4, 132)),
                 "ECDSA brainpoolP256r1": self.key(19, self.oid(bytes.fromhex("2b2403030208010107")), self.point(4, 64)),
                 "EdDSA Ed25519": self.key(22, self.oid(self.ED25519), self.point(0x40, 32)),
                 "Ed25519 v6": self.key(27, secrets.token_bytes(32), version=6), "X25519 v4": self.key(25, secrets.token_bytes(32)),
                 "DSA": dsa, "Elgamal": self.key(16, mpi(256), mpi(1), mpi(256)), "RSA": public_key_packet(300)}
        for name, raw in cases.items():
            with self.subTest(name):
                self.assertEqual(wt.pgp_packets(raw), "public", name)
                if len(raw) >= 64:   # batch 7d (B): "example" -> "real", the fields may hold a private key's bytes
                    block = pgp_armor(raw)
                    self.assertEqual(wt.secret_kind(block.split("\n")[0], tail=block[block.index("\n"):])[0], "real", name)
        block = pgp_armor(fake_text_body(120))   # batch 7d: the example path, a FAKE-text body
        self.assertEqual(wt.secret_kind(block.split("\n")[0], tail=block[block.index("\n"):])[0], "example")

    def test_unread_payloads_prove_nothing(self):   # guard (new): a payload whose bytes aren't read can hold a secret key
        uid = b"FAKE Example <fake@example.invalid>"
        pk = public_packet()
        for name, raw in (("user ID", pk + bytes([0xb4, len(uid)]) + uid), ("signature", pk + old_packet(2, b"\x04" * 40)),
                          ("trust", pk + IGNORED["trust"]), ("padding", pk + IGNORED["padding"]), ("tag 61", pk + IGNORED["tag 61"]),
                          ("another marker", pk + b"\xa8\x03XYZ")):
            self.assertIsNone(wt.pgp_packets(raw), name)
            block = pgp_armor(raw)
            self.assertEqual(wt.secret_kind(block.split("\n")[0], tail=block[block.index("\n"):])[0], "real", name)

    def test_100000_marker_packets_are_read_in_bounded_time(self):   # guard (new)
        raw = IGNORED["marker"] * 100_000 + secret_packet()
        t = time.perf_counter()
        self.assertIsNone(wt.pgp_packets(raw))
        self.assertTrue(wt._key_shaped(raw, 0))
        self.assertLess(time.perf_counter() - t, 1.0)


# ---------------------------------------------------------------- 4: a long saved connector answer
CHILD_CONNECTORS = ("import sys, time\nsys.path.insert(0, {wt_dir!r})\nimport wt\n"
                    "def run(n):\n    t = time.perf_counter()\n    wt._ax_said(dict(connectors='Gmail ' * n))\n    return time.perf_counter() - t\n"
                    "run(10)\nprint(run(1000), run(8000))\n")


CHILD_SPACES = ("import sys, time\nsys.path.insert(0, {wt_dir!r})\nimport wt\n"
                "def run(n, answers=1):\n    t = time.perf_counter()\n"
                "    for _ in range(answers):\n        wt._ax_said(dict(connectors=' ' * n + 'x'))\n    return time.perf_counter() - t\n"
                "run(10)\nprint(run(2000), run(16000), run(16000, 40))\n")


class LongConnectorAnswers(unittest.TestCase):
    def test_spaces_before_one_other_character(self):   # replay (2ccbab1: 0.8 s for 16 KB, about 32 s for 40 such answers)
        small, big, many = (float(x) for x in run_child(self, CHILD_SPACES, limit=120))
        self.assertLess(big, max(0.5, 24 * small))           # 8 times the text: linear, with room for a loaded box
        self.assertLess(many, max(5.0, 40 * 24 * small))     # 40 saved answers of 16 KB each

    def test_no_connector_words_still_read(self):   # guard: the stripped reading is the old one
        for raw in ("  none  ", "\tN/A\n", " no connectors yet ", "---", " ", "not yet set up"):
            self.assertEqual(wt.connector_answer([raw]), ([], 0, None), repr(raw))
        self.assertEqual(wt.connector_answer([" " * 16000 + "x"]), ([], 1, None))


    def test_a_long_scalar_answer_is_partial(self):   # replay (a3e535e: about 10 s, then complete: connectors_unknown None)
        got = wt._ax_said({"connectors": "Gmail " * 8000})
        self.assertEqual((got["connectors"], got["connectors_unknown"]), (["Gmail"], "partial"))

    def test_reading_scales_linearly(self):   # replay (a3e535e: 0.19 s for 1,000, 10.44 s for 8,000)
        small, big = run_child(self, CHILD_CONNECTORS)
        self.assertLess(float(big), max(1.0, 16 * float(small)))

    def test_a_fresh_reply_is_partial_too(self):   # replay: rollcall's reader is the same one
        self.assertEqual(wt.connector_answer(["Slack", "Gmail " * 8000])[::2], (["Gmail", "Slack"], "partial"))

    def test_a_long_single_name_is_still_gmail(self):   # guard
        self.assertEqual(wt.connector_answer("Gmail" + " and" * 3000), (["Gmail"], 0, None))
        self.assertEqual(wt.access_connectors(["Gmail" + " and" * 3000]), (["Gmail"], 0))

    def test_forty_names_are_complete(self):   # guard
        names = ["Gmail and Slack", "Notion", "Acme CRM"] * 13 + ["MS Teams"]
        self.assertEqual(wt.connector_answer(names), (["Gmail", "Slack", "Microsoft Teams", "Notion"], 13, None))


if __name__ == "__main__":
    unittest.main()
