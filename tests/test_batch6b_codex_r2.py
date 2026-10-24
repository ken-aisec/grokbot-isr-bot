"""Batch 6 PR2, Codex round 2 (12 high on de3b328): replays and guards. The owner's rule decides each trade-off: a signal a Bot can
write (state/, dismissed.jsonl, last_findings.json, a report file, the home folder) never lowers or hides a finding.

B5 (1-5): an example-looking secret (FAKE or placeholder text, an environment-variable reference, a key block whose body isn't a
key, a checksum by its line's format) is never left out: it is a low finding, "Looks like an example or checksum value - check
it", never Confirmed, never offered for revoking or clearing, at every place it was found. A hit is read at gitleaks' columns
only where they surely count from the file's start (a whole file of at most 100,000 bytes, or a line that ends inside them), and
only in bytes unchanged since before gitleaks started (no second scan; an equal-entropy swap fooled it). gitleaks' config and
report are in a private folder, read through its descriptor, never from state/. A key block is read with nothing on a line left
out. B6 (6, 7): a dismissal sets aside only a Worth-a-look finding, as at 5dcd0a2; one backed up by a change counts again and
says so. 8, 10: key blocks are masked by one pass with no size cap, to the end of the text when unfinished. 9, 11: placeholders
are read without backtracking; no per-finding command span. 12: KL3's marker entry needs the exact -7/+8 transition.
Fix round 3 (test_batch6b_codex_r3): "listed low" was itself too weak; an example-looking hit now keeps its rule's severity,
title, counting and Confirmed rules, with a note in its fix, and the assertions here that said low are changed to that (each
listed in CHANGELOG).

Every real-shaped key here is generated when the test runs and never committed; fake ones contain FAKE. Tests marked "replay" fail
on de3b328 on their assertion (measured with de3b328's watchtower/ sources and golden expect file, this file in place); "guard"
ones pass there too, unless marked "new" (they call something de3b328 doesn't have, or its behaviour is new)."""
import base64, gzip, hashlib, inspect, json, os, random, secrets, subprocess, sys, time, unittest
from unittest import mock
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import Box, ROOT
import isr  # noqa: E402
from test_batch6_example_keys import _Keys, der, der_int, fake_text_body, pem, public_key_packet, rsa_der, token
from test_batch6b_codex_r1 import (_Dismiss, BUN, GSIDS, MARKER, SKILL_HEAD, body_bits, golden, gl_key, pkcs8, scenario)

TITLE = "Looks like an example or checksum value - check it"   # round 2's title; round 3 keeps each finding's own
NOTE = "This looks like an example or checksum value"   # round 3: the note an example-looking hit gets in its fix


def ed25519_pkcs8():
    """A PKCS#8 Ed25519 private key, made now: 48 bytes, one 64-character base64 line."""
    return bytes.fromhex("302e020100300506032b657004220420") + secrets.token_bytes(32)


def raw_sev(f):
    return f.get("severity_was") or f["severity"]


def gitleaks_calls(pre=None, post=None):
    """isr.run, with `pre`/`post` (each given the gitleaks command) run around each `gitleaks detect`: what a Bot writing to
    Watchtower's state folder while gitleaks runs could do."""
    orig = isr.run

    def run(cmd, *a, **k):
        is_gl = len(cmd) > 1 and cmd[1] == "detect"
        if is_gl and pre:
            pre(cmd)
        out = orig(cmd, *a, **k)
        if is_gl and post:
            post(cmd)
        return out
    return mock.patch.object(isr, "run", run)


# ---------------------------------------------------------------- 1-4: example-looking hits are listed, never left out
class ExamplesAreListed(_Keys):
    def mine(self, fs, p):
        return [f for f in self.keys(fs, p) if f["rule"] == "ISR-S002"]

    def test_a_pat_in_a_later_piece_of_a_long_line(self):   # replay 1 (de3b328: the FAKE at byte 0 was judged, the PAT dropped)
        pat, fake = gl_key(0)
        p = self.put("projects/app/dump.txt", fake + "." * (125_000 - len(fake)) + pat + "\n")
        self.leak(p, pat, rule="gitlab-pat", cols=(1, len(pat)))   # gitleaks' second piece starts at byte 125,000: column 1
        fs, notes = self.scan()
        got = self.mine(fs, p)
        self.assertEqual([(f["title"], raw_sev(f)) for f in got], [("gitleaks: secrets in file", "critical")], got)

    def test_a_value_swapped_after_gitleaks_read_it(self):   # replay 2 (de3b328: a swap with the same entropy passed its rescan)
        pat, fake = gl_key(0)
        p = self.put("projects/app/deploy.sh", f"git clone https://oauth2:{pat}@gitlab.example/g/r.git\n")
        swapped = open(p).read().replace(pat, fake)
        self.leak(p, pat, rule="gitlab-pat", then=swapped)            # gitleaks read the PAT; the file then holds the FAKE
        self.leak(p, fake, rule="gitlab-pat", line=1)                 # what gitleaks finds on a copy of the swapped bytes
        fs, notes = self.scan()
        got = self.mine(fs, p)
        self.assertEqual([(f["title"], raw_sev(f)) for f in got], [("gitleaks: secrets in file", "critical")], got)

    def test_fake_shaped_credentials_are_noted(self):   # replay 3 (de3b328: each judged an example and left out)
        # round 3 (Codex 1): listed at the generic rule's own severity, with the example note, never lowered
        vals = {"a.env": "FAKE" + secrets.token_hex(32), "b.env": "<" + token("", 20) + ">", "c.env": "$K" + token("", 20),
                "d.env": token("", 3) * 6}   # FAKE then 64 random hex; <…>; a $NAME; one unit repeated
        for name, v in vals.items():
            p = self.put(f"projects/app/{name}", f'api_key = "{v}"\n')
            self.leak(p, f'api_key = "{v}"', v)
        fs, notes = self.scan()
        d = os.path.join(self.home, "projects/app")
        got = self.mine(fs, d)   # four files in one folder: one folder finding, as four real hits are
        self.assertEqual([(f["where"], f["title"], raw_sev(f), f["label"]) for f in got],
                         [(d, "gitleaks: secrets in 4 files under app", "medium", isr.MAYBE_FINE)], got)
        self.assertIn(NOTE, got[0]["fix"])
        self.assertIn("gitleaks: 4 hit(s) look like example or checksum values; each is scored as any other hit and noted, to check "
                      "(anyone can write a real key that way).", self.snap()["notes"])

    def test_checksum_framing_is_noted(self):   # replay 4 (de3b328: "sha256:" in front made a credential a checksum)
        # round 3 (Codex 2): listed at the generic rule's own severity, with the checksum note, never lowered
        hx = secrets.token_hex(32)
        p = self.put("projects/app/settings.conf", f"api_key sha256:{hx}\n")
        q = self.put("projects/app/SHA256SUMS", f"{secrets.token_hex(32)}  tools/x.tar.gz\n")
        self.leak(p, f"api_key sha256:{hx}", hx)
        hq = open(q).read().split(" ")[0]
        self.leak(q, open(q).read().rstrip("\n"), hq)
        fs, _ = self.scan()
        for path in (p, q):
            got = self.mine(fs, path)
            self.assertEqual([(f["title"], raw_sev(f)) for f in got], [("gitleaks: secrets in file", "medium")], path)
            self.assertIn("(a file's checksum)", got[0]["fix"])

    def test_every_line_and_file_is_named(self):   # guard (new): a fake in each of 5 files, two in one: none left out
        # round 3 (Codex 1): five files in one folder are one folder finding, as real hits are, naming each file and line
        d = "sand-data/workflows/setup-dev-tools/examples"
        for i in range(5):
            text = "".join(f"token: ghp_FAKE{i}{j}" + "y8" * 15 + "\n" for j in range(2 if i == 0 else 1))
            p = self.put(f"{d}/fake{i}.md", text)
            for j in range(2 if i == 0 else 1):
                self.leak(p, f"ghp_FAKE{i}{j}" + "y8" * 15, rule="github-pat")
        fs, notes = self.scan()
        got = [f for f in self.keys(fs, self.skill) if f["rule"] == "ISR-S002"]
        self.assertEqual([(f["where"], raw_sev(f)) for f in got], [(os.path.join(self.home, d), "critical")])
        self.assertEqual(got[0]["evidence"], "6 hit(s): github-pat at fake0.md:1, fake0.md:2, fake1.md:1 and 3 more")
        self.assertIn(NOTE, got[0]["fix"])

    def test_an_example_is_never_confirmed_or_offered_for_clearing(self):   # guard (new)
        # round 3 (Codex 1): Confirmed or not by the same rules as any key; never offered for clearing or revoking
        p = self.put("projects/app/logs/session.log", '{"text": "token: ghp_FAKE' + "z7" * 16 + '"}\n')   # a log: on the scrub list if real
        self.leak(p, "ghp_FAKE" + "z7" * 16, rule="github-pat")
        fs, _ = self.scan()
        mine = self.keys(fs, p)
        self.assertTrue(mine)
        self.assertTrue(all(f["label"] == isr.CONFIRMED and NOTE in f["fix"] for f in mine), mine)   # two engines agree, as on any key
        self.assertNotIn(p, isr.scrub_targets_from_findings())
        self.assertEqual(isr.revoke_targets(mine), [])
        self.assertEqual(isr.plain(mine[0])["title"], "Keys that look like examples or checksums")
        self.assertNotIn("fix it", isr.plain(mine[0])["how"])

    def test_a_live_key_where_an_example_was_read_is_critical(self):   # guard (new): the provider's answer decides
        f = isr.annotate_example(isr.finding("ISR-S002", "gitleaks: secrets in file", "critical", [], "/w/k.md:3", "1 hit(s): github-pat", "x",
                                           source="gitleaks"), "FAKE or placeholder text")
        live = {"/w/k.md": [{"status": "live", "detector": "Github", "line": 3}]}
        dead = {"/w/k.md": [{"status": "dead", "detector": "Github", "line": 3}]}
        self.assertEqual((isr.apply_key_status([f], live, ran=True)[0]["severity"]), "critical")
        out = isr.apply_key_status([f], dead, ran=True)[0]
        # round 3: the provider's "dead" lowers it as any key, but the fix never clears it on its own
        self.assertEqual((out["severity"], out["title"], isr.fix_class(out)), ("low", isr.KEY_DEAD, "only_you"))


class ExamplesInIsrBotsRules(unittest.TestCase):
    def test_t011_examples_are_noted(self):   # replay 3 (de3b328: no T011 at all)
        rules = isr.load_rules()
        for v in ("ghp_FAKE" + "x9" * 16, "AKIAFAKE" + "Q7" * 6, "sk-proj-EXAMPLEKEY1234567890abcdefgh"):
            got = [f for f in isr.scan_text(f"Use {v} here.\n", "/s/SKILL.md", rules) if f["rule"].startswith("ISR-T011")]
            # its own rule id beside ISR-T011, so a placeholder never raises ISR-T011 (test_isr_bot's test_placeholder_keys_ignored);
            # round 3 (Codex 1): ISR-T011's title and severity, with the note
            self.assertEqual([(f["rule"], f["title"], f["severity"]) for f in got], [("ISR-T011x", "Secret or key in text", "critical")], v)

    def test_a_real_t011_beside_an_example_one(self):   # replay 3 (de3b328: the example one left out): each its own severity
        real = "ghp_" + token("", 36)
        got = sorted((f["rule"], f["severity"], f["title"]) for f in isr.scan_text(f"a ghp_FAKE{'x9' * 16}\nb {real}\n", "/s/SKILL.md", isr.load_rules())
                     if f["rule"].startswith("ISR-T011"))
        self.assertEqual(got, [("ISR-T011", "critical", "Secret or key in text"), ("ISR-T011x", "critical", "Secret or key in text")])

    def test_an_example_backs_up_and_is_backed_up(self):   # guard (new: de3b328 has no example_finding)
        # round 3 (Codex 1): two engines at one place agree, whether or not one value looks like an example
        fs = isr.label_findings([isr.annotate_example(isr.finding("ISR-S001", "Secret stored in a file on the shared computer", "critical", [],
                                                               "/w/a.md:2", "x", ""), "FAKE or placeholder text"),
                                isr.finding("ISR-T011", "Secret or key in text", "critical", ["AST04"], "/w/a.md:2", "y", "f", source="other")])
        self.assertEqual([f["class"] for f in fs], ["corroborated", "corroborated"])


# ---------------------------------------------------------------- 2: no answer or config read from state/
class GitleaksPrivateFiles(_Keys):
    def real_hit(self):
        real = token("", 32)
        p = self.put("projects/app/a.env", f"API_KEY={real}\n")
        self.leak(p, f"API_KEY={real}", real)
        return p

    def test_a_report_replaced_in_state_is_never_read(self):   # replay 2 (de3b328 read state/gitleaks.json: the hit was gone)
        p = self.real_hit()
        with gitleaks_calls(post=lambda cmd: open(isr.state_path("gitleaks.json"), "w").write("[]")):
            fs, notes = self.scan()
        self.assertTrue([f for f in self.keys(fs, p) if f["rule"] == "ISR-S002"], notes)

    def test_a_config_replaced_in_state_is_never_given_to_gitleaks(self):   # replay 2 (de3b328: a planted allowlist hid it)
        p = self.real_hit()
        plant = "[extend]\nuseDefault = true\n\n[[allowlists]]\ndescription = \"planted\"\npaths = [\n  '''.*''',\n]\n"
        with gitleaks_calls(pre=lambda cmd: open(isr.state_path("gitleaks.toml"), "w").write(plant)):
            fs, notes = self.scan()
        self.assertTrue([f for f in self.keys(fs, p) if f["rule"] == "ISR-S002"], notes)
        self.assertEqual(open(isr.state_path("gitleaks.toml")).read(), plant)   # the owner's copy is only a copy

    def test_a_linked_report_is_a_failure_not_an_empty_answer(self):   # guard (new)
        p = self.real_hit()
        forged = os.path.join(self.tmp, "forged.json")
        open(forged, "w").write("[]")
        stand_in = ('#!/usr/bin/env python3\nimport os, sys\na = sys.argv[1:]\nif a and a[0] == "version":\n    print("8.30.1"); sys.exit(0)\n'
                    f'os.symlink({forged!r}, a[a.index("--report-path") + 1])\n')
        self.scanners(gitleaks=stand_in, trufflehog=None)
        r = self.audit()
        self.assertTrue(any("gitleaks FAILED on" in n and "NOT checked" in n for n in r["notes"]), r["notes"])

    def test_the_private_folder_is_gone_after(self):   # guard (new)
        import tempfile
        self.real_hit()
        before = {x for x in os.listdir(tempfile.gettempdir()) if x.startswith(("wt-gitleaks-", "wt-metadata-"))}
        self.scan()
        after = {x for x in os.listdir(tempfile.gettempdir()) if x.startswith(("wt-gitleaks-", "wt-metadata-"))}
        self.assertEqual(after - before, set())


class MetadataReportInState(Box):
    def test_a_forged_metadata_report_binds_nothing(self):   # replay 2 (de3b328 read state/gitleaks-metadata.json and bound it)
        exe = os.path.join(self.tmp, "gl")
        open(exe, "w").write('#!/usr/bin/env python3\nimport sys\na = sys.argv[1:]\nopen(a[a.index("--report-path") + 1], "w").write("[]")\n')
        os.chmod(exe, 0o755)
        fp = os.path.join(self.home, ".grok", "bundled", "manifest.json")
        hit = {"RuleID": "generic-api-key", "StartLine": 5, "EndLine": 5, "StartColumn": 3, "EndColumn": 40, "Match": "REDACTED",
               "Secret": "REDACTED", "Entropy": 3.9}

        def forge(cmd):   # a Bot writes the hits Watchtower wants to see where de3b328 read the copy's report
            src = cmd[cmd.index("--source") + 1]
            copy = [os.path.join(d, n) for d, _, ns in os.walk(src) for n in ns][0]
            open(isr.state_path("gitleaks-metadata.json"), "w").write(json.dumps([dict(hit, File=copy)]))
        isr.VERIFIED_METADATA[os.path.normpath(fp)] = b'{"FAKE": "bytes"}\n'
        try:
            with gitleaks_calls(post=forge):
                if len(inspect.signature(isr.metadata_bound).parameters) == 3:   # de3b328's: (exe, cfg, per_file)
                    with open(isr.state_path("gitleaks.toml"), "w") as f:
                        f.write(isr.GITLEAKS_CONFIG)
                    bound = isr.metadata_bound(exe, isr.state_path("gitleaks.toml"), {fp: [dict(hit, File=fp)]})
                else:
                    bound = isr.metadata_bound(exe, {fp: [dict(hit, File=fp)]})
        finally:
            isr.VERIFIED_METADATA.pop(os.path.normpath(fp), None)
        self.assertEqual(bound, {})


# ---------------------------------------------------------------- 1: columns from a later piece are never read
class FragmentOrigin(unittest.TestCase):
    def leak(self, data, at, secret, line, col):
        return {"RuleID": "gitlab-pat", "StartLine": line, "EndLine": line, "StartColumn": col, "EndColumn": col + len(secret) - 1,
                "Match": "REDACTED", "Secret": "REDACTED", "Entropy": isr.shannon_entropy(secret)}

    def test_a_long_line_is_never_read_by_its_columns(self):   # replay 1 (de3b328 returned the FAKE at byte 0)
        pat, fake = gl_key(0)
        data = (fake + "." * (125_000 - len(fake)) + pat + "\n").encode()
        self.assertIsNone(isr.gitleaks_secret(self.leak(data, 125_000, pat, 1, 1), data))

    def test_a_line_past_the_first_piece(self):   # replay 1 (de3b328 read a later line's columns as the first piece's)
        pat, fake = gl_key(0)
        head = ("x" * 99 + "\n") * 1100   # 110,000 bytes of short lines; gitleaks' second piece may start on any of them
        data = (head + "F" + fake + " " + "." * 10 + pat + "\n").encode()   # the PAT, at column 2 of a piece starting at "."
        lk = self.leak(data, 0, pat, 1101, 2)
        self.assertIsNone(isr.gitleaks_secret(lk, data))

    def test_inside_the_first_piece_it_is_read(self):   # guard
        pat, fake = gl_key(0)
        data = (("x" * 99 + "\n") * 900 + "key " + fake + "\n" + "y" * 200_000 + "\n").encode()
        lk = self.leak(data, 0, fake, 901, 6)
        self.assertEqual(isr.gitleaks_secret(lk, data)[0], fake)


# ---------------------------------------------------------------- 5: nothing on a key block's line is left out
class KeyBlockLines(unittest.TestCase):
    def test_an_annotation_never_erases_body_bytes(self):   # replay 5 (de3b328: ' # ""' kept only the empty quote: example)
        block = pem("", ed25519_pkcs8()).split("\n")
        block[1] += ' # ""'
        text = "\n".join(block)
        self.assertEqual(isr.secret_kind(text.split("\n")[0], tail=text[text.index("\n"):])[0], "real")
        got = [f for f in isr.scan_text("Key:\n" + text, "/s/SKILL.md", isr.load_rules()) if f["rule"] == "ISR-T011"]
        self.assertEqual([f["severity"] for f in got], ["critical"])

    def test_other_framings_of_a_real_key(self):   # guard: a bare one, in JSON, in code, after junk lines
        raw = ed25519_pkcs8()
        b = base64.b64encode(raw).decode()
        for text in (pem("", raw), json.dumps({"k": pem("", raw)}),
                     '"-----BEGIN PRIVATE KEY-----\\n" +\n"' + b + '\\n" +\n"-----END PRIVATE KEY-----\\n"',
                     "-----BEGIN PRIVATE KEY-----\n" + base64.b64encode(secrets.token_bytes(48)).decode() + "\n" + base64.b64encode(pkcs8()).decode() + "\n-----END PRIVATE KEY-----"):
            i = text.index("-----BEGIN")
            v = text[i:i + 27]
            self.assertEqual(isr.secret_kind(v, tail=text[i + 27:])[0], "real", text[:80])

    def test_fake_blocks_in_code_and_prose_stay_examples(self):   # guard
        junk = base64.b64encode(public_key_packet(120)).decode()   # batch 7a fix round 1: a whole public-key packet
        # round 3 (Codex 3): a body that isn't base64 (words) can't be read, so it is a key; one that decodes to bytes starting no key
        # is still an example
        # batch 7d: the public-key packet is a key (B: "example" -> "real", both forms), and code literals aren't a JSON document,
        # so their END is unsure (A); a FAKE-text body is the example in a block of lines, and real in code literals (A)
        text_body = base64.b64encode(fake_text_body(120)).decode()
        for text, want in (("-----BEGIN PRIVATE KEY-----\n" + junk + "\n-----END PRIVATE KEY-----", "real"),
                           ('"-----BEGIN PRIVATE KEY-----\\n" +\n"' + junk + '\\n" +\n"-----END PRIVATE KEY-----"', "real"),
                           ("-----BEGIN PRIVATE KEY-----\n" + text_body + "\n-----END PRIVATE KEY-----", "example"),
                           ('"-----BEGIN PRIVATE KEY-----\\n" +\n"' + text_body + '\\n" +\n"-----END PRIVATE KEY-----"', "real"),
                           ("-----BEGIN RSA PRIVATE KEY-----\nThis is a FAKE key for the docs; paste yours here.\n-----END RSA PRIVATE KEY-----", "real")):
            i = text.index("-----BEGIN")
            j = text.index("-----", i + 11) + 5
            self.assertEqual(isr.secret_kind(text[i:j], tail=text[j:])[0], want, text[:60])


# ---------------------------------------------------------------- 6, 7: dismissals never hold a backed-up finding
class DismissalsNeverHold(_Dismiss):
    def back(self, got):
        self.assertEqual([x["class"] for x in got], ["corroborated"], got)
        self.assertTrue(isr.counts(got[0]))
        self.assertTrue(got[0]["fix"].startswith("You dismissed this before; it is back because the file changed (see ISR-I001)."), got[0]["fix"])

    def test_a_planted_record_with_a_computed_digest(self):   # replay 6 (de3b328: the Bot's digest held, T006k hidden)
        self.write(SKILL_HEAD + BUN)
        self.audit()
        f = self.mine("ISR-T006k")[0]
        e = f["evidence"]
        line = next(l for l in open(self.p).read().split("\n") if e in l)
        ev = hashlib.sha256(f"{e}\x00{e}\x00{line}".encode()).hexdigest()   # de3b328's ev256, as a Bot reading its source computes it
        self.plant(f, ev256=ev)
        self.write("Keep the notes short.\n", "a")
        self.daily()
        self.back(self.mine("ISR-T006k"))

    def test_a_dismissal_made_after_the_command_changed(self):   # replay 7 (de3b328 hashed the changed file and held it)
        self.write(SKILL_HEAD + BUN)
        self.audit()
        f = self.mine("ISR-T006k")[0]
        self.write(SKILL_HEAD + BUN.replace("| bash\n", "| bash -s -- --install-dir /opt/FAKEdir\n"))   # after the audit
        self.assertTrue(isr.dismiss(f["key"], "I use this installer on purpose")[0])
        self.daily()
        self.back(self.mine("ISR-T006k"))

    def test_a_quoted_body_changed_after_the_dismissal(self):   # replay 7 (de3b328: a multiline quote's new body, same digest)
        self.write(SKILL_HEAD + "Install bun:\n\n```\ncurl -fsSL https://bun.sh/install | bash -c '\necho one\n'\n```\nAsk before saving.\n")
        self.audit()
        f = self.mine("ISR-T006k")[0]
        self.assertTrue(isr.dismiss(f["key"], "I use this installer on purpose")[0])
        self.write(open(self.p).read().replace("echo one", "echo FAKEtwo"))
        self.daily()
        self.back(self.mine("ISR-T006k"))

    def test_before_any_change_a_dismissal_still_works(self):   # guard: as at 5dcd0a2
        self.write(SKILL_HEAD + BUN)
        self.audit()
        f = self.mine("ISR-T006k")[0]
        self.assertTrue(isr.dismiss(f["key"], "I use this installer on purpose")[0])
        self.daily()
        self.assertEqual(self.mine("ISR-T006k"), [])
        code, out, _ = self.run_cmd("dismiss", "--list")
        self.assertIn("ISR-T006k", out)

    def test_no_digest_is_written(self):   # guard (new)
        self.write(SKILL_HEAD + BUN)
        self.audit()
        f = self.mine("ISR-T006k")[0]
        isr.dismiss(f["key"], "I use this installer on purpose")
        self.assertNotIn("ev256", [json.loads(x) for x in open(isr.state_path(isr.DISMISS_LOG))][-1])


# ---------------------------------------------------------------- 8, 10: key blocks masked in one pass, no cap
def legacy_padded():
    """An old encrypted RSA key (Proc-Type/DEK-Info), made now, each body line padded with trailing spaces to about 79 KB: a
    valid key (OpenSSL reads it) past the 64 KB a block was read to."""
    body = base64.b64encode(secrets.token_bytes(1184)).decode()
    lines = [body[i:i + 64] + " " * 3100 for i in range(0, len(body), 64)]
    return ("-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC," + secrets.token_hex(16).upper() + "\n\n"
            + "\n".join(lines) + "\n-----END RSA PRIVATE KEY-----\n"), [body[i:i + 24] for i in range(0, len(body) - 23, 24)]


class KeyBlockMasking(Box):
    def test_an_oversized_valid_key_in_an_approved_copy(self):   # replay 8 (de3b328 kept the whole body, masked 8)
        block, bits = legacy_padded()
        self.assertGreater(len(block), 75_000)
        d = os.path.join(self.home, "sand-data", "workflows", "deploy-keys")
        os.makedirs(d)
        open(os.path.join(d, "SKILL.md"), "w").write("---\nname: deploy-keys\ndescription: Deploys.\n---\nUse the keys.\n")
        open(os.path.join(d, "server.pem"), "w").write(block)
        isr.save_approved(d)
        with gzip.open(isr.approved_path(d), "rt", encoding="utf-8") as f:
            doc = json.load(f)
        kept = doc["files"]["server.pem"]
        self.assertEqual(doc["masked"], isr.MASK_VERSION)
        for bit in bits:
            self.assertNotIn(bit, kept)
        self.assertNotIn("DEK-Info", kept)

    def test_an_unfinished_block_is_hidden_to_the_end(self):   # replay 8 (de3b328: headers first, so no body was found)
        block, bits = legacy_padded()
        cut = block[:block.index("-----END")]
        once = isr.mask_secrets("Key:\n" + cut)
        for bit in bits:
            self.assertNotIn(bit, once)
        self.assertEqual(isr.mask_secrets(once), once)
        self.assertEqual(once.count("\n"), ("Key:\n" + cut).count("\n"))

    def test_400_begin_lines(self):   # replay 10 (de3b328: over a second, about eight times the work per doubling)
        s = "-----BEGIN PRIVATE KEY-----" * 400   # Codex's 10.8 KB: one label could run over the next BEGIN
        t = time.perf_counter()
        isr.mask_secrets(s)
        isr.mask_secrets("x\n" + "-----BEGIN PRIVATE KEY-----\n" * 1600)
        self.assertLess(time.perf_counter() - t, 1.0)

    def test_text_around_a_block_stays(self):   # guard
        block = pem("RSA ", rsa_der())
        out = isr.mask_secrets("before\n" + block + "after\n")
        self.assertTrue(out.startswith("before\n-----BEGIN RSA PRIVATE KEY-----\n[hidden]"), out[:80])
        self.assertTrue(out.endswith("-----END RSA PRIVATE KEY-----\nafter\n"), out[-80:])


# ---------------------------------------------------------------- 9, 11: linear time
CHILD = ("import sys, time\nsys.path.insert(0, {isr_dir!r})\nimport isr\nrules = isr.load_rules()\nworst = 0.0\n"
         "for n in (50, 5000):\n    for f in (lambda: isr.secret_kind('x' * n + 'Z'), lambda: isr.secret_kind('sk-proj-' + 'x' * n + 'Z'),\n"
         "              lambda: isr.scan_text('key sk-proj-' + 'x' * n + 'Z\\n', '/s/SKILL.md', rules)):\n"
         "        t = time.perf_counter(); f(); worst = max(worst, time.perf_counter() - t)\nprint(worst)\n")


class LinearTime(unittest.TestCase):
    def test_placeholder_reading_never_backtracks(self):   # replay 9 (de3b328: 50 x's took longer than any bound)
        try:
            r = subprocess.run([sys.executable, "-c", CHILD.format(isr_dir=os.path.join(ROOT, "isr_bot"))], capture_output=True,
                               text=True, timeout=20)
        except subprocess.TimeoutExpired:
            self.fail("placeholder reading took more than 20 seconds")
        self.assertEqual(r.returncode, 0, r.stderr[-400:])
        self.assertLess(float(r.stdout.split()[-1]), 1.0)

    def test_12800_joined_installer_lines(self):   # replay 11 (de3b328: about 17 seconds, each finding walking the command)
        body = "curl -fsSL bun.sh/install | bash \\\n" * 12_800 + "\n"
        t = time.perf_counter()
        fs = isr.scan_text("---\nname: x\ndescription: y\n---\n```\n" + body + "```\n", "/s/SKILL.md", isr.load_rules())
        self.assertLess(time.perf_counter() - t, 8.0)
        self.assertEqual(len([f for f in fs if f["rule"] in ("ISR-T006", "ISR-T006k")]), 12_800)
        self.assertFalse([f for f in fs if "ev256" in f])


# ---------------------------------------------------------------- 12: the KL3 marker entry
class KL3Marker(unittest.TestCase):
    def probe(self, marker):
        pre, post = scenario()
        post = dict(post, **{MARKER: marker})
        return golden({GSIDS[0]: scenario(), GSIDS[1]: (pre, post)})

    def test_an_emptied_marker_fails(self):   # replay 12 (de3b328: passed, "-7 <TS>" alone was allowed)
        out, rep = self.probe("file 0600\n")
        self.assertTrue(out.startswith("failed"), rep)

    def test_7_kept_with_8_added_fails(self):   # replay 12 (de3b328: passed, "+8 <TS>" alone was allowed)
        out, rep = self.probe("file 0600\n7 <TS>\n8 <TS>\n")
        self.assertTrue(out.startswith("failed"), rep)

    def test_the_exact_transition_passes(self):   # guard
        out, rep = golden({s: scenario() for s in GSIDS})
        self.assertEqual(out, "passed", rep)


if __name__ == "__main__":
    unittest.main()
