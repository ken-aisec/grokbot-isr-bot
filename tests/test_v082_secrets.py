"""v0.8.2 U1a (items 3, 1, 2): a key finding's verdict and example come from its own files; distinct secrets are counted
("N tokens, M copies"); a found secret that is this computer's own gh token says so.

The v0.8.1 CRITICAL "Github (8 live)" on ~/.cursor/projects was one token in 16 lines of three agent-tools spill files: the
~/.cursor/projects group (its only hit a 64-hex line in terminals/) took those files' live answers by folder prefix. The
fakes here are column-accurate stand-ins for gitleaks (Match redacted, gitleaks' Entropy, so ISR Bot finds each secret again in
the file's bytes) and TruffleHog (Raw, as it reports). Every token is built when the test runs; gh is never run (Box patches
own_gh_token; these tests patch it with create=True, so on the base the patch is inert).

Tests marked "replay" fail on e9184df (v0.8.1) at their assertion; "control" and "guard" pass there too."""
import hashlib, json, os, sys, unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import Box, TH_DONE  # noqa: E402
from test_isr_bot import fake_key  # noqa: E402
import isr  # noqa: E402

GITLEAKS = r"""#!/usr/bin/env python3
import json, sys
a = sys.argv[1:]
if a and a[0] == "version":
    print("8.30.1"); sys.exit(0)
src = a[a.index("--source") + 1].rstrip("/") + "/"
open(a[a.index("--report-path") + 1], "w").write(json.dumps([h for h in json.load(open(REPORT)) if h["File"].startswith(src)]))
"""
TRUFFLEHOG = r"""#!/usr/bin/env python3
import json, sys
for d in json.load(open(ANSWERS)):
    print(json.dumps(d))
sys.stderr.write(DONE + "\n")
"""


def pat(seed):
    """A fine-grained GitHub token's shape, made now (never committed)."""
    return "github_pat_" + fake_key(82, seed=seed)


def leaks(path, secret, rule):
    """gitleaks' hits for every line of `path` holding `secret`, with its columns (in bytes: from 1 on the first line, from 2 on
    the lines after), its redacted Match and its Entropy, as gitleaks reports them."""
    out = []
    with open(path, "rb") as f:
        data = f.read()
    for n, line in enumerate(data.split(b"\n"), 1):
        i = line.find(secret.encode())
        if i >= 0:
            d = 1 if n == 1 else 2
            out.append({"File": path, "StartLine": n, "EndLine": n, "StartColumn": i + d, "EndColumn": i + len(secret) + d - 1,
                        "RuleID": rule, "Match": "REDACTED", "Secret": "REDACTED", "Entropy": isr.shannon_entropy(secret)})
    return out


def answer(path, line, detector, verified, raw):
    return {"SourceMetadata": {"Data": {"Filesystem": {"file": path, "line": line}}}, "DetectorName": detector, "Verified": verified,
            "Raw": raw}


class _Keys(Box):
    def put(self, p, text):
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(text)
        return p

    def run_scan(self, hits, answers):
        """One audit with gitleaks reporting `hits` and TruffleHog giving `answers`; the owner's findings."""
        report, said = os.path.join(self.tmp, "leaks.json"), os.path.join(self.tmp, "answers.json")
        for p, data in ((report, hits), (said, answers)):
            with open(p, "w") as f:
                json.dump(data, f)
        self.skills(1)
        self.scanners(gitleaks=GITLEAKS.replace("REPORT", repr(report)),
                      trufflehog=TRUFFLEHOG.replace("ANSWERS", repr(said)).replace("DONE", repr(TH_DONE)))
        self.audit()
        return self.snap()["findings"]

    def s002(self, fs, where):
        got = [f for f in fs if f["rule"] == "ISR-S002" and f["where"] == where]
        self.assertEqual(len(got), 1, [(f["rule"], f["where"]) for f in fs if f["rule"].startswith("ISR-S")])
        return got[0]

    def logs(self, tok):
        """The DistinctSecrets box: one token on 16 lines of 4 of the owner's log files (a gitleaks group: 4 files in one folder),
        TruffleHog answering 8 of those lines live."""
        d = os.path.join(self.ws, "projects", "app", "logs")
        files = []
        for name, n in (("a.txt", 6), ("b.txt", 5), ("c.txt", 3), ("d.txt", 2)):
            files.append(self.put(os.path.join(d, name), "".join(f"step {i}: ok\nGH_TOKEN={tok}\n" for i in range(n))))
        hits = [h for p in files for h in leaks(p, tok, "github-fine-grained-pat")]
        self.assertEqual(len(hits), 16)
        return d, hits, [answer(h["File"], h["StartLine"], "Github", True, tok) for h in hits[:8]]


class SameFindingEvidence(_Keys):
    def tree(self):
        p = os.path.join(self.home, ".cursor", "projects", "p")
        tok, hexkey = "ghp_" + fake_key(36, seed=3), fake_key(64, alphabet="0123456789abcdef", seed=4)
        a = self.put(os.path.join(p, "agent-tools", "a.txt"), f"GH_TOKEN={tok}\n")               # tool output (silent, v0.8.1)
        t = self.put(os.path.join(p, "terminals", "7.txt"), f"API_TOKEN_value={hexkey}\n")       # the owner's
        hits = leaks(a, tok, "github-pat") + leaks(t, hexkey, "generic-api-key")
        return os.path.join(self.home, ".cursor", "projects"), a, t, tok, hexkey, hits

    def test_folder_group_never_takes_another_groups_verdict(self):   # replay (item 3)
        top, a, t, tok, _, hits = self.tree()
        g = self.s002(self.run_scan(hits, [answer(a, 1, "Github", True, tok)]), top)
        self.assertNotEqual(g["title"], isr.KEY_LIVE)          # v0.8.1: KEY_LIVE from agent-tools/a.txt's answer
        self.assertNotIn("Github", g["evidence"])             # v0.8.1: "Github (1 live)"
        self.assertIn("terminals/7.txt:1", g["evidence"])     # its own hit is what it shows

    def test_a_groups_own_live_key_is_still_live(self):   # control
        top, a, t, _, hexkey, hits = self.tree()
        g = self.s002(self.run_scan(hits, [answer(t, 1, "Generic", True, hexkey)]), top)
        self.assertEqual((g["title"], g.get("severity_was") or g["severity"], isr.label_of(g)), (isr.KEY_LIVE, "critical", isr.CONFIRMED))
        self.assertTrue(isr.counts(g))

    def test_a_live_verdict_names_where_its_answers_are(self):   # replay (item 3: the example line and the verdict agree)
        top, a, t, _, hexkey, hits = self.tree()
        g = self.s002(self.run_scan(hits, [answer(t, 1, "Generic", True, hexkey)]), top)
        self.assertIn("live, at p/terminals/7.txt:1", g["evidence"])   # v0.8.1: "Generic (1 live)", no place

    def test_the_fix_list_links_only_the_findings_own_live_keys(self):   # replay (item 3: live_key_links)
        top, a, t, tok, _, hits = self.tree()
        fs = self.run_scan(hits, [answer(a, 1, "Github", True, tok)])
        key_files = isr.load_json(isr.state_path("key_status.json"), {})["files"]
        self.assertIn(a, key_files)                                                      # TruffleHog's answer is there
        try:
            links = isr.live_key_links(key_files, fs)
        except TypeError:                                                                # v0.8.1 took the answers alone
            links = isr.live_key_links(key_files)
        self.assertEqual(links, [])                                                      # v0.8.1: [("Github", ...)] from agent-tools/a.txt
        row = isr.item_row(self.s002(fs, top), key_files)
        self.assertNotIn("live", row["reason"])                                          # v0.8.1: "Github: 1 live"


class DistinctSecrets(_Keys):
    def test_one_token_in_sixteen_lines_is_one_token_sixteen_copies(self):   # replay (item 1)
        tok = pat(11)
        d, hits, live = self.logs(tok)
        g = self.s002(self.run_scan(hits, live), d)
        self.assertIn("1 token, 16 copies", g["evidence"])    # v0.8.1: "Github (8 live)"
        self.assertEqual((g["title"], g.get("severity_was") or g["severity"]), (isr.KEY_LIVE, "critical"))   # unchanged
        self.assertTrue(g["evidence"].startswith("Github: "))
        self.assertIn("a.txt:2", g["evidence"])

    def test_two_tokens_one_copy_each(self):   # replay (item 1)
        p = os.path.join(self.home, ".cursor", "projects", "q", "terminals")
        t1, t2 = pat(21), pat(22)
        a = self.put(os.path.join(p, "a.txt"), f"x\nGH_TOKEN={t1}\n")
        b = self.put(os.path.join(p, "b.txt"), f"GH_TOKEN={t2}\n")
        hits = leaks(a, t1, "github-fine-grained-pat") + leaks(b, t2, "github-fine-grained-pat")
        g = self.s002(self.run_scan(hits, [answer(a, 2, "Github", True, t1), answer(b, 1, "Github", True, t2)]),
                      os.path.join(self.home, ".cursor", "projects"))
        self.assertIn("2 tokens, 2 copies", g["evidence"])    # v0.8.1: "Github (2 live)"

    def test_fingerprints_are_never_stored(self):   # guard (decision D1: counts and the own-token mark only)
        tok = pat(11)
        d, hits, live = self.logs(tok)
        self.run_scan(hits, live)
        fp = hashlib.sha256(tok.encode()).hexdigest()[:12]
        for name in ("last_findings.json", "key_status.json"):
            with open(isr.state_path(name)) as f:
                text = f.read()
            self.assertNotIn(fp, text, name)
            self.assertNotIn(tok, text, name)
        g = self.s002(self.snap()["findings"], d)
        self.assertFalse([m for m in g["member_hits"] if "fp" in m])
        self.assertEqual(len(g["member_hits"]), 16)


class OwnGhToken(_Keys):
    def own(self, value):
        p = mock.patch.object(isr, "own_gh_token", return_value=value, create=True); p.start(); self.addCleanup(p.stop)

    def test_the_boxs_own_gh_token_is_named(self):   # replay (item 2)
        tok = pat(11)
        self.own(tok)
        d, hits, live = self.logs(tok)
        g = self.s002(self.run_scan(hits, live), d)
        self.assertIn("own gh sign-in", g["evidence"])        # v0.8.1: "Github (8 live)" and nothing else
        self.assertIn("github.com/settings/tokens", isr.plain(g)["how"])
        self.assertIn("sign gh in", g["fix"])
        self.assertEqual((g["title"], g.get("severity_was") or g["severity"]), (isr.KEY_LIVE, "critical"))   # unchanged
        self.assertEqual(g.get("own_token"), "gh")

    def test_a_key_file_holding_the_own_token_says_so_without_trufflehog(self):   # replay (item 2: ISR-S001)
        tok = pat(12)
        self.own(tok)
        p = self.put(os.path.join(self.ws, "projects", "app", "notes.txt"), f"notes\nGH_TOKEN={tok}\n")
        self.skills(1); self.scanners(trufflehog=None)
        self.audit()
        s1 = [f for f in self.snap()["findings"] if f["rule"] == "ISR-S001" and f["where"].startswith(p + ":")]
        self.assertEqual(len(s1), 1, s1)
        self.assertIn("own gh sign-in", s1[0]["evidence"])
        self.assertIn("github.com/settings/tokens", isr.plain(s1[0])["how"])

    def test_another_token_is_not_the_own_one(self):   # control
        self.own(pat(99))
        tok = pat(11)
        d, hits, live = self.logs(tok)
        g = self.s002(self.run_scan(hits, live), d)
        self.assertNotIn("own gh sign-in", g["evidence"])
        self.assertNotIn("own_token", g)
        self.assertEqual(isr.plain(g)["title"], "Keys that still work are sitting in files")


class U1Fix1(_Keys):
    """Codex's review of U1a+U1b (edaca62). Tests marked "replay" fail on edaca62 at their assertion; "control" ones pass there too."""

    def own(self, value):
        p = mock.patch.object(isr, "own_gh_token", return_value=value, create=True); p.start(); self.addCleanup(p.stop)

    def test_a_group_with_the_own_token_and_another_live_key_keeps_both_fixes(self):   # replay (finding 1)
        tok, slack = pat(11), "xoxb-" + fake_key(12, alphabet="0123456789", seed=51) + "-" + fake_key(24, seed=52)
        self.own(tok)
        d, hits, live = self.logs(tok)
        e = self.put(os.path.join(d, "e.txt"), f"SLACK_BOT_TOKEN={slack}\n")
        g = self.s002(self.run_scan(hits + leaks(e, slack, "slack-bot-token"), live + [answer(e, 1, "Slack", True, slack)]), d)
        self.assertEqual((g["title"], g.get("own_token")), (isr.KEY_LIVE, "gh"))
        self.assertIn("Turn the key off at its provider", g["fix"])          # edaca62: the own-token fix alone
        self.assertIn("sign gh in", g["fix"])
        item = isr.needs_you([g])[0]
        self.assertIn("Slack", item["how"])                                   # edaca62: "This is the GitHub token gh ..." only
        self.assertIn("https://api.slack.com/apps", [u for _, u in item.get("links", [])])
        self.assertIn("sign gh in", item["how"])

    def test_answers_without_a_fingerprint_are_never_merged(self):   # replay (finding 2)
        tok = pat(11)
        d, hits, _ = self.logs(tok)
        g = self.s002(self.run_scan(hits, [answer(h["File"], h["StartLine"], "Github", True, None) for h in hits[:2]]), d)
        self.assertIn("2 tokens, 2 copies", g["evidence"])                    # edaca62: "1 token, 16 copies" (borrowed by place)

    def test_the_fix_plan_row_says_tokens_and_copies(self):   # replay (finding 4)
        tok = pat(11)
        self.own(tok)
        d, hits, live = self.logs(tok)
        g = self.s002(self.run_scan(hits, live), d)
        row = isr.item_row(g, isr.load_json(isr.state_path("key_status.json"), {})["files"])
        self.assertIn("1 token, 16 copies", row["reason"])                    # edaca62: "Github: 8 live"
        self.assertIn("a.txt:2", row["reason"])
        self.assertIn("own gh sign-in", row["reason"])
        self.assertNotIn("8 live", row["reason"])

    def test_an_older_records_fix_plan_row_still_counts_answers(self):   # control (finding 4: the legacy fallback)
        tok = pat(11)
        d, hits, live = self.logs(tok)
        g = self.s002(self.run_scan(hits, live), d)
        old = dict(g, evidence="16 hit(s): github-fine-grained-pat at a.txt:2, a.txt:4, a.txt:6 and 13 more")
        self.assertEqual(isr.item_row(old, isr.load_json(isr.state_path("key_status.json"), {})["files"])["reason"], "Github: 8 live")


if __name__ == "__main__":
    unittest.main()
