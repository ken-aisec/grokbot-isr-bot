"""v0.8.2 U1b (items 5, 4): ISR-S006, a tool's output spill file that holds a whole environment dump, and gitleaks' rule for
Claude sign-in tokens (sk-ant-oat...).

The v0.8.1 box: Cursor's bash tool wrote three agent-tools spill files, each a dump of the whole shell environment (set -x and
a shell-state trace), holding the box's own gh token on 16 lines and its CLAUDE_CODE_OAUTH_TOKEN on 14. Tool output is silent
(the owner's decision, 0.8.1) and two of the files were over ISR-S001's 300,000-byte read limit, so the only line about it was a
borrowed verdict U1a removes. S006 reaches exactly those files (a .txt directly in an agent-tools or terminals folder, read up
to 20 MB) and must not fire on ordinary logs. Every token is built when the test runs; gh is never run (Box patches
own_gh_token, create=True, so on the base the patch is inert).

Tests marked "replay" fail on ca18f8a (U1a) and on e9184df (v0.8.1) at their assertion; "control" ones pass there too."""
import hashlib, json, os, re, shutil, subprocess, sys, tempfile, unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import Box  # noqa: E402
from test_isr_bot import REAL_GITLEAKS, fake_key  # noqa: E402
import isr  # noqa: E402

SHELL = [("PATH", "/usr/local/bin:/usr/bin:/bin"), ("HOME", "/home/box"), ("SHELL", "/bin/bash"), ("USER", "box"), ("LOGNAME", "box"),
         ("PWD", "/workspace"), ("HOSTNAME", "box-1"), ("LANG", "C.UTF-8"), ("TERM", "xterm-256color"), ("SHLVL", "2")]
OTHER = [("EDITOR", "vi"), ("PAGER", "less"), ("TZ", "UTC"), ("COLUMNS", "120"), ("LINES", "40"), ("NODE_ENV", "production"),
         ("GOPATH", "/home/box/go"), ("XDG_CONFIG_HOME", "/home/box/.config"), ("LC_ALL", "C.UTF-8"), ("OLDPWD", "/home/box"),
         ("GIT_PAGER", "cat"), ("NO_COLOR", "1")]


def pat(seed):
    """A fine-grained GitHub token's shape, made now (never committed)."""
    return "github_pat_" + fake_key(82, seed=seed)


def oat(seed):
    """A Claude sign-in token's shape (CLAUDE_CODE_OAUTH_TOKEN), made now."""
    return "sk-ant-oat01-" + fake_key(95, seed=seed)


def dump(secrets, style='declare -x {}="{}"'):
    """One environment dump: the shell's own names, 12 more and `secrets` ((name, value) pairs), one line each."""
    return "".join(style.format(k, v) + "\n" for k, v in SHELL + OTHER + list(secrets))


def fp(value):
    return hashlib.sha256(value.encode()).hexdigest()[:12]


class _Spill(Box):
    def put(self, p, text):
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(text)
        return p

    def own(self, value):
        p = mock.patch.object(isr, "own_gh_token", return_value=value, create=True); p.start(); self.addCleanup(p.stop)

    def run_audit(self):
        self.skills(1); self.scanners()
        self.audit()
        return self.snap()["findings"]

    def s006(self, fs):
        return [f for f in fs if f["rule"] == "ISR-S006"]


class SpillDump(_Spill):
    def v081_box(self, gh, ot):
        """The three spill files of the v0.8.1 box: GH_TOKEN on 6, 8 and 2 lines, CLAUDE_CODE_OAUTH_TOKEN on 5, 7 and 2; the middle
        file over ISR-S001's 300,000 bytes."""
        d = os.path.join(self.home, ".cursor", "projects", "p", "agent-tools")
        files = []
        for name, blocks, xtrace, pad in (("a1.txt", 5, 1, 0), ("b2.txt", 7, 1, 8000), ("c3.txt", 2, 0, 0)):
            text = "".join(f"$ step {i}\n" + dump([("GH_TOKEN", gh), ("CLAUDE_CODE_OAUTH_TOKEN", ot)]) for i in range(blocks))
            text += "".join(f"+ export GH_TOKEN={gh}\n" for _ in range(xtrace))
            text += "".join(f"output line {i}: an ordinary long tool result, nothing in it\n" for i in range(pad))
            files.append(self.put(os.path.join(d, name), text))
        self.assertGreater(os.path.getsize(files[1]), 300_000)
        return d, files

    def test_the_v081_spill_files_make_one_s006(self):   # replay (item 5)
        gh, ot = pat(31), oat(32)
        self.own(gh)
        d, files = self.v081_box(gh, ot)
        fs = self.run_audit()
        got = self.s006(fs)
        self.assertEqual(len(got), 1, [(f["rule"], f["where"]) for f in fs if f["rule"].startswith("ISR-S")])   # v0.8.1: none
        f = got[0]
        self.assertEqual(f["where"], d)
        self.assertEqual(f["title"], "Tool output holds a whole environment dump")
        self.assertEqual(f.get("severity_was") or f["severity"], "high")          # decision D3
        self.assertEqual(isr.label_of(f), isr.CONFIRMED)
        self.assertTrue(isr.counts(f))
        for part in ("3 files", "2 secrets", "30 copies", "GH_TOKEN - this computer's own gh token", "CLAUDE_CODE_OAUTH_TOKEN"):
            self.assertIn(part, f["evidence"])
        self.assertEqual(f["affected_files"], sorted(files))
        self.assertEqual(f.get("own_token"), "gh")
        self.assertIn("Delete these files", f["fix"])
        self.assertIn("github.com/settings/tokens", isr.plain(f)["how"])
        self.assertIn("rotate each named secret", isr.plain(f)["how"])
        # the echo S001/S002 for the same files stay silent: the owner sees one line, not three
        self.assertEqual([x["rule"] for x in fs if x["where"].startswith(d) and x["rule"] != "ISR-S006"], [])

    def test_no_secret_value_or_fingerprint_is_stored(self):   # replay (decision D1: names and counts only)
        gh, ot = pat(31), oat(32)
        self.own(gh)
        self.v081_box(gh, ot)
        self.assertEqual(len(self.s006(self.run_audit())), 1)                    # v0.8.1: no S006
        with open(isr.state_path("last_findings.json")) as f:
            text = f.read()
        for v in (gh, ot, fp(gh), fp(ot)):
            self.assertNotIn(v, text)

    def test_a_terminals_spill_file_is_reached(self):   # replay (item 5: Cursor's terminals folder)
        d = os.path.join(self.home, ".cursor", "projects", "p", "terminals")
        self.put(os.path.join(d, "9.txt"), "$ env\n" + dump([("GH_TOKEN", pat(33))], style="{}={}"))
        got = self.s006(self.run_audit())
        self.assertEqual([(f["where"], f["severity"]) for f in got], [(d, "high")])
        self.assertIn("1 file, 1 secret (GH_TOKEN), 1 copy", got[0]["evidence"])
        self.assertNotIn("own gh", got[0]["evidence"])                           # the box's own token is another one (Box: none)

    def test_the_workspace_agent_tools_folder_is_reached(self):   # replay (item 5: /workspace/agent-tools)
        d = os.path.join(self.ws, "agent-tools")
        self.put(os.path.join(d, "out.txt"), dump([("OPENAI_API_KEY", "sk-proj-" + fake_key(48, seed=34))], style="export {}={}"))
        got = self.s006(self.run_audit())
        self.assertEqual([f["where"] for f in got], [d])
        self.assertIn("(OPENAI_API_KEY)", got[0]["evidence"])

    def test_a_secret_named_variable_counts_without_a_key_shape(self):   # replay (item 5: the name rule)
        d = os.path.join(self.home, ".cursor", "projects", "p", "agent-tools")
        self.put(os.path.join(d, "a.txt"), dump([("DB_PASSWORD", fake_key(24, seed=35))]))
        got = self.s006(self.run_audit())
        self.assertEqual(len(got), 1)
        self.assertIn("1 secret (DB_PASSWORD)", got[0]["evidence"])

    # -- controls: no S006
    def test_a_build_log_with_a_few_assignments_is_not_a_dump(self):   # control
        d = os.path.join(self.home, ".cursor", "projects", "p", "terminals")
        log = ("$ make build\n" + "".join(f"[{i}/40] compiling src/mod{i}.c\n" for i in range(40))
               + "CC=gcc\nCFLAGS=-O2\nPREFIX=/usr/local\nVERSION=1.4.2\n" + f"GH_TOKEN={pat(36)}\n" + "build ok\n")
        self.put(os.path.join(d, "build.txt"), log)
        self.assertEqual(self.s006(self.run_audit()), [])

    def test_a_short_env_listing_of_shell_names_is_not_a_dump(self):   # control
        d = os.path.join(self.home, ".cursor", "projects", "p", "terminals")
        self.put(os.path.join(d, "env.txt"), "".join(f"{k}={v}\n" for k, v in SHELL) + f"GH_TOKEN={pat(37)}\n")
        self.assertEqual(self.s006(self.run_audit()), [])

    def test_a_config_with_no_shell_names_is_not_a_dump(self):   # control
        d = os.path.join(self.home, ".cursor", "projects", "p", "agent-tools")
        conf = "".join(f"APP_SETTING_{i}=value{i}\n" for i in range(29)) + f"APP_TOKEN={pat(38)}\n"
        self.put(os.path.join(d, "config.txt"), conf)
        self.assertEqual(self.s006(self.run_audit()), [])

    def test_a_dump_whose_secrets_are_placeholders_or_references_is_not_reported(self):   # control (item 4: xxxx never counts)
        d = os.path.join(self.home, ".cursor", "projects", "p", "agent-tools")
        fake = [("GH_TOKEN", "$GH_TOKEN_FROM_VAULT"), ("CLAUDE_CODE_OAUTH_TOKEN", "sk-ant-oat01-" + "x" * 95),
                ("API_KEY", "<your-api-key-goes-here>"), ("MY_SECRET", "${SECRET_FROM_VAULT}"),
                ("GOOGLE_APPLICATION_CREDENTIALS", "/home/box/.config/gcloud/app.json"), ("NPM_TOKEN", "short")]
        self.put(os.path.join(d, "a.txt"), dump(fake))
        self.assertEqual(self.s006(self.run_audit()), [])

    def test_a_dump_outside_a_spill_place_is_not_s006(self):   # control (S001 still reports the owner's file, as before)
        p = self.put(os.path.join(self.ws, "projects", "app", "notes.txt"), dump([("GH_TOKEN", pat(39))]))
        fs = self.run_audit()
        self.assertEqual(self.s006(fs), [])
        self.assertTrue([f for f in fs if f["rule"] == "ISR-S001" and f["where"].startswith(p + ":")])

    def test_a_printenv_in_isr_bots_own_dev_tree_is_not_the_owners(self):   # control (isr_self stays silent)
        d = os.path.join(self.ws, "isr-bot-dev", "tests", "fixtures", "terminals")
        self.put(os.path.join(d, "env.txt"), dump([("GH_TOKEN", pat(40))], style="{}={}"))
        fs = self.run_audit()
        self.assertEqual(self.s006(fs), [])
        self.assertEqual([f["rule"] for f in fs if f["where"].startswith(d)], [])


class AnthropicOauth(_Spill):
    def oauth_rule(self):
        """The [[rules]] block for Claude sign-in tokens in ISR Bot's gitleaks config, read as gitleaks reads it, or None."""
        head = isr.GITLEAKS_CONFIG.split("[[allowlists]]")[0]
        for block in head.split("[[rules]]")[1:]:
            if re.search(r'^id = "anthropic-oauth-token"$', block, re.M):
                return {"regex": re.compile(re.search(r"^regex = '''(.*?)'''$", block, re.M).group(1)),
                        "entropy": float(re.search(r"^entropy = ([\d.]+)$", block, re.M).group(1)),
                        "keywords": re.findall(r'"([^"]+)"', re.search(r"^keywords = \[(.*)\]$", block, re.M).group(1))}
        return None

    def test_gitleaks_has_a_rule_for_claude_sign_in_tokens(self):   # replay (item 4)
        r = self.oauth_rule()
        self.assertIsNotNone(r)                                                     # v0.8.1: gitleaks' defaults only
        tok = oat(41)
        m = r["regex"].search(f"CLAUDE_CODE_OAUTH_TOKEN={tok}\n")
        self.assertEqual(m.group(1), tok)
        self.assertGreaterEqual(isr.shannon_entropy(m.group(1)), r["entropy"])
        self.assertEqual(r["keywords"], ["sk-ant-oat"])
        # a placeholder matches the shape, but gitleaks' entropy floor keeps it out (no name-based skip, batch 6)
        ph = r["regex"].search("CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat01-" + "x" * 95).group(1)
        self.assertLess(isr.shannon_entropy(ph), r["entropy"])
        self.assertIsNone(r["regex"].search("ANTHROPIC_API_KEY=sk-ant-api03-" + fake_key(95, seed=42)))   # gitleaks' own rule's

    @unittest.skipUnless(os.access(REAL_GITLEAKS, os.X_OK), "gitleaks is not installed")
    def test_with_the_real_gitleaks(self):   # replay (item 4)
        src = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, src, True)
        for n, t in (("real.txt", f"CLAUDE_CODE_OAUTH_TOKEN={oat(43)}\n"), ("placeholder.txt", "CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat01-" + "x" * 95 + "\n")):
            with open(os.path.join(src, n), "w") as f:
                f.write(t)
        out = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, out, True)
        cfg, rep = os.path.join(out, "gitleaks.toml"), os.path.join(out, "report.json")
        with open(cfg, "w") as f:
            f.write(isr.GITLEAKS_CONFIG)
        subprocess.run([REAL_GITLEAKS, "detect", "--source", src, "--no-git", "--redact", "--config", cfg, "--report-format", "json",
                        "--report-path", rep, "--exit-code", "0"], capture_output=True, timeout=120, check=True)
        with open(rep) as f:
            hits = sorted({(os.path.basename(h["File"]), h["RuleID"]) for h in json.load(f) if h["RuleID"] == "anthropic-oauth-token"})
        self.assertEqual(hits, [("real.txt", "anthropic-oauth-token")])

    def test_a_spill_dump_names_a_claude_sign_in_token(self):   # replay (items 4, 5)
        d = os.path.join(self.home, ".cursor", "projects", "p", "agent-tools")
        self.put(os.path.join(d, "a.txt"), dump([("CLAUDE_CODE_OAUTH_TOKEN", oat(44))]))
        got = self.s006(self.run_audit())
        self.assertEqual(len(got), 1)                                               # v0.8.1: tool output, silent
        self.assertIn("1 secret (CLAUDE_CODE_OAUTH_TOKEN)", got[0]["evidence"])

    def test_a_token_in_isr_bots_own_tests_is_not_the_owners(self):   # control
        d = os.path.join(self.ws, "isr-bot-dev", "tests", "fixtures")
        self.put(os.path.join(d, "keys.txt"), f"CLAUDE_CODE_OAUTH_TOKEN={oat(45)}\n")
        self.assertEqual([f["rule"] for f in self.run_audit() if f["where"].startswith(d)], [])


if __name__ == "__main__":
    unittest.main()
