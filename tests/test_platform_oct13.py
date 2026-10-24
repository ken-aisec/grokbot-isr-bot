"""Decision, Oct 13 (item 8 dry run follow-up): Codex's and Claude's own built-ins, the platform's /tmp/hooks hook, and the platform's
masked-secret store are Platform lines (shown, not scored). Owner plugins and stray keys still count. Replays, anonymized."""
import json, os, stat, sys, unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import Box  # noqa: E402
import isr  # noqa: E402
from test_isr_bot import fake_key  # noqa: E402

KEY = "sk-ant-api03-" + fake_key(80)


def write(p, text, mode=None):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    open(p, "w").write(text)
    if mode is not None:
        os.chmod(p, mode)


class PlatformSecretStore(Box):
    def setUp(self):
        super().setUp()
        self.skills(1); self.scanners()
        self.store = os.path.join(self.home, "sand-data", "box-secrets.json")

    def test_store_is_a_platform_note_without_the_value(self):
        write(self.store, json.dumps({"CLAUDE_CODE_OAUTH_TOKEN": KEY}), 0o600)
        self.audit()
        fs = [f for f in self.snap()["findings"] if self.store in f["where"]]
        self.assertEqual([f["rule"] for f in fs], ["ISR-I009"], fs)
        self.assertEqual(fs[0]["label"], isr.PLATFORM)
        self.assertIn("mode 0600", fs[0]["evidence"])
        self.assertFalse(isr.counts(fs[0]))
        self.assertNotIn(KEY[:20], json.dumps(self.snap()))

    def test_a_key_in_another_file_beside_it_still_counts(self):
        write(self.store, "{}", 0o600)
        other = os.path.join(self.home, "sand-data", "my-notes.txt")
        write(other, "token " + KEY + "\n")
        self.audit()
        s1 = [f for f in self.snap()["findings"] if f["rule"] == "ISR-S001" and other in f["where"]]
        self.assertTrue(s1 and all(isr.counts(f) for f in s1), s1)

    def test_a_file_with_that_name_elsewhere_is_not_the_store(self):
        stray = os.path.join(self.ws, "copy", "box-secrets.json")
        write(stray, json.dumps({"k": KEY}))
        self.audit()
        self.assertTrue([f for f in self.snap()["findings"] if f["rule"] == "ISR-S001" and stray in f["where"]])


class OtherPlatformBuiltins(Box):
    def test_codex_system_and_claude_synced_are_platform_owner_plugin_is_not(self):
        for p in ("/home/box/.codex/skills/.system/imagegen", "/home/box/.claude/plugins/synced/abc_def/skills/s"):
            self.assertTrue(isr.platform_file({"where": p}), p)
        self.assertFalse(isr.platform_file({"where": "/home/box/sand-data/plugins/cache/cursor-public/stripe/e48/skills/s"}))


class PlatformHook(Box):
    def test_platform_tmp_hook_is_a_platform_line_and_a_foreign_hook_stays_high(self):
        self.skills(1); self.scanners()
        write(os.path.join(self.home, ".cursor", "hooks.json"), json.dumps(
            {"hooks": {"beforeMCPExecution": [{"command": "python3 /tmp/hooks/expand_mcp_file_args.py"}]}}))
        write(os.path.join(self.ws, ".cursor", "hooks.json"), json.dumps(
            {"hooks": {"beforeShellExecution": [{"command": "bash /tmp/x/run.sh"}]}}))
        self.audit()
        c5 = [f for f in self.snap()["findings"] if f["rule"] == "ISR-C005"]
        plat = [f for f in c5 if "expand_mcp_file_args" in f["evidence"]]
        other = [f for f in c5 if "/tmp/x/run.sh" in f["evidence"]]
        self.assertTrue(plat and all(f["label"] == isr.PLATFORM and not isr.counts(f) for f in plat), c5)
        self.assertTrue(other and other[0]["severity"] == "high" and other[0]["label"] == isr.CONFIRMED, c5)


if __name__ == "__main__":
    unittest.main()
