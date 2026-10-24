"""Batch 6 PR3, Codex round 3 (10 highs, the final round): highs 8-10 are fixed here; highs 1-7 (webhook destinations) are not,
and are logged in docs/KNOWN-LIMITS.md under "Must-fix before release".

B8 (H8): a pinned outer package never vouches for what it runs: a launcher nested after the package options (npx, npm exec,
pnpm dlx, bunx, uvx, env) is read like the outer one; yarn, pipx, a shell, npm or pnpm without a launch subcommand, or a
launcher word among a command's arguments, is "couldn't read the launch"; a chain of nested launchers is read 16 deep.
H9, H10: the malformed-JSON key scan and the code tokenizer never rescan a failed string: the same keys and tokens, in one pass.

Tests marked "replay" fail on 2e84db6 on their assertion (measured with 2e84db6's engine sources, this file in place);
"guard" ones keep what must not change. Every URL is an example; every webhook is FAKE."""
import json, os, subprocess, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import ROOT
import isr  # noqa: E402
from test_batch4_codex_review3 import HOOK


# ---------------------------------------------------------------- H8: B8
def servers(*cmds):
    return json.dumps({"mcpServers": {f"s{i}": {"command": c[0], "args": list(c[1:])} for i, c in enumerate(cmds)}}, indent=2)


def evidence(text):
    return [e for _, e in isr.mcp_unpinned(text)]


class NestedLaunchers(unittest.TestCase):
    def test_codex_nested_npx_is_unpinned(self):   # replay (2e84db6: no ISR-M001)
        self.assertEqual(evidence(servers(("npm", "exec", "--package=npm@11.21.0", "--", "npx", "-y", "mutable"))),
                         ["npx mutable (no version)"])

    def test_other_nested_launches_are_unpinned(self):   # replay (2e84db6: no ISR-M001 for each)
        for cmd, want in ((("npx", "-y", "npm@11.21.0", "exec", "mutable"), ["npm exec mutable (no version)"]),
                          (("npx", "--package", "pnpm@9.1.0", "pnpm", "dlx", "mutable"), ["pnpm dlx mutable (no version)"]),
                          (("bunx", "--package", "tool@1.0.0", "env", "A=1", "uvx", "mutable"), ["uvx mutable (no version)"]),
                          (("uvx", "--from", "tool==1.0.0", "tool", "--", "npx", "mutable"), None),
                          (("npm", "exec", "--package=x@1.0.0", "--", "sh", "-c", "npx mutable"), None),
                          (("npm", "exec", "--package=x@1.0.0", "--", "yarn", "dlx", "mutable"), None),
                          (("uvx", "--from", "tool==1.0.0", "pipx", "run", "mutable"), None),
                          (("npx", "-y", "pnpm@9.1.0", "install"), None)):
            got = evidence(servers(cmd))
            if want is None:
                self.assertEqual(len(got), 1, (cmd, got))
                self.assertIn("couldn't read the launch", got[0], cmd)
            else:
                self.assertEqual(got, want, cmd)

    def test_pinned_nested_and_plain_commands_stay_clear(self):   # guard
        for cmd in (("npm", "exec", "--package=npm@11.21.0", "--", "npx", "-y", "safe@1.2.3"),
                    ("npx", "--package", "a@1.0.0", "--package", "b@2.0.0", "b"), ("npm", "exec", "safe@1.2.3", "--", "--port", "3000"),
                    ("uvx", "--from", "pkg==1.2.3", "pkg-server", "--flag"), ("npm", "run", "start"), ("node", "server.js")):
            self.assertEqual(evidence(servers(cmd)), [], cmd)

    def test_deep_nesting_is_bounded(self):   # replay (2e84db6: no ISR-M001; a chain is read to a limit, then "couldn't read the launch")
        got = evidence(servers(("npx",) + ("-y", "npx@10.0.0") * 5000 + ("mutable",)))
        self.assertEqual(len(got), 1, got)
        self.assertIn("couldn't read the launch", got[0])


# ---------------------------------------------------------------- H9, H10: linear scans
TIMED = ("import sys, time; sys.path.insert(0, %r); import isr\n"
         "def run(n):\n%s\n"
         "    s = time.monotonic(); r = go(t); return time.monotonic() - s, r\n"
         "small, _ = run(%d); large, r = run(%d)\nprint(small); print(large); print(repr(r))")


def timed(body, small, large):
    """(seconds for the small input, seconds for the large one, repr of the large result), or None after 30 seconds."""
    try:
        p = subprocess.run([sys.executable, "-c", TIMED % (os.path.join(ROOT, "isr_bot"), body, small, large)],
                           capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        return None
    assert p.returncode == 0, p.stderr[-2000:]
    a, b, r = p.stdout.strip().splitlines()[-3:]
    return float(a), float(b), r


class LinearScans(unittest.TestCase):
    def assertLinear(self, got, what):
        self.assertIsNotNone(got, what + ": over 30 seconds")
        small, large, _ = got
        self.assertLess(large, 5.0, what)
        self.assertLess(large, 40 * max(small, 0.02), what)   # 10x the input: quadratic would be 100x

    def test_h9_malformed_json_escaped_quotes(self):   # replay (2e84db6: over 30 s for 980 KB)
        body = ("    t = '{\"command\":\"npx\",\"x\":\"' + '\\\\\"' * n + '\"'\n"
                "    go = isr.mcp_unpinned")
        got = timed(body, 49000, 490000)   # ~98 KB and ~980 KB
        self.assertLinear(got, "malformed JSON")
        self.assertIn("read the launch", got[2])   # the file still isn't read as pinned

    def test_h10_unterminated_string_in_another_block(self):   # replay (2e84db6: over 30 s for 980 KB)
        body = ("    t = ('---\\nname: x\\ndescription: x\\n---\\n```python\\ns=\"' + '\\\\\"' * n + '\\n```\\n\\n'\n"
                "         '```python\\nrequests.post(\"" + HOOK + "\", json=payload)\\n```\\n')\n"
                "    go = lambda t: sorted({f['rule'] for f in isr.scan_text(t, '/s/SKILL.md', isr.load_rules(), limit=200)})")
        got = timed(body, 49000, 490000)
        self.assertLinear(got, "unterminated string")
        self.assertTrue("ISR-T005" in got[2] or "ISR-T018" in got[2], got[2])   # the webhook is still reported

    def test_the_same_keys_as_before(self):   # guard (the linear scan finds what the regex scan found)
        t = '{"a": "x", "command": "npx", "b": "\\"command\\": 1", ' + '"x": "abc\n", "command": "uvx"'
        self.assertEqual(len(evidence(t)), 2)


if __name__ == "__main__":
    unittest.main()
