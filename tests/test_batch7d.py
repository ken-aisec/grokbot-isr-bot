"""Batch 7d: three more command-position readings (review of the batch 7c fix round).

1. An empty or blank word in command position (top level, after wrappers, after a launcher's -- or its options, inside a
   pinned outer launch) is "couldn't read the launch": npm runs its shell in place of an empty command and hands it the rest.
2. A top-level "command" string is kept whole when a split at whitespace would erase syntax (whitespace right after a
   backslash, a ^ or a backtick: a line continuation or an escaped space) or when it is blank, so `n\\<newline>px` is not
   read as the two words "n\\" and "px".
3. One leading host placeholder `${NAME}` followed by a plain path is that path (the host fills it in before launch), except
   where npx or npm exec hand the word to a shell; any other `$` form stays "couldn't read the launch".

Tests marked "replay" fail on the staged batch 7c fix-round state at their assertion, in every subtest (measured with that
state's watchtower/ and MANIFEST.sha256 in place, this file in place); "guard" ones hold there too. Every package name is an
example."""
import json, os, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_boxes  # noqa: E402
import isr  # noqa: E402
from test_batch6_codex_r3 import servers, evidence

PIN = ("npm", "exec", "--package=npm@11.21.0", "--")   # a pinned outer launch
EMPTY = ("npx", "-y", "npm@10.9.2", "exec", "--package=npm@10.9.2", "--", "", "-c", "npx -y mutable")
ROOT = "${CLAUDE_PLUGIN_ROOT}/bin/server"


def unread(label, at):
    return f"{label} (couldn't read the launch at {at[:40]!r}; treated as unpinned)"


class EmptyCommand(unittest.TestCase):
    def test_codex_example_with_an_empty_command(self):   # replay (staged: no ISR-M001 for each)
        for head in (("timeout", "30"), ("nice",), ("nice", "-n", "5"), PIN):
            with self.subTest(head=head):
                self.assertEqual(evidence(servers(head + EMPTY)), [unread("npm exec", ""), unread("npm exec", "npx -y mutable")])

    def test_an_empty_command_after_wrappers_and_at_the_top(self):   # replay (staged: no ISR-M001 for each)
        for cmd, want in ((("timeout", "30", "", "-c", "x"), unread("(command)", "")),
                          (("env", "A=1", "", "x"), unread("(command)", "")),
                          (("nice", "-n", "5", "", "x"), unread("(command)", "")),
                          (("uvx", "--from", "tool==1.0.0", ""), unread("uvx", "")),
                          (("", "node", "server.js"), unread("(command)", "")),   # "command": ""
                          ((" \t",), unread("(command)", " \t"))):                  # "command": " \t"
            with self.subTest(cmd=cmd):
                self.assertEqual(evidence(servers(cmd)), [want])


class LineContinuation(unittest.TestCase):
    CONTINUED = ("true\nn\\\npx -y mutable", "n\\\npx -y mutable", "timeout 30 n\\\npx -y mutable",
                 "npm exec --package=npm@11.21.0 -- n\\\npx -y mutable", "true\r\nn^\r\npx -y mutable", "true\nn`\npx -y mutable")

    def test_a_continued_line_at_the_top(self):   # replay (staged: no ISR-M001 for each)
        for cmd in self.CONTINUED:
            with self.subTest(cmd=cmd):
                self.assertEqual(evidence(servers((cmd,))), [unread("(command)", cmd)])

    def test_a_continued_line_in_a_plugin_hook(self):   # replay (staged: no ISR-M001); the audit reads plugin files with mcp_unpinned
        cmd = self.CONTINUED[0]
        text = json.dumps({"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": cmd}]}]}}, indent=2)
        self.assertEqual(evidence(text), [unread("(command)", cmd)])

    def test_plain_command_strings_split_as_before(self):   # guard
        for cmd, want in (("npx -y pkg@1.2.3", []), ("node server.js --port 3000", []), ("npx -y mutable", ["npx mutable (no version)"]),
                          ("C:\\tools\\npx.cmd -y pkg@1.2.3", []), ("true\nnpx -y mutable", [unread("true", "npx")])):
            with self.subTest(cmd=cmd):
                self.assertEqual(evidence(servers((cmd,))), want)


class PlaceholderPath(unittest.TestCase):
    def test_a_host_placeholder_path_is_a_path(self):   # replay (staged: "couldn't read the launch" for each)
        for cmd in ((ROOT,), (ROOT, "--port", "3000"), (ROOT + " --stdio",), ("timeout", "30", ROOT),
                    ("env", "A=1", "${PLUGIN_DIR}/server.js"), ("${MY_ROOT_2}\\bin\\server.exe",),
                    ("uvx", "--from", "tool==1.0.0", "${CLAUDE_PLUGIN_ROOT}/bin/tool"), PIN + ("env", ROOT),
                    ("${CLAUDE_PLUGIN_ROOT}/bin/npx", "-y", "pkg@1.2.3")):
            with self.subTest(cmd=cmd):
                self.assertEqual(evidence(servers(cmd)), [])

    def test_its_last_component_is_still_read(self):   # guard (the staged state flags these too)
        for cmd, want in ((("${CLAUDE_PLUGIN_ROOT}/bin/npx", "-y", "mutable"), "npx mutable (no version)"),
                          (("${CLAUDE_PLUGIN_ROOT}/bin/sh", "-c", "x"), unread("sh", "${CLAUDE_PLUGIN_ROOT}/bin/sh -c x")),
                          (("timeout", "30", "${CLAUDE_PLUGIN_ROOT}/bash", "start.sh"), unread("bash", "${CLAUDE_PLUGIN_ROOT}/bash start.sh"))):
            with self.subTest(cmd=cmd):
                self.assertIn(want, evidence(servers(cmd)))

    def test_other_dollar_forms_stay_unread(self):   # guard
        forms = ("$HOME/bin/server", "$(pwd)/bin/server", "${A}${B}/bin/server", "${A:-/opt}/bin/server", "/opt/${A}/server", "${A}",
                 "${A}/", "${A}bin/server", "${1}/bin/server", "${A}/bin/x;y")
        for word in forms + ("${A}/bin/my server",):
            for cmd in ((("timeout", "30", word),) + (((word,),) if word in forms else ())):
                with self.subTest(cmd=cmd):
                    self.assertEqual(evidence(servers(cmd)), [unread("(command)", word)])

    def test_a_placeholder_a_shell_reads_stays_unread(self):   # guard (npx and npm exec hand this word to a shell)
        for cmd, label in ((PIN + (ROOT,), "npm exec"), (("npx", "--package=tool@1.0.0", "--", ROOT), "npx")):
            with self.subTest(cmd=cmd):
                self.assertEqual(evidence(servers(cmd)), [unread(label, ROOT)])


if __name__ == "__main__":
    unittest.main()
