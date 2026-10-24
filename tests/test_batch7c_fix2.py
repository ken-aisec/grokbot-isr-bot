"""Batch 7c fix round (Codex round 1 on 52597c5): script text in command position, and the wrapper option forms the docs name.

A command-position word with whitespace or shell syntax (_SCRIPT_SYNTAX: whitespace, quotes, ; & | $ ` < > ( ) { } [ ] * ? ! # %
^), or a backslash whose escape names a launcher, shell or wrapper (n\\px), is script text a launcher such as npm exec hands to a
shell: "couldn't read the launch", at the top, after wrappers (a wrapper's own name too), after a launcher's -- and in a pinned
outer launch, in front of whatever 83fd9bf read there, so no finding is lost.

Tests marked "replay" fail on 83fd9bf on their assertion, in every subtest (measured with 83fd9bf's watchtower/ sources and
MANIFEST.sha256 stashed, this file in place); "guard" ones hold on 83fd9bf too. Every package name is an example."""
import os, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_boxes  # noqa: E402
import isr  # noqa: E402
from test_batch6_codex_r3 import servers, evidence

PIN = ("npm", "exec", "--package=npm@11.21.0", "--")   # a pinned outer launch
CODEX = ("npx", "-y", "npm@10.9.2", "exec", "--package=npm@10.9.2", "--", "npx -y mutable")   # the last word is ONE string
SYNTAX = (" ", "\t", "\n", "'", '"', "`", ";", "&", "|", "$", "<", ">", "(", ")", "{", "}", "[", "]", "*", "?", "!", "#", "%", "^")


def unread(label, at):
    return f"{label} (couldn't read the launch at {at[:40]!r}; treated as unpinned)"


class CodexExample(unittest.TestCase):
    def test_behind_timeout(self):   # replay (83fd9bf: no ISR-M001)
        self.assertEqual(evidence(servers(("timeout", "30") + CODEX)), [unread("npm exec", "npx -y mutable")])

    def test_behind_nice(self):   # replay (83fd9bf: no ISR-M001 for each)
        for head in (("nice",), ("nice", "-n", "5"), ("nice", "-n5"), ("nice", "--adjustment=5")):
            with self.subTest(head=head):
                self.assertEqual(evidence(servers(head + CODEX)), [unread("npm exec", "npx -y mutable")])

    def test_inside_a_pinned_outer_npm_exec(self):   # replay (83fd9bf: no ISR-M001 for each)
        for cmd in (PIN + CODEX, PIN + ("env", "timeout", "30") + CODEX, PIN + ("npx -y mutable",),
                    PIN + ("sh -c 'npx -y mutable'",), PIN + ("env", "A=1", "nice", "npx -y mutable")):
            with self.subTest(cmd=cmd):
                self.assertEqual(evidence(servers(cmd)), [unread("npm exec", cmd[-1])])

    def test_at_the_top(self):   # replay (83fd9bf: no ISR-M001 for each)
        for cmd, want in (((" ".join(CODEX[:-1]) + " 'npx -y mutable'",), unread("npm exec", "'npx")),   # one "command" string
                          (CODEX, unread("npm exec", "npx -y mutable")),
                          (("x;/usr/bin/npx", "-y", "pkg@1.2.3"), unread("(command)", "x;/usr/bin/npx")),
                          (("timeout", "30", "x;/usr/bin/npx", "-y", "pkg@1.2.3"), unread("(command)", "x;/usr/bin/npx")),
                          (("x;/usr/bin/timeout", "30", "npx", "-y", "pkg@1.2.3"), unread("(command)", "x;/usr/bin/timeout")),
                          (("env", "x|/bin/nice", "npx", "-y", "pkg@1.2.3"), unread("(command)", "x|/bin/nice"))):
            with self.subTest(cmd=cmd):
                self.assertEqual(evidence(servers(cmd)), [want])


class EverySyntax(unittest.TestCase):
    def test_each_character_in_command_position(self):   # replay (83fd9bf read each as a pinned npx: no ISR-M001)
        for ch in SYNTAX:
            word = "x" + ch + "/usr/bin/npx"
            for cmd, label in ((("timeout", "30", word, "-y", "pkg@1.2.3"), "(command)"),
                               (PIN + (word, "-y", "pkg@1.2.3"), "npm exec"),
                               (("npx", "-y", "npm@10.9.2", "exec", "--package=npm@10.9.2", "--", word, "-y", "pkg@1.2.3"), "npm exec")):
                with self.subTest(cmd=cmd):
                    self.assertEqual(evidence(servers(cmd)), [unread(label, word)])

    def test_a_backslash_that_hides_a_name(self):   # replay (83fd9bf: no ISR-M001 for each)
        for cmd, want in ((PIN + ("n\\px", "-y", "mutable"), unread("npm exec", "n\\px")),
                          (PIN + ("\\s\\h", "-c", "x"), unread("npm exec", "\\s\\h")),
                          (("timeout", "30", "n\\px.cmd", "-y", "mutable"), unread("(command)", "n\\px.cmd"))):
            with self.subTest(cmd=cmd):
                self.assertEqual(evidence(servers(cmd)), [want])


class NothingLost(unittest.TestCase):
    def test_what_83fd9bf_read_is_still_reported(self):   # replay (83fd9bf: only the second line)
        for cmd, label in ((("timeout", "30", "x;/usr/bin/npx", "-y", "mutable"), "(command)"),
                           (PIN + ("$HOME/bin/npx", "-y", "mutable"), "npm exec")):
            with self.subTest(cmd=cmd):
                self.assertEqual(evidence(servers(cmd)), [unread(label, cmd[-3]), "npx mutable (no version)"])


class StaysClean(unittest.TestCase):
    def test_plainly_pinned_single_word_launches_stay_clean(self):   # guard
        for cmd in (("npx", "-y", "pkg@1.2.3"), PIN + ("npx", "-y", "safe@1.2.3"), ("timeout", "30") + CODEX[:-1] + ("npx", "-y", "safe@1.2.3"),
                    ("nice", "-n", "5") + CODEX[:-1] + ("npx", "-y", "safe@1.2.3"), PIN + ("npx", "-y", "@scope/pkg@1.2.3"),
                    ("C:\\tools\\npx.cmd", "-y", "pkg@1.2.3"), PIN + ("C:\\tools\\npx.cmd", "-y", "pkg@1.2.3"), ("\\npx", "-y", "pkg@1.2.3"),
                    ("/home/u/.local/bin/uvx", "pkg==1.2.3"), ("uvx", "pkg[cli]==1.2.3"), ("uvx", "--from", "tool[cli]==1.0.0", "tool-cmd"),
                    ("node", "server.js", "--port", "3000"), PIN + ("node", "server.js")):
            with self.subTest(cmd=cmd):
                self.assertEqual(evidence(servers(cmd)), [])


class OptionForms(unittest.TestCase):
    """Every timeout and nice option form CHANGELOG.md and docs/KNOWN-LIMITS.md name, each read (unpinned behind it names the
    package) and each clean in front of a pinned launch."""
    FORMS = (("timeout", "-v", "30"), ("timeout", "--verbose", "30"), ("timeout", "--foreground", "30"),
             ("timeout", "--preserve-status", "30"), ("timeout", "-s", "KILL", "30"), ("timeout", "-s", "9", "30"),
             ("timeout", "-sTERM", "30"), ("timeout", "-s9", "30"), ("timeout", "--signal", "TERM", "30"),
             ("timeout", "--signal=TERM", "30"), ("timeout", "--signal=SIGHUP", "30"), ("timeout", "--signal=9", "30"), ("timeout", "-k", "5", "30"),
             ("timeout", "-k5s", "30"), ("timeout", "--kill-after", "5", "30"), ("timeout", "--kill-after=5", "30"),
             ("timeout", "0.5"), ("timeout", "2h"), ("timeout", "1d"),
             ("nice",), ("nice", "-n", "5"), ("nice", "-n5"), ("nice", "-n", "-5"), ("nice", "--adjustment", "5"),
             ("nice", "--adjustment=5"), ("nice", "-10"))

    def test_each_form_is_read(self):   # guard (83fd9bf reads these too)
        for head in self.FORMS:
            with self.subTest(head=head):
                self.assertEqual(evidence(servers(head + ("npx", "-y", "mutable"))), ["npx mutable (no version)"])
                self.assertEqual(evidence(servers(head + ("npx", "-y", "pkg@1.2.3"))), [])


if __name__ == "__main__":
    unittest.main()
