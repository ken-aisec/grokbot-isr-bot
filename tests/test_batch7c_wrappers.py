"""Batch 7c (KNOWN-LIMITS must-fix 8, batch 6 PR3 Codex round 4 high): wrappers no longer hide nested launchers.

env, timeout and nice are read with their options exactly as written, in any order, at the top and in a launch, and the command
after them is read as if it stood alone; a shell (the recognised ones) is never read, -c or not; other wrappers (nohup, sudo,
xargs, …) are not read, and a launcher, shell or wrapper name among their words, a $ or a `, or xargs's argument file is
"couldn't read the launch"; names among a command's words are seen with quotes and backslashes taken out and split at shell
punctuation; Windows paths (\\ and .exe/.cmd/.bat) name the command wherever it stands. A package's own command is never
unwrapped, and unwrapping never clears a launch a3e535e couldn't read.

Tests marked "replay" fail on a3e535e on their assertion, in every subtest (measured with a3e535e's watchtower/ sources, this
file in place); "guard" ones hold on a3e535e too. Timing guards check time only; what those inputs give is checked by replays.
The box is a temp folder; every package name is an example."""
import json, os, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import Box, wt
from test_batch6_codex_r3 import servers, evidence, timed

PIN = ("npm", "exec", "--package=npm@11.21.0", "--")   # a pinned outer launch


def unread(label, at):
    return f"{label} (couldn't read the launch at {at[:40]!r}; treated as unpinned)"


class CodexRound4(unittest.TestCase):
    def test_the_five_codex_examples(self):   # replay (a3e535e: no WT-M001 for each)
        for cmd, want in ((PIN + ("env", "sh", "-c", '"npx" -y mutable'), [unread("sh", 'sh -c "npx" -y mutable')]),
                          (PIN + ("env", "yarn", "dlx", "mutable"), [unread("yarn", "yarn")]),
                          (PIN + ("env", "pipx", "run", "mutable"), [unread("pipx", "pipx")]),
                          (("timeout", "30", "sh", "-c", '"npx" -y mutable'), [unread("sh", 'sh -c "npx" -y mutable')]),
                          (("nice", "sh", "-c", '"npx" -y mutable'), [unread("sh", 'sh -c "npx" -y mutable')])):
            with self.subTest(cmd=cmd):
                self.assertEqual(evidence(servers(cmd)), want)


class Wrappers(unittest.TestCase):
    def test_combinations_reach_the_launch(self):   # replay (a3e535e: none, or "couldn't read" at the wrong word for each)
        for cmd, want in ((("env", "A=1", "timeout", "30", "nice", "-n", "5", "npx", "-y", "mutable"), ["npx mutable (no version)"]),
                          (("nice", "-n", "5", "env", "-u", "X", "npx", "-y", "mutable"), ["npx mutable (no version)"]),
                          (("timeout", "-s", "KILL", "--kill-after=5", "2.5s", "env", "--", "npx", "-y", "mutable"), ["npx mutable (no version)"]),
                          (("timeout", "30", "pnpm", "dlx", "mutable"), ["pnpm dlx mutable (no version)"]),
                          (("nice", "bunx", "mutable"), ["bunx mutable (no version)"]),
                          (("env", "A=1", "nice", "uvx", "mutable"), ["uvx mutable (no version)"]),
                          (PIN + ("env", "timeout", "30", "pnpm", "dlx", "mutable"), ["pnpm dlx mutable (no version)"]),
                          (PIN + ("timeout", "30", "bunx", "mutable"), ["bunx mutable (no version)"]),
                          (PIN + ("env", "nice", "uvx", "mutable"), ["uvx mutable (no version)"]),
                          (PIN + ("env", "-i", "timeout", "30", "npx", "-y", "mutable"), ["npx mutable (no version)"]),
                          (PIN + ("nice", "-n", "5", "yarn", "dlx", "mutable"), [unread("yarn", "yarn")]),
                          (PIN + ("env", "timeout", "5", "pipx", "run", "mutable"), [unread("pipx", "pipx")]),
                          (("pnpm", "--package=tool@1.0.0", "dlx", "env", "sh", "-c", '"npx" x'), [unread("sh", 'sh -c "npx" x')]),
                          (("bunx", "--package", "tool@1.0.0", "timeout", "30", "sh", "-c", '"npx" x'), [unread("sh", 'sh -c "npx" x')]),
                          (("uvx", "--from", "tool==1.0.0", "nice", "-n", "1", "npx", "-y", "mutable"), ["npx mutable (no version)"]),
                          (("uvx", "--from", "tool==1.0.0", "nice", "pipx", "run", "mutable"), [unread("pipx", "pipx")]),
                          (("env", "A=1", "timeout", "1", "nice", "-n", "1") * 50 + ("sh", "-c", "x"), [unread("sh", "sh -c x")])):
            with self.subTest(cmd=cmd[:12]):
                self.assertEqual(evidence(servers(cmd)), want)


class Shells(unittest.TestCase):
    def test_a_shell_is_never_read(self):   # replay (a3e535e: no WT-M001 for each)
        for cmd, want in ((("bash", "-c", "x=np; ${x}x -y mutable"), unread("bash", "bash -c x=np; ${x}x -y mutable")),
                          (("bash", "start.sh"), unread("bash", "bash start.sh")),
                          (("env", "bash", "start.sh"), unread("bash", "bash start.sh")),
                          (("sh", "-c", '"npx" -y mutable'), unread("sh", 'sh -c "npx" -y mutable')),
                          (("zsh", "-c", 'n""px mutable'), unread("zsh", 'zsh -c n""px mutable')),
                          (("dash", "-c", "\\npx mutable"), unread("dash", "dash -c \\npx mutable")),
                          (PIN + ("timeout", "30", "sh", "-c", '"npx" -y mutable'), unread("sh", 'sh -c "npx" -y mutable'))):
            with self.subTest(cmd=cmd):
                self.assertEqual(evidence(servers(cmd)), [want])

    def test_every_recognised_shell_direct_and_wrapped(self):   # replay (a3e535e: no WT-M001 for each)
        for shell, label in (("sh", "sh"), ("bash", "bash"), ("dash", "dash"), ("zsh", "zsh"), ("ksh", "ksh"), ("mksh", "mksh"),
                             ("ash", "ash"), ("fish", "fish"), ("rbash", "rbash"), ("/bin/sh", "sh"), ("busybox sh", "busybox"),
                             ("cmd", "cmd"), ("cmd.exe", "cmd"), ("powershell", "powershell"), ("pwsh", "pwsh")):
            words = tuple(shell.split()) + ("start.sh",)
            for cmd in (words, ("timeout", "30") + words, PIN + ("env",) + words):
                with self.subTest(cmd=cmd):
                    self.assertEqual(evidence(servers(cmd)), [unread(label, " ".join(words[:3]))])


class QuotedNames(unittest.TestCase):
    def test_quoted_launcher_names_are_seen(self):   # replay (a3e535e: no WT-M001 for each)
        for cmd, want in ((("xargs", "sh", "-c", '"npx" mutable'), unread("xargs", "sh")),
                          (("xargs", '"npx"', "-y", "mutable"), unread("xargs", '"npx"')),
                          (("xargs", "C:\\tools\\npx.cmd", "mutable"), unread("xargs", "C:\\tools\\npx.cmd")),
                          (PIN + ("node", "run.js", '"npx" -y mutable'), unread("node", '"npx" -y mutable')),
                          (("node", "run.js", "x;npx"), unread("node", "x;npx")),
                          (("node", "run.js", 'n""px mutable'), unread("node", 'n""px mutable')),
                          (("node", "run.js", "\\npx mutable"), unread("node", "\\npx mutable")),
                          (("timeout", "30", "node", "run.js", '"npx" -y mutable'), unread("node", '"npx" -y mutable')),
                          (("node", "run.js", "--cmd=n\\px"), unread("node", "--cmd=n\\px"))):
            with self.subTest(cmd=cmd):
                self.assertEqual(evidence(servers(cmd)), [want])


class OtherWrappers(unittest.TestCase):
    def test_wrapper_names_expansions_and_argument_files_are_unread(self):   # replay (a3e535e: no WT-M001 for each)
        for cmd, want in ((("nohup", "env", "-S", "tool"), unread("nohup", "env")),
                          (("sudo", "timeout", "30", "tool"), unread("sudo", "timeout")),
                          (("setsid", "nice", "tool"), unread("setsid", "nice")),
                          (("stdbuf", "-oL", "bash", "start.sh"), unread("stdbuf", "bash")),
                          (("nohup", "$TOOL"), unread("nohup", "$TOOL")),
                          (("chrt", "-f", "1", "${X}"), unread("chrt", "${X}")),
                          (("nohup", "tool", "`cat x`"), unread("nohup", "`cat x`")),
                          (("xargs", "-a", "args.txt"), unread("xargs", "-a")),
                          (("xargs", "--arg-file=args.txt", "tool"), unread("xargs", "--arg-file=args.txt")),
                          (("xargs", "nohup"), unread("xargs", "nohup")),
                          (PIN + ("nohup", "env", "tool"), unread("nohup", "env"))):
            with self.subTest(cmd=cmd):
                self.assertEqual(evidence(servers(cmd)), [want])

    def test_other_wrappers_of_plain_commands_stay_clear(self):   # guard
        for cmd in (("nohup", "node", "server.js"), ("sudo", "-u", "nobody", "python", "-m", "server"), ("setsid", "node", "x.js")):
            with self.subTest(cmd=cmd):
                self.assertEqual(evidence(servers(cmd)), [])


class WrapperOptions(unittest.TestCase):
    def test_unread_wrapper_options_fail_closed(self):   # replay (a3e535e named 'npx' or nothing; this names the option)
        tail = ("npx", "-y", "pkg@1.2.3")
        for head, want in ((("timeout", "--frob", "30"), unread("timeout", "--frob")),
                           (("timeout", "abc"), unread("timeout", "abc")),
                           (("timeout", "-vk5", "30"), unread("timeout", "-vk5")),
                           (("timeout", "-s", "FOO", "30"), unread("timeout", "-s")),
                           (("timeout", "--sig=KILL", "30"), unread("timeout", "--sig=KILL")),
                           (("nice", "-n", "x"), unread("nice", "-n")),
                           (("nice", "--adj=5"), unread("nice", "--adj=5"))):
            with self.subTest(head=head):
                self.assertEqual(evidence(servers(head + tail)), [want])
        with self.subTest(head=("timeout", "--foreground")):
            self.assertEqual(evidence(servers(("timeout", "--foreground"))), [unread("timeout", "(no duration)")])


class Pinned(unittest.TestCase):
    def test_pinned_behind_wrappers_is_read_as_pinned(self):   # replay (a3e535e: "couldn't read the launch at 'npx'" for each)
        for cmd in (("timeout", "30", "npx", "-y", "pkg@1.2.3"), ("nice", "-n", "5", "npx", "-y", "pkg@1.2.3"),
                    ("env", "A=1", "timeout", "-s", "KILL", "30", "nice", "npx", "-y", "pkg@1.2.3"),
                    ("timeout", "--preserve-status", "-k", "5", "30", "npx", "-y", "pkg@1.2.3"),
                    ("timeout", "-sTERM", "-k5s", "1m", "npx", "-y", "pkg@1.2.3"),
                    ("nice", "-10", "npx", "-y", "pkg@1.2.3"), ("nice", "--adjustment=5", "npx", "-y", "pkg@1.2.3"),
                    PIN + ("env", "timeout", "30", "npx", "-y", "safe@1.2.3")):
            with self.subTest(cmd=cmd):
                self.assertEqual(evidence(servers(cmd)), [])

    def test_plain_pinned_launches_and_commands_stay_clear(self):   # guard
        for cmd in (("npx", "-y", "pkg@1.2.3"), ("uvx", "pkg==1.2.3"), ("bunx", "pkg@1.2.3"), ("pnpm", "dlx", "pkg@1.2.3"),
                    ("env", "A=1", "npx", "-y", "pkg@1.2.3"), PIN + ("npx", "-y", "safe@1.2.3"),
                    ("node", "server.js", "--port", "3000"), ("npm", "run", "start"), ("python", "-m", "server"),
                    ("docker", "run", "-i", "--rm", "mcp/fs"), ("timeout", "30"), ("nice",)):
            with self.subTest(cmd=cmd):
                self.assertEqual(evidence(servers(cmd)), [])


class NeverCleared(unittest.TestCase):
    """Unwrapping never clears a launch a3e535e couldn't read (plan review, amendment 2)."""

    def test_unread_package_manager_commands_stay_unread(self):   # guard (a3e535e: "couldn't read" too, at the wrapper)
        for cmd in (("timeout", "30", "npm", "install"), ("nice", "pnpm", "add", "x"), ("env", "A=1", "timeout", "30", "npm", "run", "start"),
                    PIN + ("timeout", "30", "npm", "run", "start"), ("cmd", "/c", "npx", "-y", "pkg@1.2.3")):
            with self.subTest(cmd=cmd):
                got = evidence(servers(cmd))
                self.assertEqual(len(got), 1, got)
                self.assertIn("couldn't read the launch", got[0])

    def test_a_package_named_like_a_wrapper_is_not_unwrapped(self):   # guard (the same evidence on a3e535e)
        for cmd, want in ((("npx", "-y", "nice@1.0.0", "npx", "-y", "pkg@1.2.3"), unread("nice", "npx")),
                          (("npx", "-y", "env@1.0.0", "-S", "tool"), unread("env", "-S"))):
            with self.subTest(cmd=cmd):
                self.assertEqual(evidence(servers(cmd)), [want])

    def test_more_unread_commands_behind_wrappers(self):   # replay (a3e535e: no WT-M001 for each)
        for cmd, want in ((PIN + ("env", "npm", "install"), unread("npm", "npm")),
                          (("npx", "-y", "timeout@1.0.0", "30", "sh", "-c", "x"), unread("timeout", "30")),
                          (("npx", "-y", "env@1.0.0", "node", "server.js"), unread("env", "node"))):
            with self.subTest(cmd=cmd):
                self.assertEqual(evidence(servers(cmd)), [want])


class WindowsPaths(unittest.TestCase):
    def test_a_windows_path_names_the_command_where_it_stands(self):   # replay (a3e535e: no WT-M001 for each)
        for cmd, want in ((("C:\\tools\\npx.cmd", "-y", "mutable"), "npx mutable (no version)"),
                          (("timeout", "30", "C:\\tools\\npx.cmd", "-y", "mutable"), "npx mutable (no version)"),
                          (PIN + ("C:\\tools\\npx.cmd", "-y", "mutable"), "npx mutable (no version)"),
                          (("C:\\Windows\\System32\\cmd.exe", "/c", "start.bat"), unread("cmd", "C:\\Windows\\System32\\cmd.exe /c start.bat")),
                          (PIN + ("C:\\Windows\\System32\\cmd.exe", "/c", "start.bat"), unread("cmd", "C:\\Windows\\System32\\cmd.exe /c start.bat")),
                          (("D:\\PowerShell\\pwsh.exe", "-File", "run.ps1"), unread("pwsh", "D:\\PowerShell\\pwsh.exe -File run.ps1")),
                          (("C:\\tools\\NPM.CMD", "exec", "--package=npm@11.21.0", "--", "C:\\x\\bash.exe", "x"), unread("bash", "C:\\x\\bash.exe x"))):
            with self.subTest(cmd=cmd):
                self.assertEqual(evidence(servers(cmd)), [want])


class Depth(unittest.TestCase):
    def test_wrappers_between_launchers_are_bounded(self):   # replay (a3e535e: "timeout (couldn't read the launch at 'npm' …)")
        cmd = (PIN + ("env", "A=1", "timeout", "1", "nice")) * 5000 + ("npx", "mutable")
        self.assertEqual(evidence(servers(cmd)), ["npm exec (couldn't read the launch at '(launchers nested over 16 deep)'; treated as unpinned)"])


class Linear(unittest.TestCase):
    """Timing guards: about 100 KB, then about 1 MB, of each input (the same bounds as r3's assertLinear). Time only."""

    def assertLinear(self, args, small, large):
        body = ("    t = wt.json.dumps({'mcpServers': {'s': {'command': %r, 'args': %s}}})\n    go = wt.mcp_unpinned" % args)
        got = timed(body, small, large)
        self.assertIsNotNone(got, "over 30 seconds")
        s, l, _ = got
        self.assertLess(l, 5.0)
        self.assertLess(l, 40 * max(s, 0.02))   # 10x the input: quadratic would be 100x

    def test_many_words(self):   # guard (timing)
        for args, small, large in ((("env", "['A=1', 'timeout', '1', 'nice', '-n', '1'] + ['env', 'A=1', 'timeout', '1', 'nice', '-n', '1'] * n"
                                     " + ['sh', '-c', 'x']"), 2000, 20000),
                                   (("node", "['\"a\\\\\\\\b\"'] * n"), 8000, 80000),
                                   (("nohup", "['\"a\\\\\\\\b\"'] * n"), 8000, 80000),
                                   (("npm", "(['exec', '--package=npm@11.21.0', '--', 'env', 'A=1', 'timeout', '1', 'nice', 'npm'] * n)[:-1]"
                                     " + ['npx', 'mutable']"), 1300, 13000)):
            with self.subTest(args=args[0]):
                self.assertLinear(args, small, large)

    def test_one_long_word(self):   # guard (timing)
        for args, small, large in ((("node", "['run.js', '\"a\\\\\\\\b;' * n]"), 14000, 140000),
                                   (("nohup", "['a\\\\\\\\' * n]"), 25000, 250000),
                                   (("timeout", "['1' * n + 'x', 'npx']"), 100000, 1000000),
                                   (("nice", "['-n', '1' * n + 'x', 'npx']"), 100000, 1000000),
                                   (("sh", "['-c', 'x' * n]"), 100000, 1000000),
                                   (("node", "['/' * n + 'npx']"), 100000, 1000000)):
            with self.subTest(args=args[0] + " " + args[1][:12]):
                self.assertLinear(args, small, large)


class Audit(Box):
    def test_codex_example_is_a_wt_m001_in_the_audit(self):   # replay (a3e535e: no WT-M001)
        d = os.path.join(self.home, "x")
        os.makedirs(d)
        with open(os.path.join(d, "mcp.json"), "w") as f:
            f.write(servers(PIN + ("env", "sh", "-c", '"npx" -y mutable')))
        self.audit("--budget", "0")
        snap = self.snap()
        fs = [f for k in ("findings", "suppressed") for f in snap.get(k) or [] if f.get("rule") == "WT-M001"]
        self.assertEqual([(f["evidence"], f["fix"]) for f in fs],
                         [(unread("sh", 'sh -c "npx" -y mutable'), "Pin an exact version (pkg@1.2.3) so an update can't change what runs.")])


if __name__ == "__main__":
    unittest.main()
