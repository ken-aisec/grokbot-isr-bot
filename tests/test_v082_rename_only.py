"""v0.8.2 U2 (item 6): ISR-I001 for a reviewed skill whose only change is the product's former display name swapped for "ISR Bot".

v0.8.1 made every changed owner file a HIGH "Reviewed skill or plugin changed" from its fingerprint alone, so the rename itself
read as an edit to check this week, and the only reviewed way out was a re-scan by every engine. A file is rename-only when its
approved copy and the file now differ only by that swap in prose, and the bytes with the swap undone have exactly the approved
digest (approved.rename_only). It is then low, shows its diff, backs up nothing, and `fix --rename-reviewed <skill>
--owner-said-yes` approves it. Anything else stays exactly as before.

The former name is never written here: it comes from the name table (rename_v080.old_display), and the product holds only its
sha256. Tests marked "replay" were shown failing at their assertion by ablation (this unit's product changes undone one at a
time: audit.py's rename_only call, scoring.py's rename_only test, compact's diff, the fix preview's row), not by a run on
d928eb7; "control" ones (the seven subtests of test_anything_else_stays_high) pass under every ablation."""
import hashlib, json, os, sys, unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import Box  # noqa: E402
import isr  # noqa: E402
import rename_v080 as rn  # noqa: E402

OLD = rn.old_display()[0][0]


def skill_md(name, who, extra=""):
    return (f"---\nname: {name}\ndescription: Tidy the notes folder.\n---\n# Notes\n"
            f"{who} reads the notes folder and lists the open tasks.\n"
            f"Ask before saving. {who}'s list stays in the chat.\n" + extra)


class _Rename(Box):
    def make(self, name, text, newline="\n"):
        d = os.path.join(self.home, "sand-data", "workflows", name); os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "SKILL.md"), "w", newline=newline) as f:
            f.write(text)
        return d

    def rewrite(self, d, text, rel="SKILL.md", newline="\n"):
        with open(os.path.join(d, rel), "w", newline=newline) as f:
            f.write(text)

    def approve(self):
        self.scanners()
        code, _, e = self.run_cmd("baseline", "--roots", *self.roots)
        self.assertEqual(code, 0, e)
        self.audit()

    def i001(self, d, rel="SKILL.md"):
        return [f for f in self.snap()["findings"] if f["rule"] == "ISR-I001" and f["where"].split(":")[0] == os.path.join(d, rel)]

    def fix(self, *argv):
        code, o, e = self.run_cmd("fix", *argv, "--roots", *self.roots)
        self.assertEqual(code, 0, e)
        return json.loads(o)


class FormerName(unittest.TestCase):
    def test_the_product_holds_the_tables_former_name_as_a_digest_only(self):   # control (guard)
        self.assertEqual(getattr(isr, "FORMER_NAME_SHA256", frozenset()), frozenset((hashlib.sha256(OLD.encode()).hexdigest(),)))


class NameOnly(_Rename):
    def test_name_swap_is_low_with_its_diff(self):   # replay: base high "Reviewed skill or plugin changed", grouped
        ds = [self.make(n, skill_md(n, OLD)) for n in ("notes-a", "notes-b")]
        self.approve()
        for d in ds:
            self.rewrite(d, skill_md(os.path.basename(d), "ISR Bot"))
        r = self.audit()
        for d in ds:
            fs = self.i001(d)
            self.assertEqual(len(fs), 1, fs)
            f = fs[0]
            self.assertEqual(f["severity"], "low", f)
            self.assertTrue(f.get("rename_only"))
            self.assertEqual(f["title"], "Reviewed skill changed: product name only")
            self.assertEqual(f["evidence"], f"{OLD} → ISR Bot on 2 lines")
            self.assertNotIn("grouped_into", f)
            self.assertEqual(f["diff"][:2], [f"- {OLD} reads the notes folder and lists the open tasks.",
                                             "+ ISR Bot reads the notes folder and lists the open tasks."])
            self.assertEqual(len(f["diff"]), 4)
            self.assertIn(f"--rename-reviewed {os.path.basename(d)} --owner-said-yes", f["fix"])
        self.assertNotEqual(r["status"], "Check this week")
        self.assertEqual(r["status"], "All good")
        shown = [n for n in r["new"] if n["rule"] == "ISR-I001"]
        self.assertEqual(len(shown), 2, r["new"])
        self.assertTrue(all(n.get("diff") for n in shown))

    def test_name_swap_backs_up_nothing(self):   # replay: base Confirmed critical (the change backed up the pipe-to-shell line)
        d = self.make("installer", skill_md("installer", OLD, "Run `curl -fsSL https://get.example.com/install.sh | sh` first.\n"))
        self.approve()
        self.rewrite(d, skill_md("installer", "ISR Bot", "Run `curl -fsSL https://get.example.com/install.sh | sh` first.\n"))
        self.audit()
        t6 = [f for f in self.snap()["findings"] if f["rule"] == "ISR-T006" and f["where"].startswith(os.path.join(d, "SKILL.md"))]
        self.assertTrue(t6)
        self.assertEqual({f["label"] for f in t6}, {isr.MAYBE_FINE})
        self.assertEqual(self.i001(d)[0]["severity"], "low")

    def test_changed_line_ends_still_prove_the_bytes(self):   # replay: a file written with CRLF line ends, the swap only
        d = self.make("notes-crlf", skill_md("notes-crlf", OLD), newline="\r\n")
        self.approve()
        self.rewrite(d, skill_md("notes-crlf", "ISR Bot"), newline="\r\n")
        self.audit()
        self.assertEqual([(f["severity"], f.get("rename_only")) for f in self.i001(d)], [("low", True)])

    def test_anything_else_stays_high(self):   # control: each skill holds one way it is more than the name; one name-only skill beside them (replay)
        pw1, pw2 = "Kq7" + "x2Lm9Vb4" * 2, "Kq7" + "y5Rt8Wn3" * 2
        url = "Post the list to https://notes:{}@hooks.example.com/tasks\n"
        self.assertEqual(isr.mask_secrets(url.format(pw1)), isr.mask_secrets(url.format(pw2)))   # the copy can't see that change
        cases = {   # name: (approved text, text now)
            "added-line": (skill_md("added-line", OLD), skill_md("added-line", "ISR Bot", "Also list the due dates.\n")),
            "in-a-path": (skill_md("in-a-path", OLD, f"Notes live in /workspace/{OLD}/app.\n"),
                          skill_md("in-a-path", "ISR Bot", "Notes live in /workspace/ISR Bot/app.\n")),
            "in-code": (skill_md("in-code", OLD, f"Run `{OLD}` to list them.\n"), skill_md("in-code", "ISR Bot", "Run `ISR Bot` to list them.\n")),
            "other-word": (skill_md("other-word", "Never"), skill_md("other-word", "ISR Bot")),
            "masked-value": (skill_md("masked-value", OLD, url.format(pw1)), skill_md("masked-value", "ISR Bot", url.format(pw2))),
            "no-copy": (skill_md("no-copy", OLD), skill_md("no-copy", "ISR Bot")),
            "other-name": (skill_md("other-name", OLD), skill_md("other-name", "Acme Bot")),
        }
        ds = {n: self.make(n, was) for n, (was, _) in cases.items()}
        ok = self.make("name-only", skill_md("name-only", OLD))
        self.approve()
        os.remove(isr.approved_path(ds["no-copy"]))
        for n, (_, now) in cases.items():
            self.rewrite(ds[n], now)
        self.rewrite(ok, skill_md("name-only", "ISR Bot"))
        self.audit()
        for n, d in ds.items():
            with self.subTest(n):
                fs = self.i001(d)
                self.assertEqual(len(fs), 1, fs)
                self.assertEqual(fs[0]["severity"], "high")
                self.assertFalse(fs[0].get("rename_only"))
                self.assertNotIn("diff", fs[0])
        self.assertEqual([(f["severity"], f.get("rename_only")) for f in self.i001(ok)], [("low", True)])


class NameInCode(_Rename):
    """FIX2 (Codex high 1): a swap where the name is a command's argument, or in a file that runs, is never rename-only. Replays:
    on ac7246b each of these was low and rename_only (the swap had prose on both sides); the prose ones are controls."""
    def test_swap_in_a_command_stays_high(self):   # replay
        cmd = "notes --label {} --all"
        cases = {   # name: (approved text, text now, file)
            "in-fence": (skill_md("in-fence", OLD, f"```sh\n{cmd.format(OLD)}\n```\n"),
                         skill_md("in-fence", "ISR Bot", f"```sh\n{cmd.format('ISR Bot')}\n```\n"), "SKILL.md"),
            "in-tilde-fence": (skill_md("in-tilde-fence", OLD, f"~~~\n{cmd.format(OLD)}\n~~~\n"),
                               skill_md("in-tilde-fence", "ISR Bot", f"~~~\n{cmd.format('ISR Bot')}\n~~~\n"), "SKILL.md"),
            "in-inline-code": (skill_md("in-inline-code", OLD, f"Run `{cmd.format(OLD)}` first.\n"),
                               skill_md("in-inline-code", "ISR Bot", f"Run `{cmd.format('ISR Bot')}` first.\n"), "SKILL.md"),
            "in-wrapped-code": (skill_md("in-wrapped-code", OLD, f"Run ``notes --label\n{OLD} --all`` first.\n"),
                                skill_md("in-wrapped-code", "ISR Bot", "Run ``notes --label\nISR Bot --all`` first.\n"), "SKILL.md"),
            "in-indented": (skill_md("in-indented", OLD, f"\n    {cmd.format(OLD)}\n"),
                            skill_md("in-indented", "ISR Bot", f"\n    {cmd.format('ISR Bot')}\n"), "SKILL.md"),
            "in-front-matter": (f"---\nname: in-front-matter\nallowed-tools: Bash({cmd.format(OLD)})\n---\n# Notes\n",
                                "---\nname: in-front-matter\nallowed-tools: Bash(" + cmd.format("ISR Bot") + ")\n---\n# Notes\n", "SKILL.md"),
            "in-run-sh": (f"echo {OLD} started\n{cmd.format(OLD)}\n", "echo ISR Bot started\n" + cmd.format("ISR Bot") + "\n", "run.sh"),
            "in-notes-py": (f"# {OLD} lists the notes\n", "# ISR Bot lists the notes\n", "notes.py"),
        }
        ds = {}
        for n, (was, _, rel) in cases.items():
            ds[n] = self.make(n, skill_md(n, OLD) if rel != "SKILL.md" else was)
            if rel != "SKILL.md":
                self.rewrite(ds[n], was, rel=rel)
        self.approve()
        for n, (_, now, rel) in cases.items():
            self.rewrite(ds[n], now, rel=rel)
            if rel != "SKILL.md":
                self.rewrite(ds[n], skill_md(n, "ISR Bot"))   # the prose swap beside it stays its own low finding
        self.audit()
        rows = {r["name"]: r for r in self.fix()["changed_skills"]}
        for n, (_, _, rel) in cases.items():
            with self.subTest(n):
                fs = self.i001(ds[n], rel)
                self.assertEqual(len(fs), 1, fs)
                self.assertEqual(fs[0]["severity"], "high")
                self.assertFalse(fs[0].get("rename_only"))
                self.assertNotIn("diff", fs[0])
                self.assertFalse(rows[n].get("rename_only"))   # the skill isn't offered as name-only

    def test_code_in_a_description_stays_high(self):   # replay (FIX3, Codex high 1): on 793835f each was low and rename_only
        cases = {   # name: description lines, with {} for the name
            "desc-inline-code": "description: Run `notes --label {} --all`.\n",
            "desc-wrapped-code": "description: >\n  Run `notes\n  --label {}\n  --all` first.\n",
        }
        ds = {n: self.make(n, f"---\nname: {n}\n{desc.format(OLD)}---\n# Notes\nList the open tasks.\n") for n, desc in cases.items()}
        self.approve()
        for n, desc in cases.items():
            self.rewrite(ds[n], f"---\nname: {n}\n{desc.format('ISR Bot')}---\n# Notes\nList the open tasks.\n")
        self.audit()
        rows = {r["name"]: r for r in self.fix()["changed_skills"]}
        for n, d in ds.items():
            with self.subTest(n):
                fs = self.i001(d)
                self.assertEqual(len(fs), 1, fs)
                self.assertEqual(fs[0]["severity"], "high")
                self.assertFalse(fs[0].get("rename_only"))
                self.assertNotIn("diff", fs[0])
                self.assertFalse(rows[n].get("rename_only"))

    def desc_cases(self, cases):
        """{name: (I001 findings, preview row)} after each description (lines with {} for the name) swaps the name."""
        ds = {n: self.make(n, f"---\nname: {n}\n{desc.replace('{}', OLD)}---\n# Notes\nList the open tasks.\n") for n, desc in cases.items()}
        self.approve()
        for n, desc in cases.items():
            self.rewrite(ds[n], f"---\nname: {n}\n{desc.replace('{}', 'ISR Bot')}---\n# Notes\nList the open tasks.\n")
        self.audit()
        rows = {r["name"]: r for r in self.fix()["changed_skills"]}
        return {n: (self.i001(d), rows[n]) for n, d in ds.items()}

    def test_fenced_code_in_a_description_stays_high(self):   # replay (FIX4, Codex r4 high): on 3843eb9 each was low and rename_only
        got = self.desc_cases({   # a fenced block in a `description: |`, as the body reads one: ~~~ or ``` fences, indented ones too
            "desc-tilde-fence": "description: |\n  Tidy the notes folder:\n  ~~~sh\n  notes --label {} --all\n  ~~~\n",
            "desc-indented-tilde-fence": "description: |\n  Tidy the notes folder:\n    ~~~sh\n    notes --label {} --all\n    ~~~\n",
            "desc-backtick-fence": "description: |\n  ```sh\n  echo ```\n  notes --label {} --all\n  ```\n",
        })
        for n, (fs, row) in got.items():
            with self.subTest(n):
                self.assertEqual(len(fs), 1, fs)
                self.assertEqual(fs[0]["severity"], "high")
                self.assertFalse(fs[0].get("rename_only"))
                self.assertNotIn("diff", fs[0])
                self.assertFalse(row.get("rename_only"))

    def test_code_span_swap_in_a_description_stays_high(self):   # control (FIX4): a swap inside a span, prose swap beside it
        got = self.desc_cases({
            "desc-span-and-prose": "description: {} runs `notes --label {} --all`.\n",
            "desc-plain-backtick-fence": "description: |\n  ```sh\n  notes --label {} --all\n  ```\n",   # high on 3843eb9 too
        })
        for n, (fs, row) in got.items():
            with self.subTest(n):
                self.assertEqual([(f["severity"], f.get("rename_only")) for f in fs], [("high", None)])
                self.assertFalse(row.get("rename_only"))

    def test_prose_beside_a_description_code_span_is_name_only(self):   # replay (FIX4, Codex r4 med): on 3843eb9 each was high
        got = self.desc_cases({   # the swap is in the prose; the code span on the line (or the next one) holds no name
            "desc-prose-span": "description: {} uses `notes --all` to tidy the notes folder.\n",
            "desc-wrapped-prose-span": "description: >\n  {} uses `notes\n  --all` to tidy the notes folder.\n",
            "desc-prose-after-span": "description: >\n  Run `notes --all`, then {} lists\n  the open tasks.\n",
        })
        for n, (fs, row) in got.items():
            with self.subTest(n):
                self.assertEqual([(f["severity"], f.get("rename_only")) for f in fs], [("low", True)])
                self.assertIs(row.get("rename_only"), True)

    def test_plain_description_swap_is_still_name_only(self):   # control (FIX3): description prose, one line or wrapped
        cases = {
            "desc-prose": "description: {} tidies the notes folder.\n",
            "desc-wrapped-prose": "description: >\n  {} tidies the notes\n  folder.\n",
        }
        ds = {n: self.make(n, f"---\nname: {n}\n{desc.format(OLD)}---\n# Notes\nList the open tasks.\n") for n, desc in cases.items()}
        self.approve()
        for n, desc in cases.items():
            self.rewrite(ds[n], f"---\nname: {n}\n{desc.format('ISR Bot')}---\n# Notes\nList the open tasks.\n")
        self.audit()
        rows = {r["name"]: r for r in self.fix()["changed_skills"]}
        for n, d in ds.items():
            with self.subTest(n):
                self.assertEqual([(f["severity"], f.get("rename_only")) for f in self.i001(d)], [("low", True)])
                self.assertIs(rows[n].get("rename_only"), True)

    def test_runnable_doc_file_stays_high(self):   # replay: an executable .md and a .md with a #! line
        ex, sb = self.make("exec-md", skill_md("exec-md", OLD)), self.make("shebang-md", "#!/bin/sh\n" + skill_md("shebang-md", OLD))
        self.approve()
        self.rewrite(ex, skill_md("exec-md", "ISR Bot"))
        os.chmod(os.path.join(ex, "SKILL.md"), 0o755)
        self.rewrite(sb, "#!/bin/sh\n" + skill_md("shebang-md", "ISR Bot"))
        self.audit()
        for d in (ex, sb):
            with self.subTest(os.path.basename(d)):
                self.assertEqual([(f["severity"], f.get("rename_only")) for f in self.i001(d)], [("high", None)])

    def test_prose_next_to_code_is_still_name_only(self):   # control: prose lines, a code span elsewhere on the line, a description
        was = ("---\nname: notes-prose\ndescription: {} tidies the notes folder.\nallowed-tools: Bash(notes --all)\n---\n# Notes\n"
               "{} reads the notes. Run `notes --all` first.\n```sh\nnotes --all\n```\n{} lists the open tasks.\n"
               "- {} keeps the list.\n")
        d = self.make("notes-prose", was.format(OLD, OLD, OLD, OLD))
        os.makedirs(os.path.join(d, "references"))
        self.rewrite(d, f"{OLD} reads the notes.\n", rel="references/notes.txt")
        self.approve()
        self.rewrite(d, was.format(*["ISR Bot"] * 4))
        self.rewrite(d, "ISR Bot reads the notes.\n", rel="references/notes.txt")
        self.audit()
        self.assertEqual([(f["severity"], f.get("rename_only"), f["evidence"]) for f in self.i001(d)], [("low", True, f"{OLD} → ISR Bot on 4 lines")])
        self.assertEqual([(f["severity"], f.get("rename_only")) for f in self.i001(d, "references/notes.txt")], [("low", True)])
        self.assertIs([r for r in self.fix()["changed_skills"] if r["name"] == "notes-prose"][0].get("rename_only"), True)


class RenameReviewed(_Rename):
    def two_files(self):
        d = self.make("notes-two", skill_md("notes-two", OLD))
        os.makedirs(os.path.join(d, "references"))
        self.rewrite(d, "# Notes\nList the open tasks.\n", rel="references/notes.md")
        self.approve()
        self.rewrite(d, skill_md("notes-two", "ISR Bot"))
        self.rewrite(d, "# Notes\nList the open tasks.\nAlso list the due dates.\n", rel="references/notes.md")
        self.audit()
        return d

    def test_rename_reviewed_reapproves_only_rename_files(self):   # replay: base has no such path (an argparse error)
        d = self.two_files()
        self.assertEqual([f["severity"] for f in self.i001(d)], ["low"])
        self.assertEqual([f["severity"] for f in self.i001(d, "references/notes.md")], ["high"])
        row = [r for r in self.fix()["changed_skills"] if r["name"] == "notes-two"]
        self.assertEqual(len(row), 1, row)
        self.assertIs(row[0].get("rename_only"), False)   # one of its two changed files is more than the name
        self.assertEqual(row[0].get("rename_reviewed"), "isr.py fix --rename-reviewed notes-two --owner-said-yes")
        done = self.fix("--rename-reviewed", "notes-two", "--owner-said-yes")["done"]
        self.assertIn("notes-two: approved the new product name in 1 file(s). 1 other changed file(s) stay open for a re-scan", done)
        self.audit()
        self.assertEqual(self.i001(d), [])
        self.assertEqual([f["severity"] for f in self.i001(d, "references/notes.md")], ["high"])
        self.assertEqual(isr.skill_diff(d)["files"], ["references/notes.md"])   # the real edit keeps its old approved copy
        self.assertEqual(isr.load_baseline()[0][os.path.join(d, "SKILL.md")], isr.sha256_file(os.path.join(d, "SKILL.md")))
        events = [json.loads(l) for l in open(isr.state_path("ledger.jsonl"))]
        self.assertEqual([e["files"] for e in events if e.get("event") == "reapprove_rename"], [["SKILL.md"]])

    def test_preview_row_says_rename_only(self):   # replay: base row has no rename_only
        d = self.make("notes-one", skill_md("notes-one", OLD))
        self.approve()
        self.rewrite(d, skill_md("notes-one", "ISR Bot"))
        self.audit()
        row = [r for r in self.fix()["changed_skills"] if r["name"] == "notes-one"]
        self.assertEqual(len(row), 1, row)
        self.assertIs(row[0].get("rename_only"), True)
        self.assertEqual(row[0].get("rename_reviewed"), "isr.py fix --rename-reviewed notes-one --owner-said-yes")

    def test_rename_reviewed_needs_the_owners_yes(self):   # replay: base has no such path (an argparse error)
        d = self.make("notes-one", skill_md("notes-one", OLD))
        self.approve()
        base0 = isr.load_baseline()[0]
        self.rewrite(d, skill_md("notes-one", "ISR Bot"))
        self.audit()
        self.assertEqual([f["severity"] for f in self.i001(d)], ["low"])
        done = self.fix("--rename-reviewed", "notes-one")["done"]
        self.assertTrue(any(x.startswith("Nothing approved: --rename-reviewed needs --owner-said-yes") for x in done), done)
        self.assertEqual(isr.load_baseline()[0], base0)
        done = self.fix("--rename-reviewed", "skill-nobody-has", "--owner-said-yes")["done"]
        self.assertIn("skill-nobody-has: nothing approved. It has no open change that is the product name only", done)
        self.audit()
        self.assertEqual([f["severity"] for f in self.i001(d)], ["low"])

    def test_rename_reviewed_refuses_a_file_changed_since(self):   # replay: base has no such path (an argparse error)
        d = self.make("notes-one", skill_md("notes-one", OLD))
        self.approve()
        base0 = isr.load_baseline()[0]
        self.rewrite(d, skill_md("notes-one", "ISR Bot"))
        self.audit()
        self.assertEqual([f["severity"] for f in self.i001(d)], ["low"])
        self.rewrite(d, skill_md("notes-one", "ISR Bot", "Also list the due dates.\n"))   # after the owner read the diff
        done = self.fix("--rename-reviewed", "notes-one", "--owner-said-yes")["done"]
        self.assertIn("notes-one: nothing approved. Not a name-only change now, so it stays open: SKILL.md", done)
        self.assertEqual(isr.load_baseline()[0], base0)
        self.audit()
        self.assertEqual([f["severity"] for f in self.i001(d)], ["high"])


if __name__ == "__main__":
    unittest.main()
