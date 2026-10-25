"""v0.8.0 rename, unit h2: the leftover guard. No tracked file or path says an old name (rename_v080.old_patterns(): the old
product word in any case, and the old short name as a token of its own) outside the four places old names may stay: CHANGELOG.md
from its "## 0.7.4" heading down, tests/golden_expect/*.json, docs/KNOWN-LIMITS.md below its "Before 0.8.0" marker, and the
name table itself. The one other exception is the text-write file mode of open and gzip.open, which the table's keep_spans hold:
it is no name. Tests and the harness spell an old name through the table (tests/rename_v080.py)."""
import fnmatch, os, re, subprocess, unittest

import rename_v080 as rn

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TABLE_REL = os.path.relpath(rn.TABLE_PATH, ROOT).replace(os.sep, "/")
MARKER = "## Before 0.8.0 (entries keep the names of their time)"
WHOLE = ("tests/golden_expect/*.json", TABLE_REL)   # whole files
FROM = {"CHANGELOG.md": "## 0.7.4", "docs/KNOWN-LIMITS.md": MARKER}   # from this exact line to the end of the file
KEEP = [re.compile(k["re"]) for k in rn.TABLE["source"]["keep_spans"]]
MODE = '"%s"' % rn.kept("file_mode")
# owner's decision, Oct 25: the dev checkout's real folder name; ownership.py must name it so the dev tree is never scored.
# This one line of that one file, matched whole, and nothing else.
DEV_LINE = ("isr_bot/isr_parts/ownership.py",
            'OWNER_SELF_WORKSPACE += ("%s-dev",)   # the dev checkout\'s real folder name: the dev tree is never scored' % rn.OLD["pkg"])


def tracked():
    try:
        out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError) as e:
        raise unittest.SkipTest(f"no git checkout here ({type(e).__name__})")
    return sorted(p for p in out.decode().split("\0") if p)


def tracked_texts():
    for rel in tracked():
        p = os.path.join(ROOT, rel)
        if os.path.isfile(p) and not os.path.islink(p):
            with open(p, "rb") as f:
                yield rel, f.read().decode("utf-8", "replace")


def whole(rel):
    """True for a file that may hold old names anywhere ("*" stays inside one path segment)."""
    return any(fnmatch.fnmatch(rel, g) and rel.count("/") == g.count("/") for g in WHOLE)


def exempt_from(rel, lines):
    """The index of the first line of rel that may hold old names: 0 for a whole file, FROM's line, or len(lines) (none)."""
    if whole(rel):
        return 0
    return next((i for i, l in enumerate(lines) if rel in FROM and l == FROM[rel]), len(lines))


def unmode(line):
    """The line with the file mode a keep_span ends on blanked (the mode argument only, never the rest of the call)."""
    for rx in KEEP:
        line = rx.sub(lambda m: m.group(0)[:-len(MODE)] + " " * len(MODE) if m.group(0).endswith(MODE) else m.group(0), line)
    return line


def hits(rel, text):
    """The line numbers at which rel's text says an old name outside its exempt part."""
    lines = text.split("\n")
    return [i + 1 for i, l in enumerate(lines[:exempt_from(rel, lines)])
            if (rel, l) != DEV_LINE and any(rx.search(unmode(l)) for rx in rn.old_patterns())]


class Leftovers(unittest.TestCase):
    def test_no_old_name_in_tracked_content(self):   # guard
        texts = list(tracked_texts())
        self.assertGreater(len(texts), 150)
        bad = [f"{rel}:{n}" for rel, text in texts for n in hits(rel, text)]
        self.assertEqual(bad, [])

    def test_no_old_name_in_any_tracked_path(self):   # guard
        paths = tracked()
        self.assertIn("isr_bot/isr.py", paths)
        self.assertEqual([p for p in paths if any(rx.search(p) for rx in rn.old_patterns())], [])

    def test_the_exempt_places_are_exactly_these(self):   # bounds, both sides on synthetic text, and the table agrees
        old = rn.old_display()[0][0]
        line = f"{old} said it\n"
        for rel in ("tests/golden_expect/v074.json", "tests/golden_expect/new.json", TABLE_REL):
            self.assertEqual(hits(rel, line), [], rel)
        for rel in ("tests/golden_expect/sub/x.json", "tests/golden_expect.json", "tests/golden_expect/v074.md",
                    "golden_expect/v074.json", "tests/golden_rename_v080.md", "docs/golden_rename_v080.json", "README.md",
                    "docs/CHANGELOG.md", "KNOWN-LIMITS.md", "tests/test_v080_leftovers.py"):
            self.assertEqual(hits(rel, line), [1], rel)
        for rel, start in FROM.items():
            self.assertEqual(hits(rel, f"top\n{line}{start}\n{line}"), [2], rel)   # above the line: flagged; below it: not
            self.assertEqual(hits(rel, f"{line} {start}\n{line}"), [1, 3], rel)   # only that exact line starts it
            self.assertEqual(hits(rel, line + line), [1, 2], rel)
        for rel in ("CHANGELOG.md", "docs/KNOWN-LIMITS.md"):
            other = "docs/KNOWN-LIMITS.md" if rel == "CHANGELOG.md" else "CHANGELOG.md"
            self.assertEqual(hits(rel, f"{FROM[other]}\n{line}"), [2], rel)   # the other file's start line starts nothing here
        # the file mode: only the mode argument of an open call the keep_span holds, never a name beside it
        self.assertEqual(hits("x.py", '    with gzip.open(p, %s) as f:\n' % MODE), [])
        self.assertEqual(hits("x.py", '    with open(p, %s, encoding="utf-8") as f:\n' % MODE), [])
        for text in ('    mode = %s\n' % MODE, '    with open(%s) as f:\n' % MODE,
                     '    with gzip.open(%s.approved_path(d), %s) as f:\n' % (rn.OLD["main"][:-len(".py")], MODE)):
            self.assertEqual(hits("x.py", text), [1], text)
        # the table's own exemptions, in force from h2 on, are these same places
        src = rn.TABLE["source"]
        self.assertEqual(sorted(src["exempt_files"]), sorted(WHOLE))
        for unit in ("h2", "k", "i"):
            live = [r for r in src["exempt_regions"] if r["units"] == "all" or unit in r["units"]]
            self.assertEqual(sorted(r["file"] for r in live), sorted(FROM), unit)
            for r in live:
                with open(os.path.join(ROOT, r["file"]), encoding="utf-8") as f:
                    lines = f.read().split("\n")
                first = next(i for i, l in enumerate(lines) if any(re.match(f, l) for f in r["from"]))
                self.assertEqual(first, exempt_from(r["file"], lines), (unit, r["file"]))

    def test_no_stale_exemption(self):   # guard: each place still holds an old name, and each start line is there once
        texts = dict(tracked_texts())
        found = {}
        for rel, text in texts.items():
            lines = text.split("\n")
            part = lines[exempt_from(rel, lines):]
            if any(rx.search(l) for l in part for rx in rn.old_patterns()):
                place = next((g for g in WHOLE if whole(rel) and fnmatch.fnmatch(rel, g)), rel)
                found[place] = found.get(place, 0) + 1
        self.assertEqual(sorted(found), sorted(set(WHOLE) | set(FROM)))
        self.assertTrue([rel for rel in texts if whole(rel) and rel != TABLE_REL])
        for rel, start in FROM.items():
            self.assertEqual(texts[rel].split("\n").count(start), 1, rel)
        self.assertTrue([rel for rel, text in texts.items() for l in text.split("\n") if unmode(l) != l])   # the mode is still used


if __name__ == "__main__":
    unittest.main()
