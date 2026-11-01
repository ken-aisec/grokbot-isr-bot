"""v0.8.4 release: the scanner lock carries the fixed versions of the three packages ISR-W001 flagged (pip-audit's fix versions).

filelock 4.0.12 -> 4.2.1, langgraph-sdk 0.4.5 -> 0.4.6, pypdf 6.19.0 -> 6.21.4, each with both sha256 hashes from PyPI.

The test marked "replay" fails on abea324 at its assertion; the "guard" passes there too."""
import os, re, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import ROOT  # noqa: E402

LOCK = os.path.join(ROOT, "scripts", "scanners.lock")
FIXED = {"filelock": "4.2.1", "langgraph-sdk": "0.4.6", "pypdf": "6.21.4"}


def entries():
    """{name: [(version, [hashes])]} for every `name==version` entry in the lock, in order."""
    with open(LOCK) as f:
        text = f.read()
    out, cur = {}, None
    for line in text.splitlines():
        m = re.match(r"([A-Za-z0-9._-]+)==(\S+)", line)
        if m:
            cur = (m.group(2), [])
            out.setdefault(m.group(1).lower(), []).append(cur)
            continue
        h = re.match(r"\s+--hash=sha256:([0-9a-f]{64})", line)
        if h and cur:
            cur[1].append(h.group(1))
        elif not line.startswith(" "):
            cur = None
    return out


def version(v):
    return tuple(int(x) for x in re.findall(r"\d+", v))


class ScannerLockFixedVersions(unittest.TestCase):
    def test_the_three_flagged_pins_are_at_their_fixed_versions(self):   # replay
        lock = entries()
        for name, want in FIXED.items():
            pins = lock.get(name, [])
            self.assertEqual(len(pins), 1, (name, pins))   # one pin, so no older one of that name is left
            have, hashes = pins[0]
            self.assertGreaterEqual(version(have), version(want), name)
            self.assertEqual(len(hashes), 2, (name, have))

    def test_every_entry_still_has_a_hash(self):   # guard
        lock = entries()
        self.assertGreater(len(lock), 50)   # the parser found the lock's entries (85 at v0.8.4)
        self.assertEqual([n for n, pins in lock.items() for _, hs in pins if not hs], [])


if __name__ == "__main__":
    unittest.main()
