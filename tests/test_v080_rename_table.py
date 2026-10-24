"""v0.8.0 rename, unit 0: the reviewed name table (tests/golden_rename_v080.json) is well formed. Every entry is unique, and
where one old value holds another the longer one comes first; no entry maps a name to itself; no new value holds an old name
and each passes the name guards of test_v074_display_name, through the same blank(); the old and new layouts are complete."""
import json, re, unittest

import rename_v080 as rn
import test_v074_display_name as v074

# The engine's environment variables (plan §1: every one becomes ISR_BOT_*), by role; the rest are script-local (ISR_*)
ENGINE_ENV = ("home", "settings", "platform_reviewed", "platform_normalize", "decoy_root", "run_limit", "daily_limit",
              "engine_budget", "engine_launch_base", "engine_solo_limit")
LAYOUT_KEYS = {"pkg", "main", "parts", "parts_var", "part_loader", "home", "home_name", "sandbox_home", "repo", "rule_prefix",
               "test_module", "slug_prefix", "env"}


def no_duplicate_keys(pairs):
    keys = [k for k, _ in pairs]
    dup = sorted({k for k in keys if keys.count(k) > 1})
    if dup:
        raise ValueError(f"duplicate keys: {dup}")
    return dict(pairs)


def lists():
    """(name, [(old, new, is_regex)]) for the output list and each unit's source list."""
    t = rn.TABLE
    out = [("output", [(o, n, False) for o, n in t["output"]])]
    for unit, entries in t["source"]["units"].items():
        out.append((unit, [(e.get("old", e.get("re")), e["new"], "re" in e) for e in entries]))
    return out


def pairs():
    """Every (old, new) the table maps, wherever it is."""
    out = [(o, n) for _, entries in lists() for o, n, _ in entries]
    out += list(rn.TABLE["test_ids"].items())
    out += [(rn.OLD[k], rn.NEW[k]) for k in rn.OLD if k != "env"]
    out += [(rn.OLD["env"][k], rn.NEW["env"][k]) for k in rn.OLD["env"]]
    return out


def new_values():
    return [n for _, n in pairs()] + list(rn.TABLE["constant_keys"])


class RenameTable(unittest.TestCase):
    def test_entries_are_unique_and_longest_first(self):
        with open(rn.TABLE_PATH, encoding="utf-8") as f:
            json.load(f, object_pairs_hook=no_duplicate_keys)   # a repeated key would silently drop an entry
        self.assertEqual(list(rn.TABLE["source"]["units"]), rn.TABLE["source"]["order"])
        for name, entries in lists():
            olds = [(o, r) for o, _, r in entries]
            self.assertEqual(len(olds), len(set(olds)), name)
            plain = [o for o, _, r in entries if not r]
            bad = [(a, b) for i, a in enumerate(plain) for b in plain[i + 1:] if a in b]
            self.assertEqual(bad, [], name)   # a shorter old value first would eat the longer one's text
        self.assertEqual(len(set(rn.TABLE["test_ids"].values())), len(rn.TABLE["test_ids"]))

    def test_old_differs_from_new(self):
        same = [(o, n) for o, n in pairs() if o == n]
        self.assertEqual(same, [])
        self.assertGreater(len(pairs()), 150)

    def test_no_new_value_holds_an_old_token(self):
        bad = [n for n in new_values() for rx in rn.old_patterns() if rx.search(n)]
        self.assertEqual(bad, [])
        for o in (rn.OLD["pkg"], rn.OLD["pkg"].capitalize(), rn.OLD["main"], rn.OLD["parts"], rn.OLD["rule_prefix"] + "X004",
                  rn.OLD["env"]["install_home"], json.dumps(rn.OLD["sandbox_home"])):
            self.assertTrue(any(rx.search(o) for rx in rn.old_patterns()), o)   # the patterns do see old names

    def test_every_new_value_passes_the_name_guards(self):
        bad = []
        for n in new_values():
            text = json.dumps(n)   # as the table writes it, the only place A5 applies
            if v074.name_hits(v074.RENAME_TABLE, text) or v074.NeverShortened.FIRST.search(n):
                bad.append(n)
            bad += [n for m in re.finditer(r"(?i)\bisr\s+bot", n) if m.group(0) != v074.NAME]
        self.assertEqual(bad, [])

    def test_the_layouts_are_complete(self):
        self.assertEqual(set(rn.OLD), LAYOUT_KEYS)
        self.assertEqual(set(rn.NEW), LAYOUT_KEYS)
        self.assertEqual(set(rn.OLD["env"]), set(rn.NEW["env"]))
        for layout in (rn.OLD, rn.NEW):
            self.assertTrue(all(isinstance(v, str) and v for k, v in layout.items() if k != "env"), layout)
            self.assertTrue(layout["main"].endswith(".py") and layout["rule_prefix"].endswith("-"), layout)
            self.assertEqual(len(set(layout["env"].values())), len(layout["env"]))
        self.assertTrue(set(ENGINE_ENV) <= set(rn.OLD["env"]))
        for role, new in rn.NEW["env"].items():
            self.assertEqual(new.startswith("ISR_BOT_"), role in ENGINE_ENV, role)
            self.assertTrue(new.startswith("ISR_"), role)
        self.assertEqual(rn.old_rule("ISR-X004"), rn.OLD["rule_prefix"] + "X004")
        self.assertRaises(ValueError, rn.old_rule, "X004")
        self.assertEqual(rn.TABLE["constant_keys"], ["bulk-decoy-read", "own-scan-decoy-read"])
        self.assertIsInstance(rn.old_display(), list)


if __name__ == "__main__":
    unittest.main()
