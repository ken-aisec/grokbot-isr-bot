"""v0.8.0 rename, unit 0: the reviewed name table (tests/golden_rename_v080.json) is well formed. Every entry is unique, and
where one old value holds another the longer one comes first; no entry maps a name to itself; no new value holds an old name
and each passes the name guards of test_v074_display_name, through the same blank(); the old and new layouts are complete."""
import ast, hashlib, json, os, re, unittest
from unittest import mock

import rename_v080 as rn
import test_v074_display_name as v074

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The engine's environment variables (plan §1: every one becomes ISR_BOT_*), by role; the rest are script-local (ISR_*)
ENGINE_ENV = ("home", "settings", "platform_reviewed", "platform_normalize", "decoy_root", "run_limit", "daily_limit",
              "engine_budget", "engine_launch_base", "engine_solo_limit")
LAYOUT_KEYS = {"pkg", "main", "parts", "parts_var", "part_loader", "home", "home_name", "sandbox_home", "repo", "rule_prefix",
               "test_module", "slug_prefix", "env"}
PLAN_ORDER = ["b", "c", "d1", "d2a", "d2b", "e", "f", "g", "h1", "h2", "k", "i"]   # plan section 3, the units that map names


def read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


def entry_dicts():
    """Every source entry of every unit, and each exempt region's allowed entries."""
    src = rn.TABLE["source"]
    return [e for es in src["units"].values() for e in es] + [a for r in src["exempt_regions"] for a in r.get("allow", [])]


def apply(e, text):
    return re.sub(e["re"], e["new"], text) if "re" in e else text.replace(e["old"], e["new"])


def line_key(l):
    """How source.held_lines names a line: the sha256 of its stripped text, first 16 hex."""
    return hashlib.sha256(l.strip().encode("utf-8")).hexdigest()[:16]


def map_units(units, rel, text, protect=True):
    """text through each unit's plain source entries in turn, as the probe applies them: keep_spans held, an entry's files and
    unit_files honoured, the historical lines (and a reader file's old-output lines) left as they are and a held line spared
    its entry, unless protect is off."""
    src = rn.TABLE["source"]
    keep = [re.compile(k["re"]) for k in src["keep_spans"]]
    texts = {h["text"] for h in src["historical"]["lines"] if h["file"] == rel}
    spare = {}
    for h in src["held_lines"]["lines"]:
        if h["file"] == rel and protect:
            spare.setdefault(h["sha256"], set()).add(h["old"])
    reader = os.path.basename(rel) in src["reader_files"]
    for u in units:
        entries = [e for e in src["units"][u] if not e.get("scope") and ("files" not in e or os.path.basename(rel) in e["files"])
                   and (u not in src["unit_files"] or os.path.basename(rel) in src["unit_files"][u])]
        out = []
        for l in text.split("\n"):
            if protect and (l.strip() in texts or (reader and ("workspace/watchtower" in l or re.search(r"Watchtower\b", l)))):
                out.append(l)
                continue
            spared = spare.get(line_key(l), set())
            held = []
            for rx in keep:
                l = rx.sub(lambda m: held.append(m.group(0)) or f"\x00{len(held) - 1}\x00", l)
            for e in entries:
                if e.get("old") not in spared:
                    l = apply(e, l)
            out.append(re.sub("\x00(\\d+)\x00", lambda m: held[int(m.group(1))], l))
        text = "\n".join(out)
    return text


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
    out.append(("exempt_regions", [(a["old"], a["new"], False) for r in t["source"]["exempt_regions"] for a in r.get("allow", [])]))
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
        src = rn.TABLE["source"]
        self.assertEqual(list(src["units"]), src["order"])
        self.assertEqual(src["order"], PLAN_ORDER)
        self.assertEqual(src["units"]["d2a"], src["units"]["d2b"])   # one list: d2a applies it to its importers only, d2b to the rest
        d2a = src["unit_files"]["d2a"]
        self.assertEqual(sorted(set(src["unit_files"]) - {"about"}), ["d2a"])
        self.assertTrue(d2a and len(set(d2a)) == len(d2a) and not set(d2a) & set(src["exporters"]), d2a)
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
        kept = rn.TABLE["kept_values"]["values"]
        moved = [(k, v["value"], e) for k, v in kept.items() for e in entry_dicts() if apply(e, v["value"]) != v["value"]]
        self.assertEqual(moved, [])   # Codex r1 LOW 8: a kept value stays byte for byte; h2 spells it through kept()
        self.assertTrue(all(rx.search(v["value"]) for v in kept.values() for rx in rn.old_patterns()[1:]), kept)

    def test_no_new_value_holds_an_old_token(self):
        # d1 writes the test alias (fixes-d1: the embedded programs keep their old references for one unit); d2a and d2b take it out
        alias = "import %s as %s" % (rn.NEW["main"][:-len(".py")], rn.OLD["main"][:-len(".py")])
        units = rn.TABLE["source"]["units"]
        self.assertEqual(sorted({u for u, es in units.items() for e in es if alias in e["new"]}), ["d1"])
        for u in ("d2a", "d2b"):
            self.assertIn({"old": alias, "new": alias[:alias.index(" as ")]}, units[u])
        bad = [n for n in new_values() for rx in rn.old_patterns() if rx.search(n.replace(alias, ""))]
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
        self.assertEqual(rn.kept("platform_record_v1"), rn.TABLE["kept_values"]["values"]["platform_record_v1"]["value"])
        # every place the table protects is real now: the historical lines, and where each exempt region starts
        src = rn.TABLE["source"]
        for h in src["historical"]["lines"]:
            self.assertIn(h["text"], [l.strip() for l in read(h["file"]).splitlines()], h["file"])
        for r in src["exempt_regions"]:
            lines = read(r["file"]).splitlines()
            self.assertTrue(any(re.match(f, l) for f in r["from"] for l in lines), r["why"])
            self.assertTrue(r["units"] == "all" or set(r["units"]) <= set(src["order"]), r["why"])

    def test_golden_split_kept_strings_stay_old_through_g(self):   # replay (Codex r2 HIGH: g's map rewrote SUBST_KEEP and SUBST_KEEP_PROSE)
        rel, order = "tests/golden_split.py", rn.TABLE["source"]["order"]
        units = order[order.index("b"):order.index("g") + 1]
        text = read(rel)

        def literals(t):
            return {n.targets[0].id: ast.get_source_segment(t, n) for n in ast.parse(t).body if isinstance(n, ast.Assign)
                    and isinstance(n.targets[0], ast.Name) and n.targets[0].id in ("SUBST_KEEP", "SUBST_KEEP_PROSE")}
        self.assertEqual(sorted(literals(text)), ["SUBST_KEEP", "SUBST_KEEP_PROSE"])
        mapped = map_units(units, rel, text)
        self.assertEqual(literals(mapped), literals(text))   # h2 converts them, not b-g
        # unit h2 converts SUBST_KEEP/_PROSE to the helper, so it must update this line (its literals then hold no old name)
        self.assertNotEqual(literals(map_units(units, rel, text, protect=False)), literals(text))   # unprotected, g changes them
        # only the two literals are held: golden_split.py is no reader file, so c, d2b and f still rename the sandbox home line
        self.assertNotIn(os.path.basename(rel), rn.TABLE["source"]["reader_files"])
        # d1 fix 2: the home line may already be part renamed (c made it ISR_HOME), so it must be the old line taken through
        # some prefix of the unit order, the empty prefix included, whichever unit the tree is at
        old_line = "%s = %s if SEALED else X + %s" % (rn.OLD["env"]["install_home"], json.dumps(rn.OLD["home"]),
                                                       json.dumps("/" + rn.OLD["sandbox_home"]))
        forms = {map_units(order[:k], rel, old_line) for k in range(len(order) + 1)}
        self.assertIn(old_line, forms)
        self.assertEqual(len([l for l in text.split("\n") if l in forms]), 1, sorted(forms))
        home = next(l for l in text.split("\n") if l in forms)
        bogus = text.replace(home, home.split(" = ")[0] + " = " + json.dumps("/elsewhere"))
        self.assertEqual([l for l in bogus.split("\n") if l in forms], [])   # an unrelated home line fails the check
        self.assertIn(rn.NEW["env"]["install_home"] + " = " + json.dumps(rn.NEW["home"]), mapped)

    def test_d1_main_file_entry_spares_attributes(self):   # replay (d1 fix 1: the plain main-file entry hit the alias's python_upgrades)
        order, old, new = rn.TABLE["source"]["order"], rn.OLD["main"], rn.NEW["main"]
        units = order[:order.index("d1") + 1]
        attr = "        %s = lambda: []" % (old[:-len("py")] + "python_upgrades")   # the test alias's attribute: d2's entry renames it
        self.assertEqual(map_units(units, "tests/test_boxes.py", attr), attr)
        self.assertNotEqual(apply({"old": old, "new": new}, attr), attr)   # a plain entry changes it
        for before, after in ((f"python3 {old} vet", f"python3 {new} vet"), (f'"{old}"', f'"{new}"'),
                              (f"'{old}'", f"'{new}'"), (f"({old})", f"({new})"), (f"run {old}", f"run {new}")):
            self.assertEqual(map_units(units, "tests/test_boxes.py", before), after)

    def test_d2_open_mode_span_spares_the_module(self):   # replay (d2a fix 1: the "wt" mode span held a wt. call in the same open)
        order, old, new = rn.TABLE["source"]["order"], rn.OLD["main"][:-len("py")], rn.NEW["main"][:-len("py")]
        line = '        with gzip.open(%sapproved_path(d), "wt") as f:' % old
        want = line.replace(old, new)
        self.assertIn(', "wt")', want)   # the file mode stays
        plain = '        with open(p, "wt") as f:'
        for u, rel in (("d2a", "tests/test_batch6_mask.py"), ("d2b", "tests/test_boxes.py")):
            self.assertEqual(os.path.basename(rel) in rn.TABLE["source"]["unit_files"]["d2a"], u == "d2a")
            units = order[:order.index(u) + 1]
            self.assertEqual(map_units(units, rel, line), want)
            self.assertEqual(map_units(order, rel, plain), plain)
            # the d2a build's span held the whole call, the module reference included, so it stayed old
            with mock.patch.dict(rn.TABLE["source"], {"keep_spans": [{"re": 'open\\([^\\n]*?, "wt"'}]}):
                self.assertEqual(map_units(units, rel, line), line)

    def test_d2_open_mode_span_holds_only_the_mode(self):   # replay (d2b table fix: the "wt" mode span held a home folder in the path)
        order, old, new = rn.TABLE["source"]["order"], json.dumps(rn.OLD["sandbox_home"]), json.dumps(rn.NEW["sandbox_home"])
        line = '        with open(os.path.join(self.tmp, %s, "exports", "roster.json"), "w") as f:' % old
        want = line.replace(old, new)
        self.assertNotEqual(want, line)
        modes = ('        with gzip.open(p, "wt", encoding="utf-8") as f:', '        with open(p, "wt") as f:')
        units = order[:order.index("d2b") + 1]
        for rel in ("tests/test_v069.py", "tests/test_v074_display_name.py"):
            self.assertNotIn(os.path.basename(rel), rn.TABLE["source"]["unit_files"]["d2a"])
            self.assertEqual(map_units(units, rel, line), want)
            for m in modes:
                self.assertEqual(map_units(order, rel, m), m)   # the file mode stays
            # the d2a fix 1 span ran to any ', "wt"' in the call, the home folder included, so the folder stayed old
            with mock.patch.dict(rn.TABLE["source"], {"keep_spans": [{"re": 'open\\((?:(?!wt\\.)[^\\n])*?, "wt"'}]}):
                self.assertEqual(map_units(units, rel, line), line)

    def test_d2_alias_entry_spares_the_name_guard_data(self):   # replay (d2b fix 1: d2's alias entry hit A5, C's bounds data and a comment)
        rel, order = "tests/test_v074_display_name.py", rn.TABLE["source"]["order"]
        units = order[:order.index("d2b") + 1]
        new = rn.NEW["main"][:-len(".py")]
        alias = "import %s as %s" % (new, rn.OLD["main"][:-len(".py")])
        held = rn.TABLE["source"]["held_lines"]["lines"]
        self.assertEqual({(h["file"], h["old"]) for h in held}, {(rel, alias)})   # one entry, one file
        self.assertNotIn(os.path.basename(rel), rn.TABLE["source"]["unit_files"]["d2a"])
        text = read(rel)
        lines = text.split("\n")
        at = sorted(i for h in held for i, l in enumerate(lines) if line_key(l) == h["sha256"])
        self.assertEqual(len(held), 5)
        self.assertEqual(len(at), len(held))   # each key names one line of the file: none is stale
        self.assertEqual(map_units(units, rel, text), text)   # the 5 lines stay as they are
        # only those lines: a new alias line in the same file, or in another d2b file, still loses the alias
        self.assertEqual(map_units(units, rel, "    " + alias), "    import " + new)
        for other in ("tests/test_boxes.py", "tests/test_v069.py"):
            self.assertNotIn(os.path.basename(other), rn.TABLE["source"]["unit_files"]["d2a"])
            self.assertEqual(map_units(units, other, alias), "import " + new)
        # without the hold, d2's alias entry changes exactly those 5 lines
        with mock.patch.dict(rn.TABLE["source"], {"held_lines": {"lines": []}}):
            mapped = map_units(units, rel, text).split("\n")
        self.assertEqual(len(mapped), len(lines))
        self.assertEqual([i for i, (a, b) in enumerate(zip(lines, mapped)) if a != b], at)

    def test_f_maps_the_own_release_with_the_brief_that_reads_it(self):   # replay (f fix 1: feeds.json "installed" was only in g)
        order, units = rn.TABLE["source"]["order"], rn.TABLE["source"]["units"]
        upto_f = order[:order.index("f") + 1]
        feeds_rel, brief_rel = "rules/feeds.json", "isr_bot/isr_parts/brief.py"
        old, new = json.dumps(rn.OLD["home_name"]), json.dumps(rn.NEW["home_name"])
        own_rx = re.compile(r'"installed": ("[^"]*")')
        brief_rx = re.compile(r'(?:r\.get\("installed"\)|name) == ("[^"]*")')

        def values(feeds, brief):
            """The own release's "installed" value in feeds.json, and every value brief.py compares a release name with."""
            own = [r for r in json.loads(feeds)["releases"] if r["repo"] == rn.NEW["repo"]]
            self.assertEqual(len(own), 1)
            return own[0]["installed"], {json.loads(m.group(1)) for m in brief_rx.finditer(brief)}

        feeds, brief = map_units(upto_f, feeds_rel, read(feeds_rel)), map_units(upto_f, brief_rel, read(brief_rel))
        mine, compared = values(feeds, brief)
        self.assertEqual(len(brief_rx.findall(brief)), 2)   # version_of's check and the releases loop's
        self.assertEqual(compared, {mine})
        self.assertEqual(mine, rn.NEW["home_name"])
        # the same files before f: the own-release line and brief.py's two compares hold the old home name
        own_line = next(l for l in feeds.split("\n") if own_rx.search(l) and new in l)
        brief_lines = [l for l in brief.split("\n") if brief_rx.search(l)]
        old_feeds = feeds.replace(own_line, own_line.replace(new, old))
        old_brief = brief
        for l in brief_lines:
            old_brief = old_brief.replace(l, l.replace(new, old))
        self.assertEqual(map_units(upto_f, feeds_rel, old_feeds), feeds)
        self.assertEqual(map_units(upto_f, brief_rel, old_brief), brief)
        # the f build left the two "installed" entries in g: brief.py's compares moved and the value they read did not
        moved = [e for e in units["f"] if '"installed"' in e.get("old", "")]
        self.assertEqual(len(moved), 2)
        with mock.patch.dict(units, {"f": [e for e in units["f"] if e not in moved], "g": moved + units["g"]}):
            mine, compared = values(map_units(upto_f, feeds_rel, old_feeds), map_units(upto_f, brief_rel, old_brief))
        self.assertEqual(mine, rn.OLD["home_name"])
        self.assertNotIn(mine, compared)


if __name__ == "__main__":
    unittest.main()
