"""v0.8.0 unit i (plan section 4): the golden check across the rename's two layouts. golden_split's cross mode (golden-check.sh
--cross) runs PRE_REF's tree in its own layout twice (calibration, as always) and the working tree once, then calls check() per
scenario in place of the item diff: the old layout's outputs must map onto the new one's through the name table. Old names come
from the table only (tests/rename_v080.py); the engine is never imported, and the key recipe below is this checker's own copy
(state.py finding and finding_key, text.py guard_record).

Compared: item names (old ones mapped through the table's output list) and every exit code; the records (every dict with a
string rule in a JSON stdout, a JSON or JSON-lines file of the snapshot, or a :last_findings item) by identity at each position;
every field of each paired record but its display wording (title, fix), its references through the key map included (Codex r2
HIGH 5); each keyed record's class (N, I, G or U, decided on the old side) by the recipe; the key map the pairs give (a one-to-one
function); and every other 16-hex value at its position, through that map. Not compared: report and stdout wording (the unit
tests, the mechanical checker and the leftover guard cover it). A mismatch is reported, never guessed."""
import collections, hashlib, json, re

HEX16 = re.compile(r"[0-9a-f]{16}")
DISPLAY = frozenset(("title", "fix"))            # display wording: not compared
OWN = ("key", "key0")                            # a record's own keys: the key map, never references
ID_FIELDS = ("rule", "where", "evidence", "severity", "guarded")
FINDINGS_LISTS = frozenset(("findings", "suppressed"))   # lists in which a key is never twice
PLACEHOLDER = re.compile(r'(?<=: )<(DUR|EPOCH|PID|STAT)>(?=[,\n}\]])')   # as golden_split.PLACEHOLDER_VALUE
JSONL = re.compile(r"\.jsonl(?:\.gz)?(?: #\d+)?$")
VET_JSON = re.compile(r"^\d{3,} vet .* --json\b.*:stdout$")
NEG_KEY = hashlib.sha1(b"isr-bot-golden-neg").hexdigest()[:16]        # negative c's stand-in key
NEG_REF = hashlib.sha1(b"isr-bot-golden-neg-ref").hexdigest()[:16]    # negative b's stand-in reference
# negative b's containers, in order: the item names or keys a reference sits in (the second pass when the first finds none)
NEG_REF_PLACES = ((re.compile(r"^tree .*(/state/deltas/|events)"), frozenset(("suppressed",))),
                  (re.compile(r"^tree .*(resolved|dismissed)"), frozenset(("undelivered",))))
_MISSING = object()


def _h(text):
    return hashlib.sha1(text.encode()).hexdigest()[:16]


def map_old(text, table):
    """Old text with every old output value the table lists put to its new value, in the table's order."""
    for old, new in table["output"]:
        text = text.replace(old, new)
    return text


def plain(r):
    """The key finding() gives a record (state.py finding_key), from its raw rule, where and evidence."""
    ev = r.get("evidence") or ""
    return _h(f"{r.get('rule')}|{r.get('where')}|{str(ev).replace(chr(10), ' ')[:160]}")


def klass(r):
    """N: the key is plain(r); I: the ident form (key0 is plain(r), the key another); G: the guarded form of plain(r) (text.py
    guard_record); U: anything else (keys made from inputs the output doesn't hold)."""
    key, p = r.get("key"), plain(r)
    if key == p:
        return "N"
    if r.get("key0") == p and key != p:
        return "I"
    if key == _h(p + "|guarded"):
        return "G"
    return "U"


def _parts(name, text):
    """(the lines before an item's JSON, its JSON text) or None: a :stdout or :last_findings item whole, a `tree …` file after
    its "file NNNN" line and an optional "gzip mtime N" line."""
    if not isinstance(text, str):
        return None
    if name.startswith("tree "):
        head, _, body = text.partition("\n")
        if not head.startswith("file "):
            return None
        head += "\n"
        if body.startswith("gzip mtime "):
            line, _, body = body.partition("\n")
            head += line + "\n"
        return head, body
    return ("", text) if name.endswith((":stdout", ":last_findings")) else None


def documents(name, text):
    """The JSON documents an item holds (one per line for a .jsonl), or None when it holds none. The bare placeholders the
    normalization leaves (`"seconds": <DUR>`) are read as strings."""
    p = _parts(name, text)
    if p is None:
        return None
    body = PLACEHOLDER.sub(r'"<\1>"', p[1])
    try:
        if JSONL.search(name):
            return [json.loads(l) for l in body.split("\n") if l.strip()]
        return [json.loads(body)]
    except ValueError:
        return None


class Side:
    """What one side's items hold: records [(position, normalized record, raw record)], references [(position, value)],
    findings lists [(position, [keys])] and what couldn't be read."""
    def __init__(self, items):
        self.recs, self.refs, self.lists, self.bad = [], [], [], []
        for name in sorted(items):
            raw, norm = items[name]
            dn, dr = documents(name, norm), documents(name, raw)
            if (dn is None) != (dr is None) or (dn is not None and len(dn) != len(dr)):
                self.bad.append(f"{name!r}: the raw and normalized texts don't parse alike")
                continue
            for a, b in zip(dn or (), dr or ()):
                try:
                    self.walk(a, b, (name,))
                except ValueError as e:
                    self.bad.append(f"{name!r}: {e}")

    def walk(self, norm, raw, pos):
        """Position: the item name, then the JSON path with list indices dropped and 16-hex dict keys as <key>."""
        if isinstance(norm, dict):
            if not isinstance(raw, dict) or len(raw) != len(norm):
                raise ValueError(f"the raw and normalized documents differ in shape at {'/'.join(pos[1:])}")
            rec = isinstance(norm.get("rule"), str)
            if rec:
                self.recs.append((pos, norm, raw))
            for (k, v), rv in zip(norm.items(), raw.values()):
                if HEX16.fullmatch(k):
                    self.refs.append((pos, k))
                sub = pos + ("<key>" if HEX16.fullmatch(k) else k,)
                if rec and k in OWN:
                    continue
                if k in FINDINGS_LISTS and isinstance(v, list):
                    self.lists.append((sub, [x["key"] for x in v if isinstance(x, dict) and isinstance(x.get("rule"), str) and "key" in x]))
                self.walk(v, rv, sub)
        elif isinstance(norm, list):
            if not isinstance(raw, list) or len(raw) != len(norm):
                raise ValueError(f"the raw and normalized documents differ in shape at {'/'.join(pos[1:])}")
            for x, rx in zip(norm, raw):
                self.walk(x, rx, pos)
        elif isinstance(norm, str) and HEX16.fullmatch(norm):
            self.refs.append((pos, norm))


def _at(pos):
    return pos[0] + (" " + "/".join(pos[1:]) if len(pos) > 1 else "")


def _rec(pos, d):
    return f"{_at(pos)}: {d.get('rule')} at {str(d.get('where'))[:80]!r}"


def _sub(v, keymap):
    """v with every 16-hex value (a dict key too) put through keymap, and a nested record's display fields left out."""
    if isinstance(v, dict):
        rec = isinstance(v.get("rule"), str)
        return {keymap.get(k, k) if HEX16.fullmatch(k) else k: _sub(x, keymap) for k, x in v.items() if not (rec and k in DISPLAY)}
    if isinstance(v, list):
        return [_sub(x, keymap) for x in v]
    return keymap.get(v, v) if isinstance(v, str) and HEX16.fullmatch(v) else v


def _fields(d, keymap):
    return {k: _sub(v, keymap) for k, v in d.items() if k not in DISPLAY and k not in OWN}


def check(raw_old, raw_new, norm_old, norm_new, table):
    """(problems, summary) for one scenario. Each argument but the table is {normalized item name: text}: raw_* as the run wrote
    the items, norm_* after golden_split's normalization; *_old from the old layout's tree (names and values mapped through
    table["output"] here), *_new from the new one. summary: the old keyed records' classes, the record pairs, the references,
    the keys that changed and the new keys of class N (negative c)."""
    out = []
    conv = lambda t: map_old(t, table)
    by_name = collections.defaultdict(list)
    for k in sorted(norm_old):
        by_name[conv(k)].append(k)
    out += [f"two old items map onto one name {n!r}: {v}" for n, v in by_name.items() if len(v) > 1]
    names = {n: v[0] for n, v in by_name.items()}
    out += [f"an old item has no new one: {names[n]!r} (mapped: {n!r})" for n in sorted(set(names) - set(norm_new))]
    out += [f"a new item has no old one: {n!r}" for n in sorted(set(norm_new) - set(names))]
    out += [f"the exit code differs in {n!r}: {norm_old[names[n]]!r} (old), {norm_new[n]!r} (new)" for n in sorted(set(names) & set(norm_new))
            if n.endswith(" :rc") and norm_old[names[n]] != norm_new[n]]
    old = Side({n: (raw_old.get(k), conv(norm_old[k])) for n, k in names.items()})
    new = Side({n: (raw_new.get(n), norm_new[n]) for n in norm_new})
    out += ["old side: " + x for x in old.bad] + ["new side: " + x for x in new.bad]

    # 3. records: the same multiset of identities at every position, paired in list order within an equal group
    ident = lambda pos, d: (pos, json.dumps([d.get(f) for f in ID_FIELDS], sort_keys=True))
    go, gn = collections.defaultdict(list), collections.defaultdict(list)
    for pos, d, r in old.recs:
        go[ident(pos, d)].append((d, r))
    for pos, d, r in new.recs:
        gn[ident(pos, d)].append((d, r))
    pairs = []
    for i in sorted(set(go) | set(gn)):
        a, b = go.get(i, []), gn.get(i, [])
        if len(a) != len(b):
            out.append(f"records differ at {_at(i[0])}: {len(a)} old, {len(b)} new with (rule, where, evidence, severity, guarded) {i[1][:200]}")
        else:
            pairs += [(i[0], x, y) for x, y in zip(a, b)]

    # 4. key classes by the recipe (the old side decides) and 5. the key map
    consts = set(table["constant_keys"])
    classes = collections.Counter(klass(r) for _, d, r in old.recs if "key" in d and d["key"] not in consts)
    keymap, n_keys, changed, keyed = collections.defaultdict(set), [], 0, 0
    for pos, (od, orw), (nd, nrw) in pairs:
        for f in OWN:
            if (f in od) != (f in nd):
                out.append(f"{_rec(pos, nd)}: {f} on one side only")
        if "key" not in od or "key" not in nd:
            continue
        for side, d in (("old", od), ("new", nd)):
            for f in OWN:
                v = d.get(f, "")
                if f in d and not (isinstance(v, str) and (HEX16.fullmatch(v) or (f == "key" and v in consts))):
                    out.append(f"{_rec(pos, nd)}: the {side} {f} {v!r} is no 16-hex key")
        ko, kn = od["key"], nd["key"]
        if ko in consts or kn in consts:
            if ko != kn:
                out.append(f"{_rec(pos, nd)}: the constant key differs: {ko!r} (old), {kn!r} (new)")
        else:
            keyed += 1
        c_old, c_new = klass(orw), klass(nrw)
        if c_old != c_new:
            out.append(f"{_rec(pos, nd)}: key class {c_old} on the old side, {c_new} on the new (the key isn't the recipe's)")
        elif c_old == "N":
            n_keys.append(kn)
        if ko != kn:
            changed += 1
        elif c_old in ("I", "U") and ko not in consts:
            out.append(f"{_rec(pos, nd)}: the {c_old} key {ko} didn't change")
        for f in OWN:
            if isinstance(od.get(f), str) and isinstance(nd.get(f), str):
                keymap[od[f]].add(nd[f])
    out += [f"the old key {k} maps onto {len(v)} new keys: {sorted(v)}" for k, v in sorted(keymap.items()) if len(v) > 1]
    back = collections.defaultdict(set)
    for k, v in keymap.items():
        for x in v:
            back[x].add(k)
    out += [f"the new key {x} is the pair of {len(v)} old keys: {sorted(v)}" for x, v in sorted(back.items()) if len(v) > 1]
    keymap = {k: next(iter(v)) for k, v in keymap.items() if len(v) == 1}
    for side, s in (("old", old), ("new", new)):
        for pos, keys in s.lists:
            twice = sorted(k for k, n in collections.Counter(keys).items() if n > 1)
            if twice:
                out.append(f"{side} side: a key twice in one list at {_at(pos)}: {twice}")
    if classes and not (classes["N"] + classes["I"] + classes["G"]):
        out.append("floor: no old keyed record is N, I or G (the checker's copy of the key recipe matched none of the old engine's keys)")
    if keyed and not changed:
        out.append("no paired key changed")

    # Codex r2 HIGH 5: each pair's every non-display field, its references put through the key map, for THAT record
    for pos, (od, _), (nd, _) in pairs:
        a, b = _fields(od, keymap), _fields(nd, {})
        for f in sorted(set(a) | set(b)):
            if a.get(f, _MISSING) != b.get(f, _MISSING):
                out.append(f"{_rec(pos, nd)}: the field {f!r} differs: {str(a.get(f, '<none>'))[:120]} (old, mapped), {str(b.get(f, '<none>'))[:120]} (new)")

    # 5. references: at every position the same values, the old ones through the key map
    ro, rw = collections.defaultdict(collections.Counter), collections.defaultdict(collections.Counter)
    for pos, v in old.refs:
        ro[pos][keymap.get(v, v)] += 1
    for pos, v in new.refs:
        rw[pos][v] += 1
    for pos in sorted(set(ro) | set(rw)):
        if ro.get(pos, collections.Counter()) != rw.get(pos, collections.Counter()):
            out.append(f"references differ at {_at(pos)}: {dict(ro.get(pos, {}))} (old, mapped), {dict(rw.get(pos, {}))} (new)")
    return out, {"classes": {c: classes[c] for c in "NIGU"}, "records": len(new.recs), "pairs": len(pairs), "refs": len(new.refs),
                 "changed": changed, "n_keys": n_keys}


def _rewrite(name, text, docs):
    head = _parts(name, text)[0]
    if JSONL.search(name):
        return head + "".join(json.dumps(d) + "\n" for d in docs)
    return head + json.dumps(docs[0], indent=1) + "\n"


def _swap_ref(node, inside, keys):
    """Change the first 16-hex reference in node that sits inside a negative-b container (inside: the whole node is one; keys:
    the dict keys that open one) to NEG_REF, in place. True when one changed."""
    if isinstance(node, dict):
        rec = isinstance(node.get("rule"), str)
        for k in list(node):
            if inside and HEX16.fullmatch(k):
                kept = [(NEG_REF if x == k else x, v) for x, v in node.items()]
                node.clear()
                node.update(kept)
                return True
            if rec and k in OWN:
                continue
            here, v = inside or k in keys, node[k]
            if here and isinstance(v, str) and HEX16.fullmatch(v):
                node[k] = NEG_REF
                return True
            if _swap_ref(v, here, keys):
                return True
    elif isinstance(node, list):
        for i, v in enumerate(node):
            if inside and isinstance(v, str) and HEX16.fullmatch(v):
                node[i] = NEG_REF
                return True
            if _swap_ref(v, inside, keys):
                return True
    return False


def negatives(items, summary):
    """[(label, items)]: the three changes that must each fail check() (section 4.6), each on its own copy of the new side's
    raw items: (a) one finding dropped from a vet --json stdout, (b) one reference changed in a suppressed, delta or event
    container (else in undelivered, resolved or dismissed), (c) a class-N key replaced everywhere. One is left out when the
    scenario holds nothing it can change."""
    out = []
    for name in sorted(items):
        docs = documents(name, items[name]) if VET_JSON.match(name) else None
        if docs and isinstance(docs[0], dict) and isinstance(docs[0].get("findings"), list) and docs[0]["findings"]:
            del docs[0]["findings"][0]
            out.append(("a", dict(items, **{name: _rewrite(name, items[name], docs)})))
            break
    hit = None
    for rx, keys in NEG_REF_PLACES:
        for name in sorted(items):
            docs = documents(name, items[name])
            if docs and any(_swap_ref(d, bool(rx.search(name)), keys) for d in docs):   # any(): the first change only
                hit = name, docs
                break
        if hit:
            out.append(("b", dict(items, **{hit[0]: _rewrite(hit[0], items[hit[0]], hit[1])})))
            break
    if summary["n_keys"]:
        k = summary["n_keys"][0]
        out.append(("c", {n: v.replace(k, NEG_KEY) for n, v in items.items()}))
    return out
