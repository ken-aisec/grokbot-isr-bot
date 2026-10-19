#!/usr/bin/env python3
"""Dev-only (batch 5, d3b spike): the shape of a platform metadata JSON file, never its values.

    python3 scripts/platform-json-shape.py FILE...
    python3 scripts/platform-json-shape.py --against ROOT FILE...
    python3 scripts/platform-json-shape.py --canonical [--spec SPEC] FILE...

For each FILE: its sha256 and size, then one line per leaf: its key path, its JSON type, and the first 12 hex characters of the
sha256 of the leaf's JSON text. Run it on .grok/bundled/manifest.json (and a bucket's manifest.json, *.meta.json, cache.json)
before and after a platform sync and diff the two outputs: the key paths whose digest changed are the fields the sync rewrites.
Only those, once the host loader is shown never to read them, may go into rules/platform-normalize.json. No value is printed, so
the output is safe to share. Reads only the files given; writes nothing. A file that isn't strict JSON (duplicate keys, NaN,
Infinity, a byte-order mark, not UTF-8) is reported as such and left out.

Batch 6 (B1), two more modes for the spec's `units`:
--against ROOT: for each string leaf of each FILE, by key path only, whether it equals a file under ROOT (a platform folder) whole
  ("file"), what follows its frontmatter ("after_frontmatter"), one of its frontmatter fields ("frontmatter:<name>"), or that
  file's sha256 ("file_digest"), with the file's path under ROOT. Never a value. That says which unit kind and text mapping a
  spec entry needs.
--canonical: the release lock line ("canonical <sha256>  <path under the home folder>") of each FILE's canonical form, computed by the
  checkout's own watchtower/wt.py (canonical_platform_json, with each unit checked against the files on disk now) and the
  checkout's rules/platform-normalize.json, or SPEC. Run it on a clean box at release, from the home folder the lock is filled for."""
import hashlib, json, os, sys


class Refused(ValueError):
    pass


def pairs(items):
    seen = set()
    for k, _ in items:
        if k in seen:
            raise Refused(f"duplicate key {json.dumps(k)}")
        seen.add(k)
    return dict(items)


def constant(name):
    raise Refused(f"{name} is not JSON")


def kind(v):
    return ("null" if v is None else "bool" if isinstance(v, bool) else "number" if isinstance(v, (int, float))
            else "string" if isinstance(v, str) else "array" if isinstance(v, list) else "object")


def leaves(v, path=()):
    if isinstance(v, dict) and v:
        for k, x in v.items():
            yield from leaves(x, path + (k,))
    elif isinstance(v, list) and v:
        for i, x in enumerate(v):
            yield from leaves(x, path + (i,))
    else:
        yield path, v


def shape(p):
    with open(p, "rb") as f:
        data = f.read()
    print(f"# {p}: sha256 {hashlib.sha256(data).hexdigest()}, {len(data)} bytes")
    if data[:3] == b"\xef\xbb\xbf":
        print("  not strict JSON: it starts with a byte-order mark")
        return 1
    try:
        doc = json.loads(data.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeDecodeError, ValueError, RecursionError) as e:
        print(f"  not strict JSON: {e}")
        return 1
    for path, v in leaves(doc):
        name = "".join(f"[{k}]" if isinstance(k, int) else f".{json.dumps(k)}" for k in path) or "(top)"
        text = json.dumps(v, separators=(",", ":"), ensure_ascii=False, sort_keys=False)
        print(f"  {name}\t{kind(v)}\t{hashlib.sha256(text.encode('utf-8')).hexdigest()[:12]}")
    return 0


def strict(p):
    """The strict JSON document in p, or raises Refused / OSError."""
    with open(p, "rb") as f:
        data = f.read()
    if data[:3] == b"\xef\xbb\xbf":
        raise Refused("it starts with a byte-order mark")
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeDecodeError, ValueError, RecursionError) as e:
        raise Refused(str(e))


def name_of(path):
    return "".join(f"[{k}]" if isinstance(k, int) else f".{json.dumps(k)}" for k in path) or "(top)"


def index(root):
    """{sha256 of the text a leaf may equal: (kind, path under root)} for the plain files under root (no link followed)."""
    out = {}
    for dp, dns, fns in os.walk(root):
        dns.sort()
        for fn in sorted(fns):
            p = os.path.join(dp, fn)
            if os.path.islink(p) or not os.path.isfile(p):
                continue
            with open(p, "rb") as f:
                data = f.read(1024 * 1024 + 1)
            rel = os.path.relpath(p, root)
            out.setdefault(("digest", hashlib.sha256(data).hexdigest()), ("file_digest", rel))
            out.setdefault(("text", hashlib.sha256(data).hexdigest()), ("file", rel))
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                continue
            end = text.find("\n---\n", 3) if text.startswith("---\n") else -1
            if end < 0:
                continue
            out.setdefault(("text", hashlib.sha256(text[end + 5:].encode()).hexdigest()), ("after_frontmatter", rel))
            for line in text[4:end].split("\n"):
                k, sep, v = line.partition(":")
                v = v.strip()
                v = v[1:-1] if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'" else v
                if sep and k.strip() == k and k and v:
                    out.setdefault(("text", hashlib.sha256(v.encode()).hexdigest()), (f"frontmatter:{k}", rel))
    return out


def against(root, files):
    idx, rc = index(root), 0
    for p in files:
        print(f"# {p} against {root}")
        try:
            doc = strict(p)
        except (OSError, Refused) as e:
            print(f"  not strict JSON or can't be read: {e}")
            rc = 1
            continue
        for path, v in leaves(doc):
            if not isinstance(v, str):
                continue
            h = hashlib.sha256(v.encode("utf-8")).hexdigest()
            for hit in (idx.get(("text", h)), idx.get(("digest", v.lower())) if len(v) == 64 else None):
                if hit:
                    print(f"  {name_of(path)}\t{hit[0]}\t{hit[1]}")
    return rc


class OnDisk(dict):
    """A run's manifest as wt reads it, taken from the disk now: a plain file's sha256 (never through a link)."""
    def get(self, p, default=None):
        if p not in self:
            self[p] = (hashlib.sha256(open(p, "rb").read()).hexdigest()
                       if os.path.isfile(p) and not os.path.islink(p) else None)
        return dict.get(self, p, default)


def canonical(spec, files):
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "watchtower"))
    import wt
    if spec:
        wt.PLATFORM_NORMALIZE = os.path.abspath(spec)
    entries, why = wt._platform_normalize_state()
    if why:
        print(f"# the spec can't be used: {why}")
        return 1
    rc, disk = 0, OnDisk()
    for p in files:
        n = os.path.normpath(os.path.abspath(p))
        rels = sorted(wt._home_rels(n) & wt._home_rels(os.path.realpath(n)))
        rel = next((r for r in rels if r in entries), None)
        if rel is None:
            print(f"# {p}: the spec doesn't name it (under the home folder {os.path.expanduser('~')})")
            rc = 1
            continue
        data = wt._read_plain(n, wt.NORMALIZE_FILE_MAX)
        c = None if data is None else wt.canonical_platform_json(data, entries[rel]["fields"], entries[rel]["units"], wt._unit_checker(n, disk))
        if c is None:
            print(f"# {p}: no canonical form (not strict JSON, a field of another type, or a unit that doesn't equal its file)")
            rc = 1
            continue
        print(f"canonical {c}  {rel}")   # fix round 1 (Codex 1): the line says it lists a canonical form
    return rc


def main(argv):
    if not argv:
        print(__doc__.split("\n\n")[1].strip(), file=sys.stderr)
        return 2
    if argv[0] == "--against":
        if len(argv) < 3:
            print("--against ROOT FILE...", file=sys.stderr)
            return 2
        return against(argv[1], argv[2:])
    if argv[0] == "--canonical":
        spec = argv[2] if len(argv) > 2 and argv[1] == "--spec" else None
        files = argv[3:] if spec else argv[1:]
        if not files:
            print("--canonical [--spec SPEC] FILE...", file=sys.stderr)
            return 2
        return canonical(spec, files)
    rc = 0
    for p in argv:
        try:
            rc |= shape(p)
        except OSError as e:
            print(f"# {p}: can't be read ({e.strerror})")
            rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
