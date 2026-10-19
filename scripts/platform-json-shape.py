#!/usr/bin/env python3
"""Dev-only (batch 5, d3b spike): the shape of a platform metadata JSON file, never its values.

    python3 scripts/platform-json-shape.py FILE...

For each FILE: its sha256 and size, then one line per leaf: its key path, its JSON type, and the first 12 hex characters of the
sha256 of the leaf's JSON text. Run it on .grok/bundled/manifest.json (and a bucket's manifest.json, *.meta.json, cache.json)
before and after a platform sync and diff the two outputs: the key paths whose digest changed are the fields the sync rewrites.
Only those, once the host loader is shown never to read them, may go into rules/platform-normalize.json. No value is printed, so
the output is safe to share. Reads only the files given; writes nothing. A file that isn't strict JSON (duplicate keys, NaN,
Infinity, a byte-order mark, not UTF-8) is reported as such and left out."""
import hashlib, json, sys


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


def main(argv):
    if not argv:
        print(__doc__.split("\n\n")[1].strip(), file=sys.stderr)
        return 2
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
