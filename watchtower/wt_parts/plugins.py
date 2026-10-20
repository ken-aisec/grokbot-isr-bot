# Part of wt.py: runs inside wt.py's namespace (loaded by _wt_part); not a module on its own.
def norm_body(t):
    t = re.sub(r"(?s)\A---\n.*?\n---\n", "", t or "")
    return re.sub(r"\s+", " ", t).strip()


def saved_skill_notes(notes):
    """The template's first-run skill is the owner's saved `getting-started` skill, and an update doesn't refresh it. After
    v0.6.6 moved the decoys, the saved copy on the main computer still named the old places. Say so when it differs."""
    app = read_text(os.path.join(SELF_ROOT, "bot", "getting-started.md"))
    if not app:
        return
    seen = set()
    for root in [os.path.normpath(os.path.expanduser("~") + sub) for sub in USER_SKILL_DIRS]:   # this home folder only
        p = os.path.join(root, "getting-started", "SKILL.md")
        rp = os.path.realpath(p)
        if rp in seen or not os.path.isfile(p):
            continue
        seen.add(rp)
        saved = read_text(p) or ""
        if "You are Watchtower" not in saved or norm_body(saved) == norm_body(app):
            continue
        old = [x for x in OLD_CANARY_PATHS + PUBLISHED_CANARY_PATHS if x in saved]
        msg = (f"Your saved getting-started skill ({short_path(p)}) is older than this Watchtower"
               + (f": it still names the old decoy places ({', '.join(old)})" if old else "")
               + ". A template made from this Bot would ship it. Re-save it from /workspace/watchtower/app/bot/getting-started.md.")
        if msg not in notes:                   # the check can run twice in one audit; say it once
            notes.append(msg)


def update_notes(notes):
    """Tell the owner a newer Watchtower is out. Only tells: nothing here installs or updates anything."""
    b = load_json(state_path("last_brief.json"), {}) or {}
    upd = [u for u in b.get("updates", []) if "watchtower" in u.get("name", "").lower()]
    if upd:
        u = upd[0]
        notes.append(f"A newer Watchtower is out ({u.get('have')} → {u.get('latest')}" + (f", commit {u['commit'][:12]}" if u.get("commit") else "")
                     + "). Tell Watchtower \"update yourself\" when you want it.")
    moved = b.get("watchtower_tag_moved")
    if moved:
        notes.append(f"The {moved.get('tag')} tag on GitHub now points at commit {str(moved.get('now'))[:12]}, not {str(moved.get('installed'))[:12]}, "
                     "the one installed here. A published tag should never move: don't update from it until you know why.")


def find_key(obj, keys):
    if isinstance(obj, dict):
        for k in keys:
            if k in obj and isinstance(obj[k], (int, float)):
                return obj[k]
        for v in obj.values():
            r = find_key(v, keys)
            if r is not None:
                return r
    elif isinstance(obj, list):
        for v in obj:
            r = find_key(v, keys)
            if r is not None:
                return r
    return None


# Batch 6 (B8): an MCP server a package launcher fetches and runs is pinned only by an exact version of that package. npx, uvx,
# bunx, `pnpm dlx` and `npm exec` alike (also behind /usr/bin/env); "@latest", a range and a dist-tag can each change what runs.
# Read from the command and args of every object in the file that has a "command" (mcpServers, servers, …); a file that isn't
# JSON is read for its "command" and "args" strings. The old "an @ within 200 characters" test let `npx -y @scope/pkg` (or an email nearby) pass as pinned.
MCP_LAUNCHERS = {"npx": 1, "uvx": 1, "bunx": 1, "pnpm": ("dlx",), "npm": ("exec",)}
MCP_SKIP_FLAGS = frozenset(("-y", "--yes", "--quiet", "-q", "--"))
MCP_VALUE_FLAGS = frozenset(("-p", "--package", "--from"))
MCP_SERVERS_MAX = 2000   # servers looked at in one file; past it the rest are not
_NPM_EXACT = re.compile(r"(?:@[A-Za-z0-9._~-]+/)?[A-Za-z0-9._~-]+@v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]*)?")
_PY_EXACT = re.compile(r"[A-Za-z0-9._-]+(?:\[[^\]]*\])?(?:===?|@)v?\d[0-9A-Za-z.+-]*")
_NPM_RANGE = re.compile(r"[\^~<>=*| ]|^[\dxX*]+(?:\.[\dxX*]+){0,2}$")
_JSON_STR = r'"((?:[^"\\\n]|\\.)*)"'


def mcp_package(words):
    """(launcher, package spec) when the words (a server's command and args) run a package launcher, else None. The package is
    the value of -p/--package/--from, or the first word after the launcher that isn't a flag."""
    w = [x for x in words if isinstance(x, str)]
    if w and os.path.basename(w[0]) == "env":   # /usr/bin/env [VAR=value …] npx …
        w = w[1:]
        while w and (w[0].startswith("-") or ("=" in w[0] and not w[0].startswith(("@", ".", "/")))):
            w = w[1:]
    if not w:
        return None
    name = os.path.basename(w[0]).lower()
    sub = MCP_LAUNCHERS.get(name)
    if sub is None:
        return None
    if sub != 1:
        if len(w) < 2 or w[1] not in sub:
            return None
        name, w = f"{name} {w[1]}", w[1:]
    rest, i = w[1:], 0
    while i < len(rest):
        x = rest[i]
        if x in MCP_VALUE_FLAGS:
            return name, rest[i + 1] if i + 1 < len(rest) else ""
        if x.split("=", 1)[0] in MCP_VALUE_FLAGS and "=" in x:
            return name, x.split("=", 1)[1]
        if x in MCP_SKIP_FLAGS or x.startswith("-"):
            i += 1
            continue
        return name, x
    return name, ""


def mcp_pin_problem(launcher, spec):
    """Why `spec` isn't an exact version for this launcher ("no version", "@latest", "range …", "tag …"), or None when it is."""
    s = spec.strip()
    if launcher == "uvx":
        if _PY_EXACT.fullmatch(s):
            return None
        m = re.search(r"(===?|~=|!=|>=|<=|[<>@])", s)
        return "no version" if not m else "@latest" if s.endswith("@latest") else "range " + s[m.start():][:40]
    if _NPM_EXACT.fullmatch(s):
        return None
    at = s.find("@", 1)
    if at == -1:
        return "no version"
    v = s[at + 1:]
    if v == "latest":
        return "@latest"
    return ("range " if _NPM_RANGE.search(v) else "tag ") + v[:40]


def _mcp_servers(text):
    """[(the offset of its "command", [command, *args])] for each MCP server in `text`."""
    out = []
    try:
        doc = json.loads(text)
    except (ValueError, RecursionError):
        doc = None
    if isinstance(doc, (dict, list)):
        import collections
        where = collections.defaultdict(collections.deque)   # each "command" value -> its places in the text, in order
        for j, m in enumerate(re.finditer(r'"command"\s*:\s*' + _JSON_STR, text)):
            try:
                where[json.loads('"' + m.group(1) + '"')].append((j, m.start()))
            except ValueError:
                pass
        used, found, stack, seen = 0, [], [doc], 0
        while stack and seen < 200_000 and len(found) < MCP_SERVERS_MAX:   # every object with a "command", in the file's order
            x = stack.pop()
            seen += 1
            if isinstance(x, dict):
                if isinstance(x.get("command"), str):
                    found.append(x)
                stack += reversed(list(x.values()))
            elif isinstance(x, list):
                stack += reversed(x)
        for cfg in found:
            args = cfg.get("args") if isinstance(cfg.get("args"), list) else []
            q, at = where.get(cfg["command"]), 0
            while q and q[0][0] < used:   # the next "command" in the text with this value
                q.popleft()
            if q:
                j, at = q.popleft()
                used = j + 1
            out.append((at, cfg["command"].split() + [a for a in args if isinstance(a, str)]))
        return out
    # not JSON (comments, a trailing comma): each "command" with the "args" list after it, before the next "command"
    cmds = list(re.finditer(r'"command"\s*:\s*' + _JSON_STR, text))[:MCP_SERVERS_MAX]
    for k, m in enumerate(cmds):
        stop = cmds[k + 1].start() if k + 1 < len(cmds) else min(len(text), m.end() + 20000)
        words = m.group(1).split()
        a = re.compile(r'"args"\s*:\s*\[').search(text, m.end(), stop)
        if a:
            close = text.find("]", a.end(), stop)
            words += [s.group(1) for s in re.finditer(_JSON_STR, text[a.end():close if close != -1 else stop])]
        out.append((m.start(), words))
    return out


def mcp_unpinned(text):
    """[(line, evidence)] for each MCP server in `text` that a package launcher runs without an exact version."""
    out, line, pos = [], 1, 0
    for at, words in sorted(_mcp_servers(text), key=lambda x: x[0]):
        got = mcp_package(words)
        if got is None:
            continue
        launcher, spec = got
        why = mcp_pin_problem(launcher.split()[0], spec)
        if why is None:
            continue
        line += text.count("\n", pos, at)
        pos = at
        name = re.split(r"(?<=.)[@=<>~!]", spec, maxsplit=1)[0]
        out.append((line, f"{launcher} {name or '(no package named)'} ({why})"))
    return out


PLATFORM_FILES = ("/sand-data/gateway.json", "/agent-data/gateway.json", "/sand-data/teach-queue-key.json", "/agent-data/teach-queue-key.json")   # Grok Bot's own config; the user can't change it


PLUGIN_META_DIRS = (".grok-plugin", ".cursor-plugin", ".claude-plugin", ".codex-plugin", ".plugin")   # one plugin, one folder, whichever app it is packaged for
_PENDING = {"at": None, "roots": ()}


def plugin_identity(plugin_json):
    """(name, folder) for a plugin.json. The name comes from the file, so the same plugin reinstalled under a new
    folder name after a restart, or updated to a new version, is still the same plugin."""
    d = os.path.dirname(plugin_json)
    if os.path.basename(d) in PLUGIN_META_DIRS:
        d = os.path.dirname(d)
    data = load_json(plugin_json, None)
    name = data.get("name") if isinstance(data, dict) and isinstance(data.get("name"), str) else None
    name = name or re.sub(r"([-_@]v?\d[\w.]*)?(-[0-9a-f]{4,})?$", "", os.path.basename(d)) or os.path.basename(d)
    return name[:80], os.path.normpath(d)


CATALOG_MARKETS = ("cursor-public", "claude-plugins-official")
CATALOG_WINDOW = 600   # seconds: one sync lands its plugins within minutes of each other


def runs_code(root):
    """A plugin that brings a hook, a script or a locally launched MCP server runs code on this computer."""
    for dp, _, fns in os.walk(root):
        for fn in fns:
            p = os.path.join(dp, fn)
            if fn == "hooks.json" or os.path.splitext(fn)[1].lower() in (".sh", ".py", ".js", ".mjs", ".cjs", ".ts", ".rb", ".pl", ".ps1") \
                    or (os.path.isfile(p) and not os.path.islink(p) and os.access(p, os.X_OK)):
                return True
            if fn == "mcp.json" and re.search(r'"command"\s*:', read_text(p) or ""):
                return True
    return False


def catalog_sync(new_plugins):
    """DQ-017: new plugins that arrived together from the platform's own catalog (same marketplace, same catalog commit, within
    minutes) and run no code here are a catalog sync, not an install. Returns [(market, commit, names)] and marks them known."""
    groups = {}
    for name, roots in new_plugins.items():
        for r in roots:
            m = re.search(r"/plugins/cache/([^/]+)/[^/]+/([^/]+)$", r)
            if m and m.group(1) in CATALOG_MARKETS and not runs_code(r):
                try:
                    groups.setdefault((m.group(1), m.group(2)), []).append((name, os.stat(r).st_mtime))
                except OSError:
                    pass
                break
    out = []
    for (market, commit), items in sorted(groups.items()):
        if len(items) >= 2 and max(t for _, t in items) - min(t for _, t in items) <= CATALOG_WINDOW:
            out.append((market, commit, sorted(n for n, _ in items)))
    if out:
        st = load_json(state_path("plugins.json"), {}) or {}
        for _, _, names in out:
            for n in names:
                if n in st:
                    st[n]["status"] = "catalog"
        save_json(state_path("plugins.json"), st)
    return out


def note_plugins(inv):
    """Remember which plugins are on the computer. The first run records what is there. After that, a plugin name not
    seen before is new: the owner (or a template they said yes to) added it, and nothing vetted it first."""
    here, manifests = {}, {}
    for p in inv["plugin_files"]:
        if os.path.basename(p) == "plugin.json" and any(x in p for x in ("/plugins/", "/plugin-cache/")):
            name, d = plugin_identity(p)
            here.setdefault(name, []).append(d)
            manifests.setdefault(name, []).append(p)
    st = load_json(state_path("plugins.json"), None)
    first = not isinstance(st, dict)
    st = {} if first else st
    # Updating from a version that kept no list of plugins: "what is there" is not all known. A plugin that wasn't on the
    # computer when the owner's baseline was taken was added since, and nobody has been told about it yet.
    base = load_baseline()[0] if first else {}
    base_hashes = set(base.values())
    in_baseline = lambda name: not base or any(p in base or sha256_file(p) in base_hashes for p in manifests[name])
    for name, roots in here.items():
        if name not in st:
            st[name] = {"since": now(), "status": "known" if first and in_baseline(name) else "new"}
            # Already there on Watchtower's first run, inside the platform's catalog cache, and runs no code: the catalog's, as a
            # catalog sync would have filed it. One that runs code stays "known" and counts like any installed plugin (F1).
            if first and st[name]["status"] == "known" and all(any(x in r + "/" for x in CATALOG_CACHE) and not runs_code(r) for r in roots):
                st[name].update(status="catalog", filed="first-run")
        st[name]["roots"] = sorted(set(roots))
    if not first:
        recheck_known_plugins(st, here)
    save_json(state_path("plugins.json"), st)
    _PENDING["at"] = None
    return {name: v["roots"] for name, v in st.items() if v.get("status") == "new" and name in here}


def last_owner_baseline(before):
    """When the owner last took a baseline (the ledger's "baseline" events), at or before `before`; None if never."""
    best = None
    try:
        with open(state_path("ledger.jsonl")) as f:
            for line in f:
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                if isinstance(e, dict) and e.get("event") == "baseline" and e.get("at") and e["at"] <= before:
                    best = e["at"] if best is None or e["at"] > best else best
    except OSError:
        return None
    try:
        return dt.datetime.fromisoformat(best).timestamp() if best else None
    except ValueError:
        return None


def owner_baseline_skills(base_ts):
    """The skills the owner's baseline held, by the content of their SKILL.md: the approved copies `baseline` keeps were saved
    at or before that baseline. Later copies (the platform roll's, re-approvals) don't count, so a plugin the roll accepted
    after the baseline isn't mistaken for one the owner saw."""
    out = set()
    try:
        names = os.listdir(state_path("approved"))
    except OSError:
        return out
    for fn in names:
        try:
            with gzip.open(state_path("approved", fn), "rt", encoding="utf-8") as f:
                d = json.load(f)
            if dt.datetime.fromisoformat(d["at"]).timestamp() > base_ts + 1:
                continue
            out.update(h for rel, h in (d.get("hashes") or {}).items() if os.path.basename(rel) == "SKILL.md")
        except (OSError, ValueError, KeyError, TypeError, EOFError):
            continue
    return out


def plugin_in_baseline(roots, owned):
    """True when one of the plugin's skills is, word for word, a skill the owner's baseline held: the platform moved or
    reinstalled its folders, it didn't add it."""
    if not owned:
        return False
    for r in roots:
        for dp, dns, fns in os.walk(r):
            dns[:] = [d for d in dns if d not in SKIP_DIRS]
            if "SKILL.md" in fns and sha256_file(os.path.join(dp, "SKILL.md")) in owned:
                return True
    return False


def recheck_known_plugins(st, here):
    """Once, after updating: v0.6.3 to v0.6.5 made the plugin list on their first run and filed every plugin there as known,
    including one added after the owner's baseline (AgentMail on the main computer, installed the evening after). v0.6.6's
    fix only covered computers with no list yet. A plugin on that first list whose folders were all created after the
    owner's last baseline before it is filed as new, so it is announced once and the owner decides, unless one of its
    skills is word for word one the owner's baseline held (the platform moved or reinstalled it)."""
    flag = state_path("plugins_rechecked.json")
    if os.path.exists(flag):
        return
    firsts = [v.get("since", "") for v in st.values() if isinstance(v, dict) and v.get("since")]
    first_at = min(firsts) if firsts else None
    base_ts = last_owner_baseline(first_at) if first_at else None
    moved, kept = [], []
    if base_ts:
        owned = owner_baseline_skills(base_ts)
        for name, v in st.items():
            if not isinstance(v, dict) or v.get("status") != "known" or v.get("kept") or v.get("since") != first_at or name not in here:
                continue
            try:
                born = min(os.stat(r).st_ctime for r in here[name])
            except (OSError, ValueError):
                continue
            if born > base_ts + 1:
                if plugin_in_baseline(here[name], owned):   # its folders changed in a platform update; its skills are the owner's baseline's
                    kept.append(name)
                    continue
                v.update(status="new", rechecked=now())
                moved.append(name)
    save_json(flag, {"at": now(), "baseline": base_ts, "filed_as_new": moved, "kept_in_baseline": kept})
    if moved:
        ledger({"event": "plugin-recheck", "new": moved})


def pending_plugin_roots():
    path = state_path("plugins.json")
    try:
        at = os.stat(path).st_mtime
    except OSError:
        return ()
    if _PENDING["at"] != at:
        st = load_json(path, {}) or {}
        _PENDING.update(at=at, roots=tuple(r for v in st.values() if isinstance(v, dict) and v.get("status") == "new" for r in v.get("roots", [])))
    return _PENDING["roots"]


def in_pending_plugin(where):
    w = (where or "").split(":")[0]
    return any(w == r or w.startswith(r + "/") for r in pending_plugin_roots())


def keep_plugin(where):
    """The owner said this plugin is theirs: from now on it is treated like any other installed plugin."""
    st = load_json(state_path("plugins.json"), {}) or {}
    w = os.path.normpath((where or "").split(":")[0])
    kept = [n for n, v in st.items() if v.get("status") == "new" and w in v.get("roots", [])]
    for n in kept:
        st[n].update(status="known", kept=now())
    if kept:
        save_json(state_path("plugins.json"), st)
        _PENDING["at"] = None
        ledger({"event": "plugin-kept", "plugins": kept})
    return kept


REFRESH_RULE = "WT-I008"
PLATFORM_DANGER_KINDS = frozenset(RISK_KIND[r] for r in BEHAVIOR_RULES)   # credential, exfil, pipe, obfuscation, exec


def unconfirmed_platform_vote(f, fs):
    """DQ-042 (Ken, Oct 16): vendor skill updates shouldn't be flagged. A routine update to the bundled learn skill came back
    "SkillSpector + husk; Memory Poisoning: Memory Manipulation; analysis-evasion: …" and daily raised a high alert. On the
    platform's own skill folders (platform_skill_path), two engines agreeing is Confirmed only when their words name a dangerous
    behavior (the kinds of BEHAVIOR_RULES), or a Confirmed critical/high Watchtower finding in the same skill backs it. Engines
    that agree only on wording (override, secrecy) or name no kind at all are a Platform line, the same line v0.7.1 item 2
    draws: wording alone is never Confirmed. A built-in that turns bad in a way Watchtower sees still alerts (Claude v0.7.1 F4)."""
    if (f["rule"] != "WT-X003" or f.get("kinds_incomplete") or not platform_skill_path(f.get("where") or "", line=False)
            or kinds_of(f) & PLATFORM_DANGER_KINDS):
        return False
    here = _path_part(f["where"], line=False)
    return not any(g is not f and not g["rule"].startswith(("WT-I", "WT-X")) and g.get("label") == CONFIRMED
                   and (g.get("severity_was") or g["severity"]) in ("critical", "high")
                   and _covers(here, _path_part(g["where"]) if str(g.get("where") or "").startswith("/") else _place(g)) for g in fs)


def summarize_refresh(fs):
    """v0.7.1 precision item 6 (Ken, Oct 12): change alerts name the source. Changes to Grok Bot's own files (a platform refresh)
    are one summary line, a Tip, never an alert — unless the change brings a new Confirmed critical or high (Claude v0.7.1 F4).
    Then daily gets a real alert: the built-in turned bad; don't use it until Grok Bot fixes it. Unflagged platform changes
    still roll into the one Tip. Owner skill changes and installed-plugin changes still alert as before."""
    ref = [f for f in fs if f.get("refresh") and f["rule"] in ("WT-I001", "WT-I002", "WT-I003")]
    if not ref:
        return fs
    # Confirmed critical/high on a platform path (label may already be set; else evidence/corroboration still counts).
    bad, index = [], None
    for f in fs:
        if f in ref or f["severity"] not in ("critical", "high"):
            continue
        if not (f.get("scope") == "platform" or platform_file(f)) or unconfirmed_platform_vote(f, fs):   # DQ-042
            continue
        if not (f.get("label") == CONFIRMED or is_evidence(f)) and CORROB_INDEX and index is None:
            index = CorrobIndex(fs)   # batch 5 (c5): one index for every finding here, not a read of all of them per finding
        if f.get("label") == CONFIRMED or is_evidence(f) or corroborated(f, fs, index):
            bad.append(f)

    def skill_of_path(w):
        w = w.split(":")[0]
        root = skill_root(w) if os.path.exists(w) else None
        return root or os.path.dirname(w), skill_name(root) if root else os.path.basename(os.path.dirname(w))

    def bad_for(rf):
        w = rf["where"].split(":")[0]
        root, _ = skill_of_path(w)
        for b in bad:
            bw = b["where"].split(":")[0]
            if bw == w or bw.startswith(w.rstrip("/") + "/") or (root and (bw == root or bw.startswith(root.rstrip("/") + "/"))):
                return b
        return None

    flagged, unflagged = [], []
    for rf in ref:
        (flagged if bad_for(rf) else unflagged).append(rf)

    out = [f for f in fs if f not in ref]
    seen = set()
    for rf in flagged:
        b = bad_for(rf)
        root, n = skill_of_path(rf["where"])
        if n in seen:
            continue
        seen.add(n)
        title = (f"Grok Bot's own {n} changed and now {b['title']}; it's theirs to fix, but don't use it until they do")
        alert = finding(rf["rule"], title, b["severity"], ["AST07", "ASI03"], rf["where"],
                        rf.get("evidence") or b.get("evidence", ""),
                        "Grok Bot's own skill went bad. Don't use it until they fix it. Watchtower keeps it listed.",
                        ident=f"platform-bad-{n}")
        alert["scope"] = "platform"
        alert["label"] = CONFIRMED
        alert["class"] = "corroborated"
        out.append(alert)
    if unflagged:
        names = []
        for f in unflagged:
            _, n = skill_of_path(f["where"])
            if n not in names:
                names.append(n)
        c = {r: sum(1 for f in unflagged if f["rule"] == r) for r in ("WT-I001", "WT-I002", "WT-I003")}
        shown = ", ".join(names[:6]) + (f", +{len(names) - 6} more" if len(names) > 6 else "")
        fix = ("Nothing to do. Grok Bot updated its own skills or plugin catalog; every new or changed file here from its own "
               "skill folders is on Grok Bot's release list. Watchtower re-checks the new files and accepts them on the next full audit when nothing "
               "flags them.")
        # batch 6 (B1): a metadata file verified by content (platform_verified) says how it was checked
        meta = sorted(dict.fromkeys(_platform_place(f["where"])[0] for f in unflagged if _path_part(f["where"]) in VERIFIED_METADATA))
        if meta:
            fix = (f"Nothing to do. Grok Bot updated its list of what it loads ({', '.join(meta[:4])}{' …' if len(meta) > 4 else ''}). "
                   "Watchtower compared it with the released version: only dates, and copies of files Watchtower checked itself, changed."
                   + (" " + fix[len("Nothing to do. "):] if len(meta) < len(unflagged) else ""))
        tip = finding(REFRESH_RULE, f"Platform refresh: {len(unflagged)} of Grok Bot's own files changed ({shown})", "info", ["AST07"],
                      "platform-refresh", f"{c['WT-I001']} updated, {c['WT-I002']} added, {c['WT-I003']} removed", fix, ident="platform-refresh")
        tip["class"], tip["label"] = "tip", TIP   # created after label_findings; keep it a Tip
        out.append(tip)
    return out


def builtin(f):
    """Shipped by the platform or a plugin, not made or installed by hand by the user. A plugin that is new and that the
    owner hasn't kept yet is not built-in: it counts in full until they decide."""
    w = f.get("where", "")
    if in_pending_plugin(w):
        return False
    # item 8 (R3): a real vendor folder or Grok Bot's config at exactly its place, never a name anywhere in the path
    return bool(vendor_root_path(w) or platform_config_finding(f) or w.startswith("system python package "))


SECRET_RULES = ("WT-S001", "WT-S002", "WT-K003")   # a key or a decoy copy counts wherever it sits (v0.7.0 review R3)

# v0.7.1 precision item 4 (Ken, Oct 12): built-ins never move the score. Grok Bot's own files (the bundled and managed skills,
# its config files, the platform's plugin catalog cache, the computer's own Python packages) go in a separate Platform section,
# one line each. Plugins the owner installed still count as before (critical and high), and a new plugin nobody kept counts in full.
PLATFORM = "Platform (Grok Bot's own file)"
PLATFORM_FIX = "This is Grok Bot's own file; nothing for you to do."
PLATFORM_CONFIRMED_FIX = ("This is Grok Bot's own file, so it doesn't move your score. Two checks agree it matters, so tell Grok Bot "
                          "support (it's theirs to fix); Watchtower keeps it listed until it changes.")
CATALOG_CACHE = tuple(f"/plugins/cache/{m}/" for m in CATALOG_MARKETS)
_CATALOG = {"at": None, "roots": ()}
_RUNS_CODE = {}


def catalog_plugin_roots():
    """Folders of plugins the catalog sync filed as "catalog" (arrived together from the platform's catalog, run no code)."""
    path = state_path("plugins.json")
    try:
        at = os.stat(path).st_mtime
    except OSError:
        return ()
    if _CATALOG["at"] != at:
        st = load_json(path, {}) or {}
        _CATALOG.update(at=at, roots=tuple(r for v in st.values() if isinstance(v, dict) and v.get("status") == "catalog" for r in v.get("roots", [])))
    return _CATALOG["roots"]


def in_catalog_plugin(where):
    """Claude review Oct 13 (F1): the marketplace cache folders also hold plugins the owner installs. Only a plugin the catalog
    sync filed as "catalog" that still runs no code is Grok Bot's own; a known, kept or new plugin, or one that runs code, never is."""
    w = (where or "").split(":")[0]
    if not any(x in w for x in CATALOG_CACHE):
        return False
    # PR A, Codex round 1 (7): an owner's skill folder is never the catalog's, whatever state/plugins.json says about a folder in it
    try:
        if skill_tier(w) == "user":   # as written or where it really leads
            return False
    except (OSError, ValueError):
        return False
    for r in catalog_plugin_roots():
        if w == r or w.startswith(r + "/"):
            if r not in _RUNS_CODE:
                _RUNS_CODE[r] = runs_code(r)
            return not _RUNS_CODE[r]
    return False


# Ken, Oct 13 (item 8 dry run): Codex's and Claude's own built-in skills and plugins are the platform's, shown not scored.
# (Folded into PLATFORM_ROOT_SUBS / under_platform_root — Claude v0.7.1 F3.)
# Ken, Oct 13: the platform's masked-secret store (values saved through the secure secret request). Never read by Watchtower.
PLATFORM_SECRET_STORE = ("sand-data/box-secrets.json", "agent-data/box-secrets.json",
                         ".grok/auth.json")   # Ken, Oct 14: the Grok CLI sign-in file is expected; that exact path only
GROK_CLI_SIGN_IN = ".grok/auth.json"


def is_platform_secret_store(p):
    # item 8 (from Codex's batch 3 round 1): matched exactly like is_platform_config; cutting at the first colon made <store>:3 the store
    return _exactly_at(os.path.abspath(str(p)), secret_store_places())


def secret_store_places():
    return {os.path.normpath(os.path.join(b, s)) for b in dict.fromkeys((os.path.expanduser("~"), "/home/box")) for s in PLATFORM_SECRET_STORE}


def platform_secret_store_note(p):
    try:
        mode = os.stat(p).st_mode & 0o777
    except OSError:
        mode = None
    m = f"mode {mode:04o}" if mode is not None else "mode unknown"
    tight = mode is not None and not (mode & 0o077)
    if os.path.normpath(str(p)).endswith(os.sep + os.path.normpath(GROK_CLI_SIGN_IN)):
        return finding("WT-I009", "Grok CLI sign-in file present" + ("" if tight else " (readable beyond its owner)"), "info", ["ASI03"], p,
                       f"{m}; value not read", "This is the platform's own Grok CLI sign-in file. Watchtower never reads it. Nothing for you to do"
                       + ("." if tight else "; its permissions are wider than 0600, worth reporting to the platform."), ident="platform-grok-cli-sign-in")
    return finding("WT-I009", "Platform secret store present" + ("" if tight else " (readable beyond its owner)"), "info", ["ASI03"], p,
                   f"{m}; value not read", "This is the platform's own store for secrets saved through the secure secret request. "
                   "Watchtower never reads it. Nothing for you to do" + ("." if tight else "; its permissions are wider than 0600, worth reporting to the platform."),
                   ident="platform-secret-store")


def platform_file(f, catalog=True):
    """Grok Bot's own file: real platform skill roots (realpath prefix), its config files, catalog plugins, or system packages.
    A user skill whose path merely contains a platform-looking segment is never platform (Claude v0.7.1 F3). catalog=False
    leaves out catalog plugins, which only state/plugins.json says are the catalog's (platform_scope, PR A Codex round 1, 7)."""
    w = f.get("where", "") if isinstance(f, dict) else str(f)
    if isinstance(f, dict) and f.get("unverified_platform"):   # item 8 (R3): not shown to be the platform's, so it counts as the owner's
        return False
    if in_pending_plugin(w):
        return False
    if isinstance(f, dict) and f.get("platform_hook"):
        return True
    lit = literal_path(f)   # item 8: the producer's own file, when it recorded one
    if (lit in secret_store_places()) if lit else (f"{w}".startswith("/") and is_platform_secret_store(w)):
        return True
    if platform_config_finding(f) or (catalog and in_catalog_plugin(w)) or w.startswith("system python package "):
        return True
    path = lit or (w.split(":")[0] if isinstance(w, str) else "")
    return bool(path.startswith("/")) and under_platform_root(path)


REVIEWED_LABEL = "Platform note (checked)"


def mark_reviewed(fs, manifest):
    """Batch 5 (d2): a platform finding an entry of rules/platform-reviewed.json covers (platform_reviewed: that file's exact bytes,
    that rule and line) is a checked platform note: severity info (the rule's own kept as severity_was), the entry's note as its fix,
    never new and never a rug-pull alert. Run before summarize_refresh and mark_platform. Each finding's _snap (the fingerprint
    of the bytes it was found in, audit) is used here and dropped."""
    for f in fs:
        e = platform_reviewed(f, manifest, f.pop("_snap", None))
        if e is not None:
            f.update({"class": "platform", "label": REVIEWED_LABEL, "severity_was": f.get("severity_was") or f["severity"], "severity": "info",
                      "fix": e["note"], "reviewed": True})
    return fs


def mark_platform(fs):
    """Label Grok Bot's own findings. Worth-a-look and Tips there become one Platform line each; a Confirmed one stays
    Confirmed (it is still shown and still alerts when new) but never counts. Two engines agreeing on a platform skill in words
    that name no dangerous behavior is a Platform line too (DQ-042). A checked one (mark_reviewed) stays as it is."""
    for f in fs:
        if f.get("scope") != "platform" or f.get("guarded") or f.get("reviewed"):
            continue
        if f.get("class") in ("pattern", "tip") or f.get("platform_hook") or unconfirmed_platform_vote(f, fs):   # Ken, Oct 13: the platform's hook is a Platform line
            f["class"], f["label"] = "platform", PLATFORM
            f["fix"] = f["fix"] if f.get("platform_hook") or f["rule"] == "WT-I009" else PLATFORM_FIX
            if f["severity"] != "info" and not f.get("platform_hook"):   # the hook keeps its low (listed fact), never scored
                f["severity_was"], f["severity"] = f["severity"], "info"
        elif f["rule"] not in SECRET_RULES:
            if f["rule"] == "WT-X003" and f["severity"] == "info" and f.get("severity_was"):   # daily re-adds last run's Platform line;
                f["severity"] = f.pop("severity_was")                                        # Watchtower now backs it (DQ-042)
            f["fix"] = PLATFORM_CONFIRMED_FIX
    return fs


def counts(f):
    """Only what the user owns moves the score. Built-in findings count when they are critical or high (two scanners
    agreeing a plugin is dangerous still matters); the rest are listed for information.
    DQ-022/023/024/028–030: true quarantine, sample/test folders outside loadable locations, and fiction inside
    built-in templates never move the score. Sample-named folders inside a loadable skill still count.
    R3: keys and decoy copies (SECRET_RULES) count wherever they sit, including quarantine and sample folders."""
    if f.get("unverified_platform"):
        return True   # Codex, item 8 review 2 (high 1): a platform name is loaded from where it is, even when it leads into quarantine
    w = f.get("where", "")
    path = w.split(":")[0]
    if path and not w.startswith(("rollcall:", "system python package ")) and f["rule"] not in SECRET_RULES:
        if is_quarantined_path(path):
            return False
        if is_sample_skill_path(path) and not is_loadable_skill_location(path):
            return False
    if f.get("scope") == "platform" or platform_file(f):   # v0.7.1 item 4: never, except a real key outside Grok Bot's config
        # batch 6 (B2): nor a gitleaks pattern hit in a metadata file the release list vouches for (metadata_hit_note)
        return f["rule"] in SECRET_RULES and not platform_config_finding(f) and not metadata_hit_note(f)
    return not builtin(f) or f["severity"] in ("critical", "high")


def metadata_hit_note(f):
    """Batch 6 (B2), fix round 1 (Codex 2, 3, 4): a gitleaks pattern hit in Grok Bot's own metadata file that is a platform note,
    not counted. Decided again each time it is asked, never from a stored flag (6cd1ab4's `verified_metadata` is ignored): the
    hit is gitleaks' alone (no provider confirmed a key: TruffleHog's live, dead or unsure, or a critical, always counts), on
    one line of one file; its `metadata_sha256` is the bytes gitleaks_findings bound it to (a private copy of the verified
    bytes gave gitleaks exactly the same hits); and the file has those bytes now, they verify against the release list, and
    every unit's file is itself on it (metadata_proof). Anything else counts, with its cleanup."""
    if f.get("rule") != "WT-S002" or f.get("source") != "gitleaks" or f.get("severity") == "critical":
        return False
    if f.get("title") not in ("gitleaks: secrets in file", KEY_MAYBE):
        return False
    path, _, ln = str(f.get("where") or "").rpartition(":")
    return path.startswith("/") and ln.isdigit() and metadata_proof(path, f.get("metadata_sha256"))


def platform_owned(fs):
    """The platform's own config and the computer's own Python packages can't be fixed by the user and aren't theirs to
    upgrade: they stay visible as low, for-information findings and never count."""
    for f in fs:
        w = f.get("where", "")
        if platform_config_finding(f) and f["rule"] in ("WT-S001", "WT-S002"):   # item 8: exactly Grok Bot's config, never a name in the path
            f.update(severity="low", title="The platform's own access token (every Bot can read it)" if "gateway.json" in w
                     else "The platform's own key file (every Bot can read it)",
                     fix="This is Grok Bot's own config file. You can't change it; it's listed so you know every Bot on this computer can read it.")
    return fs
