# Part of isr.py: runs inside isr.py's namespace (loaded by _isr_part); not a module on its own.
# v0.8.3: the daily check says when the rule list, the settings or the access map changed since the last daily run. A rule no
# pattern flags (added, removed, an Ask-first rule taken out) used to give NO_CHANGES. state/rules_snapshot.json keeps each rule's
# sha256 and its text masked and cut, never the raw text. Unknown is not zero: a side ISR Bot couldn't read is not compared.
RULES_SNAPSHOT = "rules_snapshot.json"
RULE_TEXT_MAX = 200
RULES_SHOWN = 10
# (snapshot field, the access map's shared field it comes from): compared only when that field was checked and seen whole both times
RULE_MAP_FIELDS = (("auto_allow", "settings"), ("auto_review", "settings"), ("runs_programs", "settings"), ("mcp_tools", "mcp"),
                   ("plugins", "plugins"), ("scheduled", "scheduled"), ("hooks", "hooks"), ("webhooks", "webhooks"),
                   ("cli_logins", "cli_logins"), ("browser_sites", "browser"), ("browser_sensitive", "browser"))
RULE_MAP_NAMES = (("mcp", "mcp_tools"), ("plugins", "plugins"))


def _rule_text(s):
    """A rule as it is kept and shown: secrets masked, controls shown as their codes, at most RULE_TEXT_MAX characters."""
    return exact_line(mask_secrets(str(s)))[:RULE_TEXT_MAX]


def _rule_kind(entry):
    return "allow" if re.match(r"(?i)\s*allow\s+automatically", entry) else "ask" if re.match(r"(?i)\s*ask\s+first", entry) else None


def rules_snapshot_now():
    """This run's snapshot: the rules (native settings, read as the linter reads them, and the auto-review exports), the
    settings, and the counts and names from the access map this run built."""
    seen = []

    def read(p):
        if _look(p, follow=True) is not False:   # there, or ISR Bot couldn't look: not "missing"
            seen.append(p)
        return load_json(p, None)
    nat = native_settings(entries=True, read=read)
    found = "found" if nat else "unreadable" if seen else "missing"
    # the exports are a source of their own (Codex, fix round 1): read with or without a settings file, "unreadable" when any
    # auto-review export couldn't be read, so its rules are never taken as removed
    exports = os.path.join(home(), "exports")
    names = [fn for fn in sorted(os.listdir(exports)) if fn.lower().startswith(("auto-review", "autoreview"))] if os.path.isdir(exports) else []
    texts = [read_text(os.path.join(exports, fn)) for fn in names]
    ex_found = "missing" if not names else "unreadable" if None in texts else "found"
    rules, have = [], set()
    for src, entries in (("settings", list(nat[0]) if nat else []), ("exports", [e for t in texts if t is not None for e in rule_entries(t)])):
        for raw in rule_entries(entries):
            kind, h = _rule_kind(raw), auto_allow_fingerprint(raw)
            if kind and (src, h) not in have:
                have.add((src, h))
                text = re.sub(r"(?i)^\s*(allow\s+automatically|ask\s+first)\s*:\s*", "", raw)
                rules.append({"h": h, "kind": kind, "src": src, "text": _rule_text(text)})
    s = nat[1] if nat else {}
    cur = {"v": 1, "rules": rules, "settings": {"local_execution": s.get("local_execution"), "auto_review": s.get("auto_review"), "found": found},
           "exports": ex_found, "map": {}, "map_names": {}, "map_known": []}
    m = load_access_map()
    sh = m.get("shared") if isinstance(m, dict) and isinstance(m.get("shared"), dict) else None
    if sh is None:
        return cur
    b = sh["browser"] or {}
    cur["map"] = {"auto_allow": sum(sh["auto_allow_areas"].values()), "auto_review": sh["auto_review"], "runs_programs": sh["runs_programs"],
                  "mcp_tools": sh["mcp"]["count"], "plugins": sh["plugins"]["added"] + sh["plugins"]["grok"], "scheduled": _ax_jobs(sh),
                  "hooks": sh["hooks"]["platform"] + sh["hooks"]["other"], "webhooks": sh["webhook_count"], "cli_logins": sh["cli_count"],
                  "browser_sites": b.get("sites"), "browser_sensitive": b.get("sensitive_count")}
    # a plugin kept in a version folder (<name>/1.1.1) is named by its version: a bump is no new plugin (DQ-047, v0.8.1: silent)
    cur["map_names"] = {"mcp": sorted({t["name"] for t in sh["mcp"]["tools"]}),
                        "plugins": sorted({n for n in sh["plugins"]["names"] if not re.fullmatch(r"v?\d+(\.\d+)+\S*", n)})}
    cur["map_known"] = [f for f, area in RULE_MAP_FIELDS if _ax_complete(sh, area) and (area != "settings" or sh["settings"] == "found")]
    return cur


def load_rules_snapshot():
    """The last daily run's snapshot, or None. The Bot can write state/, so every text is masked and cut again."""
    d = load_json_regular(state_path(RULES_SNAPSHOT), None)
    if not (isinstance(d, dict) and d.get("v") == 1 and isinstance(d.get("rules"), list) and isinstance(d.get("settings"), dict)):
        return None
    d["rules"] = [dict(r, text=_rule_text(r.get("text", ""))) for r in d["rules"]
                  if isinstance(r, dict) and isinstance(r.get("h"), str) and r.get("kind") in ("allow", "ask") and r.get("src") in ("settings", "exports")]
    d["exports"] = d.get("exports") if isinstance(d.get("exports"), str) else None
    for k in ("map", "map_names"):
        d[k] = d[k] if isinstance(d.get(k), dict) else {}
    d["map_names"] = {k: [_rule_text(n)[:40] for n in v if isinstance(n, str)] for k, v in d["map_names"].items() if isinstance(v, list)}
    d["map_known"] = [f for f in d.get("map_known") or [] if isinstance(f, str)] if isinstance(d.get("map_known"), list) else []
    return d


def _capped(texts):
    return texts[:RULES_SHOWN] + ([f"+{len(texts) - RULES_SHOWN} more"] if len(texts) > RULES_SHOWN else [])


def diff_rules(prev, cur):
    """What changed from `prev` to `cur` ({rules, settings, map, names, rules_not_compared}, only the parts that did), or None.
    A source's rules (the settings file, the auto-review exports) are compared only when it was read both times, the settings
    only when the settings file was; a map field only when it was checked and seen whole both times. An edited rule is one
    removed and one added."""
    out = {}
    state = {"settings": (prev["settings"].get("found"), cur["settings"]["found"]), "exports": (prev.get("exports"), cur["exports"])}
    both = {src for src, (p, c) in state.items() if p == c == "found"}
    if both:
        rules, counts = {}, {}
        for kind in ("allow", "ask"):
            a = {r["h"]: r["text"] for r in prev["rules"] if r["kind"] == kind and r["src"] in both}
            b = {r["h"]: r["text"] for r in cur["rules"] if r["kind"] == kind and r["src"] in both}
            for what, texts in (("added", [t for h, t in b.items() if h not in a]), ("removed", [t for h, t in a.items() if h not in b])):
                if texts:
                    rules[f"{kind}_{what}"] = _capped(texts)
            counts[kind] = [len(a), len(b)]
        if rules:
            out["rules"] = dict(rules, counts=counts)
    if "settings" in both:
        s = {k: [prev["settings"].get(k), cur["settings"][k]] for k in ("local_execution", "auto_review") if prev["settings"].get(k) != cur["settings"][k]}
        if s:
            out["settings"] = s
    # said once, when it changes: a reader failure never reads as "all rules removed"
    nc = [f"{name} {state[src][1]}" for src, name in (("settings", "settings.json"), ("exports", "auto-review exports"))
          if state[src][1] not in (state[src][0], "found")]
    if nc:
        out["rules_not_compared"] = ", ".join(nc)
    known = set(prev["map_known"]) & set(cur["map_known"])
    m = {f: [prev["map"].get(f), cur["map"].get(f)] for f, _ in RULE_MAP_FIELDS if f in known and prev["map"].get(f) != cur["map"].get(f)}
    if m:
        out["map"] = m
    names = {}
    for n, field in RULE_MAP_NAMES:
        if field in known:
            a, b = prev["map_names"].get(n, []), cur["map_names"].get(n, [])
            for what, got in (("added", [x for x in b if x not in a]), ("removed", [x for x in a if x not in b])):
                if got:
                    names[f"{n}_{what}"] = _capped(got)
    if names:
        out["names"] = names
    return out or None


def rule_changes_line(chg):
    """One line for the daily output: what changed, counts only (the texts are in rule_changes)."""
    parts = []
    r = chg.get("rules") or {}
    for kind, word in (("allow", "Allow-automatically rules"), ("ask", "Ask-first rules")):
        if any(k.startswith(kind + "_") for k in r):
            a, b = r["counts"][kind]
            parts.append(f"{word} changed ({a} -> {b})")
    for k, (a, b) in (chg.get("settings") or {}).items():
        parts.append(f"{k} {a} -> {b}")
    for k, (a, b) in (chg.get("map") or {}).items():
        parts.append(f"access map {k} {a} -> {b}")
    words = {"mcp_added": "new MCP tools", "mcp_removed": "MCP tools gone", "plugins_added": "new plugins", "plugins_removed": "plugins gone"}
    for k, v in (chg.get("names") or {}).items():
        parts.append(f"{words[k]}: " + ", ".join(v[:3]) + (" and more" if len(v) > 3 else ""))
    if chg.get("rules_not_compared"):
        parts.append(f"rules not compared: {chg['rules_not_compared']}")
    return "; ".join(parts)[:300]


def rule_changes():
    """(this run's changes since the last daily run's snapshot or None, this run's snapshot). The first run on a box has nothing
    to compare: it says nothing. The snapshot is saved by keep_rules_snapshot, only after the output is printed."""
    cur = rules_snapshot_now()
    prev = load_rules_snapshot()
    return (diff_rules(prev, cur) if prev else None), cur


def keep_rules_snapshot(cur):
    """Save `cur` as state/rules_snapshot.json (0600) when it differs from the saved one; a quiet day writes nothing."""
    p = state_path(RULES_SNAPSHOT)
    prev = load_json_regular(p, None)
    if isinstance(prev, dict) and {k: v for k, v in prev.items() if k != "at"} == cur:
        return
    try:
        os.close(os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600))   # a new file is 0600 from the start
    except FileExistsError:
        pass
    save_json_keep_mode(p, dict(cur, at=now()))
    if prev is None:
        ledger({"event": "rules-snapshot-first"})
