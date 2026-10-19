# Part of wt.py: runs inside wt.py's namespace (loaded by _wt_part); not a module on its own.
# ---------------------------------------------------------------- roll-call: memories, routines, connectors per Bot
MEMORY_DIRECTIVE = re.compile(
    r"(?i)\b(always|never|from now on|whenever|every time|automatically|by default|without asking|don'?t ask|skip (the )?approval|"
    r"no need to (ask|confirm)|treat .{0,30} as (trusted|authori[sz]ed)|has (admin|full) (access|permission))\b")
PRIVATE_DATA = re.compile(r"(?i)\b(gmail|outlook|email|drive|docs|notion|slack|calendar|granola|dropbox|supabase|crm|hubspot|salesforce)\b")
UNTRUSTED_IN = re.compile(r"(?i)\b(web|browser|search|x\b|twitter|rss|inbox|incoming|reddit|scrape|tinyfish|fetch)\b")
EXTERNAL_OUT = re.compile(r"(?i)\b(send|reply|post|publish|tweet|email|message|slack|share|upload|webhook|x\b)\b")


# A memory that gives a Bot more room: skip the ask, trust a sender, hold admin rights. "Never send without asking" is the
# opposite and is never flagged; Watchtower never suggests removing a rule that holds a Bot back.
LOOSENING = re.compile(r"(?i)\b(without (asking|approval|confirmation|checking)|don'?t (need to )?(ask|confirm|check)|no need to (ask|confirm|check)|"
                       r"skip(ping)? (the )?(approval|ask|confirmation|gate)|bypass|auto[- ]?approv\w*|allow(ed)? automatically|"
                       r"treat .{0,30} as (trusted|authori[sz]ed)|(has|have|with) (admin|full|unrestricted) (access|permission|rights))")
STANDING = re.compile(r"(?i)\b(always|from now on|whenever|every (time|day|morning|week|weekday|hour)|each (day|morning|week)|automatically|by default)\b")


def memory_loosens(t, rules=None):
    """A memory that loosens permissions: a loosening phrase that isn't itself negated ("never skip the approval").
    Since Ken's call of Oct 10 a plain standing order ("every morning send the digest") is not enough on its own."""
    for m in LOOSENING.finditer(t):
        if not DEFEAT_NEGATED.search(t[max(0, m.start() - 20):m.start()]) and not re.search(r"(?i)\b(never|not|n't)\b[^.;]{0,30}$", t[max(0, m.start() - 40):m.start()]):
            return True
    return False


# Outside content: a memory carrying a link or address, a quoted message, an injection phrase, or words that it came from somewhere else.
OUTSIDE_MEMORY = re.compile(r"(?i)(https?://|www\.|\b[\w.+-]+@[\w-]+\.[\w.]+|\b\d{1,3}(\.\d{1,3}){3}\b|^\s*(from|subject|to|reply-to)\s*:|"
                            r"\b(ignore|disregard|forget)\s+(all\s+|any\s+)?(previous|prior|earlier|your|the\s+above)\s+(instructions|rules)|"
                            r"\bnew\s+instructions\b|^\s*(system|assistant)\s*:|\bon\s+behalf\s+of\b|"
                            r"\b(per|according\s+to|from|as\s+(stated|requested)\s+in)\s+(the|an?|this|that)\s+(e-?mail|message|dm|website|web\s*page|page|post|tweet|doc|document|pdf|comment|issue|ticket|invite|attachment)\b|"
                            r"\b(the|an?|this|that)\s+(e-?mail|message|website|page|post|tweet|doc|document|pdf|comment|issue)\s+(says|said|asks|asked|instructs|wants|told)\b|"
                            r"@\w+\s+(says|said|wants|asked|told))", re.M)
# Owner setup notes: a dated log line "(2026-09-10) ...", "2026-09-10: ...", a tag "[log]" / "[setup]" / "[pref]", a label
# "Owner:", "Setup:", "Profile:", "Preference:", "Note:", a "<Name> 2026-09-25:" line, a first-person note ("I prefer ...", "My ..."),
# or a memory record whose source says the owner or setup wrote it.
OWNER_NOTE = re.compile(r"^\s*(\(?\d{4}-\d{2}-\d{2}\)?\s*[:\-–]?|\[(log|setup|note|pref\w*|profile|owner)\]|"
                        r"(owner|setup|profile|preferences?|notes?|context)\s*:|[A-Z][a-z]+\s+\d{4}-\d{2}-\d{2}\s*:|(I|I'm|I am|My|We|Our)\s)", re.I)
OWNER_SOURCES = {"owner", "user", "setup", "me", "manual"}
OUTSIDE_SOURCES = {"email", "web", "website", "tool", "message", "dm", "document", "import", "external"}


def owner_note(m):
    if isinstance(m, dict):
        src = str(m.get("source") or m.get("origin") or m.get("written_by") or "").strip().lower()
        if src in OWNER_SOURCES:
            return True
        if src in OUTSIDE_SOURCES:
            return False
        m = str(m.get("text") or m.get("content") or m.get("memory") or "")
    return bool(OWNER_NOTE.match(m or ""))


def memory_flag(m, rules=None):
    """Why a memory is a standing order worth a flag, or None. Only two reasons: it loosens permissions, or it looks like outside
    content. A setup note the owner wrote is never flagged for looking like outside content (a link in your own note is fine).
    A loosening line is flagged even in note form: the note marker is plain text anyone can copy."""
    t = m if isinstance(m, str) else json.dumps(m)
    if memory_loosens(t):
        return "loosens permissions"
    if not owner_note(m):
        src = str(m.get("source") or m.get("origin") or "").strip().lower() if isinstance(m, dict) else ""
        if src in OUTSIDE_SOURCES or OUTSIDE_MEMORY.search(t):
            return "looks like it came from outside content"
    return None


# v0.7.1 red-team (second account, Oct 14): any agent can send the roll-call and Bots can't check who is asking, so the question
# asks only for a shape: counts, names and yes/no answers. Nothing in a reply should be worth stealing. Analysis reads only that
# shape (shape_reply); any other field, and any text where a count, a name or a yes/no belongs, is dropped unread and never kept.
ROLLCALL_TRIGGERS = ("schedule", "slack", "github", "email", "webhook", "other")
ROLLCALL_ASK_FIRST = ("email", "messages", "posts", "calendar", "files", "purchases", "settings")
ROLLCALL_SEND_AREAS = frozenset(("email", "messages", "posts"))
ROLLCALL_FIELDS = frozenset(("name", "connectors", "routines", "memories", "ask_first", "auto_allow_rules",
                             "sends_or_posts_without_asking", "reads_outside_content"))
ROLLCALL_ROUTINE_FIELDS = frozenset(("name", "trigger", "sends_or_posts", "asks_first", "reads_outside_content"))
ROLLCALL_MEMORY_FIELDS = frozenset(("count", "loosen_permissions", "from_outside_content"))
RC_NAME_MAX = 60
RC_CONN_MAX = 40


def _rc_yesno(v):
    """A yes/no answer, or None when the reply put anything else there."""
    if isinstance(v, bool):
        return v
    if isinstance(v, str) and v.strip().lower() in ("yes", "no", "true", "false"):
        return v.strip().lower() in ("yes", "true")
    return None


def _rc_count(v):
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return max(0, min(v, 100000))
    if isinstance(v, str) and re.fullmatch(r"\s*\d{1,6}\s*", v):
        return int(v)
    return None


def _rc_name(v, n):
    """A short name, masked. Text longer than a name is not a name: it is dropped, never truncated into the report. PR B, Codex
    round 1 (1): secrets are masked too (mask_secrets: a token, "password=..."), before anything is kept."""
    if not isinstance(v, str):
        return None
    t = re.sub(r"\s+", " ", v).strip()
    if not t or len(t) > n:
        return None
    return mask_rollcall(mask_secrets(t), n)


def shape_reply(d):
    """Keep only the roll-call shape from a parsed reply. Returns (shape, extra) where extra lists, by field name only, what the
    reply carried beyond the question (never the values)."""
    extra = set()
    for k in d:
        if k not in ROLLCALL_FIELDS:
            extra.add(str(k)[:30])
    out = {"name": _rc_name(d.get("name"), RC_NAME_MAX)}
    if d.get("name") is not None and out["name"] is None:
        extra.add("name (not a short name)")
    conns, raw = [], d.get("connectors")
    for c in (raw if isinstance(raw, list) else ([] if raw is None else [raw]))[:40]:
        nm = _rc_name(c, RC_CONN_MAX)
        if nm is None:
            extra.add("connectors (not names)")
        else:
            conns.append(nm)
    out["connectors"] = conns
    # batch 5 PR B, Codex round 3 (2): for the access map, every connector the reply lists (it is at most 64 KB, _rc_read) is read
    # for the vocabulary's labels before any limit, so a name too long to keep ("Gmail account for the operations department") is
    # still Gmail; only labels and a count of other connectors are kept (access_connectors), never the text. An answer without a
    # connector list, or with an item that isn't a name, leaves the Bot's connectors not known whole (rollcall_access).
    items = raw if isinstance(raw, list) else [] if raw is None or (isinstance(raw, str) and not raw.strip()) else [raw]
    out["connector_labels"], out["connectors_other"] = access_connectors([c for c in items if isinstance(c, str)])
    out["connectors_known"] = None if not items and not isinstance(raw, list) else not any(not isinstance(c, str) for c in items)
    rts, raw = [], d.get("routines")
    if raw is not None and not isinstance(raw, list):
        extra.add("routines (not a list)")
        raw = []
    past = [r for r in (raw or [])[60:] if isinstance(r, dict)]   # round 2 (4): counted for the access map, never kept; round 3 (2): all
    out["routines_more"] = len(past)
    out["routines_more_sending"] = sum(1 for r in past if _rc_yesno(r.get("sends_or_posts")) and _rc_yesno(r.get("asks_first")) is not True)
    for r in (raw or [])[:60]:
        if not isinstance(r, dict):
            extra.add("routines (not the asked shape)")
            continue
        for k in r:
            if k not in ROLLCALL_ROUTINE_FIELDS:
                extra.add(f"routines.{str(k)[:24]}")
        trig = r.get("trigger")
        trig = trig.strip().lower() if isinstance(trig, str) and trig.strip().lower() in ROLLCALL_TRIGGERS else "other"
        if r.get("trigger") is not None and trig == "other" and str(r.get("trigger")).strip().lower() != "other":
            extra.add("routines.trigger (not one of the listed kinds)")
        nm = _rc_name(r.get("name"), RC_NAME_MAX)
        if r.get("name") is not None and nm is None:
            extra.add("routines.name (not a short name)")
        rts.append({"name": nm or f"routine {len(rts) + 1}", "trigger": trig, "sends_or_posts": _rc_yesno(r.get("sends_or_posts")),
                    "asks_first": _rc_yesno(r.get("asks_first")), "reads_outside_content": _rc_yesno(r.get("reads_outside_content"))})
    out["routines"] = rts
    mem, raw = {}, d.get("memories")
    if isinstance(raw, dict):
        for k in raw:
            if k not in ROLLCALL_MEMORY_FIELDS:
                extra.add(f"memories.{str(k)[:24]}")
        for k in ROLLCALL_MEMORY_FIELDS:
            mem[k] = _rc_count(raw.get(k))
            if raw.get(k) is not None and mem[k] is None:
                extra.add(f"memories.{k} (not a count)")
    elif raw is not None:
        extra.add("memories (text, not counts)")            # an old-style or naive answer: never read, only its size is known
        mem = {"count": len(raw) if isinstance(raw, list) else None, "loosen_permissions": None, "from_outside_content": None}
    out["memories"] = mem
    af, raw = [], d.get("ask_first")
    for a in (raw if isinstance(raw, list) else ([] if raw is None else [raw])):
        v = a.strip().lower() if isinstance(a, str) else None
        if v in ROLLCALL_ASK_FIRST:
            af.append(v)
        else:
            extra.add("ask_first (not one of the listed areas)")
    out["ask_first"] = sorted(set(af))
    out["auto_allow_rules"] = _rc_count(d.get("auto_allow_rules"))
    if d.get("auto_allow_rules") is not None and out["auto_allow_rules"] is None:
        extra.add("auto_allow_rules (not a count)")
    for k in ("sends_or_posts_without_asking", "reads_outside_content"):
        out[k] = _rc_yesno(d.get(k))
        if d.get(k) is not None and out[k] is None:
            extra.add(f"{k} (not yes/no)")
    return out, sorted(extra)


def _rc_read(p):
    """Read one reply file without following a link, then remove it at once (analysis keeps only the shape)."""
    try:
        if os.path.islink(p) or not os.path.isfile(p):
            return None
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as f:
            raw = f.read(65536)
        try:
            return json.loads(raw.decode("utf-8", "replace"))
        except ValueError:
            return None
    except OSError:
        return None


def _rc_remove(p, rdir):
    if owned_rollcall_dir(rdir):
        try:
            os.remove(p)
            return 1
        except OSError:
            pass
    return 0


def merge_rollcall(prev, rnd, findings, bots, answered, access=None):
    """Oct 15: Foxtrot's late reply, run on its own, replaced all ten Bots' findings with its own. A run in the same roll-call
    round (`rnd`) as the saved file now merges per Bot: a Bot that answered this run (`answered`) replaces only its own findings,
    every other Bot keeps its findings and its name. Outside a round, or against a file from another round or from before
    shape-only replies, this run's findings replace the file as before. A finding's Bot is the `bot` saved with it, never read
    back out of `where`: a Bot may be named "Alpha:memories", which is also where Alpha's WT-M010 points. A finding with no
    saved Bot is kept, never dropped on a guess. Batch 5 (a, Ken's decision 5): `access`, what each Bot said it can reach
    (rollcall_access), is merged per Bot the same way."""
    fresh = {"at": now(), "round": rnd, "masked": VERSION, "shape_only": True, "bots": list(bots), "findings": list(findings),
             "access": dict(access or {})}
    if (rnd is None or not isinstance(prev, dict) or prev.get("round") != rnd or prev.get("shape_only") is not True or not prev.get("masked")
            or not isinstance(prev.get("bots"), list) or not isinstance(prev.get("findings"), list)):
        return fresh
    # PR B, Codex round 1 (1): what is carried over from the file (the Bot can write it) is masked and reduced again
    kept = [dict(f, evidence=mask_rollcall(mask_secrets(str(f.get("evidence") or "")))) for f in prev["findings"]
            if isinstance(f, dict) and not (isinstance(f.get("bot"), str) and f["bot"] in answered)]
    earlier = [b for b in prev["bots"] if isinstance(b, str) and b not in answered]
    pa = prev.get("access") if isinstance(prev.get("access"), dict) else {}
    said = {b: rollcall_said(a) for b, a in pa.items() if b in earlier and isinstance(a, dict)}
    return dict(fresh, bots=earlier + fresh["bots"], findings=kept + fresh["findings"], access=dict(said, **fresh["access"]))


def rollcall_access(sh):
    """What a Bot said it can reach, kept for the access map (batch 5, a; Ken's decision 5): from the reply's shape only, each
    routine's trigger and flags, the memory count (never memory text) and the reply's date. A routine's name is never kept: a naive
    Bot pastes memory text there (test_v071_rollcall_redteam), and the map only counts routines. PR B, Codex round 1 (1): nor is a
    connector's own text: only the vocabulary's label for it, or a count of other connectors (rollcall_said). The access map
    labels all of it "what the Bot said; not checked"."""
    mem = sh["memories"].get("count") if isinstance(sh.get("memories"), dict) else None
    known = sh.get("connectors_known")   # round 3 (2): None, no connector list; False, an item that isn't a name
    return rollcall_said({"said_at": now()[:10], "connectors": list(sh.get("connector_labels", [])), "connectors_other": sh.get("connectors_other", 0),
                          "connectors_unknown": "unsaid" if known is None else None if known else "partial",
                          "routines": [{"trigger": r["trigger"], "sends_without_asking": bool(r["sends_or_posts"]) and r["asks_first"] is not True,
                                        "asks_first": r["asks_first"]} for r in sh["routines"][:60]],
                          "routines_more": sh.get("routines_more", 0), "routines_more_sending": sh.get("routines_more_sending", 0),
                          "memories": mem, "reads_outside_content": sh["reads_outside_content"],
                          "sends_without_asking": sh["sends_or_posts_without_asking"]})


def rollcall_findings(rdir, removed=None, kept=None):
    """Each reply is read once, reduced to its shape, and deleted right away (in Watchtower's own folder). Findings name what
    the Bot said about itself in counts and yes/no answers; no reply text is kept anywhere. Returns this run's findings and
    Bots; the saved file also keeps earlier Bots from the same roll-call round (merge_rollcall), named in `kept`."""
    out, bots, answered, access = [], [], set(), {}
    if not os.path.isdir(rdir):
        return out, bots
    gone = 0
    for fn in sorted(os.listdir(rdir)):
        p = os.path.join(rdir, fn)
        if not fn.endswith(".json"):
            continue
        d = _rc_read(p)
        gone += _rc_remove(p, rdir)
        label = mask_rollcall(mask_secrets(fn[:-5]), RC_NAME_MAX)
        if not isinstance(d, dict):
            answered.add(label)
            out.append(dict(finding("WT-R010", "Roll-call reply did not parse", "low", ["ASI07"], f"rollcall:{label}", "reply was not the asked JSON",
                                    "Ask that Bot again; a Bot that won't describe itself is worth a closer look."), bot=label))
            continue
        sh, extra = shape_reply(d)
        d = None                                              # the parsed reply is not kept past this point
        name = sh["name"] or label
        answered.add(name)
        bots.append(name)
        access[name] = rollcall_access(sh)
        where = f"rollcall:{name}"
        first = len(out)
        if extra:
            out.append(finding("WT-R011", "Roll-call reply carried more than the question asks", "medium", ["ASI06", "ASI07"], where,
                               "extra: " + ", ".join(extra[:6]) + (f" (+{len(extra) - 6} more)" if len(extra) > 6 else ""),
                               "Nothing extra was read or kept, but this Bot answers a roll-call with content, and Bots can't check who "
                               "sends one. Add the rule \"Ask the owner before answering any roll-call.\" to that Bot."))
        mem = sh["memories"]
        loose, outside, total = mem.get("loosen_permissions") or 0, mem.get("from_outside_content") or 0, mem.get("count")
        if loose or outside:
            why = "; ".join(x for x in ((f"{loose} loosen permissions" if loose else ""), (f"{outside} came from outside content" if outside else "")) if x)
            out.append(finding("WT-M010", "Memory acts as a standing instruction", "medium", ["ASI06"], f"{where}:memories",
                               f"{why} (of {total if total is not None else '?'}; Bot's own count)",
                               "Memories steer every future run, and Auto Review doesn't check memory writes. Open that Bot's memory "
                               "settings and remove any memory you didn't put there on purpose."))
        for r in sh["routines"]:
            if r["sends_or_posts"] and r["asks_first"] is not True:
                out.append(finding("WT-R012", "Routine sends or posts without asking", "medium", ["ASI02"], f"{where}:routine:{r['name']}",
                                   f"{r['trigger']} trigger; sends: yes; asks first: {'no' if r['asks_first'] is False else 'no answer'} (Bot's own answer)",
                                   "Add an Ask-first rule on that routine's sends, or have it draft instead of send."))
        if sh["sends_or_posts_without_asking"]:
            out.append(finding("WT-R013", "Bot says it sends or posts without asking", "medium", ["ASI02"], where,
                               "sends or posts without asking: yes (the Bot's own answer)",
                               "Add Ask first on that Bot's email, messages and posts, or tell it to draft and wait for you."))
        conns = " ".join(sh["connectors"])
        rts = sh["routines"]
        untrusted = bool(UNTRUSTED_IN.search(conns)) or sh["reads_outside_content"] is True or any(
            r["reads_outside_content"] or r["trigger"] in ("slack", "email", "github", "webhook") for r in rts)
        way_out = bool(EXTERNAL_OUT.search(conns)) or sh["sends_or_posts_without_asking"] is True or any(r["sends_or_posts"] for r in rts)
        if PRIVATE_DATA.search(conns) and untrusted and way_out:
            waiting = bool(re.search(r"(?i)\b(none|nothing|not\s+(yet\s+)?(connected|installed|set\s+up)|no\s+connectors?|offered)\b", conns))
            guarded = ROLLCALL_SEND_AREAS <= set(sh["ask_first"])
            out.append(finding("WT-L001", "Risky combination once its connectors are added: private data + untrusted input + a way out" if waiting
                               else "Lethal trifecta: private data + untrusted input + a way out", "medium" if (waiting or guarded) else "high", ["ASI01", "ASI02"], where,
                               ("connectors: " + ", ".join(sh["connectors"][:8]) + ("; Ask first on email, messages and posts" if guarded else ""))[:150],
                               "This Bot can read private data, reads content strangers control, and can send outward. "
                               "That's the combination prompt injection needs. Split the jobs across Bots or put Ask first on every send."))
        for f in out[first:]:                             # each finding names its Bot, so a merge never parses `where`
            f["bot"] = name
    if removed is not None:
        removed.append(gone)
    for f in out:                                         # only masked findings are kept, never the reply itself
        f["evidence"] = mask_rollcall(mask_secrets(f["evidence"]))   # PR B, Codex round 1 (1): secrets too
    p = state_path("rollcall_findings.json")
    prev = load_json_regular(p, None)                     # a link or FIFO put there is not read (and never waited on)
    rc = merge_rollcall(prev, current_rollcall_round(), out, bots, answered, access)
    save_json_keep_mode(p, rc)
    if kept is not None:
        kept.extend(rc["bots"][:len(rc["bots"]) - len(bots)])
    return out, bots


ROLLCALL_MAX_DAYS = 35
ROLLCALL_ROUND_DAYS = 7     # a round opens at --question/--save; late replies within it merge, the next monthly roll-call starts fresh


def current_rollcall_round():
    """When the open roll-call round began (its id), or None: no round, a garbled or time-zone-less time, one in the future,
    or one opened more than ROLLCALL_ROUND_DAYS ago."""
    d = load_json_regular(state_path("rollcall_round.json"), None)
    try:
        opened = d["opened"]
        t = dt.datetime.fromisoformat(opened)
        age = dt.datetime.now(dt.timezone.utc) - t
    except (KeyError, TypeError, ValueError):
        return None
    return opened if dt.timedelta(0) <= age <= dt.timedelta(days=ROLLCALL_ROUND_DAYS) else None


def open_rollcall_round():
    """Handing out the question or saving a reply opens a round when none is open. Asking a slow Bot again, or saving its late
    reply, stays in the round that is open: it never starts a new one."""
    rnd = current_rollcall_round()
    if rnd is None:
        rnd = now()
        save_json_keep_mode(state_path("rollcall_round.json"), {"opened": rnd})     # never through a link planted beside it
        ledger({"event": "rollcall-opened", "round": rnd})
    return rnd


def roster_bots():
    """Bot names on the roster the Bot last saved (exports/roster.json), or None when there is no roster to go by."""
    roster = load_json(os.path.join(home(), *ROSTER_FILE), None)
    items = roster.get("entries", roster.get("roster", [])) if isinstance(roster, dict) else roster
    if not isinstance(items, list):
        return None
    return {e["name"].strip() for e in items if isinstance(e, dict) and isinstance(e.get("name"), str) and str(e.get("kind", "")).lower() in BOT_KINDS}


def prune_removed_bots(rc):
    """DQ-018: a Bot the owner removed leaves the report. When the saved roster is newer than the roll-call, findings for Bots not
    on it are dropped from rollcall_findings.json itself (never hand-edited)."""
    bots = roster_bots()
    rpath = os.path.join(home(), *ROSTER_FILE)
    if not bots or not os.path.isfile(rpath):
        return rc, []
    if dt.datetime.fromtimestamp(os.path.getmtime(rpath), dt.timezone.utc).isoformat() < rc.get("at", ""):
        return rc, []
    bot_of = lambda f: f["bot"] if isinstance(f.get("bot"), str) else (f["where"].split(":")[1] if f.get("where", "").startswith("rollcall:") else None)
    gone = sorted({b for b in rc.get("bots", []) if b not in bots} | {bot_of(f) for f in rc.get("findings", []) if bot_of(f) and bot_of(f) not in bots})
    said = rc.get("access") if isinstance(rc.get("access"), dict) else {}
    gone = sorted(set(gone) | {b for b in said if b not in bots})
    if gone:
        rc = dict(rc, bots=[b for b in rc.get("bots", []) if b in bots], findings=[f for f in rc.get("findings", []) if bot_of(f) in bots],
                  **({"access": {b: a for b, a in said.items() if b in bots}} if "access" in rc else {}))
        save_json_keep_mode(state_path("rollcall_findings.json"), rc)
        ledger({"event": "rollcall-removed-bots-dropped", "count": len(gone)})
    return rc, gone


def roster_hint(rc):
    """DQ-018 leftover: removed Bots drop out only against a saved roster newer than the roll-call. Without one, say so (main box,
    Oct 12: no roster.json, so the Oct 9 roll-call kept naming Bots removed on Oct 10)."""
    if not rc or not rc.get("findings"):
        return None
    rpath = os.path.join(home(), *ROSTER_FILE)
    day = str(rc.get("at", ""))[:10]
    if not os.path.isfile(rpath) or not roster_bots():
        return (f"No roster saved: roll-call findings from {day} may name Bots you removed. Save the current roster to "
                "exports/roster.json (the audit skill does this first) and they drop out on the next run.")
    if dt.datetime.fromtimestamp(os.path.getmtime(rpath), dt.timezone.utc).isoformat() < rc.get("at", ""):
        return (f"The saved roster (exports/roster.json) is older than the roll-call from {day}, so removed Bots are not dropped. "
                "Save the current roster and they drop out on the next run.")
    return None


REPLY_MAX_AGE = 3600


def sweep_old_replies(rdir=None):
    """The daily check removes any roll-call reply file older than an hour (a roll-call that never finished) and logs it."""
    rdir = rdir or default_rollcall_dir()
    if not owned_rollcall_dir(rdir):
        return clear_legacy_replies()
    gone, cutoff = 0, time.time() - REPLY_MAX_AGE
    for fn in os.listdir(rdir):
        p = os.path.join(rdir, fn)
        try:
            if (os.path.islink(p) or os.path.isfile(p)) and os.lstat(p).st_mtime < cutoff:
                os.remove(p); gone += 1
        except OSError:
            pass
    if gone:
        ledger({"event": "rollcall-replies-swept", "count": gone, "older_than_seconds": REPLY_MAX_AGE})
    return gone + clear_legacy_replies()


def migrate_rollcall_state():
    """A rollcall_findings.json written before v0.6.8 kept evidence unmasked. Mask it once with mask_rollcall, keeping only
    at/bots/findings; if it can't be read as findings, delete it. Either way it is logged. It is read the same hardened way as
    the merge (no link followed, no FIFO waited on), so a link or FIFO in its place is deleted as unreadable, never opened."""
    p = state_path("rollcall_findings.json")
    if not os.path.lexists(p):
        return None
    d = load_json_regular(p, None)
    if isinstance(d, dict) and d.get("masked"):
        return None
    try:
        fs = d["findings"]
        assert isinstance(fs, list) and all(isinstance(f, dict) and isinstance(f.get("rule"), str) and isinstance(f.get("where"), str) for f in fs)
        for f in fs:
            f["evidence"] = mask_rollcall(f.get("evidence", ""))
        bots = [mask_rollcall(b, 60) for b in d.get("bots", []) if isinstance(b, str)]
        save_json_keep_mode(p, {"at": d.get("at") or now(), "masked": VERSION, "bots": bots, "findings": fs})
        ledger({"event": "rollcall-state-masked", "findings": len(fs)})
        return "masked"
    except (KeyError, TypeError, AssertionError):
        try:
            os.remove(p)
        except OSError:
            return None
        ledger({"event": "rollcall-state-deleted", "why": "written before v0.6.8 and could not be masked"})
        return "deleted"


ROSTER_FILE = ("exports", "roster.json")
ROOM_KINDS = {"room", "rooms", "group", "group room", "group chat", "groupchat", "team room", "channel"}
BOT_KINDS = {"bot", "agent", "dm", "direct message", "person"}


def roster_rooms(roster):
    """The group rooms in the roster the roll-call saw: entries marked as a room or group, or with two or more members.
    Bots, people and anything it can't tell are left out, so an unclear entry never becomes a room."""
    items = roster.get("entries", roster.get("roster", [])) if isinstance(roster, dict) else roster
    out = []
    for e in items if isinstance(items, list) else []:
        if not isinstance(e, dict) or not isinstance(e.get("name"), str):
            continue
        kind = str(e.get("kind") or e.get("type") or "").strip().lower()
        room = kind in ROOM_KINDS or (not kind and isinstance(e.get("members"), list) and len(e["members"]) >= 2)
        if not room or kind in BOT_KINDS:
            continue
        name = re.sub(r"(?i)\s+room$", "", re.sub(r"[\r\n#]+", " ", e["name"]).strip())[:60].strip()
        if name and name.lower() not in {x.lower() for x in out}:
            out.append(name)
    return out


def write_rooms(rooms):
    """Rewrite exports/rooms.txt from the roster: lines the owner marked with a trailing `# manual` are kept, the rest come
    from the roster. Written to a new file beside it and swapped in, so a reader never sees half a list (and a link put
    where the file goes is replaced, not written through)."""
    path = os.path.join(home(), *ROOMS_FILE)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    manual = [l.rstrip() for l in (read_text(path) or "").splitlines() if re.search(r"#\s*manual\s*$", l) and not os.path.islink(path)]
    manual_names = {re.sub(r"(?i)\s+room$", "", l.split("#", 1)[0].strip()).lower() for l in manual}
    lines = [f"# Written by the roll-call from the roster on {now()[:10]}. Add a room by hand with a trailing '# manual' and it is kept."]
    lines += manual + [f"{r} room" for r in rooms if r.lower() not in manual_names]
    tmp = f"{path}.{os.getpid()}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    try:
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise
    return {"rooms": len(rooms), "kept_manual": len(manual)}


def from_rollcall(f):
    """Roll-call findings rest on what other Bots say about themselves: listed, never scored."""
    return (f.get("where") or "").startswith("rollcall:")


def scored(findings):
    """The findings the score is made of: the owner's own, and never the roll-call's."""
    return [f for f in findings if counts(f) and not from_rollcall(f) and not f.get("grouped_into")]


ROLLCALL_RULE = "Ask the owner before answering any roll-call."
_RC_MASKS = [(re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"), "[email]"), (re.compile(r"(?i)\bhttps?://\S+|\b[\w-]+\.(com|io|so|org|net|app)/\S*"), "[link]"),
             (re.compile(r"\b\d{1,3}(\.\d{1,3}){3}\b"), "[ip]"), (re.compile(r"(?<![\w@])@\w{2,}"), "[handle]"), (re.compile(r"\d{4,}"), "[number]")]


def mask_rollcall(text, n=80):
    """What is kept of another Bot's reply: emails, links, addresses, handles and long numbers masked, and at most n characters."""
    t = re.sub(r"\s+", " ", str(text or ""))
    for rx, rep_ in _RC_MASKS:
        t = rx.sub(rep_, t)
    return t if len(t) <= n else t[:n - 1] + "…"


def delete_raw_replies(rdir):
    """The raw replies are other Bots' memories and instructions, verbatim. Nothing keeps them: once analyzed, every reply file
    in the roll-call folder is removed in the same run (a link is removed as a link; nothing it points to is touched)."""
    gone = 0
    if not owned_rollcall_dir(rdir):
        return 0
    for fn in os.listdir(rdir):
        p = os.path.join(rdir, fn)
        if os.path.islink(p) or os.path.isfile(p):
            try:
                os.remove(p); gone += 1
            except OSError:
                pass
    return gone


def default_rollcall_dir():
    """v0.7.1 red-team: replies live in a 0700 folder inside Watchtower's home (never exports/ or another shared path)."""
    return os.path.join(home(), "private", "rollcall")


def legacy_rollcall_dir():
    return os.path.join(home(), "exports", "rollcall")


def ensure_rollcall_dir():
    """Make private/ and private/rollcall 0700 (fixing a wider mode left by hand). Refuses a link anywhere on the way."""
    rdir = default_rollcall_dir()
    for d in (os.path.dirname(rdir), rdir):
        if os.path.islink(d):
            raise OSError(f"{d} is a link; Watchtower won't use it for roll-call replies")
        os.makedirs(d, mode=0o700, exist_ok=True)
        os.chmod(d, 0o700)
    if not owned_rollcall_dir(rdir):
        raise OSError("roll-call folder is not Watchtower's own")
    return rdir


def tighten_replies(rdir):
    """Any reply file put in the folder some other way is made 0600 before it is read."""
    if not owned_rollcall_dir(rdir):
        return
    for fn in os.listdir(rdir):
        p = os.path.join(rdir, fn)
        if os.path.isfile(p) and not os.path.islink(p):
            try:
                os.chmod(p, 0o600)
            except OSError:
                pass


def clear_legacy_replies():
    """Replies an older version left in exports/rollcall (a folder every Bot can list) are removed; links only as links."""
    d = legacy_rollcall_dir()
    n = os.path.normpath(d)
    if os.path.islink(n) or not os.path.isdir(n) or os.path.realpath(n) != n:
        return 0
    gone = 0
    for fn in os.listdir(n):
        p = os.path.join(n, fn)
        if os.path.islink(p) or os.path.isfile(p):
            try:
                os.remove(p); gone += 1
            except OSError:
                pass
    try:
        os.rmdir(n)
    except OSError:
        pass
    return gone


def save_reply(bot, text):
    """`wt.py rollcall --save <Bot>`: write one reply (stdin) as a 0600 file in the 0700 folder. Prints no reply text."""
    rdir = ensure_rollcall_dir()
    base = re.sub(r"[^\w.-]+", "_", str(bot or "bot")).strip("._")[:RC_NAME_MAX] or "bot"
    for i in range(1, 100):
        p = os.path.join(rdir, f"{base}.json" if i == 1 else f"{base}-{i}.json")
        try:
            fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            continue
        with os.fdopen(fd, "w") as f:
            os.fchmod(f.fileno(), 0o600)
            f.write(text[:65536])
        return p
    raise OSError("too many replies saved for one Bot")


def owned_rollcall_dir(rdir):
    """R01: replies are only ever deleted from Watchtower's own roll-call folder, reached without a link anywhere on the way.
    A folder named with --dir is the owner's; nothing in it is deleted."""
    try:
        n = os.path.normpath(os.path.abspath(rdir))
        return n == os.path.normpath(default_rollcall_dir()) and os.path.realpath(n) == n and os.path.isdir(n)
    except (TypeError, ValueError, OSError):
        return False


def cmd_rollcall(args):
    if getattr(args, "question", False) is True:
        open_rollcall_round()
        print(ROLLCALL_PROMPT)
        return 0
    if isinstance(getattr(args, "save", None), str):
        try:
            p = save_reply(args.save, sys.stdin.read())
        except OSError as e:
            print(f"NOT SAVED: {e}")
            return 2
        open_rollcall_round()
        print(f"Saved {os.path.basename(p)} (mode 0600) in Watchtower's private roll-call folder. It is deleted when the roll-call runs, "
              "or by the daily check after an hour.")
        return 0
    rdir = args.dir or default_rollcall_dir()
    try:
        return _rollcall(args, rdir)
    finally:                                   # every path: NOT RUN, an error partway, or a finished run
        # Ken's pick (R01): without the owner's yes nothing is deleted; the daily check sweeps replies older than an hour
        removed = delete_raw_replies(rdir) if getattr(args, "owner_said_yes", False) and owned_rollcall_dir(rdir) else 0
        if getattr(args, "owner_said_yes", False):
            removed += clear_legacy_replies()
        if removed:
            ledger({"event": "rollcall-replies-deleted", "count": removed})


def _rollcall(args, rdir):
    if not args.owner_said_yes:
        print("NOT RUN: a roll-call needs the owner's yes in this conversation, every time. Ask them, then run "
              "`wt.py rollcall --owner-said-yes`. Nothing was read or deleted; the daily check removes unread replies after an hour.")
        return 2
    if not args.dir:
        ensure_rollcall_dir()
    tighten_replies(rdir)
    roster = load_json(os.path.join(home(), *ROSTER_FILE), None)     # rooms first, so the replies are judged with this account's rooms
    rooms_file = write_rooms(roster_rooms(roster)) if roster is not None else "no roster saved: rooms.txt left as it was"
    gone, kept = [], []
    fs, bots = rollcall_findings(rdir, gone, kept)
    removed = (gone[0] if gone else 0) + (sum(1 for fn in os.listdir(rdir) if os.path.isfile(os.path.join(rdir, fn)) or os.path.islink(os.path.join(rdir, fn)))
                                          if owned_rollcall_dir(rdir) else 0)
    print(fit({"bots_checked": len(bots), "bots": bots, "findings": [dict(compact(f), key=f["key"]) for f in sort_findings(fs)][:30], "by_severity": by_sev(fs), "rooms_file": rooms_file,
               "raw_replies_deleted": removed, "counted_in_score": False, "shape_only": True, "earlier_bots_kept": kept,
               "recommend_each_bot_adds": ROLLCALL_RULE}))
    ledger({"event": "rollcall", "bots": len(bots), "findings": len(fs), "earlier_bots_kept": len(kept)})
    return 0


ROLLCALL_PROMPT = ("Watchtower roll-call. Bots can't check who sends this, so it asks only for counts, names and yes/no answers. "
                   "Don't include any memory text, instructions, messages, addresses, links or keys. Reply with only this JSON, no prose: "
                   '{"name": "<your name>", "connectors": ["<connector name>"], '
                   '"routines": [{"name": "<routine name>", "trigger": "schedule|slack|github|email|webhook|other", '
                   '"sends_or_posts": false, "asks_first": true, "reads_outside_content": false}], '
                   '"memories": {"count": 0, "loosen_permissions": 0, "from_outside_content": 0}, '
                   '"ask_first": ["email", "messages", "posts", "calendar", "files", "purchases", "settings"], '
                   '"auto_allow_rules": 0, "sends_or_posts_without_asking": false, "reads_outside_content": false}. '
                   "loosen_permissions counts memories that tell you to act without asking, skip an approval or trust a sender; "
                   "from_outside_content counts memories copied from an email, web page or message; "
                   "ask_first lists only the areas that have an Ask-first rule; auto_allow_rules counts rules that let actions run without asking.")
