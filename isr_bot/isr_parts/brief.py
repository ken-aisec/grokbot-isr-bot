# Part of isr.py: runs inside isr.py's namespace (loaded by _isr_part); not a module on its own.
# ---------------------------------------------------------------- weekly threat brief
def http_get(url, timeout=15, accept="*/*"):
    import urllib.request
    req = urllib.request.Request(url, headers={"User-Agent": f"ISR-Bot/{VERSION} (+threat brief)", "Accept": accept})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read(3_000_000).decode("utf-8", errors="replace")


def strip_tags(t):
    t = re.sub(r"(?is)<(script|style).*?</\1>", " ", t or "")
    t = re.sub(r"<[^>]+>", " ", t)
    t = html.unescape(t)
    return re.sub(r"\s+", " ", t).strip()


def parse_date(s):
    from email.utils import parsedate_to_datetime
    s = (s or "").strip()
    for fn in (lambda x: parsedate_to_datetime(x), lambda x: dt.datetime.fromisoformat(x.replace("Z", "+00:00"))):
        try:
            d = fn(s)
            return d if d.tzinfo else d.replace(tzinfo=dt.timezone.utc)
        except (TypeError, ValueError, IndexError):
            continue
    return None


def parse_feed(xml_text):
    import xml.etree.ElementTree as ET
    items = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return items
    strip_ns = lambda t: t.split("}")[-1]
    for el in root.iter():
        tag = strip_ns(el.tag)
        if tag not in ("item", "entry"):
            continue
        d = {}
        for c in el:
            ct = strip_ns(c.tag)
            if ct == "title":
                d["title"] = strip_tags(c.text or "")
            elif ct == "link":
                d["link"] = c.attrib.get("href") or (c.text or "").strip() or d.get("link", "")
            elif ct in ("pubDate", "published", "updated", "date") and "date" not in d:
                d["date"] = parse_date(c.text)
            elif ct in ("description", "summary", "content", "encoded"):
                # The article text is never kept or passed on (it is someone else's words, and may be written to steer a Bot).
                # Only the CVE IDs in it are taken.
                d.setdefault("cves", set()).update(x.upper() for x in CVE_ID.findall(c.text or ""))
        if d.get("title"):
            d["cves"] = sorted(d.get("cves", set()) | {x.upper() for x in CVE_ID.findall(d["title"])})
            items.append(d)
    return items


CVE_ID = re.compile(r"(?i)\bCVE-\d{4}-\d{4,7}\b")


def version_of(name):
    if name == "isr-bot":
        return VERSION
    exe = tool(name)
    if not exe:
        return None
    for args in (["--version"], ["version"]):
        code, out_s, err = run([exe] + args, 20)
        m = re.search(r"v?(\d+\.\d+(\.\d+)?)", out_s + err)
        if m:
            return m.group(1)
    return None


def vtuple(v):
    return tuple(int(x) for x in re.findall(r"\d+", v or "")[:3])


# ---------------------------------------------------------------- weekly threat brief (watch report)
FEEDS_PATH = os.path.join(HERE, "..", "rules", "feeds.json")

# Categories: how a story touches a Grok Bot account. Order = tie-break priority.
CATEGORIES = [
    ("mcp", "MCP and connectors", r"(?i)\bmcp\b|model context protocol|connector|oauth|tool (description|poisoning)"),
    ("hijack", "Agent hijacking", r"(?i)prompt[- ]injection|indirect injection|jailbreak|agent[^.]{0,40}(bypass|hijack|escap|exfiltrat|takeover)|(bypass|escap)[^.]{0,30}(sandbox|control|guardrail)"),
    ("supply", "Supply chain", r"(?i)malicious (package|npm|pypi|extension|skill|plugin|template)|typosquat|npm|pypi|crate|extension|marketplace|dependency|supply[- ]chain"),
    ("creds", "Credentials and data exposure", r"(?i)credential|token|api key|secret|exposed|leak|exfiltrat|billing|session"),
    ("browser", "Browser and sessions", r"(?i)browser|chrom|cookie|extension|session hijack"),
    ("platform", "Platform and models", r"(?i)\bgrok\b|\bxai\b|x\.ai|cursor|openai|anthropic|claude|gemini|copilot|codex|model"),
]
BOOST = [
    (r"(?i)\bcve-\d{4}-\d+", 3), (r"(?i)actively exploited|in the wild|zero[- ]day|0-day", 4), (r"(?i)critical|cvss\s*(9|10)|9\.\d", 2),
    (r"(?i)\bmcp\b|model context protocol", 4), (r"(?i)prompt[- ]injection", 4), (r"(?i)malicious (package|npm|pypi|extension|skill)", 3),
    (r"(?i)agent", 2), (r"(?i)steal|exfiltrat|bypass|escape|takeover|remote code|command execution|\brce\b", 2),
    (r"(?i)oauth|credential|token|api key", 2), (r"(?i)browser|chrome|extension", 1), (r"(?i)\bgrok\b|\bxai\b|cursor", 3),
    (r"(?i)agents?\b[^.]{0,60}(bypass|escap|exfiltrat|expos|leak|steal|delet|wip|rogue|went around)", 4),
    (r"(?i)(bypass|escap)\w*[^.]{0,40}(control|sandbox|guardrail|restriction|approval)", 2),
]
DAMPEN = [r"(?i)how we (found|built|used)|we found \d+|using (our|an) (open[- ]source )?ai|podcast|webinar|sponsored|partner content|how .{0,40} (can|should) modernize|framework for|\bguide to\b|ebook|survey finds|report details|predictions|roundup|best practices"]
SOURCE_WEIGHT = {"research": 2, "standards": 2, "supply-chain": 1, "news": 0}


def clip(t, n):
    """End on a full sentence when possible, never mid-word."""
    t = (t or "").strip()
    complete = t.endswith((".", "!", "?", '"', "”", "…", ")"))
    if len(t) <= n and complete:
        return t
    cut = t[:n]
    end = max(cut.rfind(". "), cut.rfind("? "), cut.rfind("! "))
    if end > (20 if not complete and len(t) <= n else len(cut) * 0.45):
        return cut[:end + 1]
    return cut[:cut.rfind(" ")].rstrip(",;:") + "…"


def classify(text):
    for cid, label, rx in CATEGORIES:
        if re.search(rx, text):
            return cid, label
    return "platform", "Platform and models"


ACCESS_BOOST = 3   # batch 5 (b): a story about something this computer actually reaches ranks higher, by this much at most


def story_score(text, kind, touches=False):
    sc = SOURCE_WEIGHT.get(kind, 0) + sum(w for rx, w in BOOST if re.search(rx, text)) + (ACCESS_BOOST if touches else 0)
    if any(re.search(rx, text) for rx in DAMPEN):
        sc -= 5
    return sc


def account_context():
    """Real numbers from this computer, used to say what a story means here."""
    snap = load_snapshot({}) or {}
    inv = snap.get("inventory", {})
    fs = snap.get("findings", [])
    sess = next((f for f in fs if f["rule"] == "ISR-S004"), None)
    sites = None
    if sess:
        ev = sess.get("evidence") or ""
        m = re.search(r"sensitive:\s*(.+)$", ev)
        if m:
            sens = m.group(1).strip()
            if sens and sens != "none":
                sites = len([x.strip() for x in sens.split(",") if x.strip()])
    pkg = load_json(state_path("package_vulns.json"), {}) or {}
    rc = load_json(state_path("rollcall_findings.json"), {}) or {}
    return {"mcp": inv.get("mcp_configs", 0), "skills": inv.get("skills", 0), "plugins": inv.get("plugin_files", 0),
            "sites": sites, "packages": pkg.get("packages"), "bots": len(rc.get("bots", [])) or None,
            "cli": sum(1 for f in fs if f["rule"] == "ISR-S003"), "secrets": sum(1 for f in fs if f["rule"] in ("ISR-S001", "ISR-S002") and f["severity"] == "critical")}


def means_here(cat, ctx, amap=None):
    """What a story of this category means on this computer. Batch 5 (b): with an access map, its counts and tool names are used
    where it has them; without one (an older box) the text is exactly what it was."""
    n = lambda v, one, many: f"{v} {one if v == 1 else many}" if v else None
    if amap is not None:
        sh = amap["shared"]
        tools, total = [t["name"] for t in sh["mcp"]["tools"]], sh["mcp"]["count"]   # PR B, Codex round 1 (3): the whole count
        if cat == "mcp" and tools:
            names = ", ".join(tools[:3]) + (f" and {total - len(tools[:3])} more" if total > 3 else "")
            return (f"This computer has {n(total, 'tool connection', 'tool connections')} ({names}). Every Bot that loads a poisoned "
                    "tool description follows it, with the logins all your Bots share.")
        ctx = dict(ctx, sites=(sh["browser"] or {}).get("sites") or ctx.get("sites"), secrets=sh["key_files"] or ctx.get("secrets"))
    if cat == "mcp":
        bits = [n(ctx["mcp"], "MCP config", "MCP configs"), n(ctx["plugins"], "plugin file", "plugin files")]
        have = " and ".join(b for b in bits if b) or "MCP connectors"
        return f"This computer has {have}. Every Bot that loads a poisoned tool description follows it, with the logins all your Bots share."
    if cat == "hijack":
        return ("Your Bots read web pages, email and posts that strangers write. Injected text there can steer a Bot, and on a shared "
                "computer that Bot can reach every login" + (f" (the browser is signed in to {ctx['sites']} sites)." if ctx["sites"] else "."))
    if cat == "supply":
        return (f"Templates add skills ({ctx['skills']} are on this computer now), and Bots install packages on request. "
                "Anything installed runs with every Bot's access.")
    if cat == "creds":
        extra = f" ISR Bot found {ctx['secrets']} files with live-looking secrets on this computer." if ctx["secrets"] else ""
        return "Any Bot can read any file on the shared computer, including tokens other tools leave behind." + extra
    if cat == "browser":
        return (f"All your Bots share one browser profile" + (f", signed in to {ctx['sites']} sites" if ctx["sites"] else "") +
                ". A browser-level attack reaches every account at once.")
    return ("Your Bots work through AI tools and gateways like this one. A flaw here shows what an attacker can do once an agent "
            "holds access, which on a shared computer means every login.")


DO_THIS = {
    "mcp": "Remove connectors no Bot uses, and put Ask first on anything that sends or shares.",
    "hijack": "Make sure every Bot that reads outside content has an approval line before it sends, posts or buys.",
    "supply": "Ask ISR Bot to vet any template before you add it, and let the daily watch flag new skills.",
    "creds": "Ask ISR Bot for an audit and clear the secret findings; rotate anything that looks live.",
    "browser": "Sign the shared browser out of sites no Bot needs; keep AI consoles and admin sites signed out.",
    "platform": "Skim the change; ask ISR Bot for a fresh audit if it touches approvals, routines or connectors.",
}


WORDS = {1: "One", 2: "Two", 3: "Three", 4: "Four", 5: "Five"}


def split_stories(b):
    """Top five: stories with a concrete way to reach a Grok Bot account; generic platform news only if it scores high."""
    top = [r for r in b["research"] if r["category"] != "platform" or r["score"] >= 8][:5]
    ids = {r["id"] for r in top}
    return top, [r for r in b["research"] if r["id"] not in ids]


def threat_level(b, snap, stories):
    fs = (snap or {}).get("findings", [])
    pts = min(2, sum(1 for k in b["kev"] if k["relevant"])) + min(2, sum(1 for s in stories if s["tier"] == "act"))
    pts += 2 if any(f["severity"] == "critical" and not f["rule"].startswith("ISR-K") for f in fs) else 0
    pts += 3 if any(f["rule"].startswith("ISR-K") for f in fs) else 0  # a tripwire firing is the strongest signal there is
    pts += 1 if (snap or {}).get("score", 100) < 50 else 0
    for i, (lvl, cut) in enumerate((("Low", 1), ("Guarded", 3), ("Elevated", 5), ("High", 7))):
        if pts <= cut:
            return i, lvl, pts
    return 4, "Severe", pts


def app_commit():
    """The commit this copy of ISR Bot was installed from (install.sh keeps the clone's .git), or None."""
    g = os.path.join(SELF_ROOT, ".git")
    try:
        head = open(os.path.join(g, "HEAD")).read().strip()
        if head.startswith("ref: "):
            head = open(os.path.join(g, head[5:])).read().strip()
        return head if re.fullmatch(r"[0-9a-f]{40}", head) else None
    except OSError:
        return None


def isr_bot_update(r, get):
    """ISR Bot is published as tags, not GitHub releases, so releases/latest has nothing to say. Read the tags, take the
    highest version, and check that the tag for the installed version still points at the commit installed here.
    Returns (update or None, tag-moved warning or None). Only reads: it never installs or updates."""
    tags = json.loads(get(f"https://api.github.com/repos/{r['repo']}/tags?per_page=100", accept="application/vnd.github+json"))
    vers = [(vtuple(t["name"]), t) for t in tags if isinstance(t, dict) and re.fullmatch(r"v?\d+\.\d+(\.\d+)?", str(t.get("name", "")))]
    if not vers:
        return None, None
    best = max(vers, key=lambda x: x[0])[1]
    have = VERSION
    mine = next((t for v, t in vers if v == vtuple(have)), None)
    installed, moved = app_commit(), None
    if mine and installed and (mine.get("commit") or {}).get("sha") and mine["commit"]["sha"] != installed:
        moved = {"tag": mine["name"], "now": mine["commit"]["sha"], "installed": installed}
    if vtuple(best["name"]) > vtuple(have):
        sha = (best.get("commit") or {}).get("sha", "")
        return ({"name": r["name"], "have": have, "latest": best["name"].lstrip("v"), "tag": best["name"], "commit": sha,
                 "url": f"https://github.com/{r['repo']}/tree/{best['name']}"}, moved)
    return None, moved


def gather_brief(cfg, offline=None):
    """Collect everything the brief needs. offline: dict of url->text for tests."""
    get = (lambda u, **k: offline[u]) if offline is not None else http_get
    days = cfg.get("window_days", 7)
    since = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)
    rel = re.compile(cfg["relevance"])
    sources, research = [], []
    amap = load_access_map()
    for fd in cfg["feeds"]:
        try:
            items = parse_feed(get(fd["url"], accept="application/rss+xml, application/atom+xml, application/xml"))
            sources.append({"name": fd["name"], "url": fd["url"], "status": "ok", "items": len(items)})
        except Exception as e:
            sources.append({"name": fd["name"], "url": fd["url"], "status": f"unavailable ({type(e).__name__})", "items": 0})
            continue
        for it in items:
            if it.get("date") and it["date"] < since:
                continue
            text = f"{it['title']} {' '.join(it.get('cves', []))}"   # title and CVE IDs only, never the article text
            if not (fd.get("all_relevant") or rel.search(text)):
                continue
            if re.search(r"(?i)\b(podcast|webinar|sponsored|ebook|whitepaper|on-demand|register now|live demo)\b", it["title"]):
                continue  # formats, not events
            sc = story_score(text, fd["kind"])
            if sc < 3:
                continue
            if story_touch(text, amap)[1]:   # batch 5 (b): ranked up by what it touches here, never let in by it
                sc = story_score(text, fd["kind"], touches=True)
            cat, label = classify(text)
            research.append({"id": hashlib.sha1(it["title"].encode()).hexdigest()[:8], "source": fd["name"], "kind": fd["kind"],
                             "title": it["title"], "link": it.get("link", ""), "date": it["date"].date().isoformat() if it.get("date") else "",
                             "cves": it.get("cves", []), "score": sc, "category": cat, "category_label": label})
    seen, dedup = set(), []
    for r in sorted(sorted(research, key=lambda x: x["date"], reverse=True), key=lambda x: -x["score"]):
        k = re.sub(r"\W+", "", r["title"].lower())[:60]
        if k not in seen:
            seen.add(k)
            dedup.append(r)
    for i, r in enumerate(dedup):
        r["tier"] = "act" if r["score"] >= 8 and i < 3 else "watch" if r["score"] >= 6 else "know"
    research = dedup[:16]

    kev, kev_status = [], "ok"
    try:
        data = json.loads(get(cfg["kev_url"], accept="application/json"))
        watch = re.compile(cfg["kev_watch"])
        for v in data.get("vulnerabilities", []):
            added = parse_date(v.get("dateAdded", "") + "T00:00:00+00:00")
            if added and added >= since:
                text = f"{v.get('vendorProject')} {v.get('product')}"
                used, hit = story_touch(text, amap)   # batch 5 (b): relevant too when the product is one this computer reaches
                kev.append({"cve": v.get("cveID"), "vendor": v.get("vendorProject"), "product": v.get("product"),
                            "name": v.get("vulnerabilityName"), "added": v.get("dateAdded"), "due": v.get("dueDate"),
                            "ransomware": v.get("knownRansomwareCampaignUse") == "Known", "relevant": bool(watch.search(text)) or hit})   # no free text from the feed
                if hit:
                    kev[-1]["used_here"] = used["label"]   # the vocabulary's own label, never the feed's words
        kev.sort(key=lambda x: (not x["relevant"], x["added"]))
    except Exception as e:
        kev_status = f"unavailable ({type(e).__name__})"
    sources.append({"name": "CISA Known Exploited Vulnerabilities", "url": cfg["kev_url"], "status": kev_status, "items": len(kev)})

    updates, tag_moved = [], None
    for r in cfg.get("releases", []):
        if r.get("installed") == "isr-bot":    # v0.6.6 skipped its own repo here, so the newer-version notice could never fire
            try:
                u, tag_moved = isr_bot_update(r, get)
                if u:
                    updates.append(u)
            except Exception:
                pass
            continue
        try:
            rel_ = json.loads(get(f"https://api.github.com/repos/{r['repo']}/releases/latest", accept="application/vnd.github+json"))
            latest = (rel_.get("tag_name") or "").lstrip("v")
            have = version_of(r["installed"])
            if latest and have and vtuple(latest) > vtuple(have):
                updates.append({"name": r["name"], "have": have, "latest": latest, "url": rel_.get("html_url", "")})
        except Exception:
            continue

    pages, page_state = [], load_json(state_path("watch_pages.json"), {})
    for pg in cfg.get("watch_pages", []):
        try:
            text = strip_tags(get(pg["url"], accept="text/html"))
            m = re.search(r"(?i)last updated[^\w]{0,5}((?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.? \d{1,2},? \d{4}|\d{4}-\d{2}-\d{2})", text)
            stamp = m.group(1) if m else hashlib.sha256(text[:20000].encode()).hexdigest()[:16]
            prev = page_state.get(pg["url"])
            if prev and prev != stamp:
                pages.append({"name": pg["name"], "url": pg["url"], "was": prev, "now": stamp})
            page_state[pg["url"]] = stamp
        except Exception:
            continue
    save_json(state_path("watch_pages.json"), page_state)
    return {"research": research, "kev": kev, "updates": updates, "pages": pages, "sources": sources, "window_days": days, "isr_bot_tag_moved": tag_moved}


EXPOSURE_AREAS = [
    ("Secrets on the shared computer", ("ISR-S001", "ISR-S002", "ISR-S003", "ISR-T011", "ISR-T011x")),   # batch 6: T011x is T011
    ("Logged-in browser sessions", ("ISR-S004",)),
    ("Skills and templates", ("ISR-X001", "ISR-X002", "ISR-X003", "ISR-T001", "ISR-T002", "ISR-T003", "ISR-T004", "ISR-T005", "ISR-T006", "ISR-T007", "ISR-T008", "ISR-T018", "ISR-I001")),
    ("Approvals and settings", ("ISR-A001", "ISR-A002", "ISR-A003", "ISR-A004", "ISR-A005", "ISR-C001", "ISR-C003", "ISR-C005")),
    ("Bots, memories and routines", ("ISR-M010", "ISR-L001", "ISR-R002", "ISR-T013", "ISR-R011", "ISR-R012", "ISR-R013")),
    ("Packages", ("ISR-D001",)),
    ("Tripwires and history", ("ISR-K001", "ISR-K002", "ISR-K003", "ISR-K006", "ISR-H001", "ISR-H002", "ISR-H003", "ISR-H004", "ISR-H005", "ISR-H006", "ISR-H009")),
]


def exposure(snap):
    fs = [f for f in (snap or {}).get("findings", []) if f["severity"] in ("critical", "high", "medium")]
    rows = []
    for label, rules in EXPOSURE_AREAS:
        hits = [f for f in fs if f["rule"] in rules]
        if not hits:
            rows.append({"area": label, "state": "clear", "count": 0, "top": None})
            continue
        top = sorted(hits, key=lambda f: SEV_ORDER.index(f["severity"]))[0]
        rows.append({"area": label, "state": top["severity"], "count": len(hits), "top": top})
    return rows


def handled_this_week():
    since = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=7)).isoformat()
    fixed = sum(1 for v in (load_json(state_path("resolved.json"), {}) or {}).values() if v >= since)
    cleaned = 0
    try:
        with open(state_path("ledger.jsonl")) as f:
            for line in f:
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                if e.get("at", "") < since:
                    continue
                if e.get("event") == "fix":
                    cleaned += e.get("steps", 0)
    except OSError:
        pass
    return fixed, cleaned


def svg_trend(hist):
    pts = hist[-10:]
    w, h, pad = 300, 92, 6
    if len(pts) < 2:
        return "<p class='quiet'>The trend appears after the second audit.</p>"
    step = (w - 2 * pad) / (len(pts) - 1)
    xy = [(pad + i * step, pad + (h - 2 * pad) * (1 - p[1] / 100)) for i, p in enumerate(pts)]
    line = " ".join(f"{x:.1f},{y:.1f}" for x, y in xy)
    area = f"{pad},{h - pad} " + line + f" {xy[-1][0]:.1f},{h - pad}"
    grid = "".join(f"<line x1='{pad}' x2='{w - pad}' y1='{pad + (h - 2 * pad) * (1 - v / 100):.1f}' y2='{pad + (h - 2 * pad) * (1 - v / 100):.1f}' class='g'/>" for v in (50, 80))
    last = xy[-1]
    rings = "".join(f"<circle cx='{x:.1f}' cy='{y:.1f}' r='5' class='ring'/>" for (x, y), pt in zip(xy, pts) if len(pt) > 3 and pt[3])
    note = ("<p class='quiet' style='margin:6px 0 0'>○ ISR Bot itself changed here (a new version or scanner), "
            "so a jump at that point isn't new problems.</p>") if rings else ""
    return (f"<svg viewBox='0 0 {w} {h}' class='trend' role='img' aria-label='Security score over the last {len(pts)} checks, now {pts[-1][1]}'>"
            f"{grid}<polygon points='{area}' class='a'/><polyline points='{line}' class='l'/>{rings}<circle cx='{last[0]:.1f}' cy='{last[1]:.1f}' r='4' class='d'/></svg>"
            f"<div class='axis'><span>{pts[0][0][5:10]}</span><span>now</span></div>{note}")


def svg_areas(exp):
    rows = [r for r in exp if r["count"]]
    if not rows:
        return "<p class='quiet'>Nothing open in any area.</p>"
    mx = max(r["count"] for r in rows)
    out = []
    for r in rows:
        wpct = max(4, round(r["count"] / mx * 100))
        out.append(f"<div class='ar'><span class='an'>{html.escape(r['area'])}</span><span class='ab'><i class='sev-{r['state']}' style='width:{wpct}%'></i></span><b>{r['count']}</b></div>")
    return "".join(out)


AREA_SHORT = {"Secrets on the shared computer": "Keys and logins", "Logged-in browser sessions": "Browser logins",
              "Skills and templates": "Skills", "Approvals and settings": "Approval settings",
              "Bots, memories and routines": "Bots and routines", "Packages": "Software updates", "Tripwires and history": "Decoys and history"}
