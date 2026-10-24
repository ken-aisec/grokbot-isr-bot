# Part of wt.py: runs inside wt.py's namespace (loaded by _wt_part); not a module on its own.
def is_sample_skill_path(path):
    """True when the path sits under a test/sample/docs folder segment (FIXTURE_PATH spirit for skills)."""
    p = os.path.normpath(os.path.abspath(str(path).split(":")[0])).replace(os.sep, "/")
    return bool(SAMPLE_SKILL_PATH.search(p))


def workspace_quarantine_roots():
    """The one workspace holding folder Watchtower uses for hand-quarantine (sibling of Watchtower-home),
    plus the production /workspace/quarantine tree. Matched as real path prefixes, never by segment name."""
    roots = set()
    try:
        sibling = os.path.realpath(os.path.join(os.path.dirname(home()), "quarantine"))
        roots.add(sibling)
    except OSError:
        pass
    try:
        roots.add(os.path.realpath("/workspace/quarantine"))
    except OSError:
        roots.add(os.path.normpath("/workspace/quarantine"))
    return {r for r in roots if r}


def is_quarantined_path(path):
    """True only for Watchtower-home quarantine, the workspace holding folder (realpath prefix), or a
    quarantine.json `to` that is under Watchtower-home quarantine / owned as quarantine. Never `from`,
    never a path segment named quarantine anywhere (DQ-028/030)."""
    p = os.path.normpath(os.path.abspath(str(path).split(":")[0]))
    try:
        pr = os.path.realpath(p)
    except OSError:
        pr = p
    qhome = os.path.normpath(os.path.join(home(), "quarantine"))
    try:
        qhome_r = os.path.realpath(qhome)
    except OSError:
        qhome_r = qhome
    if p == qhome or pr == qhome_r or _under(p, {qhome}) or _under(pr, {qhome_r}):
        return True
    for hold in workspace_quarantine_roots():
        if p == hold or pr == hold or _under(p, {hold}) or _under(pr, {hold}):
            return True
    for e in load_json(state_path("quarantine.json"), []) or []:
        t = e.get("to")
        if not t:
            continue
        tn = os.path.normpath(t)
        try:
            tr = os.path.realpath(tn)
        except OSError:
            tr = tn
        # Only real quarantine destinations: owned quarantine entry, or under Watchtower-home quarantine.
        if not (owned_path(tn, "quarantine", log=False) or tr == qhome_r or _under(tr, {qhome_r})
                or tn == qhome or _under(tn, {qhome})):
            continue
        if p == tn or pr == tr or _under(p, {tn}) or _under(pr, {tr}):
            return True
    return False


# Item 8 dry run (Oct 13): snapshot folders inside the owner's skill folder (workflows/_archive/2026-10-13/...) are copies
# nobody loads. Only folders named like an archive; tests/docs/references/quarantine names stay live (DQ-028/029).
ARCHIVE_SEGMENT = re.compile(r"(?i)^[._]?archived?$|^_old$|^_snapshots?$")
# Item 8 dry run (Oct 13): the platform loads ~/.agents/skills, not the .agents/skills folder inside every cloned project.
PROJECT_LOCAL_VENDOR = "/.agents/skills/"


def in_archive_folder(p, roots):
    for r in roots:
        if p.startswith(r + os.sep):
            return any(ARCHIVE_SEGMENT.match(s) for s in os.path.relpath(p, r).split(os.sep)[:-1])
    return False


def home_agents_skills():
    return [os.path.normpath(b + "/.agents/skills") for b in dict.fromkeys((os.path.expanduser("~"), "/home/box"))]


def is_loadable_skill_location(path):
    """User skill roots, plugin/marketplace/bundled skill folders (VENDOR_CODE). Always live and scored
    regardless of folder names inside them (DQ-028/029), except archive-named snapshot folders inside the
    owner's skill roots, and a cloned project's own .agents/skills (item 8 dry run, Oct 13)."""
    p = os.path.normpath(os.path.abspath(str(path).split(":")[0]))
    try:
        pr = os.path.realpath(p)
    except OSError:
        pr = p
    roots = user_skill_roots()
    rroots = {os.path.realpath(r) for r in roots}
    if _under(p, roots) or _under(pr, rroots):
        return not (in_archive_folder(p, roots) or in_archive_folder(pr, rroots))
    slash = p.replace(os.sep, "/")
    real_slash = pr.replace(os.sep, "/")
    hits = [x for x in VENDOR_CODE if x in slash or x in real_slash]
    if hits == [PROJECT_LOCAL_VENDOR]:
        homes = home_agents_skills()
        return _under(p, homes, strict=True) or _under(pr, {os.path.realpath(h) for h in homes}, strict=True)
    return bool(hits)


def is_vendor_template_file(path):
    """Example/story files inside the platform's own bundled skills (e.g. .grok/bundled/.../templates/*.js). DQ-024.
    Marketplace and user plugins are never covered (v0.7.0 review R2). Realpath prefix only (Claude v0.7.1 F3)."""
    p = os.path.normpath(os.path.abspath(str(path).split(":")[0])).replace(os.sep, "/")
    return under_platform_root(path) and bool(VENDOR_TEMPLATE_PATH.search(p))


# v0.7.1 precision item 1 (decision, Oct 12): live-only by default. Skill wording and drift rules run only on what the platform
# loads; archives, clones and other projects are listed once as "Not scanned". `audit --everything` opts in (kept in
# state/scope.json until `--live-only`). Keys are checked everywhere either way (secret scan does not use this).
SCAN_EVERYTHING = False


def scope_everything(args=None):
    """The scan scope for this run: --everything / --live-only change it and are remembered; otherwise the last choice."""
    path = state_path("scope.json")
    if args is not None and getattr(args, "everything", False):
        save_json(path, {"everything": True, "at": now()})
    elif args is not None and getattr(args, "live_only", False):
        save_json(path, {"everything": False, "at": now()})
    return bool((load_json(path, {}) or {}).get("everything"))


def is_live_skill_path(path):
    """A SKILL.md counts as an installed skill unless it sits under real quarantine. Anything under a
    loadable location (user roots, plugin/marketplace/bundled) is always live, even if a folder is named
    quarantine/tests/docs/references (DQ-028/029). Sample trees outside loadable locations stay non-live
    (DQ-022). Other places (archives, clones, other projects) are live only when the owner said "scan everything"
    (v0.7.1 item 1); when they are, they get the full rules (R15)."""
    p = os.path.normpath(os.path.abspath(str(path).split(":")[0]))
    if is_quarantined_path(p):
        return False
    if is_loadable_skill_location(p):
        return True
    if is_sample_skill_path(p):
        return False
    return SCAN_EVERYTHING


def out_of_scope_but_present(p):
    """A baselined file that still exists but is no longer scanned (outside loadable places, not 'scan everything')."""
    if not os.path.isfile(p):
        return False
    root = skill_root(p)
    md = os.path.join(root, "SKILL.md") if root else p
    return not is_live_skill_path(md)


def not_scanned_places(paths, roots):
    """Top-level folder names (under the scan root that holds them) of SKILL.md files left out of the scan."""
    rs = sorted({os.path.normpath(os.path.abspath(os.path.expanduser(r))) for r in roots}, key=len, reverse=True)
    out = set()
    for p in paths:
        n = os.path.normpath(os.path.abspath(p))
        if is_quarantined_path(n):
            out.add("quarantine"); continue
        root = next((r for r in rs if _under(n, {r}, strict=True)), None)
        rel = os.path.relpath(n, root) if root else n.lstrip("/")
        out.add(rel.split(os.sep)[0] if os.sep in rel else os.path.basename(os.path.dirname(n)) or rel)
    return sorted(out)


def owned_path(p, kind, log=True):
    """Every path Watchtower moves or deletes comes from one of its own state files, and anything that can write there
    could aim it anywhere. Before acting, the path is resolved (links followed) and must be inside the place that kind of
    thing belongs: quarantine (a folder directly inside Watchtower's quarantine folder), skill (inside the owner's own skill
    folders), decoy (exactly one of the decoy files, not reached through a link), project (a project in the owner's home or
    workspace, never inside Watchtower's own folder), home (Watchtower's own folder itself, not a link). Anything else is
    refused and written to the ledger."""
    ok = False
    try:
        n = os.path.normpath(os.path.abspath(os.path.expanduser(str(p))))
        rp = os.path.realpath(n)
        if kind == "quarantine":
            q = os.path.realpath(os.path.join(home(), "quarantine"))
            ok = os.path.dirname(rp) == q and os.path.basename(rp) == os.path.basename(n) and not os.path.islink(n)
        elif kind == "skill":
            ok = _under(rp, {os.path.realpath(r) for r in user_skill_roots()}, strict=True) and _under(n, user_skill_roots(), strict=True)
        elif kind == "decoy":
            allowed = decoy_places() | {os.path.normpath(os.path.expanduser(x)) for x in OLD_CANARY_PATHS}
            if os.path.basename(n) == WITNESS:   # the witness beside a decoy (batch 2)
                allowed = {os.path.join(os.path.dirname(x), WITNESS) for x in allowed}
            d = os.path.dirname(n)
            ok = n in allowed and not os.path.islink(d) and os.path.realpath(d) == os.path.join(os.path.realpath(os.path.dirname(d)), os.path.basename(d))
        elif kind == "workspace-skill":   # DQ-021: a skill copy in the workspace that two engines flag; never platform or Watchtower folders
            ws, h = os.path.realpath(os.path.dirname(home())), os.path.realpath(home())
            ok = rp == n and _under(rp, {ws}, strict=True) and not _under(rp, {h}) and not _under(rp, {os.path.realpath(x) for x in PLATFORM_SKILL_DIRS()}) \
                and os.path.isfile(os.path.join(rp, "SKILL.md"))
        elif kind == "project":
            h = os.path.realpath(home())
            places = {os.path.realpath(os.path.expanduser("~")), os.path.realpath(os.path.dirname(home()))}
            ok = _under(rp, places, strict=True) and not _under(rp, {h})
        elif kind == "home":
            ok = rp == n and os.path.basename(n) == "watchtower" and os.path.isdir(os.path.join(n, "state")) and n not in ("/", os.path.realpath(os.path.expanduser("~")))
    except (TypeError, ValueError, OSError):
        ok = False
    if not ok and log:
        try:
            ledger({"event": "refused-path", "kind": kind, "path": str(p)[:300]})
        except OSError:
            pass
    return ok


SESSION_FILES = ("chrome-cookie-seed.json", "cookie-seed.json", "cookies.json")


SENSITIVE_SITE = re.compile(r"(anthropic|claude|openai|x\.ai|github|google|microsoft|aws|stripe|bank|paypal|slack|notion|"
                            r"bitwarden|1password|lastpass|dashlane|keeper|vercel|cloudflare|okta)")   # ISR-S004 summary wording only
# ISR-S005: registered domains, matched exactly or as a dot-suffix (fonts.googleapis.com, max.ai and notionalvalue.io are not these).
SENSITIVE_DOMAINS = ("anthropic.com", "claude.ai", "openai.com", "chatgpt.com", "x.ai", "grok.com", "github.com", "google.com",
                     "microsoft.com", "live.com", "microsoftonline.com", "aws.amazon.com", "amazon.com", "stripe.com", "paypal.com",
                     "slack.com", "notion.so", "notion.com", "bitwarden.com", "1password.com", "lastpass.com", "dashlane.com",
                     "keepersecurity.com", "vercel.com", "cloudflare.com", "okta.com", "x.com", "twitter.com")
# Dots/hyphens allowed (chatgpt __Secure-next-auth.session-token). logged_in dropped: GitHub sets logged_in=no for anonymous visits.
SESSION_COOKIE = re.compile(r"(?i)^([\w.-]*(session|sess)[\w.-]*|sid|ssid|hsid|apisid|sapisid|[\w.-]*_sid|"
                            r"[\w.-]*auth[\w.-]*|[\w.-]*token[\w.-]*|sessionkey)$")
# Mixpanel (_mpxl_*), GetDisplay (_gd_session): look like session names but are analytics only (DQ-026).
NOT_SESSION_COOKIE = re.compile(r"(?i)^(_mpxl_[\w.-]+|_gd_session)$")


def is_session_cookie(name):
    """True for real login cookies. Visit/tracking names that fit the pattern (csrf_*, Mixpanel sid, _gd_session) stay out."""
    n = str(name or "")
    if re.match(r"(?i)^csrf", n):
        return False
    if NOT_SESSION_COOKIE.match(n):
        return False
    return bool(SESSION_COOKIE.match(n))


def sensitive_site(host):
    h = str(host).lower().lstrip(".")
    return any(h == d or h.endswith("." + d) for d in SENSITIVE_DOMAINS)
BROWSER_JARS = ("~/chrome-profile/Default/Cookies", "~/.config/google-chrome/Default/Cookies")
CHROME_EPOCH = 11644473600


def browser_jar_hosts():
    """Sites with a cookie in the shared browser: {host: (first creation time, has a session-style cookie)}. Reads host, creation
    time and cookie name from the browser's cookie database (opened read-only); never a cookie's value."""
    import sqlite3
    for j in BROWSER_JARS:
        p = os.path.expanduser(j)
        if not os.path.isfile(p):
            continue
        try:
            c = sqlite3.connect(f"file:{p}?immutable=1", uri=True)
            rows = c.execute("select host_key, name, creation_utc from cookies").fetchall()   # never the value
            c.close()
        except sqlite3.Error:
            continue
        out = {}
        for h, n, t in rows:
            if not h or not t:
                continue
            h = str(h).lstrip("."); t = t / 1_000_000 - CHROME_EPOCH
            first, sess = out.get(h, (t, False))
            out[h] = (min(first, t), sess or is_session_cookie(n))
        return out
    return None


def _prev_host_sessions(prev):
    """host -> had a session cookie. Legacy list format: known hosts count as already-session so we don't re-alarm on upgrade."""
    if not isinstance(prev, dict):
        return {}
    h = prev.get("hosts", {})
    if isinstance(h, list):
        return {x: True for x in h}
    if isinstance(h, dict):
        return {k: bool(v) for k, v in h.items()}
    return {}


def new_sign_ins(seen=None):
    """ISR-S005: a sensitive site that got its first session in the shared browser since the last look. The first look is a baseline.
    State stores per-host whether a session cookie was seen, so a visit that later becomes a sign-in still alarms.
    The sessions ISR-S004 lists are carried across box resets by the platform's cookie seed; a new one is something that happened.
    `seen` (a dict) gets "hosts": {host: had a session cookie} from this look, or None with no jar (batch 5 a: the access map)."""
    hosts = browser_jar_hosts()
    if seen is not None:
        seen["hosts"] = None if hosts is None else {h: bool(hosts[h][1]) for h in sorted(hosts)}
    if hosts is None:
        return []
    path = state_path("browser_hosts.json")
    prev = load_json(path, None)
    save_json(path, {"at": now(), "hosts": {h: bool(hosts[h][1]) for h in sorted(hosts)}})
    if not isinstance(prev, dict):
        return []
    known = _prev_host_sessions(prev)
    when = lambda h: dt.datetime.fromtimestamp(hosts[h][0]).strftime("%Y-%m-%d %H:%M")
    signed, cookies = [], []
    for h in sorted(hosts):
        if not sensitive_site(h):
            continue
        sess = bool(hosts[h][1])
        if h not in known:
            (signed if sess else cookies).append(h)
        elif sess and not known[h]:
            signed.append(h)   # visit-only host flipped to a real session
    out = []
    if signed:
        out.append(finding("ISR-S005", NEW_SIGN_IN, "high", ["ASI03", "AST06"], "shared browser",
                           "; ".join(f"{h} first session {when(h)}" for h in signed)[:200],
                           "Every Bot can now use this login. If neither you nor a Bot you asked signed in there, sign out of that site from its "
                           "security settings (all sessions) and change its password.", ident=",".join(signed)))
    if cookies:
        out.append(finding("ISR-S005", "New cookies from a sensitive site (no session cookie seen)", "medium", ["ASI03"], "shared browser",
                           "; ".join(f"{h} first cookie {when(h)}" for h in cookies)[:200],
                           "Probably a visit, not a sign-in. If you don't expect any Bot to use this site, clear its cookies in the Grok Bot browser.",
                           ident="cookies:" + ",".join(cookies)))
    return out


def browser_sessions(roots):
    """Grok Bot seeds the shared browser with login cookies. Report which domains, never values.
    A sensitive domain is signed-in only when at least one of its cookies is a session/auth cookie (same test as ISR-S005)."""
    out, seen = [], set()
    for r in [os.path.expanduser("~/sand-data"), os.path.expanduser("~/agent-data")] + list(roots):
        if not os.path.isdir(r) or os.path.realpath(r) in seen:
            continue   # sand-data and agent-data are often the same folder under two names
        seen.add(os.path.realpath(r))
        for fn in SESSION_FILES:
            p = os.path.join(r, fn)
            data = load_json(p, None)
            if data is None:
                continue
            items = data if isinstance(data, list) else data.get("cookies", []) if isinstance(data, dict) else []
            by_dom = {}
            for c in items:
                if not isinstance(c, dict) or not c.get("domain"):
                    continue
                d = str(c.get("domain", "")).lstrip(".")
                by_dom.setdefault(d, []).append(str(c.get("name") or ""))
            domains = sorted(by_dom)
            # DQ-026: visit/analytics cookies on a sensitive domain are not a sign-in
            signed_in = [d for d in domains
                         if SENSITIVE_SITE.search(d) and any(is_session_cookie(n) for n in by_dom[d])]
            if signed_in:
                title, sev, ident = "Logged-in browser sessions shared by every Bot", "high", "sensitive"
                fix = ("Every Bot can reuse these logins. In the Grok Bot browser, sign out of sites no Bot needs; "
                       "for AI consoles and admin sites, also log out all sessions from that site's security settings.")
            else:
                title, sev, ident = "Shared browser cookies visible to every Bot", "medium", "plain"
                fix = ("These are cookies every Bot can see. Visit/analytics cookies on sensitive domains are not treated as a "
                       "sign-in. Clear cookies for sites no Bot needs.")
            out.append(finding("ISR-S004", title, sev, ["ASI03", "AST06"], p,
                               f"{len(domains)} domains; sensitive: {', '.join(signed_in[:8]) or 'none'}",
                               fix, ident=ident))
            break
    return out


def move_boundary(p):
    """The kind of folder a file sits in, for move matching: the owner's own skills (either workflows folder: Grok Bot renames
    one to the other), one kind of vendor folder (plugins in sand-data or agent-data, .agents/skills, .codex/skills,
    .claude/plugins), or anywhere else; and its tier. A file moved across this line is a new file where it lands. Platform
    folders are never part of a move (match_moves)."""
    tier = skill_tier(p)
    if _under(p, set(user_skill_roots()), strict=True):
        return "user", tier
    for sub in VENDOR_ROOT_SUBS:
        if _under(p, {os.path.normpath(os.path.join(b, sub)) for b in (os.path.expanduser("~"), "/home/box")}, strict=True):
            return "vendor:" + sub.replace("agent-data/", "sand-data/"), tier
    return None, tier


def match_moves(base, manifest):
    """(approved paths moved away, new paths they moved to). Any new file with the sha256 of any approved file used to be
    "moved", so one deleted bundled SKILL.md hid the same bytes planted in .codex/skills/.system (Codex, item 8 high 2). Each
    approved file that is gone from disk now accounts for at most one new file, with the same name and bytes, in the same trust
    boundary (move_boundary). A platform-ish path (platform_ish) is never on either side: a platform file relocated or copied
    is new where it lands, and needs a release-list line for its new path."""
    gone, came = {}, {}
    for q, hq in base.items():
        if q not in manifest and not q.startswith("persist:") and not hq.startswith("unreadable") and not os.path.lexists(q) and not platform_ish(q):
            gone.setdefault((os.path.basename(q), hq, move_boundary(q)), []).append(q)
    for p, h in manifest.items():
        if p not in base and not h.startswith("unreadable") and not platform_ish(p):
            came.setdefault((os.path.basename(p), h, move_boundary(p)), []).append(p)
    moved_from, moved_to = set(), set()
    for k in gone.keys() & came.keys():
        olds, news = sorted(gone[k]), sorted(came[k])
        n = min(len(olds), len(news))
        moved_from.update(olds[:n])
        moved_to.update(news[:n])
    return moved_from, moved_to


def is_vendor(path):
    """Shipped by the platform or a plugin: reduced (malicious-indicator) rules. R15: a skill in a place Watchtower doesn't
    recognize is not trusted vendor content; it gets the full rules (and still no wider permission to be changed)."""
    return skill_tier(path) == "vendor" and vendor_root_path(path)   # item 8 (R3): a vendor folder's prefix, never a name in the path
