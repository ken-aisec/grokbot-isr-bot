# Part of isr.py: runs inside isr.py's namespace (loaded by _isr_part); not a module on its own.
# ---------------------------------------------------------------- observation (status only: collected here, rendered in artifacts)
OBS_DIR = "observations"
OBS_KEEP = 12
OBS_MAX_BYTES = 1024 * 1024
_OBS_ID = re.compile(r"obs-\d{8}T\d{6}Z(?:-\d)?")
_OBS_FILE = re.compile(r"obs-\d{8}T\d{6}Z(?:-\d)?\.json")
_OBS_AT = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\+00:00|Z)")
_OBS_PID = re.compile(r"b-[0-9a-f]{10}")
OBS_COMMANDS = ("artifacts",)
OBS_CRED_STATES = ("present", "link", "under-link", "missing", "other", "unknown")
OBS_BOT_STATUS = ("answered", "no-detail", "silent", "listed")
OBS_TAMPER = ("Stored in a folder any process running as this user can write; not tamper-proof and not authenticated. "
              "Sanitizing bounds its shape, not its truth or completeness.")
REACH_UNDETERMINED = ("Effective readability by other Bots: not determined (their uids, ACLs, parent-folder permissions and link "
                      "targets are not checked).")
PLATFORM_LABEL = "Platform context supplied to ISR Bot's developer (not observed)"
NOT_A_SANDBOX = "Approval rules are review policy, not technical isolation; the policy layer is not a sandbox."
PLATFORM_FACTS_REL = "rules/platform_facts.json"
PLATFORM_FACTS = os.path.join(HERE, "..", PLATFORM_FACTS_REL)
PLATFORM_FACTS_MAX_BYTES = 16 * 1024
PLATFORM_FACT_KEYS = ("id", "text", "source", "date")


class ObservationStoreError(Exception):
    pass


def cred_status():
    """Each known CLI sign-in file's name looked at with os.lstat only: whether it is there, a link (its target never looked
    at), its mode bits and whether ISR Bot's uid owns it. No file is opened and nothing is read."""
    h = os.path.expanduser("~")
    uid = os.getuid()
    out = []
    for rel in sorted(KNOWN_CRED_FILES):
        c = {"file": "~/" + rel, "tool": KNOWN_CRED_FILES[rel], "state": "unknown", "mode": None, "owned": None}
        parts = rel.split("/")
        try:
            for i in range(1, len(parts)):   # a linked parent folder is never walked through: the file under it isn't looked at
                if stat.S_ISLNK(os.lstat(os.path.join(h, *parts[:i])).st_mode):
                    c["state"] = "under-link"
                    break
            if c["state"] == "under-link":
                out.append(c)
                continue
            st = os.lstat(os.path.join(h, rel))
        except (FileNotFoundError, NotADirectoryError):
            c["state"] = "missing"
        except OSError:
            pass
        else:
            c["state"] = ("link" if stat.S_ISLNK(st.st_mode) else "present" if stat.S_ISREG(st.st_mode) else "other")
            c["owned"] = st.st_uid == uid
            if c["state"] != "link":
                c["mode"] = "0%03o" % stat.S_IMODE(st.st_mode)
        out.append(c)
    return out


def cred_words(c):
    """One credential file's status, in the words ISR Bot may use: never who can read it."""
    if c["state"] == "missing":
        return "not found"
    if c["state"] == "unknown":
        return "couldn't be looked at"
    if c["state"] == "under-link":
        return "a parent folder is a link (not followed; this file not looked at)"
    if c["state"] == "link":
        return "a link (target not checked)" + ("; the link is owned by ISR Bot's uid" if c["owned"] else "")
    bits = []
    if c["mode"]:
        m = int(c["mode"], 8)
        reads = [w for b, w in ((0o040, "group read"), (0o004, "others read")) if m & b]
        bits.append(f"mode {c['mode']}: mode bits permit " + (" and ".join(reads) if reads else "owner read only"))
    if c["owned"] is not None:
        bits.append("owned by ISR Bot's uid" if c["owned"] else "not owned by ISR Bot's uid")
    return "; ".join(["present" if c["state"] == "present" else "present, not a plain file"] + bits)


def bot_pid(basis):
    return "b-" + hashlib.sha256(("isr-bot-pid-v1\0" + basis).encode("utf-8")).hexdigest()[:10]


def _obs_profiles(bases):
    """({masked profile name: [agent folder ids]}, whether every agent folder and profile was read), as _ax_known_bots lists them."""
    names, ok, seen = {}, True, set()
    cands = [os.path.expanduser(b) for b in ("~/agent-data/agents", "~/sand-data/agents")]
    for d in [d for d in cands if not os.path.islink(os.path.dirname(d))] + [d for d in cands if os.path.islink(os.path.dirname(d))]:
        try:
            real = os.path.realpath(d)
        except OSError:
            real = d
        if real in seen:
            continue
        seen.add(real)
        ids, good = _ax_listdir(d)
        ok = ok and good
        for i in ids[:200]:
            if not _AX_AGENT_ID.fullmatch(i):
                continue
            p = os.path.join(d, i, "profile.json")
            st = _look(p)
            if st is None:
                ok = False
            if not st:
                continue
            prof = _ax_json_file(p, bases)
            if prof is None:
                ok = False
            elif isinstance(prof, dict) and isinstance(prof.get("name"), str) and prof["name"].strip():
                n = mask_rollcall(prof["name"].strip()[:60], 60)
                names.setdefault(n, [])
                if i not in names[n]:
                    names[n].append(i)
    return names, ok


def _obs_roster(bases):
    """(masked Bot names the saved roster lists, whether the roster was read)."""
    roster = _ax_json_file(os.path.join(home(), *ROSTER_FILE), bases)
    items = roster.get("entries", roster.get("roster", [])) if isinstance(roster, dict) else roster
    if not isinstance(items, list):
        return set(), False
    return {mask_rollcall(e["name"].strip(), 60) for e in items if isinstance(e, dict) and isinstance(e.get("name"), str)
            and e["name"].strip() and str(e.get("kind", "")).lower() in BOT_KINDS}, True


def _obs_bots(m, profiles, roster):
    """Every Bot this observation knows of, by pseudonym: its id from its agent folder when exactly one profile has its name,
    else from its (masked) name. What a Bot said stays under that Bot."""
    said = {b["name"]: b for b in m["bots"]}
    status = {}
    for n in said:
        status[n] = "answered"
    for n in m["bots_no_detail"]:
        status.setdefault(n, "no-detail")
    for n in m["bots_silent"]:
        status.setdefault(n, "silent")
    for n in sorted(set(profiles) | roster):
        status.setdefault(n, "listed")
    out = []
    for n in sorted(status):
        ids = profiles.get(n, [])
        basis = ("uuid", ids[0]) if len(ids) == 1 else ("name", n)
        b = said.get(n)
        out.append({"pid": bot_pid(basis[1]), "id_basis": basis[0], "name": n, "status": status[n],
                    "listed": n in roster or n in profiles,
                    "said": None if b is None else {"said_at": b["said_at"], "connectors": b["connectors"],
                                                    "connectors_other": b["connectors_other"], "connectors_unknown": b["connectors_unknown"],
                                                    "routines": _ax_routines(b)[0], "routines_sending": _ax_routines(b)[1]}})
    return out


def _obs_coverage(m, creds, listing):
    """{area: "complete" or why not}, from the record itself."""
    sh, cov = m["shared"], {}
    for k in ACCESS_SHARED:
        if _ax_complete(sh, k):
            cov[k] = "complete"
        elif k in sh["checked"]:
            cov[k] = "incomplete: " + ACCESS_WHY_WORDS.get(sh["incomplete"].get(k), "not seen whole")
        elif k in sh["cached"]:
            cov[k] = "from the last audit" + (f" ({_ax_day(sh['cached_at'])})" if sh.get("cached_at") else "") + ", not observed here"
        else:
            cov[k] = "not checked"
    cov["cli_files"] = ("complete" if all(c["state"] != "unknown" for c in creds) and len(creds) == len(KNOWN_CRED_FILES)
                        else "incomplete: a file name couldn't be looked at")
    rc = m["rollcall"]
    cov["bots"] = ("complete" if rc["fresh"] and not rc["profiles_unreadable"] else
                   "incomplete: no roll-call within %d days" % ROLLCALL_MAX_DAYS if not rc["fresh"] else "incomplete: a profile couldn't be read")
    cov["bot_list"] = ("complete" if listing["roster"] and listing["profiles"] else
                       "incomplete: " + ("the roster couldn't be read" if not listing["roster"] else "an agent folder or profile couldn't be read"))
    return cov


OBS_AREAS = ACCESS_SHARED + ("cli_files", "bots", "bot_list")


def _obs_at_ok(v):
    """A stored time in the one form ISR Bot writes that is also a real date and time (a shape alone can say 2026-99-99)."""
    if not (isinstance(v, str) and _OBS_AT.fullmatch(v)):
        return False
    try:
        dt.datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


def obs_record(doc, stored=True):
    """The one shape an observation is kept, loaded or shown in. A stored one is sanitized again: its coverage may only fall
    (an area is complete only when its own data and its stored coverage both say so). None when it isn't an observation."""
    if not isinstance(doc, dict) or doc.get("v") != 1:
        return None
    oid, at = doc.get("observation_id"), doc.get("observed_at")
    if not (isinstance(oid, str) and _OBS_ID.fullmatch(oid) and _obs_at_ok(at)):
        return None
    txt = lambda v, rx: v if isinstance(v, str) and re.fullmatch(rx, v) else None
    m = access_record(doc.get("map"))
    by_file = {}
    for c in doc.get("creds") if isinstance(doc.get("creds"), list) else []:
        if isinstance(c, dict) and isinstance(c.get("file"), str) and c["file"][2:] in KNOWN_CRED_FILES and c["file"].startswith("~/"):
            by_file.setdefault(c["file"], c)
    creds = []
    for rel in sorted(KNOWN_CRED_FILES):
        c = by_file.get("~/" + rel, {})
        st_ = c.get("state") if c.get("state") in OBS_CRED_STATES else "unknown"
        creds.append({"file": "~/" + rel, "tool": KNOWN_CRED_FILES[rel], "state": st_,
                      "mode": txt(c.get("mode"), r"0[0-7]{3}") if st_ in ("present", "other") else None,
                      "owned": c.get("owned") if isinstance(c.get("owned"), bool) and st_ not in ("missing", "unknown", "under-link") else None})
    labels = {e_["label"] for e_ in access_vocab() if "connector_rx" in e_["_rx"]}
    bots, pids = [], set()
    for b in doc.get("bots") if isinstance(doc.get("bots"), list) else []:
        if not (isinstance(b, dict) and isinstance(b.get("pid"), str) and _OBS_PID.fullmatch(b["pid"]) and b["pid"] not in pids):
            continue
        name = mask_rollcall(_ax_text(b.get("name"), 60) or "", 60)
        if not name or len(bots) >= ACCESS_MAX_BOTS * 2:
            continue
        pids.add(b["pid"])
        s = b.get("said") if isinstance(b.get("said"), dict) else None
        said = None if s is None else {
            "said_at": _ax_date(s.get("said_at")), "connectors": [x for x in _ax_list(s.get("connectors"), 40) if x in labels],
            "connectors_other": _ax_count(s.get("connectors_other")),
            "connectors_unknown": s.get("connectors_unknown") if s.get("connectors_unknown") in ACCESS_CONNECTORS_UNKNOWN else None,
            "routines": _ax_count(s.get("routines")), "routines_sending": _ax_count(s.get("routines_sending"))}
        bots.append({"pid": b["pid"], "id_basis": b.get("id_basis") if b.get("id_basis") in ("uuid", "name") else "name", "name": name,
                     "status": b.get("status") if b.get("status") in OBS_BOT_STATUS else "listed", "listed": b.get("listed") is True,
                     "said": said})
    lst = doc.get("listing") if isinstance(doc.get("listing"), dict) else {}
    listing = {"roster": lst.get("roster") is True, "profiles": lst.get("profiles") is True}
    cov = _obs_coverage(m, creds, listing)
    if stored:
        kept = doc.get("coverage") if isinstance(doc.get("coverage"), dict) else {}
        for k in OBS_AREAS:
            if cov[k] == "complete" and kept.get(k) != "complete":
                cov[k] = "incomplete: the stored record didn't say it was complete"
    return {"v": 1, "observation_id": oid, "observed_at": at,
            "written_by_version": txt(doc.get("written_by_version"), r"\d{1,3}\.\d{1,3}\.\d{1,3}") or "unknown",
            "written_at": doc["written_at"] if _obs_at_ok(doc.get("written_at")) else "unknown",
            "command": doc.get("command") if doc.get("command") in OBS_COMMANDS else "unknown",
            "uid": doc.get("uid") if type(doc.get("uid")) is int and doc["uid"] >= 0 else None,
            "map": m, "creds": creds, "bots": bots, "listing": listing, "coverage": cov}


def access_observation(command="artifacts"):
    """One status-only observation of this computer: the access map built now (access_map_now), each known CLI sign-in file's
    lstat, the Bots this computer lists, and ISR Bot's own uid. No credential file is opened, no secret is read, nothing runs
    but what access_map_now runs (the crontab listing), and nothing reaches the network."""
    at = now()
    try:
        m = access_map_now()
    except Exception as e:   # noqa: BLE001 - every area then reads "not checked"; the reason is logged by type
        ledger({"event": "observation-map-failed", "error": type(e).__name__})
        m = None
    m = access_record(m)
    bases = _ax_bases(access_roots())
    profiles, prof_ok = _obs_profiles(bases)
    roster, roster_ok = _obs_roster(bases)
    stamp = dt.datetime.fromisoformat(at).strftime("%Y%m%dT%H%M%SZ")
    raw = {"v": 1, "observation_id": "obs-" + stamp, "observed_at": at, "written_by_version": VERSION, "written_at": at,
           "command": command, "uid": os.getuid(), "map": m, "creds": cred_status(), "bots": _obs_bots(m, profiles, roster),
           "listing": {"roster": roster_ok, "profiles": prof_ok}}
    return obs_record(raw, stored=False)


def _obs_dir_fd(create):
    """An fd on state/observations: a real folder (no link on the way from ISR Bot's home), owned by this uid, mode 0700."""
    uid, fd = os.getuid(), None
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open(home(), flags)
        for part in ("state", OBS_DIR):
            try:
                nfd = os.open(part, flags, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(part, 0o700, dir_fd=fd)
                nfd = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = nfd
        st = os.fstat(fd)
        if st.st_uid != uid:
            raise ObservationStoreError("the observations folder isn't owned by ISR Bot's uid")
        if stat.S_IMODE(st.st_mode) != 0o700:
            os.fchmod(fd, 0o700)
        return fd
    except ObservationStoreError:
        if fd is not None:
            os.close(fd)
        raise
    except OSError as e:
        if fd is not None:
            os.close(fd)
        if isinstance(e, FileNotFoundError) and not create:
            return None
        raise ObservationStoreError(f"the observations folder can't be used safely ({errno.errorcode.get(e.errno, 'error')}: "
                                    "a link or something other than a folder on its path)")


def save_observation(obs):
    """Keep this observation as state/observations/<id>.json (0600, created new, never through a link), and only the newest
    OBS_KEEP. Returns the id it was kept under. Raises ObservationStoreError when it can't be kept safely."""
    fd = _obs_dir_fd(True)
    try:
        oid = obs["observation_id"][:20]
        for n in range(10):
            name = (oid if n == 0 else f"{oid}-{n}") + ".json"
            data = json.dumps(dict(obs, observation_id=name[:-5]), sort_keys=True).encode("utf-8")
            try:
                f = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
            except FileExistsError:
                continue
            try:
                os.fchmod(f, 0o600)
                os.write(f, data)
                os.fsync(f)
            finally:
                os.close(f)
            break
        else:
            raise ObservationStoreError("ten observations already have this second's name")
        keep = sorted(x for x in os.listdir(fd) if _OBS_FILE.fullmatch(x))
        for old in keep[:-OBS_KEEP]:
            os.unlink(old, dir_fd=fd)
        return name[:-5]
    except OSError as e:
        raise ObservationStoreError(f"the observation couldn't be written ({errno.errorcode.get(e.errno, 'error')})")
    finally:
        os.close(fd)


def load_observations():
    """([every kept observation that still reads as one, sanitized again (obs_record), oldest first], why the folder couldn't
    be read or "")."""
    try:
        fd = _obs_dir_fd(False)
    except ObservationStoreError as e:
        return [], str(e)
    if fd is None:
        return [], ""
    out = []
    try:
        for name in sorted(x for x in os.listdir(fd) if _OBS_FILE.fullmatch(x)):
            try:
                f = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
            except OSError:
                continue
            try:
                if not stat.S_ISREG(os.fstat(f).st_mode):
                    continue
                data = os.read(f, OBS_MAX_BYTES + 1)
            except OSError:
                continue
            finally:
                os.close(f)
            if len(data) > OBS_MAX_BYTES:
                continue
            try:
                r = obs_record(json.loads(data.decode("utf-8")))
            except (UnicodeDecodeError, ValueError, RecursionError):
                r = None
            if r is not None:
                out.append(r)
    finally:
        os.close(fd)
    return sorted(out, key=lambda r: (r["observed_at"], r["observation_id"])), ""


def platform_facts():
    """([{id, text, source, date}], why they can't be used or ""): the platform context supplied to ISR Bot's developer, from ISR Bot's own
    rules file (held to MANIFEST.sha256). Never observed by ISR Bot; with any problem, none is shown."""
    data, why = _release_file(PLATFORM_FACTS, PLATFORM_FACTS_REL, PLATFORM_FACTS_MAX_BYTES)
    if why:
        return [], why
    try:
        doc = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return [], "it isn't JSON"
    facts = doc.get("facts") if isinstance(doc, dict) else None
    good = lambda e_: (isinstance(e_, dict) and tuple(sorted(e_)) == tuple(sorted(PLATFORM_FACT_KEYS))
                       and all(isinstance(e_[k], str) and 0 < len(e_[k]) <= 300 and e_[k].isprintable() for k in PLATFORM_FACT_KEYS)
                       and re.fullmatch(r"\d{4}-\d{2}-\d{2}", e_["date"]) and re.fullmatch(r"[a-z0-9-]{1,40}", e_["id"]))
    if not (isinstance(facts, list) and facts and all(good(e_) for e_ in facts)):
        return [], "it isn't a list of {id, text, source, date} facts"
    return facts, ""
