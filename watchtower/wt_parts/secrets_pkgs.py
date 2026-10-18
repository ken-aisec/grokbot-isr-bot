# Part of wt.py: runs inside wt.py's namespace (loaded by _wt_part); not a module on its own.
GITLEAKS_CONFIG = r"""[extend]
useDefault = true

[[allowlists]]
description = "Watchtower: package caches, tests, lockfiles, headers and its own state"
paths = [
  '''(^|/)(go/pkg|pkg/mod|\.local/go|node_modules|\.cache|\.npm|\.venv|site-packages|dist-packages)/''',
  '''(^|/)\.config/(google-chrome[^/]*|chromium[^/]*|BraveSoftware)/''',
  '''(^|/)scoped_dir[^/]*/''',
  '''(^|/)chrome-profile/''',
  '''(^|/)(\.codex/auth\.json|\.claude/\.credentials\.json|\.config/gh/hosts\.yml|\.aws/credentials|\.git-credentials|\.netrc|\.docker/config\.json|\.npmrc)$''',
  '''(^|/)watchtower/(state|reports|app|\.venv|scanners|bin)/''',
  '''chrome-cookie-seed\.json$''',
  '''\.(test|spec)\.(ts|tsx|js|jsx|mjs|cjs|py)$''',
  '''(^|/)(tests?|__tests__|fixtures?|testdata)/''',
  '''\.h$''',
  '''(^|/)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|go\.sum|Cargo\.lock|marketplace\.json)$''',
]
regexTarget = "line"
regexes = [
  '''(?i)x-amz-(credential|signature|security-token)=''',
  '''(?i)[?&](AWSAccessKeyId|Signature|Expires)=''',
  '''(?i)(authorization|x-api-key|api[_-]?key|token)[^\n]{0,30}(\$\{?[A-Za-z_]+\}?|<[^>]{1,40}>|your[_ -]?(token|key|api)|x{4,}|\*{3,}|\.\.\.)''',
]

[[allowlists]]
description = "A bare 40-character hex string is a git commit, not a Sourcegraph token"
targetRules = ["sourcegraph-access-token"]
regexTarget = "secret"
regexes = ['''^[a-fA-F0-9]{40}$''']

[[allowlists]]
description = "A code name made of short lowercase words and version numbers (eapi-grok-4-3-internal, self.eapi_4_3_x_algo) is not a key"
targetRules = ["generic-api-key"]
regexTarget = "secret"
regexes = ['''^((([a-z]{1,12}|[0-9]{1,4})[._-])*[0-9]{1,4}([._-]([a-z]{1,12}|[0-9]{1,4}))+|(([a-z]{1,12}|[0-9]{1,4})[._-])+[0-9]{1,4})$''']

[[allowlists]]
description = "A paging cursor (next_token, nextPageToken, prev_cursor...) in an API result is not a key. Matched on the found text, not the line"
targetRules = ["generic-api-key"]
regexTarget = "match"
regexes = ['''(?i)^["']?(next|prev|previous|page|pagination|continuation)_?(page_?)?(token|cursor)\b''']
"""


GROUPED_DIRS = ("/agent-transcripts", "/agent-tools", "/.cursor/projects")
TOOL_CACHE_DIRS = ("/agent-tools",)


VENDOR_CODE = ("/plugins/", "/plugin-cache/", "/managed-skills/", "/skills-library/", "/.agents/skills/", "/.codex/skills/", "/.grok/bundled/")


def secret_severity(path, generic):
    """Documentation-style hits in shipped plugin code are medium; real token types in tool caches are high
    (usually someone else's token inside an API response); anywhere else a real token type is critical."""
    if generic or vendor_root_path(path):   # item 8 (R3): a real vendor folder, never a name in the path
        return "medium"
    if any(x in path for x in TOOL_CACHE_DIRS):
        return "high"
    return "critical"


def group_dir(fpath):
    """Folders that fill up with machine output are grouped at their top, not per subfolder."""
    fpath = fpath or ""
    for g in GROUPED_DIRS:
        i = fpath.find(g + "/")
        if i >= 0:
            return fpath[:i + len(g)]
    return os.path.dirname(fpath)


def gitleaks_findings(roots, notes):
    exe = tool("gitleaks")
    if not exe:
        scanner_absent(notes, "gitleaks", "gitleaks not installed: secrets checked with Watchtower's rules only.")
        return []
    out = []
    cfg = state_path("gitleaks.toml")
    with open(cfg, "w") as f:
        f.write(GITLEAKS_CONFIG)
    tmp = state_path("gitleaks.json")
    for r in roots:
        r = os.path.expanduser(r)
        if not os.path.isdir(r):
            continue
        try:
            os.remove(tmp)
        except OSError:
            pass
        code, _, err = run([exe, "detect", "--source", r, "--no-git", "--redact", "--config", cfg, "--report-format", "json",
                            "--report-path", tmp, "--exit-code", "0", "--max-target-megabytes", "5"], 180)
        if code != 0 or not os.path.exists(tmp):
            reason = next((l for l in re.sub(r"\x1b\[[0-9;]*m", "", err).splitlines() if "FTL" in l or "error" in l.lower()), err.strip()[:160] or "no report written")
            fail_note(notes, f"gitleaks FAILED on {r} ({reason.strip()[-160:]}): secrets there were NOT checked by gitleaks.")
            continue
        per_file, decoys, skipped_tool = {}, canary_paths(), 0
        for leak in load_json(tmp, []) or []:
            if os.path.abspath(str(leak.get("File") or "")) in decoys:
                continue
            if is_platform_secret_store(str(leak.get("File") or "")):
                continue                                  # Ken, Oct 13: the platform's masked-secret store is one Platform note (WT-I009)
            if in_toolchain_tree(str(leak.get("File") or "")):
                skipped_tool += 1
                continue                                  # item 8 dry run: test vectors in a language toolchain or package store                                  # Watchtower's own decoys (their names are this install's, not in this config)
            per_file.setdefault(leak.get("File"), []).append(leak)
        by_dir = {}
        for fpath in per_file:
            by_dir.setdefault(group_dir(fpath), []).append(fpath)
        for d, files in by_dir.items():
            if len(files) >= 4 or any(x in d for x in GROUPED_DIRS):  # transcripts, tool output: one finding per folder
                leaks = [l for fp in files for l in per_file.pop(fp)]
                kinds = sorted({l.get("RuleID", "secret") for l in leaks})
                generic = all(k.startswith("generic") for k in kinds)
                cache = any(x in d for x in TOOL_CACHE_DIRS)
                sev = secret_severity(d + "/", generic)
                why = ("Tool-overflow cache: oversized API results (Notion pages, GitHub payloads) land here and any Bot can read them. "
                       "Hits are often third-party tokens inside those payloads. Check for any of yours, then clear the folder; it refills on its own."
                       if cache else "Check which of these tokens are still live and revoke them, then clear the folder or move it off "
                       "the shared computer. Transcripts and tool output often capture tokens by accident.")
                # name the files and lines: the folder alone sent the owner re-running gitleaks to find the hit. The files in
                # these folders come and go, so the finding keeps one name (ident) while its evidence changes
                locs = [f"{os.path.relpath(l.get('File') or d, d)}:{l.get('StartLine')}" for l in leaks]
                at = ", ".join(locs[:3]) + (f" and {len(locs) - 3} more" if len(locs) > 3 else "")
                out.append(finding("WT-S002", f"gitleaks: secrets in {len(files)} {'file' if len(files) == 1 else 'files'} under {os.path.basename(d)}", sev,
                                   ["ASI03", "LLM02"], d, f"{len(leaks)} hit(s): {', '.join(kinds)[:60]} at {at}", why, source="gitleaks",
                                   ident="gitleaks:" + ",".join(kinds)))
        for fpath, leaks in per_file.items():
            kinds = sorted({l.get("RuleID", "secret") for l in leaks})
            generic = all(k.startswith("generic") for k in kinds)
            out.append(finding("WT-S002", "gitleaks: secrets in file", secret_severity(fpath or "", generic), ["ASI03", "LLM02"],
                               f"{fpath}:{leaks[0].get('StartLine')}", f"{len(leaks)} hit(s): {', '.join(kinds)[:100]}",
                               "Check whether these are live credentials. Revoke live ones, then delete or scrub the file.", source="gitleaks",
                               path=fpath if isinstance(fpath, str) and fpath.startswith("/") else None))
        if skipped_tool:
            notes.append(f"gitleaks: {skipped_tool} hit(s) in language toolchains and package stores (Go, pnpm, ...) not listed: "
                         "those are the tools' own test keys. A key TruffleHog proves live is still reported wherever it is.")
        try:
            os.remove(tmp)
        except OSError:
            pass
    return out


TOOLCHAIN_TREE = re.compile(r"/\.local/go[^/]*/|/\.local/share/pnpm/|/go/pkg/mod/|/\.rustup/toolchains/|/\.cargo/registry/")


def in_toolchain_tree(p):
    """Item 8 dry run (Oct 13): a Go toolchain kept as a rollback (~/.local/go.prev-1.27.1) and the pnpm store gave 11 gitleaks
    lines from their own crypto test vectors. SKIP_PATH_PARTS already skipped ~/.local/go/ for the other stages."""
    return bool(TOOLCHAIN_TREE.search(os.path.normpath(os.path.abspath(p)) + "/"))


def installed_python_packages():
    """Packages in the computer's own Python, not Watchtower's venv."""
    py = "/usr/bin/python3" if os.path.exists("/usr/bin/python3") else (shutil.which("python3") or "python3")
    code, out_s, _ = run([py, "-m", "pip", "list", "--format", "json", "--disable-pip-version-check"], 60)
    try:
        return {p["name"]: p["version"] for p in json.loads(out_s)}
    except (ValueError, KeyError, TypeError):
        return {}


def user_python_packages():
    """Packages the user (or a Bot) installed themselves with pip. Everything else came with the computer."""
    py = "/usr/bin/python3" if os.path.exists("/usr/bin/python3") else (shutil.which("python3") or "python3")
    code, out_s, _ = run([py, "-m", "pip", "list", "--user", "--format", "json", "--disable-pip-version-check"], 60)
    try:
        return {p["name"].lower() for p in json.loads(out_s)}
    except (ValueError, KeyError, TypeError, AttributeError):
        return set()


def package_findings(notes):
    exe = tool("pip-audit")
    if not exe:
        scanner_absent(notes, "pip-audit", "pip-audit not installed: installed Python packages not checked for known vulnerabilities.")
        return []
    pkgs = installed_python_packages()
    if not pkgs:
        return []
    req = state_path("installed-requirements.txt")
    with open(req, "w") as f:
        f.write("\n".join(f"{n}=={v}" for n, v in sorted(pkgs.items())))
    code, out_s, err = run([exe, "-r", req, "--no-deps", "--disable-pip", "-f", "json", "--progress-spinner", "off"], 120)
    out = []
    try:
        data = json.loads(out_s)
        if not isinstance(data, dict):
            raise ValueError
    except ValueError:
        fail_note(notes, f"pip-audit FAILED ({(err.strip().splitlines() or ['no answer'])[-1][:120]}): installed Python packages were NOT checked this run.")
        return []
    mine = user_python_packages()
    for d in (data.get("dependencies", []) if isinstance(data, dict) else []):
        vulns = d.get("vulns", [])
        if not vulns:
            continue
        fixes = sorted({fv for v in vulns for fv in v.get("fix_versions", [])}, key=vtuple)
        ids = list(dict.fromkeys(v.get("id", "") for v in vulns))
        if str(d.get("name", "")).lower() not in mine:      # came with the computer: the platform's to update, not the user's
            out.append(finding("WT-D001", f"Built-in Python package {d.get('name')} {d.get('version')} has known holes", "low", ["ASI04", "AST02"],
                               f"system python package {d.get('name')}", f"{len(ids)} known: {', '.join(ids[:4])}{'…' if len(ids) > 4 else ''}",
                               "It came with the computer and every Bot shares it. The platform's updates fix it; Watchtower doesn't touch system packages.",
                               source="pip-audit", ident=f"{d.get('name')} {d.get('version')}"))
            continue
        out.append(finding("WT-D001", f"Vulnerable package {d.get('name')} {d.get('version')}", "high", ["ASI04", "AST02"],
                           f"python package {d.get('name')}", f"{len(ids)} known: {', '.join(ids[:4])}{'…' if len(ids) > 4 else ''}",
                           f"Upgrade to {fixes[-1]} or later." if fixes else "No fixed version yet; remove it if nothing needs it.",
                           source="pip-audit"))
    save_json(state_path("package_vulns.json"), {"at": now(), "packages": len(pkgs), "findings": out})
    return out


def scanners_python():
    """Watchtower's scanner venv Python (scanners/bin/python), only when it leads to the pinned, root-owned interpreter
    (trusted_interpreter). run() starts it as that interpreter, never through the link."""
    py = os.path.join(scanner_bin(), "python")
    return py if os.path.lexists(py) and trusted_interpreter(py) else None


def self_findings(notes):
    """Watchtower holds its own tools to the same standard: known holes in the scanners' packages, and whether they were
    installed from the checksum lock."""
    py, exe, out = scanners_python(), tool("pip-audit"), []
    update_notes(notes)
    if not py:
        # Codex, batch 3 round 1: a missing or refused scanner Python returned here with the stage marked finished, so last
        # run's WT-W001 lines read as fixed. When there is a Python that isn't trusted, or there were W001 results to keep,
        # this is "not checked", never "clean". A computer that never had the scanners stays a plain skip, as before.
        if os.path.lexists(os.path.join(scanner_bin(), "python")) or carry(("WT-W001",)):
            fail_note(notes, "Watchtower's own tools were NOT checked for known holes this run (its scanner Python is missing or "
                             "isn't the computer's own); the last results are kept.")
        return out
    if not os.path.isfile(os.path.join(os.path.dirname(os.path.dirname(py)), "LOCKED")):
        out.append(finding("WT-W002", "Watchtower's scanners were installed without the checksum lock", "low", ["ASI04", "AST02"], "watchtower scanners",
                           "no LOCKED marker", "Run `bash /workspace/watchtower/app/scripts/install.sh --scanners` again; it installs only from the lock, and stops and says why if this computer's Python doesn't fit it."))
    if not exe:
        if scanner_unavailable("pip-audit")[0]:   # batch 3: pip-audit's own line says why; this stage's last results are kept too
            fail_note(notes, "Watchtower's own tools were NOT checked for known holes this run (pip-audit didn't run); the last results are kept.")
        return out
    code, out_s, _ = run([py, "-m", "pip", "list", "--format", "json", "--disable-pip-version-check"], 60)
    try:
        pkgs = {p_["name"]: p_["version"] for p_ in json.loads(out_s)}
    except (ValueError, KeyError, TypeError):
        fail_note(notes, "Watchtower's own tools FAILED to list their packages: they were NOT checked this run.")
        return out
    req = state_path("scanner-requirements.txt")
    with open(req, "w") as f:
        f.write("\n".join(f"{n}=={v}" for n, v in sorted(pkgs.items()) if n.lower() != "skillspector"))
    code, out_s, err = run([exe, "-r", req, "--no-deps", "--disable-pip", "-f", "json", "--progress-spinner", "off"], 90)
    try:
        data = json.loads(out_s)
        deps = data.get("dependencies", [])
    except (ValueError, AttributeError):
        fail_note(notes, f"Watchtower's own tools FAILED their package check ({(err.strip().splitlines() or ['no answer'])[-1][:100]}): NOT checked this run.")
        return out
    for d in deps:
        if d.get("vulns"):
            ids = list(dict.fromkeys(v.get("id", "") for v in d["vulns"]))
            out.append(finding("WT-W001", f"Watchtower's own tool needs an update: {d.get('name')} {d.get('version')}", "low", ["ASI04", "AST02"],
                               "watchtower scanners", f"{len(ids)} known: {', '.join(ids[:3])}",
                               "Update Watchtower: each release carries newer pinned scanners. This package lives only in Watchtower's own folder.", source="pip-audit"))
    return out
