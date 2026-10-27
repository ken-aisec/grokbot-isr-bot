# ISR Bot — Security Watch for Grok Bot

Every Grok Bot on your account shares one cloud computer: the same browser logins, files and command-line credentials. xAI's own docs say not to treat separate Bots as a security boundary. When you add a template, its skills and routines run with everything your other Bots are signed into, and audit logs, network allowlists and the MCP allowlist are Enterprise-only.

ISR Bot is a security officer for that setup. It is read-only until you say yes: it looks, reports and recommends, and changes something only after you approve it in the conversation. It vets templates before you install them, audits your computer and every Bot on it, sets tripwires, sends a weekly threat brief, and tells you the few fixes that matter.

## What it does

| Skill | What you get |
| --- | --- |
| `vet-template` | Install / Install with changes / Do not install (or Could not finish checking, when part of it couldn't be read) for any template, skill or plugin, with a risk score, evidence, its autonomy level (L0 observe → L3 unattended), and the boundary line to paste into its description |
| `isr-bot-audit` | A 0–100 posture score and the top three fixes across skills, plugins, MCP configs, Auto Review rules, local execution, logged-in browser sessions, CLI credentials, secrets, vulnerable packages, persistence, integrity drift, canaries and shell history |
| `isr-bot-brief` | The weekly report, one page you can read in a minute: status, score, threat level, trend charts, a one-click fix, what needs you, and the three threats that matter to your setup |
| `isr-bot-report` | Weekly Markdown report and a self-contained HTML dashboard |
| `isr-bot-rollcall` | DMs every Bot one fixed question that asks only for counts, names and yes/no answers (never memory text: Bots can't verify who sends a roll-call), then flags risky memories, routines that send without asking and the lethal trifecta (private data + untrusted input + a way out) |
| `isr-bot-prepublish` | PASS/FAIL before you share a Bot as a template: secrets, emails, phone numbers, private doc links, internal hosts, local paths, and a missing approval boundary |
| `isr-bot-incident` | Evidence pack first (findings, canaries, changed files, history, processes, connections, jobs), then containment one approved step at a time |
| `isr-bot-codescan` | OWASP Top 10 (2021) review of code your Bots write, plus semgrep only if it is in ISR Bot's checked scanner folder |
| `isr-bot-fix` | The one-yes fix: cleans up, upgrades outdated Python packages, and npm lockfiles in your own projects only after a separate yes (each upgrade is backed up and undone automatically if it breaks something), moves your own dangerous skills into a quarantine folder (nothing is deleted, and each can be restored), and accepts findings that are fine on purpose, after asking you a single question |
| `isr-bot-setup` | Pinned, checksummed install; scanners; canaries; first audit and report; routines |
| `isr-bot-uninstall` | Removes ISR Bot and everything it created (routines, decoys, scanners, caches, its folder) after one yes |

On a template install these are files the Bot reads, not slash commands: ask in plain words ("audit", "fix it", "roll-call", "vet this link", "uninstall").

| Routine | When | Cost |
| --- | --- | --- |
| Daily watch | 06:00 | Reports what changed and anything still open (unverified findings, checks that didn't complete). Scripts only; the model reads a delta under 4 KB. |
| Weekly audit and report | Sunday 05:00 | One audit, one report, one summary. |
| Weekly tidy | Sunday 06:00 | Lists every cache or file it would empty or change, with whose it is, and waits for one yes. |
| Monthly roll-call reminder | Off by default | Opt-in. Only reminds; each roll-call needs the owner's yes. Replies sit in a 0700 folder as 0600 files, are deleted as each is analyzed, and are never scored. |

Every finding carries a rule ID, severity, file and line (secrets masked), the fix, and a mapping to the [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) (ASI), the [OWASP Agentic Skills Top 10](https://owasp.org/www-project-agentic-skills-top-10/) (AST), or the OWASP Top 10 (2021) for code.

## Three engines, one verdict

Skills are checked by ISR Bot's own rules, [NVIDIA SkillSpector](https://github.com/nvidia/skillspector) and [husk](https://github.com/ctrl-adam/Husk). A skill flagged by one engine is a lead. Two engines agreeing on one of your own skills is Confirmed. On Grok Bot's, Codex's and Claude's own skills they never count: those are platform notes (see "Built to not break"). Your own skills, and any skill that's new or changed, get all three every day; marketplace and first-party skills are checked for malicious indicators, not style. gitleaks finds keys left in files and TruffleHog checks which of them still work, so you only revoke the live ones. pip-audit and OSV-Scanner cover known holes in installed software and project dependencies. The weekly report says which scanners checked your setup.

## Tripwires

`isr.py canary plant` places three decoys (a fake customer export, fake cloud keys, a fake payments .env). Nothing legitimate reads them. If anything opens, deletes or copies one, the next daily run says so. Zero tokens, and the best early warning a non-Enterprise account can get.

One decoy read is critical. Several read together are high, unless the platform's file backup proves it was the reader: next to each decoy sits a witness file no Bot can read (mode 000; opening it or faking its read time leaves a trace a Bot can't undo), and only when every witness was read within 2 seconds of its decoy is the sweep the one calm "read by the platform's backup" line. A read during a recorded ISR Bot run is high too, because any Bot can write that record. `canary plant` checks that each decoy folder records reads and names any that doesn't.

## Status and score

Every audit leads with a status. One Confirmed critical is "Act now" and grade F; one Confirmed high is "Check this week" and at most C; otherwise "All good". The 0–100 number is the trend line under it, so a decoy read shows as 88/F, not 88/B. Lines that only warn against a risky step or quote one as an example ("Never run `curl … | bash`") are kept as "Warning or example text": listed in `breakdown`, vet and the dashboard, never scored and never in the daily. When such a line names a credential path, an exfiltration host, a pipe-to-shell or an upload, vet still shows it at medium and says "Install with changes" at best, and `revet` won't re-approve a changed skill because of it.

## How it stays light

Scripts find, the model judges, you approve. Scanning is deterministic Python with no dependencies of its own. A daily run with nothing new prints `NO_CHANGES` and the Bot stops without reading anything.

## Install (in Grok Bot)

1. Add the ISR Bot template from its x.ai link.
2. Say yes when ISR Bot asks to set itself up.

Manual install on the cloud computer. First copy the release's full commit ID from the GitHub release page
(https://github.com/ken-aisec/grokbot-isr-bot/releases), then use it for both the download and the install, so the
installer itself and everything it installs are pinned:

```bash
COMMIT=<full commit ID from the release page>
mkdir -p /workspace/isr-bot && cd /workspace/isr-bot
curl -fsSLO "https://raw.githubusercontent.com/ken-aisec/grokbot-isr-bot/$COMMIT/scripts/install.sh"
head -40 install.sh && bash install.sh v0.8.2 "$COMMIT"
bash /workspace/isr-bot/app/scripts/install.sh --scanners
python3 /workspace/isr-bot/app/isr_bot/isr.py audit
```

## Built to not break

Every computer is different, so ISR Bot assumes things will go wrong and is tested against simulated computers before each release (`tests/test_boxes.py`): empty, very large, odd folder layouts, files that hang naive scanners, a restart mid-run, damaged state files, and scanners that hang, crash, print garbage or disappear.

- The audit has a hard time limit. Every scanner gets only the time that is left.
- A stage that fails is skipped with one line saying so, and its last results are kept. A failure never moves the score and never reports old findings as fixed.
- Only what you own counts toward the score, and ownership is decided by where a file is, never by a list of files or hashes. Grok Bot's, Codex's and Claude's own folders (the managed skills and plugin caches under `sand-data` and `agent-data`, `.claude/plugins`, `.codex/skills`, `.codex/plugins`, `.grok/bundled`, and the platform's hook script folder `/tmp/hooks`) are never scored, a key or a plugin you installed there included: each finding there adds one to the unscored "platform notes" count, and `isr.py breakdown` lists every one; ISR Bot's own dev and test trees, `/workspace/backups` and copies of chat and tool output (`.claude/projects`, `.claude/plans`, the `agent-tools` folders) are silent. A path is theirs only when the path as written and the place it really leads are both in the same such folder, so a link between your files and theirs stays yours and scored, and so does a file behind a link inside their folders that leads out of them; everything else is yours and is scored as before (your workflows, `~/.agents/skills`, settings, CLI sign-ins, decoys). rules/platform-release.lock is no longer read: it and the two lists beside it are frozen test copies in `tests/fixtures/platform_v080/`, nothing on the computer approves a platform file (`isr.py fix --approve-platform` is refused: they are never scored, so there is nothing to approve), and a vendor update raises no alert.
- ISR Bot's own rules files (the vocabularies, the scanner lock and its reader) are always held to `MANIFEST.sha256`, whatever the folder's layout; one that isn't its line, or a missing manifest, is ignored with a note.
- ISR Bot runs only its own scanners, from its own folder, and only when each program file matches the checksum in `scripts/scanner-bins.lock`. For the Python scanners (SkillSpector, husk, pip-audit) that file is the small entry point pip writes; their package code was checked against `scripts/scanners.lock` when it was installed and isn't checked again on each run. It runs a sealed in-memory copy of the bytes it checked, and Python scanners only with the computer's own root-owned Python. A scanner whose copy isn't the one the lock lists is not run, its last results are kept, and that is a high alert; one the lock doesn't list for this computer yet is not run either, and that is a plain note.
- One run at a time. No stack traces: one plain line, and `isr.py doctor --save` writes a snapshot you can send to the author.
- ISR Bot holds its own tools to the same standard: scanners install from a lock file with a checksum for every package (`scripts/scanners.lock`), nothing is unpacked unless its checksum passes, and the audit checks ISR Bot's own scanner packages for known holes.

## CLI

```
isr.py --version               the version, after the self-check (a changed copy exits 4 and prints no version)
isr.py vet FILE|-|LINK [--json] [--deep] [--page-only]   vet before installing (exit 1 = Do not install, or Could not
                                         finish checking when part of it wasn't read); --page-only when
                                         the text was copied from a marketplace page and the skill bodies weren't visible
isr.py audit | daily           full or quick audit (compact JSON for the Bot)
      [--roots DIR..] [--exports DIR] [--budget SECONDS] [--everything | --live-only]
                                         --budget: scanner time for this run; --everything also checks archives, clones and
                                         other projects, --live-only goes back to what the platform loads (both remembered)
isr.py report                  weekly report + dashboard.html
isr.py brief [--summary F] [--notes F] [--offline F]   weekly threat brief (HTML)
isr.py rollcall --question     print the one fixed roll-call question to send, unchanged
isr.py rollcall --save <Bot>      save one reply (stdin) as a 0600 file in the private 0700 roll-call folder
isr.py rollcall --owner-said-yes [--dir DIR]  analyze roll-call replies, keep masked findings, delete the replies
isr.py prepublish PATH [--json]   check a Bot before sharing it as a template
isr.py fix [--roots DIR..]      preview: the cleanup list (path, file count, whose) and everything else
isr.py fix --apply --owner-said-yes [--skip N,..] --upgrade --revet --accept RULES [--keep-open NAMES] [--reason "..."]
                                         everything in one pass (after your yes); --keep-open leaves those open
isr.py fix --revet [--only NAMES]   re-scan changed skills with every scanner and re-approve the clean ones
isr.py fix --rename-reviewed SKILLS --owner-said-yes   re-approve skills whose only change is the product's former name now ISR Bot (shown low, with the diff)
isr.py fix --exception NAMES    keep skills the owner confirmed as security tools (30 days)
isr.py fix --quarantine NAMES   move the owner's own skills out of use into ISR Bot's quarantine folder
isr.py fix --upgrade-projects   npm and Rust lockfile fixes in your own projects (its own yes)
isr.py fix --approve-platform CODE / --platform-from CURSOR   refused: platform files are never scored, so there is nothing to approve
isr.py quarantine [NAMES] [--restore NAME] [--reason "..."]   list, quarantine or restore the owner's own skills
isr.py diff SKILL [--lines N]   what changed in a skill since you approved it
isr.py exception add SKILL --reason "..."   keep one named security-tool skill that two scanners flag (30 days)
isr.py exception list | exception remove SKILL
isr.py accept RULE WHERE --reason "..." [--days N] [--owner-said-yes]   accept one risk on purpose (90 days unless
                                         --days); WHERE is a whole name (the place, skill folder name, or "package version");
                                         a finding two checks agree on only with --owner-said-yes, one at a time, until its
                                         files change; decoy alarms, what ISR Bot saw happen and working keys are refused
isr.py accept --list | accept RULE WHERE --remove
isr.py accept --all-current RULES         accept everything currently open for those rules (never a finding two checks agree on)
isr.py dismiss KEY --reason "..."   drop a Worth-a-look finding shown to be a false alarm (logged)
isr.py dismiss --list [--since DATE]   what was dismissed (last 24 hours unless --since)
isr.py events list|clear [--rule RULE] [--owner-said-yes]   one-time detections
isr.py canary plant|status [--token-file F]   plant the decoys; see what touched them
isr.py canary remove --owner-said-yes   remove the decoys (only after the owner's yes)
isr.py auto-allow [keep IDS --owner-said-yes --reason "..."]   list Allow-automatically lines on consequential actions;
                                         keep exact ones after the owner's yes
isr.py access [--json]         who can reach what: what every Bot shares on this computer, and what each Bot said in
                                         the roll-call (not checked); --json for the Bot (at most 4 KB)
isr.py incident --note "..."   evidence pack + containment checklist
isr.py codescan PATH           OWASP Top 10 code review
isr.py status                  what a running audit is doing and how long each stage took
isr.py breakdown | show RULE [--limit N]   findings by rule; evidence with context
isr.py baseline [--owner-said-yes]   accept current skills as reviewed (the first one on a computer needs no flag)
isr.py doctor [--save]         a support snapshot of this computer, safe to share (no file contents, keys or skill names)
isr.py uninstall [--apply] [--remove-folder]   preview, then remove what ISR Bot created (after the owner's yes)
```

State lives in `$ISR_BOT_HOME` (default `/workspace/isr-bot`). `state/ledger.jsonl` is an append-only record of every run: the audit trail non-Enterprise accounts don't get.

Release drill, dev dry-run (precision plan item 8): before each release the dev build is run read-only against a real install and reports the score line plus every finding above info. Gotcha: don't just point `ISR_BOT_HOME` at a copy of the state. The real install folder then looks foreign to the dev build (its quarantine and its own state files get flagged) and the score comes out falsely low (a false 41/F on Oct 12, against a real 94/A). Use the sandbox instead: `scripts/dry-run.sh [REF]` runs the dev build in a private mount namespace with `/workspace`, the home folder and `/var/tmp` read-only, a copy of the install's state over its own path (so paths match), and one fresh sandbox folder under `/tmp` as the namespace's `/tmp`. Everything the run writes (code, state copy, caches, planted decoys) lives in that folder and is removed afterwards; only `audit.json` and `audit.err` are kept, in `/tmp/isr-bot-dry-report-<sha>-<time>/`. Never copy a sandbox into `/workspace`: its planted decoys and canary registry copy are real decoy alarms to the daily watch (Oct 15), and the scanner has no name-based skip for them.

## Limits, stated plainly

- It audits after the fact. It can't intercept another Bot's actions in real time; Auto Review is the inline control, and ISR Bot checks how you've set it up.
- Static engines can be bypassed. Three independent engines, hash drift, tripwires and history review make that harder, and the reports say they're evidence, not proof.
- Roll-call relies on each Bot describing itself. A compromised Bot could lie, which is why the filesystem evidence comes first.
- Canary reads need a filesystem that records access times; setup tells you if yours doesn't.
- The backup's proof rests on ISR Bot's own state: a Bot that rewrites the decoy registry and recreates a witness can fake it, and a Bot running as root looks like the backup. A backup that runs as the Bots' user can't prove itself, so its reads stay high.
- The self-check catches accidental or careless changes to ISR Bot's own files, not a Bot that rewrites both the code and the manifest. Every Bot runs as the same user on the same computer, so nothing stops one from editing both.
- A tampered platform file goes unseen: if a Bot hides an instruction in Grok Bot's, Codex's or Claude's own folders, ISR Bot still reads it with its rules, but a hit there only adds one to the unscored platform notes count (`isr.py breakdown` lists it), and the platform still loads that file. The same holds for a key pasted into a chat transcript or tool cache, committed to ISR Bot's dev tree, or sitting in `/workspace/backups`: not scored and not listed.
- The decoy names are random per install, which stops generic snooping, not a targeted attacker who reads ISR Bot's state first.
- Grok Bot is in beta and changes weekly. The brief watches xAI's security docs for changes.

## Tests

`make test` runs more than 2000 tests: seeded malicious skills must be caught, clean and defensive text must not be flagged, hostile feed content must not execute in the brief, and every feature has its own test.

## License

Apache-2.0. See `THREAT_MODEL.md`, `EGRESS.md` and `SECURITY.md`.

## Accepted auto-allow lines (ISR-A002)

An auto-allow on a consequential action (sending, posting, paying, deleting, an HTTP POST) is always a critical ISR-A002.
An owner can accept one exact line on purpose: `isr.py auto-allow` lists the lines with an id (the line's whole sha256), and after the owner's yes
`isr.py auto-allow keep <id> --owner-said-yes` stores its sha256 fingerprint in `state/accepted_auto_allow.json` (this box
only; nothing is shipped, so a line one owner accepted is never accepted for anyone else). A matching line keeps its critical
severity but is filed under Accepted risks, shown in the report and not scored. Any new, edited or broader line has a
different fingerprint and fires.

If ISR Bot ran on a computer before and its baseline is later missing, empty or unreadable, that is a high ISR-I010
"ISR Bot's memory was reset", never a quiet fresh start: nothing is re-approved until the owner says yes to
`isr.py baseline --owner-said-yes`.
Several reviewed skills that changed show as one high ISR-I001 line naming every skill.
