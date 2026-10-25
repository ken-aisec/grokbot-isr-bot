# ISR Bot threat model

ISR Bot runs on the same shared Grok Bot computer it audits, so it is held to the rules it enforces.

## What it defends
| Risk | OWASP | Check |
| --- | --- | --- |
| Malicious or trojaned template or skill | AST01, AST02, ASI04 | `vet`, text rules, optional SkillSpector/husk |
| Prompt injection in skills | AST05, LLM01 | ISR-T001, T002, T008 |
| Over-privileged routines, missing approval lines | AST03, ASI02 | ISR-T013, R002, R003, T014 |
| Broad Auto Review allow rules | ASI03, ASI09 | ISR-A001–A003 |
| Local execution on Always allow | ASI03, ASI05 | ISR-C001 |
| Secrets on the shared computer or in shareable configs | AST04, LLM02 | ISR-T011, S001, S002 |
| Update drift after review | AST07 | ISR-I001 |
| Persistence (cron, units, shell rc) | ASI10 | ISR-P001 |
| Unpinned MCP servers, vulnerable packages | AST02, ASI04 | ISR-M001, D001 |
| Memory poisoning | ASI06 | roll-call: ISR-M010 from each Bot's own counts (no memory text is asked for or kept) |
| Roll-call sent by someone else | ASI03, ASI07 | the question asks only for counts, names and yes/no answers; replies 0600 in a 0700 folder, deleted as read; ISR-R011 when a Bot answers with content |
| Lethal trifecta on one Bot | ASI01, ASI02 | ISR-L001 |
| Data theft in progress | ASI03, ASI10 | canaries: ISR-K001–K003 |
| Commands nobody meant to run | ASI05, ASI10 | shell history: ISR-H001–H009 |
| Secrets or private links shipped in a template | AST04, LLM02 | pre-publish: ISR-PP01–PP07 |
| Vulnerable code written by Bots | OWASP Top 10 (2021) | codescan: ISR-WA01–WA10 |
| Evasion of a single scanner | AST08 | three engines; ISR-X001–X003 |

## What it trusts
The pinned release verified against `MANIFEST.sha256`; Python's standard library; the user's answers during setup. Who owns a file is decided by where it is (v0.8.1), never by a list of files or hashes, the owner's yes, or a record in ISR Bot's state or the ledger. Grok Bot's, Codex's and Claude's own folders (the managed skills and plugin caches under `sand-data` and `agent-data`, `.claude/plugins`, `.codex/skills`, `.codex/plugins`, `.grok/bundled`, `/tmp/hooks`) are the vendor's: never scored, only counted in the platform notes. ISR Bot's own dev and test trees, `/workspace/backups` and copies of chat and tool output are silent. A path is not the owner's only when the path as written and the place it really leads are both inside the same such folder; a link either way between the owner's files and those folders, and a file behind a link inside a vendor folder that leads out of it, stay the owner's and are scored. Everything else is the owner's. No vendor file is fingerprinted, so a vendor update raises nothing.

## What it does not trust
Every file it scans, every web page and feed it reads, and every reply from another Bot. They are data. An instruction found in them is a finding.

## Known gaps
- The self-check holds the installed copy to its own `MANIFEST.sha256`, so it shows changes made after the install, not who made them. ISR Bot runs as the Bot's user, and the Bot can write to `/workspace/isr-bot`. A Bot that rewrites `MANIFEST.sha256` together with the files it lists before a run passes the self-check, and so do `scripts/scanner-bins.lock` and its reader (a scanner the Bot chose then counts as verified). The same Bot could rewrite `isr.py` itself. Inside one run, ISR Bot uses the manifest it checked at the start and never reads it again. If the lock, its reader or the folder behind `app` changes after the self-check, every scanner is reported as changed (ISR-X005). Only a reinstall from the pinned release (setup, section 1) restores the release. install.sh, the setup skill's version check, the daily and tidy routines and the audit skill start `isr.py` with `python3 -I`, so a module planted next to it (`isr_bot/argparse.py`) can't run before the self-check. The other skills still start it without `-I`.
- A tampered platform file goes unseen (v0.8.1, the owner's choice): an instruction a Bot hides in Grok Bot's, Codex's or Claude's own folders is still read by ISR Bot's rules, but a hit there only adds one to the unscored platform notes count, and the platform still loads that file. How likely that is can't be told; the vendor's next update usually overwrites such a file. Watching closely would mean a hash list per vendor release again, which goes stale at every vendor update. A working key inside a vendor folder is only counted too. A key pasted into a chat transcript or tool cache, committed to ISR Bot's dev tree, or sitting in `/workspace/backups` is not scored and not listed.
- `state/engine_cache.json` is Bot-writable: a forged clean answer hides a scanner vote, but ISR Bot's own rules still read the file's bytes in every run.

## Out of scope
Connector OAuth tokens (kept on Cursor's backend), other users' computers, model serving, and anything that requires Enterprise APIs.
