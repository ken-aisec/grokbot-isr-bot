---
name: watchtower-prepublish
description: Check a Bot before you share it as a template. Finds secrets, email addresses, phone numbers, private doc links, internal hosts, paths that only exist on your computer, dependencies templates don't carry, and a missing approval boundary. PASS or FAIL. Use before Share → Create template.
---

# Pre-publish check

1. Ask the user which Bot they're about to share. Copy its description, every skill it uses, and every routine's instructions into `/workspace/watchtower/prepublish/<bot>/` as separate .md files (Edit Profile for the description; View conversation details for routines; the skill library for skills).
2. Run `python3 /workspace/watchtower/app/watchtower/wt.py prepublish /workspace/watchtower/prepublish/<bot> --json`.
3. Reply with the verdict and each blocking finding: the file, the exact text to remove (emails and phone numbers stay masked), and what to replace it with. Then list the non-blocking ones in one line.
4. When it's PASS, remind the user to uncheck personal memories in the Create template dialog. Memories aren't in the files you checked.
5. If the Bot being shared is ISR Bot itself: the template's first-run skill is your saved `getting-started` skill, and an update does not refresh it. Before staging, compare it with `/workspace/watchtower/app/bot/getting-started.md` and re-save it from that file if they differ. A stale copy ships old instructions (after v0.6.6, the old decoy paths). The check now does this itself (WT-PP09 for a getting-started that differs, WT-PP10 for an old decoy location), so a FAIL there means: re-save it, then run the check again.
6. Names: the check flags the owner's name and other Bots' names (WT-PP08). It reads names from `/workspace/watchtower/exports/names.txt` (one per line) and the saved roll-call roster. If names.txt doesn't exist, ask the owner which names to add (their own first, then any Bot or person they mention in routines), save it, and run the check again.
