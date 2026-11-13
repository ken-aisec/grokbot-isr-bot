---
name: isr-bot-incident
description: Something looks wrong (a canary fired, an unknown routine appeared, a Bot did something nobody asked for). Collects an evidence pack first, then walks the user through containment one approved step at a time.
---

# Incident mode

1. Ask the user in one line what they saw, then run `python3 /workspace/isr-bot/app/isr_bot/isr.py incident --note "<their words>"`. It writes `/workspace/isr-bot/incidents/incident-<time>.md` with open findings, canary status, files changed in the last 24 hours, shell history (masked), processes, network connections and scheduled jobs. It changes nothing.
2. Read the evidence pack and tell the user, in at most 6 lines, what most likely happened and which Bot, skill or routine it points to. Say plainly when the evidence doesn't explain it.
3. Offer the containment checklist from the JSON in order. Do one step only after the user says yes to that step, and confirm it's done before offering the next. You may only advise on steps that happen in the Grok Bot app or another service; never claim you did them.
4. When contained, run `isr.py audit` and `isr.py canary plant` (re-arms tripwires), and suggest vetting whatever was installed most recently (the vet-template skill).

## Decoy lines, in plain words
- ISR-K001 (one decoy opened) and ISR-K003 (a decoy's value used in a command, or written to another file) are alarms: start here. A K003 that follows a sweep names that sweep's read.
- ISR-K008 "A file sweep passed over a decoy" is info, not an alarm: the files beside the decoy and far from it were read with it, as `grep -r`, a key scanner, a backup or an indexer does. Only if nothing of the owner's swept then is it worth a look.
- ISR-K009 is info too: a decoy's value shows up only in a scanner's report that names the decoy's own path, or in a copy of the whole decoy folder tree. Nothing used it.
- A K001, K008 or K009 line names the session logs that made a tool call within 2 minutes of it, by path only. Those are the first suspects; read the pack, not the logs' secrets.

## Never
- Delete evidence, reset the computer, or revoke anything on your own.
- Clear a decoy alarm without the owner's yes (`isr.py events clear` refuses until you pass `--owner-said-yes`, and you only pass it after they said yes in this conversation).
- Open, list or search the decoy files yourself; `isr.py canary status` only looks and changes nothing.
