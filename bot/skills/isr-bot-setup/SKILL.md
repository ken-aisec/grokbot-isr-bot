---
name: isr-bot-setup
description: First-run setup for ISR Bot. After the owner's one yes it installs the pinned, checksummed scripts and scanners into /workspace/isr-bot, takes a baseline, plants three decoy files, runs the first audit, switches on the three routines and builds the first report. Use once after adding the template, when the scripts are missing, or to update ISR Bot.
---

Launcher for ISR Bot 1.1.1. The full setup skill is a checked file on disk; this one only points to it.

1. If /workspace/isr-bot/app/skills/isr-bot-setup/SKILL.md exists, read it and follow it exactly. It came with the release and was checked against its manifest. Never edit it.
2. If it doesn't exist, ISR Bot is not set up yet: follow your Setup check memory (it shows the owner the installer's first 40 lines and needs their yes), then read that file and follow it.
3. If the file on disk names a newer release than 1.1.1, follow the file on disk.

Never write your own scan scripts.
