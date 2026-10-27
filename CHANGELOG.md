# Changelog

## 0.1.1 - 2026-10-27

- The privileged-function inventory (AD-01) is now reported as an inventory under the auditor handoff section and is no longer counted as hits in the summary, so large projects don't get an inflated count.

## 0.1.0 - 2026-10-27

- First version: 36 rules across access control, upgradeability, external calls, oracles, token handling, math, signatures, admin surface, randomness/time, denial of service and hygiene.
- Pre-audit readiness section (9 items) and auditor handoff section.
- Markdown and JSON output, `--min`, `--only`, `--fail-on`, `--include-tests`, `--include-lib`.
