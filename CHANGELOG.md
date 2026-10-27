# Changelog

## 0.2.0 - unreleased

- New rules (42 total): EX-05 arbitrary external call with caller-supplied target and calldata, EX-06 swap with minimum output hardcoded to 0, EX-07 block.timestamp as a swap/liquidity deadline, SG-04 keccak256(abi.encodePacked()) over two or more dynamic types, DS-03 msg.value read inside a loop, MA-05 share math with no virtual offset (first-depositor inflation).
- AC-01: accepts `x == msg.sender` with msg.sender on the right and `isAuthorized[x][msg.sender]` checks; skips functions that only write msg.sender-keyed storage; skips ERC-4626/ERC-20 user functions (deposit, mint, withdraw, redeem, transfer, approve) implemented as overrides or in an ERC4626/ERC20 contract.
- AC-03: same ERC-4626/ERC-20 user-function skip.
- EX-02: counts writes to struct fields in mappings (`info[user].owed = 0`) and treats `_safeMint` as an external call.
- EX-03: no longer flags a transfer whose `require(` opens on the previous line.
- OR-02: also looks at internal/private helpers in the same file called by the function.
- Tests: extra vulnerable/safe pairs for these patterns in `test/extra_cases.js`.

## 0.1.1 - 2026-10-27

- The privileged-function inventory (AD-01) is now reported as an inventory under the auditor handoff section and is no longer counted as hits in the summary, so large projects don't get an inflated count.

## 0.1.0 - 2026-10-27

- First version: 36 rules across access control, upgradeability, external calls, oracles, token handling, math, signatures, admin surface, randomness/time, denial of service and hygiene.
- Pre-audit readiness section (9 items) and auditor handoff section.
- Markdown and JSON output, `--min`, `--only`, `--fail-on`, `--include-tests`, `--include-lib`.
