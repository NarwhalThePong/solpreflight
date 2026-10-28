# solpreflight

A checklist-driven pre-audit self-review report for Solidity projects.

Run it on your repo before you hand code to an auditor or a contest. It walks your contracts, matches common risk patterns, and writes a Markdown (or JSON) report with a checklist, file:line hits, a readiness section, and an auditor handoff section (contracts, entry points, privileged functions, dependencies).

**It is not an audit.** It does not prove anything is safe. It uses regular expressions and a lightweight parser, so it will report false positives and will miss real issues. Use it as a list of questions to answer before review.

- Node.js 18+, no dependencies, works offline
- No compiler (solc) needed
- Foundry and Hardhat layouts

## Usage

```sh
npx solpreflight .                      # Markdown report to stdout
npx solpreflight ./contracts -o report.md
npx solpreflight . --json > report.json
npx solpreflight . --min medium         # hide low/info hits
npx solpreflight . --only AC,OR-02      # selected rules
npx solpreflight . --fail-on high       # exit 1 if any high-priority hit (CI)
npx solpreflight --list-rules
```

By default `node_modules/`, `lib/`, `out/`, `cache/`, and test, script and mock files are skipped. Use `--include-tests` or `--include-lib` to change that.

See [docs/SAMPLE_REPORT.md](docs/SAMPLE_REPORT.md) for output from the intentionally vulnerable fixture in `fixtures/vulnerable-vault`.

## Report sections

1. **Summary**: hit counts by review priority.
2. **Checklist**: every rule, ticked if no hits, with why it matters, how to verify, and file:line hits.
3. **Pre-audit readiness**: tests present, build config, README/docs, NatSpec coverage on public/external functions, pinned pragma, SPDX headers, LICENSE, known-issues file, scope file.
4. **Auditor handoff**: contracts with nSLOC, external state-changing entry points, privileged functions, imported packages.

"Review priority" (high/medium/low/info) is a hint for where to look first. It is not a severity rating of a confirmed issue.

## Rules

| ID | Review priority | Category: title |
|---|---|---|
| AC-01 | medium | Access control: State-changing public/external function with no access modifier |
| AC-02 | high | Access control: tx.origin used |
| AC-03 | high | Access control: Owner-style contract with unprotected withdraw/upgrade/set function |
| UP-01 | high | Upgradeability: Upgradeable implementation without _disableInitializers() in constructor |
| UP-02 | high | Upgradeability: initialize() without initializer modifier |
| UP-03 | low | Upgradeability: Upgradeable contract without storage gap |
| UP-04 | high | Upgradeability: delegatecall |
| UP-05 | medium | Upgradeability: selfdestruct |
| UP-06 | high | Upgradeability: _authorizeUpgrade with empty body and no modifier |
| EX-01 | high | External calls: Low-level call without success check |
| EX-02 | high | External calls: External value call before state update (possible reentrancy) |
| EX-03 | medium | External calls: Unchecked ERC20 transfer/transferFrom return value |
| EX-04 | low | External calls: approve() to non-zero amount (approval race / USDT-style tokens) |
| EX-05 | high | External calls: Arbitrary external call with caller-supplied target and calldata |
| EX-06 | high | External calls: Swap with minimum output hardcoded to 0 |
| EX-07 | medium | External calls: block.timestamp passed as a swap/liquidity deadline |
| OR-01 | medium | Oracles: Deprecated latestAnswer() |
| OR-02 | high | Oracles: latestRoundData without staleness or price > 0 check |
| OR-03 | high | Oracles: Spot price from pool reserves / slot0 |
| TK-01 | medium | Token handling: Credits the requested amount after transferFrom (fee-on-transfer assumption) |
| TK-02 | medium | Token handling: balanceOf(address(this)) used for accounting |
| TK-03 | low | Token handling: Hardcoded 18-decimal assumption |
| MA-01 | medium | Math: Division before multiplication |
| MA-02 | info | Math: unchecked block |
| MA-03 | medium | Math: Downcast to a smaller integer type |
| MA-04 | info | Math: Rounding direction review (division in share/asset math) |
| MA-05 | medium | Math: Share math with no virtual offset (first-depositor inflation) |
| SG-01 | high | Signatures: ecrecover without zero-address check |
| SG-02 | high | Signatures: Signature check without nonce / deadline / chainId |
| SG-03 | medium | Signatures: Raw ecrecover (malleability) |
| SG-04 | medium | Signatures: keccak256(abi.encodePacked()) over two or more dynamic types |
| AD-01 | info | Admin surface: Privileged function inventory |
| AD-02 | info | Admin surface: Pause / emergency functions |
| AD-03 | low | Admin surface: Privileged setters without a timelock |
| RT-01 | high | Randomness / time: blockhash / prevrandao / timestamp used as randomness |
| RT-02 | info | Randomness / time: block.timestamp dependence |
| DS-01 | medium | Denial of service: Loop over a storage array of unbounded length |
| DS-02 | medium | Denial of service: External call inside a loop |
| DS-03 | high | Denial of service: msg.value read inside a loop |
| EV-01 | low | Events / hygiene: Privileged setter emits no event |
| EV-02 | info | Events / hygiene: Floating pragma |
| EV-03 | info | Events / hygiene: Missing SPDX license identifier |

Each rule has a vulnerable and a safe test snippet in `test/cases.js` (with extra pairs for known tricky patterns in `test/extra_cases.js`); the test suite checks it fires on the first and stays quiet on the second. That is the only claim made about detection: the rules match the patterns shown in the tests.

## Limitations

- No type information, inheritance resolution or data-flow analysis. Modifiers defined in a parent contract are recognised only by common names (`onlyOwner`, `onlyRole`, `auth`, `requiresAuth`, ...).
- Inline assembly is not analysed.
- Cross-function and cross-contract reentrancy are not detected; EX-02 only looks for a state write after a value call in the same function.
- Expect false positives, especially for AC-01, MA-01, TK-03, RT-02 and DS-01. Expect false negatives everywhere.
- A clean report does not mean the code is safe.

## Development

```sh
npm test
npm run sample   # regenerate docs/SAMPLE_REPORT.md
```

## License

MIT

## Related

A printable 66-item pre-audit checklist, scoring sheet and scope/known-issues/threat-model templates are available as a separate paid pack from the same author: [Smart Contract Pre-Audit Review Pack ($19)](https://payhip.com/b/G5agO). The scanner is free and open source on its own, and neither one is an audit or a security guarantee.

## Other free tools from the same author

- [sorobanpreflight](https://github.com/NarwhalThePong/sorobanpreflight): a pre-audit checklist scanner for Soroban (Rust) contracts.
- [foundry-invariant-kit](https://github.com/NarwhalThePong/foundry-invariant-kit): generates Foundry invariant and fuzz test scaffolds for ERC-20 and ERC-4626 contracts (lending is experimental).
- [upgrade-safety-diff](https://github.com/NarwhalThePong/upgrade-safety-diff): compares two proxy storage layouts and flags layout-level upgrade hazards. It checks layout only and does not prove an upgrade is safe.

Each is a self-review aid, not an audit or a guarantee.
