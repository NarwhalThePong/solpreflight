# Contributing

- One rule = one entry in `src/rules.js` with id, category, title, priority, why, verify and check.
- Every new or changed rule needs a `bad` and a `good` snippet in `test/cases.js`. The test suite fails if a rule has no case.
- Keep rules dependency-free and fast. Prefer fewer false positives over more hits.
- Run `npm test` and `npm run sample` before opening a pull request.
- Do not describe a rule as finding vulnerabilities; describe the pattern it matches.
