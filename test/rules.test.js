'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { analyzeSource } = require('../src/scan');
const { rules } = require('../src/rules');
const cases = require('./cases');

test('every rule has a test case', () => {
  for (const r of rules) assert.ok(cases[r.id], `missing case for ${r.id}`);
});

for (const r of rules) {
  test(`${r.id} fires on vulnerable snippet`, () => {
    const hits = analyzeSource(cases[r.id].bad, 'bad.sol').findings.filter(f => f.rule === r.id);
    assert.ok(hits.length > 0, `${r.id} did not fire`);
  });
  test(`${r.id} stays quiet on safe snippet`, () => {
    const hits = analyzeSource(cases[r.id].good, 'good.sol').findings.filter(f => f.rule === r.id);
    assert.deepStrictEqual(hits, [], `${r.id} false positive: ${JSON.stringify(hits)}`);
  });
}

test('comments and strings do not trigger rules', () => {
  const src = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.24;\ncontract T {\n// tx.origin selfdestruct(x)\n/* delegatecall( */\nstring s = "tx.origin";\n}\n';
  const ids = analyzeSource(src).findings.map(f => f.rule);
  for (const id of ['AC-02', 'UP-04', 'UP-05']) assert.ok(!ids.includes(id), id);
});

test('line numbers point at the hit', () => {
  const src = cases['AC-02'].bad;
  const hit = analyzeSource(src).findings.find(f => f.rule === 'AC-02');
  assert.match(src.split('\n')[hit.line - 1], /tx\.origin/);
});
