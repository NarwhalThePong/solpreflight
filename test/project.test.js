'use strict';
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { execFileSync } = require('child_process');
const { scan } = require('../src/scan');
const { toMarkdown, toJSON } = require('../src/report');

const VULN = path.join(__dirname, '..', 'fixtures', 'vulnerable-vault');
const SAFE = path.join(__dirname, '..', 'fixtures', 'safe-vault');
const BIN = path.join(__dirname, '..', 'bin', 'solpreflight.js');
const ids = r => new Set(r.findings.map(f => f.rule));

test('classic patterns in vulnerable fixture are flagged', () => {
  const r = ids(scan(VULN));
  // reentrancy, tx.origin, unprotected init, stale oracle, spot price, unchecked call, signature replay, weak randomness
  for (const id of ['EX-02', 'AC-02', 'UP-02', 'UP-01', 'OR-02', 'OR-03', 'EX-01', 'SG-02', 'SG-01', 'RT-01', 'AC-03', 'DS-01'])
    assert.ok(r.has(id), `expected ${id}`);
});

test('safe fixture has no high-priority hits', () => {
  const res = scan(SAFE, { minPriority: 'high' });
  assert.deepStrictEqual(res.findings, []);
});

test('test files are excluded by default', () => {
  assert.ok(!scan(VULN).filesScanned.some(f => f.includes('test/')));
});

test('readiness and handoff sections', () => {
  const res = scan(VULN);
  assert.ok(res.readiness.items.find(i => i.id === 'RD-01').ok);
  assert.ok(!res.readiness.items.find(i => i.id === 'RD-09').ok);
  assert.ok(res.handoff.contracts.some(c => c.name === 'SimpleVault' && c.loc > 10));
  assert.ok(res.handoff.privileged.some(p => p.fn === 'setOracle'));
  assert.ok(res.handoff.deps.includes('@openzeppelin/contracts'));
  const md = toMarkdown(res);
  assert.match(md, /not an audit/);
  assert.match(md, /## Auditor handoff/);
  assert.doesNotThrow(() => JSON.parse(toJSON(res)));
});

test('CLI --json and --fail-on', () => {
  const out = execFileSync('node', [BIN, VULN, '--json']).toString();
  assert.ok(JSON.parse(out).findings.length > 0);
  let code = 0;
  try { execFileSync('node', [BIN, VULN, '--fail-on', 'high'], { stdio: 'pipe' }); } catch (e) { code = e.status; }
  assert.strictEqual(code, 1);
  execFileSync('node', [BIN, SAFE, '--fail-on', 'high'], { stdio: 'pipe' });
});
