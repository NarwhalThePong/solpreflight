'use strict';
const fs = require('fs');
const path = require('path');
const { parseFile } = require('./parse');
const { rules } = require('./rules');

const SKIP_DIRS = new Set(['node_modules', 'lib', '.git', 'out', 'cache', 'artifacts', 'typechain', 'typechain-types', 'broadcast', 'coverage']);
const PRIORITY_ORDER = { high: 0, medium: 1, low: 2, info: 3 };

function walk(dir, opts, acc = []) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return acc; }
  for (const e of entries) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (SKIP_DIRS.has(e.name) && !(opts.includeLib && e.name === 'lib')) continue;
      if (e.name.startsWith('.')) continue;
      walk(p, opts, acc);
    } else if (e.name.endsWith('.sol')) acc.push(p);
  }
  return acc;
}

const isTestFile = rel => /(^|\/)(test|tests|script|mocks?)\//i.test(rel) || /\.t\.sol$|\.s\.sol$|Mock\w*\.sol$/i.test(rel);

function analyzeSource(src, relPath = 'input.sol') {
  const parsed = parseFile(src);
  const file = { path: relPath, src, ...parsed };
  const findings = [];
  for (const r of rules) {
    let hits = [];
    try { hits = r.check(file) || []; } catch (e) { hits = []; }
    for (const h of hits) findings.push({ rule: r.id, file: relPath, line: h.line, note: h.note || file.lines[h.line - 1]?.trim().slice(0, 140) || '' });
  }
  return { file, findings };
}

function readiness(root, srcFiles, testFiles, parsedFiles) {
  const exists = (...names) => names.find(n => fs.existsSync(path.join(root, n)));
  const anyMatch = re => { try { return fs.readdirSync(root).find(n => re.test(n)); } catch { return undefined; } };
  let fns = 0, documented = 0;
  for (const pf of parsedFiles) {
    for (const c of pf.file.contracts) for (const fn of c.functions) {
      if (c.kind === 'interface' || fn.name === 'constructor') continue;
      if (!(fn.visibility === 'public' || fn.visibility === 'external')) continue;
      fns++;
      const above = pf.file.lines.slice(Math.max(0, fn.line - 8), fn.line - 1).join('\n');
      if (/\/\/\/|@notice|@dev|@param|\/\*\*/.test(above)) documented++;
    }
  }
  const pragmas = parsedFiles.map(pf => (pf.file.src.match(/pragma\s+solidity\s+([^;]+);/) || [, null])[1]).filter(Boolean);
  const pinned = pragmas.filter(p => /^\s*=?\s*\d+\.\d+\.\d+\s*$/.test(p)).length;
  const licensed = parsedFiles.filter(pf => /SPDX-License-Identifier/.test(pf.file.src)).length;
  const items = [
    { id: 'RD-01', label: 'Test files present', ok: testFiles.length > 0, detail: `${testFiles.length} test file(s) found` },
    { id: 'RD-02', label: 'Build config (foundry.toml / hardhat.config.*)', ok: !!(exists('foundry.toml') || anyMatch(/^hardhat\.config\./)), detail: exists('foundry.toml') || anyMatch(/^hardhat\.config\./) || 'none found' },
    { id: 'RD-03', label: 'README / docs', ok: !!(exists('README.md', 'readme.md', 'docs')), detail: exists('README.md', 'readme.md', 'docs') || 'none found' },
    { id: 'RD-04', label: 'NatSpec on public/external functions (target >= 80%)', ok: fns === 0 || documented / fns >= 0.8, detail: fns ? `${documented}/${fns} (${Math.round(100 * documented / fns)}%)` : 'no public functions' },
    { id: 'RD-05', label: 'Pinned pragma in all source files', ok: pragmas.length > 0 && pinned === pragmas.length, detail: `${pinned}/${pragmas.length} pinned` },
    { id: 'RD-06', label: 'SPDX license in all source files', ok: licensed === parsedFiles.length, detail: `${licensed}/${parsedFiles.length}` },
    { id: 'RD-07', label: 'Repository LICENSE file', ok: !!exists('LICENSE', 'LICENSE.md', 'LICENSE.txt'), detail: exists('LICENSE', 'LICENSE.md', 'LICENSE.txt') || 'none found' },
    { id: 'RD-08', label: 'Known-issues file', ok: !!(exists('KNOWN_ISSUES.md', 'known-issues.md', 'docs/known-issues.md', 'docs/KNOWN_ISSUES.md')), detail: exists('KNOWN_ISSUES.md', 'known-issues.md', 'docs/known-issues.md', 'docs/KNOWN_ISSUES.md') || 'none found' },
    { id: 'RD-09', label: 'Scope file', ok: !!(exists('scope.md', 'SCOPE.md', 'scope.txt', 'docs/scope.md')), detail: exists('scope.md', 'SCOPE.md', 'scope.txt', 'docs/scope.md') || 'none found' },
  ];
  return { items, score: items.filter(i => i.ok).length, total: items.length };
}

function handoff(parsedFiles) {
  const contracts = [], entry = [], privileged = [];
  const deps = new Set();
  for (const pf of parsedFiles) {
    const f = pf.file;
    for (const m of f.src.matchAll(/import\s+(?:[^'"]*from\s+)?["']([^"']+)["']/g)) if (!m[1].startsWith('.')) deps.add(m[1].split('/').slice(0, m[1].startsWith('@') ? 2 : 1).join('/'));
    for (const c of f.contracts) {
      const loc = f.cleanLines.slice(c.line - 1, c.endLine).filter(l => l.trim()).length;
      contracts.push({ name: c.name, kind: c.kind, file: f.path, line: c.line, loc, inherits: c.inherits });
      if (c.kind === 'interface') continue;
      for (const fn of c.functions) {
        if (fn.name === 'constructor' || !(fn.visibility === 'public' || fn.visibility === 'external') || fn.mutability === 'view' || fn.mutability === 'pure') continue;
        const rec = { contract: c.name, fn: fn.name, file: f.path, line: fn.line, modifiers: fn.modifiers, payable: fn.mutability === 'payable' };
        const priv = fn.modifiers.some(m => /^only|auth|restricted|requiresAuth/i.test(m)) || /(require|if)\s*\([^;]*msg\.sender\s*(==|!=)|_checkOwner|_checkRole/.test(fn.body);
        (priv ? privileged : entry).push(rec);
      }
    }
  }
  return { contracts, entry, privileged, deps: [...deps].sort() };
}

function scan(root, opts = {}) {
  root = path.resolve(root);
  const stat = fs.statSync(root);
  const all = stat.isFile() ? [root] : walk(root, opts);
  const base = stat.isFile() ? path.dirname(root) : root;
  const rel = p => path.relative(base, p) || path.basename(p);
  const srcFiles = all.filter(p => opts.includeTests || !isTestFile(rel(p)));
  const testFiles = all.filter(p => isTestFile(rel(p)) && /(^|\/)tests?\/|\.t\.sol$/.test(rel(p)));
  // JS/TS hardhat tests
  const jsTests = stat.isFile() ? [] : findJsTests(base);
  const parsedFiles = srcFiles.map(p => analyzeSource(fs.readFileSync(p, 'utf8'), rel(p)));
  let findings = parsedFiles.flatMap(pf => pf.findings);
  if (opts.only) findings = findings.filter(fd => opts.only.some(o => fd.rule.startsWith(o)));
  if (opts.minPriority) { const max = PRIORITY_ORDER[opts.minPriority]; const pr = Object.fromEntries(rules.map(r => [r.id, r.priority])); findings = findings.filter(fd => PRIORITY_ORDER[pr[fd.rule]] <= max); }
  return {
    tool: 'solpreflight', version: require('../package.json').version, root: base,
    filesScanned: srcFiles.map(rel), findings,
    readiness: stat.isFile() ? null : readiness(base, srcFiles, testFiles.concat(jsTests), parsedFiles),
    handoff: handoff(parsedFiles),
  };
}

function findJsTests(base) {
  const out = [];
  for (const d of ['test', 'tests']) {
    const p = path.join(base, d);
    try { for (const n of fs.readdirSync(p)) if (/\.(js|ts)$/.test(n)) out.push(path.join(d, n)); } catch {}
  }
  return out;
}

module.exports = { scan, analyzeSource, PRIORITY_ORDER };
