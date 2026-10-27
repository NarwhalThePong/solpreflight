'use strict';
// Lightweight Solidity parser: strips comments/strings (preserving line numbers),
// finds contracts and functions with brace matching. Not a full grammar.

function stripComments(src) {
  let out = '';
  let i = 0;
  const n = src.length;
  while (i < n) {
    const c = src[i], d = src[i + 1];
    if (c === '/' && d === '/') {
      while (i < n && src[i] !== '\n') { out += ' '; i++; }
    } else if (c === '/' && d === '*') {
      out += '  '; i += 2;
      while (i < n && !(src[i] === '*' && src[i + 1] === '/')) { out += src[i] === '\n' ? '\n' : ' '; i++; }
      out += '  '; i += 2;
    } else if (c === '"' || c === "'") {
      const q = c; out += q; i++;
      while (i < n && src[i] !== q) {
        if (src[i] === '\\') { out += '  '; i += 2; continue; }
        out += src[i] === '\n' ? '\n' : ' '; i++;
      }
      out += q; i++;
    } else { out += c; i++; }
  }
  return out;
}

function lineOf(text, idx) {
  let l = 1;
  for (let i = 0; i < idx && i < text.length; i++) if (text[i] === '\n') l++;
  return l;
}

function matchBrace(text, open) {
  let depth = 0;
  for (let i = open; i < text.length; i++) {
    if (text[i] === '{') depth++;
    else if (text[i] === '}') { depth--; if (depth === 0) return i; }
  }
  return text.length - 1;
}

const KEYWORDS = new Set(['public', 'external', 'internal', 'private', 'view', 'pure', 'payable', 'virtual', 'override', 'returns', 'nonpayable']);

function parseFile(src) {
  const clean = stripComments(src);
  const contracts = [];
  const cRe = /\b(abstract\s+contract|contract|library|interface)\s+(\w+)([^{]*)\{/g;
  let m;
  while ((m = cRe.exec(clean))) {
    const open = m.index + m[0].length - 1;
    const close = matchBrace(clean, open);
    const kind = m[1].includes('contract') ? (m[1].startsWith('abstract') ? 'abstract' : 'contract') : m[1];
    const inherits = (m[3].match(/\bis\b([\s\S]*)/) || [, ''])[1].split(',').map(s => s.trim().split(/[\s(]/)[0]).filter(Boolean);
    const c = { name: m[2], kind, inherits, start: open, end: close, line: lineOf(clean, m.index), endLine: lineOf(clean, close), functions: [], body: clean.slice(open + 1, close) };
    const fRe = /\b(function\s+(\w+)|constructor|receive|fallback)\s*\(([^)]*)\)([^{;]*)([{;])/g;
    fRe.lastIndex = open;
    let f;
    while ((f = fRe.exec(clean)) && f.index < close) {
      const header = f[4];
      const name = f[2] || f[1];
      const visibility = (header.match(/\b(public|external|internal|private)\b/) || [, (name === 'receive' || name === 'fallback') ? 'external' : 'public'])[1];
      const mutability = (header.match(/\b(view|pure|payable)\b/) || [, 'nonpayable'])[1];
      const hdrNoReturns = header.replace(/\breturns\s*\([^)]*\)/, '');
      const modifiers = [];
      const modRe = /\b([A-Za-z_]\w*)\b(\s*\([^)]*\))?/g;
      let mm;
      while ((mm = modRe.exec(hdrNoReturns))) if (!KEYWORDS.has(mm[1])) modifiers.push(mm[1]);
      let body = '', bodyStart = f.index + f[0].length, endIdx = bodyStart;
      if (f[5] === '{') { endIdx = matchBrace(clean, bodyStart - 1); body = clean.slice(bodyStart, endIdx); fRe.lastIndex = endIdx; }
      c.functions.push({ name, params: f[3], visibility, mutability, modifiers, body, header, line: lineOf(clean, f.index), bodyOffset: bodyStart, hasBody: f[5] === '{', contract: c.name });
    }
    contracts.push(c);
    if (kind !== 'interface') cRe.lastIndex = open + 1; // allow nested? contracts are not nested; keep simple
    cRe.lastIndex = close;
  }
  return { clean, contracts, lines: src.split('\n'), cleanLines: clean.split('\n') };
}

module.exports = { stripComments, parseFile, lineOf, matchBrace };
