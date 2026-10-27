'use strict';
const { lineOf } = require('./parse');

// Each rule: id, category, title, priority (info|low|medium|high review priority),
// why, verify, check(file) -> [{line, note}]
// file = { path, src, clean, contracts, lines, cleanLines }

function grepLines(file, re, filter) {
  const hits = [];
  file.cleanLines.forEach((l, i) => { if (re.test(l) && (!filter || filter(l, i))) hits.push({ line: i + 1 }); });
  return hits;
}
function fnLine(file, fn, idxInBody) { return lineOf(file.clean, fn.bodyOffset + idxInBody); }
function eachFn(file, pred) {
  const out = [];
  for (const c of file.contracts) {
    if (c.kind === 'interface') continue;
    for (const fn of c.functions) if (fn.hasBody) { const r = pred(fn, c); if (r) out.push(...[].concat(r)); }
  }
  return out;
}
const isEntry = fn => fn.visibility === 'public' || fn.visibility === 'external';
const isMut = fn => fn.mutability === 'nonpayable' || fn.mutability === 'payable';
const ACCESS_MOD = /^(only\w*|auth|requiresAuth|restricted|whenNotPaused|initializer|reinitializer|onlyInitializing|onlyRole|onlyOwner|onlyProxy|ownerOnly|adminOnly|governance\w*|isAuthorized|authorized)$/i;
const hasAccessMod = fn => fn.modifiers.some(m => ACCESS_MOD.test(m) && !/^whenNotPaused$/i.test(m));
const inlineAuth = body => /(require|if)\s*\([^;]*(msg\.sender\s*(==|!=)|(==|!=)\s*msg\.sender\b|\w+\[[^\]]+\]\[\s*msg\.sender\s*\])|_checkOwner\s*\(|_checkRole\s*\(|hasRole\s*\([^)]*msg\.sender|_authorize\w*\(|_onlyOwner\s*\(|revert\s+\w*Unauthori[sz]ed/.test(body);
const PRIV_NAME = /^(set|update|change|withdraw|sweep|rescue|upgrade|mint|burn|pause|unpause|emergency|kill|transferOwnership|grant|revoke|configure|add|remove)/i;
// Writes that only touch storage keyed by the caller (balances[msg.sender] = ...) are self-scoped.
const SENDER_KEYED = /\[\s*msg\.sender\s*\]/;
// ERC-4626 / ERC-20 user entry points implemented as overrides are open by design.
const STD_USER_FN = /^(deposit|mint|withdraw|redeem|transfer|transferFrom|approve)$/;
const isStdUserFn = (fn, c) => STD_USER_FN.test(fn.name) && (/\boverride\b/.test(fn.header || '') || /ERC4626|ERC20/.test(c.inherits.join(' '))) && fn.params.split(',').filter(x => x.trim()).length >= 2;
// Parse "type [location] name" params into [{type, name}]
const paramList = fn => fn.params.split(',').map(x => x.trim().split(/\s+/)).filter(x => x[0]).map(x => ({ type: x[0], name: x[x.length - 1] }));
function loopBodies(fn) {
  const out = []; const re = /\b(for|while)\s*\([^)]*\)\s*\{/g; let m;
  while ((m = re.exec(fn.body))) {
    const open = m.index + m[0].length - 1;
    let d = 0, end = open; for (let k = open; k < fn.body.length; k++) { if (fn.body[k] === '{') d++; else if (fn.body[k] === '}') { d--; if (!d) { end = k; break; } } }
    out.push({ idx: m.index, text: fn.body.slice(open, end) });
  }
  return out;
}
const STATE_WRITE = /(^|[^=!<>])=(?!=)|\+\+|--|\+=|-=|\.push\(|\.pop\(|delete\s|\bcall\s*[{(]|\.transfer\(|\.send\(|selfdestruct|_mint\(|_burn\(/;

const rules = [
  // ---------- Access control ----------
  {
    id: 'AC-01', category: 'Access control', title: 'State-changing public/external function with no access modifier', priority: 'medium',
    why: 'Functions anyone can call that change state are the main attack surface. Many are intentionally open (deposit, swap), but each one should be a conscious decision.',
    verify: 'For each hit, confirm the function is meant to be callable by anyone, or add a modifier / msg.sender check. List intentional open functions in your scope notes.',
    check: f => eachFn(f, (fn, c) => isEntry(fn) && isMut(fn) && !['constructor', 'receive', 'fallback'].includes(fn.name) && !hasAccessMod(fn) && !inlineAuth(fn.body) && STATE_WRITE.test(fn.body) && PRIV_NAME.test(fn.name) && !SENDER_KEYED.test(fn.body) && !isStdUserFn(fn, c)
      ? { line: fn.line, note: `${fn.contract}.${fn.name}() has a privileged-sounding name and no access check` } : null),
  },
  {
    id: 'AC-02', category: 'Access control', title: 'tx.origin used', priority: 'high',
    why: 'tx.origin-based authorization can be bypassed by a malicious contract the owner interacts with (phishing).',
    verify: 'Replace tx.origin authorization with msg.sender. tx.origin == msg.sender as an EOA check is a separate, weaker pattern; document it if intended.',
    check: f => grepLines(f, /\btx\.origin\b/),
  },
  {
    id: 'AC-03', category: 'Access control', title: 'Owner-style contract with unprotected withdraw/upgrade/set function', priority: 'high',
    why: 'Contracts that import Ownable/AccessControl but leave a withdraw, upgrade or setter unguarded are a common, high-impact mistake.',
    verify: 'Confirm each listed function has onlyOwner/onlyRole or an equivalent check. Functions that only touch the caller\'s own balance (balances[msg.sender]) are skipped.',
    check: f => eachFn(f, (fn, c) => {
      const owned = /Ownable|AccessControl|Auth|Owned/.test(c.inherits.join(' ')) || /\bowner\b|onlyOwner|onlyRole/.test(c.body);
      return owned && isEntry(fn) && isMut(fn) && /^(set|withdraw|upgrade|sweep|rescue|emergency|mint)/i.test(fn.name) && !hasAccessMod(fn) && !inlineAuth(fn.body) && !SENDER_KEYED.test(fn.body) && !isStdUserFn(fn, c)
        ? { line: fn.line, note: `${fn.contract}.${fn.name}() in an owner-managed contract has no access check` } : null;
    }),
  },
  // ---------- Upgradeability ----------
  {
    id: 'UP-01', category: 'Upgradeability', title: 'Upgradeable implementation without _disableInitializers() in constructor', priority: 'high',
    why: 'An uninitialized implementation can be initialized by anyone; for UUPS this has led to implementations being taken over.',
    verify: 'Add constructor() { _disableInitializers(); } to every upgradeable implementation.',
    check: f => f.contracts.filter(c => c.kind !== 'interface' && (/Initializable|UUPSUpgradeable|Upgradeable/.test(c.inherits.join(' ')) || /\binitializer\b/.test(c.body)) && !/_disableInitializers\s*\(/.test(c.body))
      .map(c => ({ line: c.line, note: `${c.name} looks upgradeable but never calls _disableInitializers()` })),
  },
  {
    id: 'UP-02', category: 'Upgradeability', title: 'initialize() without initializer modifier', priority: 'high',
    why: 'An initialize function without the initializer guard can be called again to reset owner or parameters.',
    verify: 'Use the initializer / reinitializer(n) modifier, or an explicit one-time flag.',
    check: f => eachFn(f, fn => /^init(ialize)?\w*$/i.test(fn.name) && isEntry(fn) && !fn.modifiers.some(m => /initializer|reinitializer/i.test(m)) && !/\binitialized\b|_initialized/.test(fn.body)
      ? { line: fn.line, note: `${fn.contract}.${fn.name}() has no initializer guard` } : null),
  },
  {
    id: 'UP-03', category: 'Upgradeability', title: 'Upgradeable contract without storage gap', priority: 'low',
    why: 'Base contracts in an upgradeable hierarchy without __gap (or ERC-7201 namespaced storage) make adding variables later risky.',
    verify: 'Add uint256[50] private __gap; or use namespaced storage (@custom:storage-location).',
    check: f => f.contracts.filter(c => c.kind !== 'interface' && /Upgradeable|Initializable/.test(c.inherits.join(' ')) && !/__gap/.test(c.body) && !/custom:storage-location/.test(f.src))
      .map(c => ({ line: c.line, note: `${c.name}: no __gap or namespaced storage found` })),
  },
  {
    id: 'UP-04', category: 'Upgradeability', title: 'delegatecall', priority: 'high',
    why: 'delegatecall runs foreign code in this contract\'s storage context. A user-controlled target is critical.',
    verify: 'Confirm the target is fixed or trusted and cannot be supplied by callers; check storage layout compatibility.',
    check: f => grepLines(f, /\.delegatecall\s*\(/),
  },
  {
    id: 'UP-05', category: 'Upgradeability', title: 'selfdestruct', priority: 'medium',
    why: 'selfdestruct is deprecated (EIP-6780) and its behavior changed; it can still move ETH and is a red flag in implementations.',
    verify: 'Remove it, or document why it is needed and who can call it.',
    check: f => grepLines(f, /\bselfdestruct\s*\(|\bsuicide\s*\(/),
  },
  {
    id: 'UP-06', category: 'Upgradeability', title: '_authorizeUpgrade with empty body and no modifier', priority: 'high',
    why: 'In UUPS, _authorizeUpgrade is the only thing preventing anyone from upgrading the proxy.',
    verify: 'Make sure _authorizeUpgrade has onlyOwner/onlyRole or an explicit check.',
    check: f => eachFn(f, fn => fn.name === '_authorizeUpgrade' && !hasAccessMod(fn) && !inlineAuth(fn.body) && fn.body.trim() === ''
      ? { line: fn.line, note: `${fn.contract}._authorizeUpgrade is unguarded` } : null),
  },
  // ---------- External calls ----------
  {
    id: 'EX-01', category: 'External calls', title: 'Low-level call without success check', priority: 'high',
    why: 'call/send return false on failure instead of reverting. Ignoring it can silently lose funds or desync state.',
    verify: 'Capture (bool ok, ) and require(ok), or use Address.sendValue / functionCall.',
    check: f => {
      const hits = [];
      f.cleanLines.forEach((l, i) => {
        if (/\.(call|send|staticcall)\s*[({]/.test(l) && !/\.delegatecall/.test(l)) {
          const captured = /\(\s*bool\s+\w+|\b\w+\s*,?\s*\)?\s*=\s*[^=]*\.(call|send|staticcall)|require\s*\([^;]*\.(send|call)|if\s*\(\s*!?[^;]*\.(send|call)|return\s+[^;]*\.(call|send)/.test(l) || /^\s*\(\s*bool/.test(l) || /=\s*$/.test(f.cleanLines[i - 1] || '');
          if (!captured) hits.push({ line: i + 1 });
        }
      });
      return hits;
    },
  },
  {
    id: 'EX-02', category: 'External calls', title: 'External value call before state update (possible reentrancy)', priority: 'high',
    why: 'Sending ETH or calling out before updating balances lets the callee re-enter while state is stale (classic DAO pattern).',
    verify: 'Follow checks-effects-interactions: update state before the call, or add nonReentrant. Check cross-function reentrancy too.',
    check: f => eachFn(f, fn => {
      if (fn.modifiers.some(m => /nonReentrant|lock|noReentr/i.test(m))) return null;
      const b = fn.body;
      const call = b.search(/\b_safeMint\s*\(|\.call\s*\{\s*value|\.call\s*\.value\s*\(|\.transfer\s*\(\s*\w+\s*\)\s*;|\.safeTransfer(From)?\s*\(/);
      if (call < 0) return null;
      const after = b.slice(call);
      const stmtEnd = after.indexOf(';');
      const rest = after.slice(stmtEnd + 1);
      return /\b\w+(\[[^\]]+\])+(\.\w+)*\s*(-=|\+=|=(?!=))|\b(balance|balances|shares|debt|total\w*|amount\w*)\s*(-=|\+=|=(?!=))|\bdelete\s/.test(rest)
        ? { line: fnLine(f, fn, call), note: `${fn.contract}.${fn.name}(): state written after external call, no nonReentrant` } : null;
    }),
  },
  {
    id: 'EX-03', category: 'External calls', title: 'Unchecked ERC20 transfer/transferFrom return value', priority: 'medium',
    why: 'Some tokens (e.g. USDT) return no value or false instead of reverting. Plain transfer() may silently fail or revert unexpectedly.',
    verify: 'Use SafeERC20 safeTransfer/safeTransferFrom, or check the boolean return.',
    check: f => grepLines(f, /\.(transfer|transferFrom)\s*\(\s*[^)]*,/, (l, i) => !/require\s*\(|=\s*\w*\.(transfer|transferFrom)|if\s*\(|safeTransfer|return\s/.test(l) && !/payable\s*\(/.test(l)
      && !/(require|assert|if)\s*\(\s*$|=\s*$/.test(f.cleanLines[i - 1] || '')),
  },
  {
    id: 'EX-04', category: 'External calls', title: 'approve() to non-zero amount (approval race / USDT-style tokens)', priority: 'low',
    why: 'Changing a non-zero allowance to another non-zero value can be front-run; some tokens revert unless allowance is first set to 0.',
    verify: 'Use forceApprove / safeIncreaseAllowance, or set to 0 first.',
    check: f => grepLines(f, /\.approve\s*\(\s*[^,]+,\s*(?!0\s*\))[^)]+\)/, l => !/function\s+approve/.test(l)),
  },
  {
    id: 'EX-05', category: 'External calls', title: 'Arbitrary external call with caller-supplied target and calldata', priority: 'high',
    why: 'If callers choose both the target and the calldata, they can make the contract call any token\'s transferFrom and spend approvals users granted to it.',
    verify: 'Restrict targets to an allowlist, or decode and validate the calldata; never hold user approvals in a contract that forwards arbitrary calls.',
    check: f => eachFn(f, fn => {
      if (!isEntry(fn) || hasAccessMod(fn)) return null;
      const ps = paramList(fn);
      const addrs = ps.filter(p => /^address/.test(p.type)).map(p => p.name), datas = ps.filter(p => /^bytes$/.test(p.type)).map(p => p.name);
      const re = /\b(\w+)\.call\s*(\{[^}]*\})?\s*\(\s*(\w+)\s*\)/g; let m; const out = [];
      while ((m = re.exec(fn.body))) if (addrs.includes(m[1]) && datas.includes(m[3])) out.push({ line: fnLine(f, fn, m.index), note: `${fn.contract}.${fn.name}(): ${m[1]}.call(${m[3]}) with both from the caller` });
      return out;
    }),
  },
  {
    id: 'EX-06', category: 'External calls', title: 'Swap with minimum output hardcoded to 0', priority: 'high',
    why: 'A swap that accepts any output amount can be sandwiched for most of its value.',
    verify: 'Pass a caller-supplied or oracle-derived minimum output.',
    check: f => grepLines(f, /\.(swap\w*|exactInput\w*)\s*\(\s*[^,;()]+,\s*0\s*,|amountOutMin(imum)?\s*:\s*0\b/),
  },
  {
    id: 'EX-07', category: 'External calls', title: 'block.timestamp passed as a swap/liquidity deadline', priority: 'medium',
    why: 'A deadline of block.timestamp is always satisfied, so a pending transaction can be held and executed later at a worse price.',
    verify: 'Take the deadline as a caller-supplied parameter.',
    check: f => grepLines(f, /\.(swap\w*|addLiquidity\w*|removeLiquidity\w*|exactInput\w*|exactOutput\w*)\s*\([^;]*block\.timestamp|deadline\s*:\s*block\.timestamp/),
  },
  // ---------- Oracles ----------
  {
    id: 'OR-01', category: 'Oracles', title: 'Deprecated latestAnswer()', priority: 'medium',
    why: 'latestAnswer gives no round or timestamp data, so staleness cannot be checked.',
    verify: 'Use latestRoundData and validate updatedAt and answer > 0.',
    check: f => grepLines(f, /\.latestAnswer\s*\(/),
  },
  {
    id: 'OR-02', category: 'Oracles', title: 'latestRoundData without staleness or price > 0 check', priority: 'high',
    why: 'Stale or zero/negative prices from a feed can be used to borrow or liquidate at the wrong price.',
    verify: 'Check updatedAt against a heartbeat, answer > 0, and (on L2) the sequencer uptime feed.',
    check: f => eachFn(f, fn => {
      const i = fn.body.search(/\.latestRoundData\s*\(/);
      if (i < 0) return null;
      // Include bodies of internal/private helpers in the same file that this function calls (one level).
      const helpers = [];
      for (const c of f.contracts) for (const h of c.functions) if (h !== fn && h.hasBody && /internal|private/.test(h.visibility) && new RegExp(`\\b${h.name}\\s*\\(`).test(fn.body)) helpers.push(h.body);
      const scope = [fn.body, ...helpers].join('\n');
      const stale = /updatedAt|block\.timestamp\s*-|heartbeat|STALE|stale/i.test(scope);
      const pos = /(answer|price)\w*\s*>\s*0|(answer|price)\w*\s*<=\s*0|>\s*int256\(0\)/i.test(scope) || (helpers.length > 0 && /\b\w+\s*(>\s*0|<=\s*0)\b/.test(helpers.join('\n')));
      return stale && pos ? null : { line: fnLine(f, fn, i), note: `${fn.contract}.${fn.name}(): missing ${[!stale && 'staleness', !pos && 'price > 0'].filter(Boolean).join(' and ')} check` };
    }),
  },
  {
    id: 'OR-03', category: 'Oracles', title: 'Spot price from pool reserves / slot0', priority: 'high',
    why: 'getReserves() and slot0() spot prices can be moved within one transaction (flash loans).',
    verify: 'Use a TWAP or an external oracle for anything value-bearing; document if spot use is intentional.',
    check: f => grepLines(f, /\.getReserves\s*\(|\.slot0\s*\(/),
  },
  // ---------- Token handling ----------
  {
    id: 'TK-01', category: 'Token handling', title: 'Credits the requested amount after transferFrom (fee-on-transfer assumption)', priority: 'medium',
    why: 'Fee-on-transfer and rebasing tokens deliver less than `amount`; crediting `amount` makes accounting insolvent.',
    verify: 'Measure balance before/after, or explicitly document that such tokens are unsupported.',
    check: f => eachFn(f, fn => {
      const i = fn.body.search(/\.(safeTransferFrom|transferFrom)\s*\([^;]*address\(this\)/);
      if (i < 0) return null;
      if (/balanceOf\s*\(\s*address\(this\)\s*\)/.test(fn.body)) return null;
      return /\+=\s*(amount|_amount|assets|value)\b/.test(fn.body) ? { line: fnLine(f, fn, i), note: `${fn.contract}.${fn.name}() credits the nominal amount` } : null;
    }),
  },
  {
    id: 'TK-02', category: 'Token handling', title: 'balanceOf(address(this)) used for accounting', priority: 'medium',
    why: 'Anyone can donate tokens to change balanceOf(this); share-price and first-depositor inflation attacks rely on this.',
    verify: 'Track internal balances, or prove donations cannot be used to manipulate pricing (virtual shares/offset).',
    check: f => grepLines(f, /balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)/),
  },
  {
    id: 'TK-03', category: 'Token handling', title: 'Hardcoded 18-decimal assumption', priority: 'low',
    why: 'Tokens like USDC (6) or WBTC (8) break math that assumes 1e18 units.',
    verify: 'Read decimals() or normalize explicitly; document which tokens are supported.',
    check: f => grepLines(f, /\b1e18\b|10\s*\*\*\s*18\b/, l => !/WAD|PRECISION|constant/.test(l)),
  },
  // ---------- Math ----------
  {
    id: 'MA-01', category: 'Math', title: 'Division before multiplication', priority: 'medium',
    why: 'Integer division truncates; multiplying afterwards amplifies the precision loss.',
    verify: 'Reorder to multiply first or use mulDiv; add a test with small values.',
    check: f => grepLines(f, /\/\s*[\w.()\[\]]+\s*\*/, l => !/^\s*(\*|\/\/)/.test(l) && !/\*\*/.test(l)),
  },
  {
    id: 'MA-02', category: 'Math', title: 'unchecked block', priority: 'info',
    why: 'Overflow checks are disabled inside unchecked. Usually a gas optimization, but each block needs a reason it cannot overflow.',
    verify: 'Add a comment proving the bound for each unchecked block, and fuzz it.',
    check: f => grepLines(f, /\bunchecked\s*\{/),
  },
  {
    id: 'MA-03', category: 'Math', title: 'Downcast to a smaller integer type', priority: 'medium',
    why: 'Explicit downcasts silently truncate in Solidity 0.8.',
    verify: 'Use SafeCast or bound-check before casting.',
    check: f => grepLines(f, /\b(uint(8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|160|192|224)|int(8|16|32|64|128))\s*\(\s*[^)]*[a-zA-Z_]/, l => !/SafeCast|type\(/.test(l)),
  },
  {
    id: 'MA-04', category: 'Math', title: 'Rounding direction review (division in share/asset math)', priority: 'info',
    why: 'Rounding should favor the protocol (round down on mint/withdraw-out, up on burn/withdraw-in). Wrong direction leaks value over many calls.',
    verify: 'For each conversion, write down which side benefits from rounding and test edge amounts (1 wei).',
    check: f => grepLines(f, /(shares|assets|supply)\w*\s*[\/*][^;]*\/|mulDiv\s*\(/i),
  },
  {
    id: 'MA-05', category: 'Math', title: 'Share math with no virtual offset (first-depositor inflation)', priority: 'medium',
    why: 'With no virtual shares/assets or minimum first deposit, the first depositor can donate assets to inflate the share price and round later deposits down to zero shares.',
    verify: 'Add a virtual offset (e.g. OpenZeppelin ERC4626 _decimalsOffset), mint dead shares, or enforce a minimum first deposit; test a 1-wei deposit followed by a donation.',
    check: f => /_decimalsOffset|VIRTUAL_|virtualShares|virtualAssets|DEAD_SHARES|MINIMUM_LIQUIDITY|MIN_DEPOSIT|MIN_SHARES/i.test(f.clean) ? []
      : grepLines(f, /\*\s*(totalSupply|_totalSupply|totalShares)\w*(\s*\(\s*\))?\s*\/|mulDiv\s*\([^,;]+,\s*(totalSupply|_totalSupply|totalShares)\w*(\s*\(\s*\))?\s*,/),
  },
  // ---------- Signatures ----------
  {
    id: 'SG-01', category: 'Signatures', title: 'ecrecover without zero-address check', priority: 'high',
    why: 'ecrecover returns address(0) for invalid signatures; if the expected signer can be 0, any signature passes.',
    verify: 'Use OpenZeppelin ECDSA.recover, or require(recovered != address(0)).',
    check: f => eachFn(f, fn => {
      const i = fn.body.search(/\becrecover\s*\(/);
      return i >= 0 && !/!=\s*address\s*\(\s*0\s*\)|==\s*address\s*\(\s*0\s*\)/.test(fn.body) ? { line: fnLine(f, fn, i), note: `${fn.contract}.${fn.name}()` } : null;
    }),
  },
  {
    id: 'SG-02', category: 'Signatures', title: 'Signature check without nonce / deadline / chainId', priority: 'high',
    why: 'Without a nonce the same signature can be replayed; without chainId or domain separator it can be replayed on other chains; without deadline it never expires.',
    verify: 'Use EIP-712 with a domain separator (chainId, verifyingContract), a per-signer nonce and a deadline.',
    check: f => eachFn(f, fn => {
      const i = fn.body.search(/\becrecover\s*\(|ECDSA\.recover\s*\(|\.recover\s*\(|SignatureChecker\./);
      if (i < 0) return null;
      const scope = fn.body + fn.params;
      const missing = [!/nonce/i.test(scope) && 'nonce', !/deadline|expiry|validUntil/i.test(scope) && 'deadline', !/chainid|DOMAIN_SEPARATOR|_hashTypedDataV4|domainSeparator/i.test(scope) && 'chainId/domain'].filter(Boolean);
      return missing.length ? { line: fnLine(f, fn, i), note: `${fn.contract}.${fn.name}(): no ${missing.join(', ')}` } : null;
    }),
  },
  {
    id: 'SG-03', category: 'Signatures', title: 'Raw ecrecover (malleability)', priority: 'medium',
    why: 'Raw ecrecover accepts both high-s and low-s signatures; using signatures as unique IDs breaks.',
    verify: 'Use ECDSA.recover (enforces low-s) and never key on the signature bytes.',
    check: f => eachFn(f, fn => {
      const i = fn.body.search(/\becrecover\s*\(/);
      return i >= 0 && !/0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0/i.test(fn.body) ? { line: fnLine(f, fn, i), note: 'no low-s check' } : null;
    }),
  },
  {
    id: 'SG-04', category: 'Signatures', title: 'keccak256(abi.encodePacked()) over two or more dynamic types', priority: 'medium',
    why: 'Packed encoding of adjacent dynamic values is ambiguous ("a"+"bc" == "ab"+"c"), so different inputs can hash to the same value (SWC-133).',
    verify: 'Use abi.encode, or ensure at most one dynamic argument.',
    check: f => {
      const dyn = new Set(); const re = /\b(string|bytes|[\w.]+\[\])\s+(memory\s+|calldata\s+|storage\s+)?(public\s+|private\s+|internal\s+|immutable\s+)*(\w+)/g; let m;
      while ((m = re.exec(f.clean))) dyn.add(m[4]);
      const hits = []; const kr = /keccak256\s*\(\s*abi\.encodePacked\s*\(([^;]*?)\)\s*\)/g;
      while ((m = kr.exec(f.clean))) {
        const args = m[1].split(',').map(a => a.trim());
        if (args.filter(a => dyn.has(a)).length >= 2) hits.push({ line: lineOf(f.clean, m.index), note: `dynamic args: ${args.filter(a => dyn.has(a)).join(', ')}` });
      }
      return hits;
    },
  },
  // ---------- Admin surface ----------
  {
    id: 'AD-01', category: 'Admin surface', title: 'Privileged function inventory', priority: 'info',
    why: 'Auditors and users need a clear list of what admins can do.',
    verify: 'Confirm each item in the handoff "privileged functions" list is expected and documented.',
    check: f => eachFn(f, fn => isEntry(fn) && (hasAccessMod(fn) || inlineAuth(fn.body)) && !fn.modifiers.some(m => /^(initializer|reinitializer)$/i.test(m)) ? { line: fn.line, note: `${fn.contract}.${fn.name}() [${fn.modifiers.join(' ') || 'inline check'}]` } : null),
  },
  {
    id: 'AD-02', category: 'Admin surface', title: 'Pause / emergency functions', priority: 'info',
    why: 'Pause and emergency paths are high-trust powers and often under-tested.',
    verify: 'Test what still works while paused (withdrawals? liquidations?), and who can unpause.',
    check: f => eachFn(f, fn => /^(pause|unpause|emergency\w*|shutdown|kill)$/i.test(fn.name) ? { line: fn.line, note: `${fn.contract}.${fn.name}()` } : null),
  },
  {
    id: 'AD-03', category: 'Admin surface', title: 'Privileged setters without a timelock', priority: 'low',
    why: 'Instant parameter changes give users no time to exit before a malicious or mistaken change.',
    verify: 'Route admin actions through a TimelockController, or document the trust assumption.',
    check: f => /Timelock|timelock|delay/.test(f.src) ? [] : eachFn(f, fn => isEntry(fn) && hasAccessMod(fn) && /^(set|update|change|upgrade)/i.test(fn.name) ? { line: fn.line, note: `${fn.contract}.${fn.name}()` } : null),
  },
  // ---------- Randomness / time ----------
  {
    id: 'RT-01', category: 'Randomness / time', title: 'blockhash / prevrandao / timestamp used as randomness', priority: 'high',
    why: 'These values are known or influenced by block producers.',
    verify: 'Use a VRF or commit-reveal scheme.',
    check: f => grepLines(f, /\bblockhash\s*\(|block\.prevrandao|block\.difficulty|keccak256\s*\([^;]*block\.timestamp/),
  },
  {
    id: 'RT-02', category: 'Randomness / time', title: 'block.timestamp dependence', priority: 'info',
    why: 'Timestamps can drift a few seconds; strict equality or very short windows are fragile.',
    verify: 'Avoid == comparisons with timestamps; confirm windows tolerate small drift.',
    check: f => grepLines(f, /\bblock\.timestamp\b|\bnow\b(?!\w)/, l => !/keccak256/.test(l)),
  },
  // ---------- DoS ----------
  {
    id: 'DS-01', category: 'Denial of service', title: 'Loop over a storage array of unbounded length', priority: 'medium',
    why: 'If the array grows with user actions, the loop can exceed the block gas limit and brick the function.',
    verify: 'Bound the array, paginate, or switch to a pull pattern.',
    check: f => {
      const arrays = new Set();
      for (const c of f.contracts) {
        const re = /^\s*[\w.]+(\[\])+\s+(public\s+|private\s+|internal\s+)?(\w+)\s*;/gm; let m;
        while ((m = re.exec(c.body))) arrays.add(m[3]);
      }
      if (!arrays.size) return [];
      return grepLines(f, /\b(for|while)\s*\(/, l => [...arrays].some(a => new RegExp(`\\b${a}\\.length\\b`).test(l)));
    },
  },
  {
    id: 'DS-02', category: 'Denial of service', title: 'External call inside a loop', priority: 'medium',
    why: 'One reverting recipient can block the whole batch (push-payment DoS).',
    verify: 'Use pull payments or try/catch, and make failures non-blocking where appropriate.',
    check: f => eachFn(f, fn => {
      const out = []; const re = /\b(for|while)\s*\([^)]*\)\s*\{/g; let m;
      while ((m = re.exec(fn.body))) {
        const open = m.index + m[0].length - 1;
        let d = 0, end = open; for (let k = open; k < fn.body.length; k++) { if (fn.body[k] === '{') d++; else if (fn.body[k] === '}') { d--; if (!d) { end = k; break; } } }
        if (/\.(call|transfer|send|safeTransfer)\s*[({]/.test(fn.body.slice(open, end))) out.push({ line: fnLine(f, fn, m.index), note: `${fn.contract}.${fn.name}()` });
      }
      return out;
    }),
  },
  {
    id: 'DS-03', category: 'Denial of service', title: 'msg.value read inside a loop', priority: 'high',
    why: 'msg.value is the same on every iteration, so the same ETH can be counted more than once.',
    verify: 'Read msg.value once, split or track the remaining amount, and check the total spent.',
    check: f => eachFn(f, fn => loopBodies(fn).filter(l => /\bmsg\.value\b/.test(l.text)).map(l => ({ line: fnLine(f, fn, l.idx), note: `${fn.contract}.${fn.name}()` }))),
  },
  // ---------- Events ----------
  {
    id: 'EV-01', category: 'Events / hygiene', title: 'Privileged setter emits no event', priority: 'low',
    why: 'Off-chain monitoring and users cannot see admin changes without events.',
    verify: 'Emit an event with old and new value on every privileged state change.',
    check: f => eachFn(f, fn => isEntry(fn) && (hasAccessMod(fn) || inlineAuth(fn.body)) && /^(set|update|change)/i.test(fn.name) && !/\bemit\s/.test(fn.body)
      ? { line: fn.line, note: `${fn.contract}.${fn.name}()` } : null),
  },
  {
    id: 'EV-02', category: 'Events / hygiene', title: 'Floating pragma', priority: 'info',
    why: 'Deployed bytecode should be compiled with a known compiler version.',
    verify: 'Pin the pragma (e.g. pragma solidity 0.8.24;) for deployable contracts.',
    check: f => grepLines(f, /pragma\s+solidity\s*[\^>~]/),
  },
  {
    id: 'EV-03', category: 'Events / hygiene', title: 'Missing SPDX license identifier', priority: 'info',
    why: 'The compiler warns, and auditors and users need to know the license.',
    verify: 'Add // SPDX-License-Identifier: <license> at the top.',
    check: f => /SPDX-License-Identifier/.test(f.src) ? [] : [{ line: 1 }],
  },
];

module.exports = { rules };
