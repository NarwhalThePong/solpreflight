'use strict';
// For every rule: a minimal vulnerable snippet (must fire) and a safe snippet (must not fire).
const H = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.24;\n';
const W = body => H + 'contract T {\n' + body + '\n}\n';

module.exports = {
  'AC-01': {
    bad: W('uint256 public fee;\nfunction setFee(uint256 f) external { fee = f; }'),
    good: W('uint256 public fee; address owner;\nfunction setFee(uint256 f) external { require(msg.sender == owner); fee = f; }\nfunction deposit() external payable { fee += msg.value; }'),
  },
  'AC-02': {
    bad: W('address owner;\nfunction kill() external { require(tx.origin == owner); }'),
    good: W('address owner;\nfunction kill() external { require(msg.sender == owner); }'),
  },
  'AC-03': {
    bad: H + 'contract T is Ownable {\nfunction withdraw(uint256 a) external { payable(msg.sender).transfer(a); }\n}',
    good: H + 'contract T is Ownable {\nfunction withdraw(uint256 a) external onlyOwner { payable(msg.sender).transfer(a); }\n}',
  },
  'UP-01': {
    bad: H + 'contract T is Initializable, UUPSUpgradeable {\nfunction initialize() external initializer {}\n}',
    good: H + 'contract T is Initializable, UUPSUpgradeable {\nconstructor() { _disableInitializers(); }\nfunction initialize() external initializer {}\n}',
  },
  'UP-02': {
    bad: W('address owner;\nfunction initialize(address o) external { owner = o; }'),
    good: W('address owner;\nfunction initialize(address o) external initializer { owner = o; }'),
  },
  'UP-03': {
    bad: H + 'contract T is Initializable {\nuint256 x;\n}',
    good: H + 'contract T is Initializable {\nuint256 x;\nuint256[49] private __gap;\n}',
  },
  'UP-04': {
    bad: W('function exec(address t, bytes calldata d) external { (bool ok,) = t.delegatecall(d); require(ok); }'),
    good: W('function exec(address t, bytes calldata d) external { (bool ok,) = t.call(d); require(ok); }'),
  },
  'UP-05': {
    bad: W('function bye() external { selfdestruct(payable(msg.sender)); }'),
    good: W('function bye() external { }'),
  },
  'UP-06': {
    bad: W('function _authorizeUpgrade(address) internal override {}'),
    good: W('function _authorizeUpgrade(address) internal override onlyOwner {}'),
  },
  'EX-01': {
    bad: W('function pay(address to) external { to.call{value: 1}(""); }'),
    good: W('function pay(address to) external { (bool ok, ) = to.call{value: 1}(""); require(ok); }'),
  },
  'EX-02': {
    bad: W('mapping(address=>uint256) balances;\nfunction withdraw() external {\n uint256 a = balances[msg.sender];\n (bool ok,) = msg.sender.call{value: a}("");\n require(ok);\n balances[msg.sender] = 0;\n}'),
    good: W('mapping(address=>uint256) balances;\nfunction withdraw() external {\n uint256 a = balances[msg.sender];\n balances[msg.sender] = 0;\n (bool ok,) = msg.sender.call{value: a}("");\n require(ok);\n}'),
  },
  'EX-03': {
    bad: W('IERC20 token;\nfunction pay(address to, uint256 a) external { token.transfer(to, a); }'),
    good: W('IERC20 token;\nfunction pay(address to, uint256 a) external { token.safeTransfer(to, a); }'),
  },
  'EX-04': {
    bad: W('IERC20 token;\nfunction a(address s, uint256 x) external { token.approve(s, x); }'),
    good: W('IERC20 token;\nfunction a(address s, uint256 x) external { token.forceApprove(s, x); }'),
  },
  'OR-01': {
    bad: W('IFeed feed;\nfunction p() external view returns (int256) { return feed.latestAnswer(); }'),
    good: W('IFeed feed;\nfunction p() external view returns (int256) { return 1; }'),
  },
  'OR-02': {
    bad: W('IFeed feed;\nfunction p() public view returns (int256) { (, int256 answer,,,) = feed.latestRoundData(); return answer; }'),
    good: W('IFeed feed;\nfunction p() public view returns (int256) { (, int256 answer,, uint256 updatedAt,) = feed.latestRoundData(); require(answer > 0); require(block.timestamp - updatedAt < 3600); return answer; }'),
  },
  'OR-03': {
    bad: W('IPair pair;\nfunction price() public view returns (uint256) { (uint112 r0, uint112 r1,) = pair.getReserves(); return r1 * 1e18 / r0; }'),
    good: W('IOracle o;\nfunction price() public view returns (uint256) { return o.consult(30 minutes); }'),
  },
  'TK-01': {
    bad: W('IERC20 token; mapping(address=>uint256) bal;\nfunction deposit(uint256 amount) external { token.safeTransferFrom(msg.sender, address(this), amount); bal[msg.sender] += amount; }'),
    good: W('IERC20 token; mapping(address=>uint256) bal;\nfunction deposit(uint256 amount) external { uint256 b = token.balanceOf(address(this)); token.safeTransferFrom(msg.sender, address(this), amount); bal[msg.sender] += token.balanceOf(address(this)) - b; }'),
  },
  'TK-02': {
    bad: W('IERC20 token;\nfunction total() public view returns (uint256) { return token.balanceOf(address(this)); }'),
    good: W('uint256 totalAssets_;\nfunction total() public view returns (uint256) { return totalAssets_; }'),
  },
  'TK-03': {
    bad: W('function norm(uint256 a) public pure returns (uint256) { return a * 1e18; }'),
    good: W('uint256 constant WAD = 1e18;\nfunction norm(uint256 a, uint8 d) public pure returns (uint256) { return a * 10 ** (18 - d); }'),
  },
  'MA-01': {
    bad: W('function f(uint256 a, uint256 b, uint256 c) public pure returns (uint256) { return a / b * c; }'),
    good: W('function f(uint256 a, uint256 b, uint256 c) public pure returns (uint256) { return a * c / b; }'),
  },
  'MA-02': {
    bad: W('function f(uint256 i) public pure returns (uint256) { unchecked { return i + 1; } }'),
    good: W('function f(uint256 i) public pure returns (uint256) { return i + 1; }'),
  },
  'MA-03': {
    bad: W('function f(uint256 a) public pure returns (uint128) { return uint128(a); }'),
    good: W('function f(uint256 a) public pure returns (uint128) { return SafeCast.toUint128(a); }'),
  },
  'MA-04': {
    bad: W('uint256 totalSupply; uint256 totalAssets;\nfunction toShares(uint256 assets) public view returns (uint256) { return assets * totalSupply / totalAssets; }'),
    good: W('function add(uint256 a, uint256 b) public pure returns (uint256) { return a + b; }'),
  },
  'SG-01': {
    bad: W('address signer;\nfunction v(bytes32 h, uint8 v_, bytes32 r, bytes32 s, uint256 nonce, uint256 deadline) public view returns (bool) { bytes32 d = keccak256(abi.encode(block.chainid, h)); return ecrecover(d, v_, r, s) == signer; }'),
    good: W('address signer;\nfunction v(bytes32 h, uint8 v_, bytes32 r, bytes32 s) public view returns (bool) { address a = ecrecover(h, v_, r, s); require(a != address(0)); return a == signer; }'),
  },
  'SG-02': {
    bad: W('address signer;\nfunction claim(bytes32 h, bytes calldata sig) external { require(ECDSA.recover(h, sig) == signer); }'),
    good: W('address signer; mapping(address=>uint256) nonces;\nfunction claim(uint256 amount, uint256 deadline, bytes calldata sig) external { require(block.timestamp <= deadline); bytes32 d = _hashTypedDataV4(keccak256(abi.encode(msg.sender, amount, nonces[msg.sender]++, deadline))); require(ECDSA.recover(d, sig) == signer); }'),
  },
  'SG-03': {
    bad: W('function v(bytes32 h, uint8 v_, bytes32 r, bytes32 s) public pure returns (address a) { a = ecrecover(h, v_, r, s); require(a != address(0)); }'),
    good: W('function v(bytes32 h, bytes calldata sig) public pure returns (address) { return ECDSA.recover(h, sig); }'),
  },
  'AD-01': {
    bad: W('uint256 x;\nfunction setX(uint256 v) external onlyOwner { x = v; emit X(v); }'),
    good: W('uint256 x;\nfunction bump() external { x++; }'),
  },
  'AD-02': {
    bad: W('bool paused;\nfunction pause() external onlyOwner { paused = true; }'),
    good: W('bool paused;\nfunction bump() external { }'),
  },
  'AD-03': {
    bad: W('uint256 x;\nfunction setX(uint256 v) external onlyOwner { x = v; emit X(v); }'),
    good: W('uint256 x; TimelockController timelock;\nfunction setX(uint256 v) external onlyOwner { x = v; emit X(v); }'),
  },
  'RT-01': {
    bad: W('function roll() public view returns (uint256) { return uint256(keccak256(abi.encode(block.prevrandao, msg.sender))) % 6; }'),
    good: W('function roll(uint256 vrfWord) public pure returns (uint256) { return vrfWord % 6; }'),
  },
  'RT-02': {
    bad: W('uint256 end;\nfunction open() public view returns (bool) { return block.timestamp < end; }'),
    good: W('uint256 end;\nfunction open(uint256 nowTs) public view returns (bool) { return nowTs < end; }'),
  },
  'DS-01': {
    bad: W('address[] users;\nfunction join() external { users.push(msg.sender); }\nfunction count() external view returns (uint256 n) { for (uint256 i = 0; i < users.length; i++) n++; }'),
    good: W('address[] users;\nfunction count(uint256 start, uint256 end) external view returns (uint256 n) { for (uint256 i = start; i < end; i++) n++; }'),
  },
  'DS-02': {
    bad: W('address[] users;\nfunction payAll(address[] calldata to) external { for (uint256 i; i < to.length; i++) { payable(to[i]).transfer(1); } }'),
    good: W('mapping(address=>uint256) owed;\nfunction claim() external { uint256 a = owed[msg.sender]; owed[msg.sender] = 0; payable(msg.sender).transfer(a); }'),
  },
  'EV-01': {
    bad: W('uint256 fee;\nfunction setFee(uint256 f) external onlyOwner { fee = f; }'),
    good: W('uint256 fee; event FeeSet(uint256);\nfunction setFee(uint256 f) external onlyOwner { fee = f; emit FeeSet(f); }'),
  },
  'EV-02': {
    bad: '// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\ncontract T {}\n',
    good: '// SPDX-License-Identifier: MIT\npragma solidity 0.8.24;\ncontract T {}\n',
  },
  'EV-03': {
    bad: 'pragma solidity 0.8.24;\ncontract T {}\n',
    good: '// SPDX-License-Identifier: MIT\npragma solidity 0.8.24;\ncontract T {}\n',
  },
  'EX-05': {
    bad: W('function exec(address target, bytes calldata data) external { (bool ok,) = target.call(data); require(ok); }'),
    good: W('address immutable router;\nconstructor(address r) { router = r; }\nfunction exec(bytes calldata data) external { (bool ok,) = router.call(data); require(ok); }'),
  },
  'EX-06': {
    bad: W('IRouter router;\nfunction harvest(address[] calldata path, uint256 a) external { router.swapExactTokensForTokens(a, 0, path, address(this), block.timestamp); }'),
    good: W('IRouter router;\nfunction harvest(address[] calldata path, uint256 a, uint256 minOut, uint256 deadline) external { router.swapExactTokensForTokens(a, minOut, path, address(this), deadline); }'),
  },
  'EX-07': {
    bad: W('IRouter router;\nfunction swap(address[] calldata path, uint256 a, uint256 m) external { router.swapExactTokensForTokens(a, m, path, msg.sender, block.timestamp); }'),
    good: W('IRouter router;\nfunction swap(address[] calldata path, uint256 a, uint256 m, uint256 deadline) external { router.swapExactTokensForTokens(a, m, path, msg.sender, deadline); }'),
  },
  'SG-04': {
    bad: W('function id(string calldata a, string calldata b) public pure returns (bytes32) { return keccak256(abi.encodePacked(a, b)); }'),
    good: W('function id(string calldata a, string calldata b) public pure returns (bytes32) { return keccak256(abi.encode(a, b)); }'),
  },
  'DS-03': {
    bad: W('mapping(address=>uint256) bal;\nfunction buyMany(address[] calldata to) external payable { for (uint256 i; i < to.length; i++) { bal[to[i]] += msg.value; } }'),
    good: W('mapping(address=>uint256) bal;\nfunction buyMany(address[] calldata to) external payable { uint256 each = msg.value / to.length; for (uint256 i; i < to.length; i++) { bal[to[i]] += each; } }'),
  },
  'MA-05': {
    bad: W('IERC20 asset; uint256 totalSupply;\nfunction deposit(uint256 assets) external returns (uint256 shares) { uint256 ta = asset.balanceOf(address(this)); shares = totalSupply == 0 ? assets : assets * totalSupply / ta; totalSupply += shares; }'),
    good: W('IERC20 asset; uint256 totalSupply; uint256 totalAssets_;\nfunction deposit(uint256 assets) external returns (uint256 shares) { shares = assets * (totalSupply + 1e3) / (totalAssets_ + 1); totalSupply += shares; totalAssets_ += assets; }'),
  },
};
