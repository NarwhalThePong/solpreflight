'use strict';
// Additional vulnerable/safe pairs for existing rules: each covers a pattern the
// first version got wrong (a false positive on the safe snippet or a miss on the
// vulnerable one). Same shape as cases.js, plus the rule id under test.
const H = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.24;\n';
const W = body => H + 'contract T {\n' + body + '\n}\n';

module.exports = {
  'AC-01#onBehalf-reversed': {
    rule: 'AC-01',
    bad: W('uint256 public fee;\nfunction setFee(uint256 f) external { fee = f; }'),
    good: W('mapping(address=>mapping(address=>bool)) isAuthorized; mapping(address=>uint256) pos;\nfunction withdrawCollateral(uint256 a, address onBehalf) external { require(onBehalf == msg.sender || isAuthorized[onBehalf][msg.sender]); pos[onBehalf] -= a; }'),
  },
  'AC-01#sender-keyed': {
    rule: 'AC-01',
    bad: W('mapping(address=>bool) public isAdmin;\nfunction setAdmin(address a, bool v) external { isAdmin[a] = v; }'),
    good: W('mapping(address=>mapping(address=>bool)) public isAuthorized;\nfunction setAuthorization(address a, bool v) external { isAuthorized[msg.sender][a] = v; }'),
  },
  'AC-01#erc4626': {
    rule: 'AC-01',
    bad: W('uint256 supply;\nfunction mint(address to, uint256 a) external { supply += a; }'),
    good: H + 'contract T is ERC4626 {\nfunction mint(uint256 shares, address receiver) public override returns (uint256 a) { a = _mintShares(receiver, shares); }\nfunction withdraw(uint256 assets, address receiver, address owner) public override returns (uint256 s) { s = _withdraw(receiver, owner, assets); }\n}\n',
  },
  'AC-03#erc4626': {
    rule: 'AC-03',
    bad: H + 'contract T is Ownable {\nuint256 rate;\nfunction setRate(uint256 r) external { rate = r; }\n}\n',
    good: H + 'contract T is Ownable, ERC4626 {\nfunction withdraw(uint256 assets, address receiver, address owner) external override returns (uint256 s) { s = _withdraw(receiver, owner, assets); }\n}\n',
  },
  'AC-03#sender-keyed': {
    rule: 'AC-03',
    bad: H + 'contract T is Ownable {\nmapping(address=>bool) isOperator;\nfunction setOperator(address a, bool v) external { isOperator[a] = v; }\n}\n',
    good: H + 'contract T is Ownable {\nmapping(address=>mapping(address=>bool)) isAuthorized;\nfunction setAuthorization(address a, bool v) external { isAuthorized[msg.sender][a] = v; }\n}\n',
  },
  'EX-02#struct-field': {
    rule: 'EX-02',
    bad: W('struct I { uint256 owed; }\nmapping(address=>I) info;\nfunction claim() external {\n (bool ok,) = msg.sender.call{value: info[msg.sender].owed}("");\n require(ok);\n info[msg.sender].owed = 0;\n}'),
    good: W('struct I { uint256 owed; }\nmapping(address=>I) info;\nfunction claim() external {\n uint256 a = info[msg.sender].owed;\n info[msg.sender].owed = 0;\n (bool ok,) = msg.sender.call{value: a}("");\n require(ok);\n}'),
  },
  'EX-02#safeMint': {
    rule: 'EX-02',
    bad: W('uint256 minted; mapping(address=>uint256) mintedBy;\nfunction mint() external {\n require(mintedBy[msg.sender] == 0);\n _safeMint(msg.sender, minted);\n mintedBy[msg.sender] = 1;\n minted++;\n}'),
    good: W('uint256 minted; mapping(address=>uint256) mintedBy;\nfunction mint() external {\n require(mintedBy[msg.sender] == 0);\n mintedBy[msg.sender] = 1;\n uint256 id = minted++;\n _safeMint(msg.sender, id);\n}'),
  },
  'EX-03#multiline-require': {
    rule: 'EX-03',
    bad: W('IERC20 token;\nfunction pay(address to, uint256 a) external {\n token.transfer(to, a);\n}'),
    good: W('IERC20 token;\nfunction pay(address to, uint256 a) external {\n require(\n  token.transfer(to, a),\n  "fail"\n );\n}'),
  },
  'OR-02#helper-check': {
    rule: 'OR-02',
    bad: W('IFeed feed;\nfunction p() public view returns (int256) { (, int256 answer,, uint256 updatedAt,) = feed.latestRoundData(); _log(answer, updatedAt); return answer; }\nfunction _log(int256 a, uint256 u) internal pure { }'),
    good: W('IFeed feed;\nfunction p() public view returns (int256) { (, int256 answer,, uint256 updatedAt,) = feed.latestRoundData(); _validate(answer, updatedAt); return answer; }\nfunction _validate(int256 a, uint256 u) internal view { require(a > 0); require(block.timestamp - u < 3600); }'),
  },
};
