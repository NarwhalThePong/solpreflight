// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// Intentionally vulnerable fixture. Do not deploy.
contract Airdrop {
    address public signer;
    mapping(address => uint256) public claimed;

    constructor(address s) { signer = s; }

    // Replayable: no nonce, no deadline, no chainId; ecrecover result not checked against zero
    function claim(uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 h = keccak256(abi.encodePacked(msg.sender, amount));
        require(ecrecover(h, v, r, s) == signer, "bad sig");
        claimed[msg.sender] += amount;
        payable(msg.sender).transfer(amount);
    }

    // Weak randomness
    function lottery() external view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(block.prevrandao, block.timestamp, msg.sender))) % 100;
    }
}
