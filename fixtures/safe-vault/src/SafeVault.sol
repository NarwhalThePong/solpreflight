// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

interface IAggregator {
    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80);
}

/// @title SafeVault fixture
contract SafeVault is Ownable, ReentrancyGuard {
    IAggregator public oracle;
    mapping(address => uint256) public balances;
    uint256 public fee;
    uint256 public constant HEARTBEAT = 3600;

    event FeeSet(uint256 oldFee, uint256 newFee);

    constructor(address o) Ownable(msg.sender) { oracle = IAggregator(o); }

    /// @notice Deposit ETH
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    /// @notice Withdraw full balance
    function withdraw() external nonReentrant {
        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
    }

    /// @notice Set fee
    function setFee(uint256 newFee) external onlyOwner {
        emit FeeSet(fee, newFee);
        fee = newFee;
    }

    /// @notice Oracle price with checks
    function price() public view returns (uint256) {
        (, int256 answer, , uint256 updatedAt, ) = oracle.latestRoundData();
        require(answer > 0, "bad price");
        require(block.timestamp - updatedAt <= HEARTBEAT, "stale");
        return uint256(answer);
    }
}
