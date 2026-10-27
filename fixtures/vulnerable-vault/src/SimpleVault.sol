// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

interface IAggregator {
    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80);
}

interface IPair {
    function getReserves() external view returns (uint112, uint112, uint32);
}

/// Intentionally vulnerable fixture used to test solpreflight. Do not deploy.
contract SimpleVault is Initializable {
    address public owner;
    IERC20 public token;
    IAggregator public oracle;
    IPair public pair;
    mapping(address => uint256) public balances;
    address[] public depositors;
    uint256 public fee;

    // Unprotected initializer: anyone can call it and become owner
    function initialize(address _token, address _oracle) external {
        owner = _token == address(0) ? msg.sender : msg.sender;
        token = IERC20(_token);
        oracle = IAggregator(_oracle);
    }

    function deposit() external payable {
        if (balances[msg.sender] == 0) depositors.push(msg.sender);
        balances[msg.sender] += msg.value;
    }

    // Classic reentrancy: external call before state update
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
        balances[msg.sender] = 0;
    }

    // tx.origin auth
    function emergencyWithdraw(address to) external {
        require(tx.origin == owner, "not owner");
        to.call{value: address(this).balance}("");
    }

    // Missing access control on setter
    function setFee(uint256 newFee) external {
        fee = newFee;
    }

    function setOracle(address o) external {
        require(msg.sender == owner, "not owner");
        oracle = IAggregator(o);
    }

    // No staleness or price > 0 check
    function collateralValue(address user) public view returns (uint256) {
        (, int256 answer, , , ) = oracle.latestRoundData();
        return balances[user] / 1e8 * uint256(answer);
    }

    // Spot price from reserves
    function spotPrice() public view returns (uint256) {
        (uint112 r0, uint112 r1, ) = pair.getReserves();
        return uint256(r1) * 1e18 / uint256(r0);
    }

    // Unbounded loop over storage array
    function totalDeposits() external view returns (uint256 t) {
        for (uint256 i = 0; i < depositors.length; i++) t += balances[depositors[i]];
    }

    function payToken(address to, uint256 amount) external {
        require(msg.sender == owner);
        token.transfer(to, amount);
    }
}
