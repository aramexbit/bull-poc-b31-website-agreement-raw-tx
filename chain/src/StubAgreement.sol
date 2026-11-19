// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Minimal stand-in for the live Bull Agreement (0x84C6…) for the honest
// controls only: vote()/release() with the same selectors the website's
// honest server responses would carry. The exploit cases never touch it.
contract StubAgreement {
    mapping(uint256 => bool) public voted;
    mapping(uint256 => bool) public released;
    address public payee;
    constructor(address _payee) { payee = _payee; }
    function vote(uint256 id, uint256 index) external returns (bool) { voted[id] = true; return true; }
    function object(uint256 id, uint256 index) external returns (bool) { return true; }
    function attest(uint256 id, uint256 index) external returns (bool) { return true; }
    function release(uint256 id) external returns (bool) {
        released[id] = true;
        payable(payee).transfer(address(this).balance);
        return true;
    }
    function refund(uint256 id) external returns (bool) { return true; }
    receive() external payable {}
}
