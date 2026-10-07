// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Minimal subset of Foundry's cheatcodes, so the tests need no external library.
/// Foundry intercepts calls to this fixed address and runs the cheatcode.
interface Vm {
    function prank(address sender) external;              // next call comes from `sender`
    function expectRevert(bytes4 selector) external;      // next call must revert with this error
}

Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
