// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {Test, console2} from "forge-std/Test.sol";

import {BadRootBaseTest} from "./BadRootBase.t.sol";

contract BadRootTest is BadRootBaseTest {
    function testExploit() external validation {}
}
