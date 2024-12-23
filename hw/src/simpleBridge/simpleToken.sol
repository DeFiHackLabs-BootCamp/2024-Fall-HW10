// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract simpleToken is ERC20 {
    uint256 internal constant INITIAL_SUPPLY = 1_000_000;

    constructor() ERC20("simpleBridgeToken", "sBT") {
        _mint(msg.sender, INITIAL_SUPPLY * 10 ** decimals());
    }
}
