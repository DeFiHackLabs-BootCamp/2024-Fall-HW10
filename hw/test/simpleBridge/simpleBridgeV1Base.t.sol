// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Test, console2} from "forge-std/Test.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {IERC20} from "@openzeppelin/contracts/interfaces/IERC20.sol";

import {simpleBridge} from "../../src/simpleBridge/simpleBridge.sol";
import {simpleVault} from "../../src/simpleBridge/simpleVault.sol";
import {simpleToken} from "../../src/simpleBridge/simpleToken.sol";

contract simpleBridgeV1BaseTest is Test {
    event TokenDeposit(address from, address to, uint256 amount);

    address Deployer = makeAddr("Deployer");

    address user = makeAddr("user");
    address userInL2 = makeAddr("userInL2");
    Account operator = makeAccount("operator");

    simpleToken token;
    simpleBridge tokenBridge;
    simpleVault vault;

    modifier validation() {
        assertEq(token.balanceOf(address(this)), 1 ether);
        _;
        assertEq(token.balanceOf(address(this)), 10 ether);
    }

    function setUp() public {
        deal(address(this), 0 ether);

        // Deployer
        vm.startPrank(Deployer);

        token = new simpleToken();
        token.transfer(address(user), 1000 ether);

        tokenBridge = new simpleBridge(IERC20(token));
        vault = tokenBridge.vault();

        tokenBridge.setSigner(operator.addr, true);

        vm.stopPrank();

        // User

        vm.startPrank(user);
        uint256 depositAmount = 100 ether;
        uint256 userInitialBalance = token.balanceOf(address(user));

        token.approve(address(tokenBridge), depositAmount);
        tokenBridge.depositTokensToL2(user, userInL2, depositAmount);

        (uint8 v, bytes32 r, bytes32 s) = _signMessage(_getTokenWithdrawalMessage(address(this), 1 ether), operator.key);
        tokenBridge.withdrawTokensToL1(address(this), 1 ether, v, r, s);

        vm.stopPrank();
    }

    function _getTokenWithdrawalMessage(address recipient, uint256 amount) internal view returns (bytes memory) {
        return abi.encode(address(token), 0, abi.encodeCall(IERC20.transferFrom, (address(vault), recipient, amount)));
    }

    function _signMessage(bytes memory message, uint256 privateKey)
        internal
        pure
        returns (uint8 v, bytes32 r, bytes32 s)
    {
        return vm.sign(privateKey, MessageHashUtils.toEthSignedMessageHash(keccak256(message)));
    }

    function receiveBridgeMessage() external virtual {}
}
