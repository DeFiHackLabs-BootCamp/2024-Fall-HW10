// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/interfaces/IERC20.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

import {simpleVault} from "./simpleVault.sol";

interface ISimpleBridgeReceiver {
    function receiveBridgeMessage() external;
}

contract simpleBridge is Ownable, Pausable, ReentrancyGuard {
    IERC20 public immutable token;
    simpleVault public immutable vault;

    bool exceedDepositLimit = false;
    uint256 public tokenDepositLimit = 8_000 ether;
    mapping(address account => bool isSigner) public signers;

    error simpleBridge__DepositLimitReached();
    error simpleBridge__InvalidDepositLimit();
    error simpleBridge__Unauthorized();
    error simpleBridge__ExecutionFailed();

    event TokenDeposit(address from, address to, uint256 amount);
    event TokenWithdrawn(address to, uint256 amount);

    constructor(IERC20 _token) Ownable(msg.sender) {
        token = _token;
        vault = new simpleVault(token);
        vault.approveTo(address(this), type(uint256).max); // Grants the bridge permission to transfer tokens from the vault for withdrawals.
    }

    // DAO Govenored Operation

    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }

    function setSigner(address account, bool enabled) external onlyOwner {
        signers[account] = enabled;
    }

    function updateTokenDepositLimit(uint256 amount) external onlyOwner {
        if (amount <= tokenDepositLimit) revert simpleBridge__InvalidDepositLimit();

        if (amount > token.balanceOf(address(this)) + tokenDepositLimit) exceedDepositLimit = true;

        tokenDepositLimit = amount;
    }

    /**
     * @notice Deposits tokens into the vault for L2 minting.
     * @dev Locks tokens in the vault and emits a Deposit event, which triggers
     *      the minting process on L2. Nodes listening to this event will handle
     *      the L2 minting. This process currently relies on centralized services.
     *
     * @param from The address depositing tokens on L1.
     * @param l2Recipient The recipient address on L2.
     * @param amount The amount of tokens to deposit.
     */
    function depositTokensToL2(address from, address l2Recipient, uint256 amount) external whenNotPaused {
        _checkDepositLimit(amount);

        token.transferFrom(from, address(vault), amount);

        emit TokenDeposit(from, l2Recipient, amount);
    }

    /**
     * @notice Withdraws tokens from L2 to L1.
     * @dev A similar mechanism exists on L2 for withdrawing tokens from L1.
     *      A valid signature is required to prevent replay attacks.
     *
     * @param to The recipient address on L1.
     * @param amount The amount of tokens to withdraw.
     * @param v The 'v' component of the signature.
     * @param r The 'r' component of the signature.
     * @param s The 's' component of the signature.
     */
    function withdrawTokensToL1(address to, uint256 amount, uint8 v, bytes32 r, bytes32 s) external whenNotPaused {
        bytes memory message = abi.encode(
            address(token), 0, abi.encodeWithSelector(IERC20.transferFrom.selector, address(vault), to, amount)
        );
        _validateAndExecuteMessage(v, r, s, message);

        token.transferFrom(address(vault), to, amount);

        ISimpleBridgeReceiver(to).receiveBridgeMessage();

        emit TokenWithdrawn(to, amount);
    }

    /**
     * @notice Withdraws ETH from L2 to L1.
     * @dev Requires a valid signature to authorize the withdrawal.
     *
     * @param v The 'v' component of the signature.
     * @param r The 'r' component of the signature.
     * @param s The 's' component of the signature.
     * @param message The data payload to send to L1 (can be empty).
     */
    function sendToL1(uint8 v, bytes32 r, bytes32 s, bytes memory message) public nonReentrant whenNotPaused {
        _validateAndExecuteMessage(v, r, s, message);

        (address target, uint256 value, bytes memory data) = abi.decode(message, (address, uint256, bytes));

        (bool success,) = target.call{value: value}(data);

        if (!success) {
            revert simpleBridge__ExecutionFailed();
        }

        emit TokenWithdrawn(target, value);
    }

    function _checkDepositLimit(uint256 amount) internal {
        if (exceedDepositLimit == true) revert simpleBridge__DepositLimitReached();

        if (token.balanceOf(address(vault)) + amount > tokenDepositLimit) {
            exceedDepositLimit = true;
        }
    }

    function _validateAndExecuteMessage(uint8 v, bytes32 r, bytes32 s, bytes memory message) internal {
        address signer = ECDSA.recover(MessageHashUtils.toEthSignedMessageHash(keccak256(message)), v, r, s);

        if (!signers[signer]) {
            revert simpleBridge__Unauthorized();
        }
    }
}
