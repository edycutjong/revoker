// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

interface IERC20 {
    function allowance(address owner, address spender) external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transferFrom(address from, address to, uint256 value) external returns (bool);
}

/// @title RoachMotelSpender
/// @notice Test fixture standing in for the contract you approved months ago
///         and forgot about — the one that later turns on you. "Approvals check
///         in, they don't check out."
///
/// @dev This is a *demonstration target*, not an attack tool. It is constrained
///      so it cannot be pointed at a stranger:
///
///        - `drain()` is owner-only, so only the demo operator can trigger it.
///        - It can only ever move tokens a victim explicitly approved to it.
///          Revoking that approval renders it completely inert — which is the
///          entire point Revoker exists to prove.
///        - It is deployed to Sepolia and holds no real value.
///
///      It exists so the detect→revoke race can be demonstrated against a real
///      on-chain adversary instead of a mock. Not audited. Testnet only.
contract RoachMotelSpender {
    address public immutable owner;

    /// @notice Emitted when the spender successfully pulls approved tokens.
    event Drained(address indexed token, address indexed victim, uint256 amount);
    /// @notice Emitted when a pull attempt found nothing left to take.
    event DrainFailed(address indexed token, address indexed victim, string reason);

    error NotOwner();
    error TransferFromFailed();

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        _onlyOwner();
        _;
    }

    function _onlyOwner() internal view {
        if (msg.sender != owner) revert NotOwner();
    }

    /// @notice Attempt to pull everything `victim` has approved to this contract.
    /// @dev Returns the amount taken. Returns 0 (and emits DrainFailed) when the
    ///      approval has already been revoked — the outcome Revoker produces.
    function drain(address token, address victim) external onlyOwner returns (uint256) {
        uint256 allowed = IERC20(token).allowance(victim, address(this));
        if (allowed == 0) {
            emit DrainFailed(token, victim, "allowance revoked");
            return 0;
        }

        uint256 balance = IERC20(token).balanceOf(victim);
        uint256 amount = allowed < balance ? allowed : balance;
        // `amount` is a min() computed two lines above, not an external balance
        // or a timestamp — the class of bug this detector targets cannot apply.
        // slither-disable-next-line incorrect-equality
        if (amount == 0) {
            emit DrainFailed(token, victim, "victim balance empty");
            return 0;
        }

        // arbitrary-send-erc20 is INTENTIONAL and is the entire point of this
        // contract. Slither is right that an arbitrary `from` in transferFrom is
        // high severity in production code — that is how a drainer works. This
        // IS the drainer: an adversarial fixture whose job is to attempt the
        // pull, so the demo can show it taking nothing once the approval is
        // gone. Owner-gated, testnet-only, inert without an approval it was
        // explicitly granted.
        //
        // reentrancy-events: the event is emitted after the transfer on
        // purpose. Emitting first would record a drain that may then revert,
        // and a log claiming things that did not happen is precisely the
        // failure mode this project exists to prevent. No state is read after.
        //
        // Suppressed inline with justification rather than filtered globally,
        // so both detectors keep working everywhere else in the codebase.
        // slither-disable-next-line arbitrary-send-erc20,reentrancy-events
        if (!IERC20(token).transferFrom(victim, owner, amount)) revert TransferFromFailed();
        emit Drained(token, victim, amount);
        return amount;
    }

    /// @notice How much this contract could take from `victim` right now.
    /// @dev The watcher uses this as an independent read of exposure.
    function exposureOf(address token, address victim) external view returns (uint256) {
        uint256 allowed = IERC20(token).allowance(victim, address(this));
        uint256 balance = IERC20(token).balanceOf(victim);
        return allowed < balance ? allowed : balance;
    }
}
