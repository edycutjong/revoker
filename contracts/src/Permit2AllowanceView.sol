// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

interface IPermit2Allowance {
    /// @dev Permit2's own getter. THREE return values — this shape is the whole
    ///      reason this contract exists. See the notice below.
    function allowance(address user, address token, address spender)
        external
        view
        returns (uint160 amount, uint48 expiration, uint48 nonce);
}

/// @title Permit2AllowanceView
/// @notice Flattens Permit2's 3-tuple allowance getter down to a single
///         `uint160`, so an execution API that can only compare ONE returned
///         value against a threshold can still guard a Permit2 revoke.
///
/// @dev THE HAZARD THIS CONTRACT EXISTS FOR — do not "simplify" it away.
///
///      Revoker's Permit2 revoke runs through KeeperHub's `check-and-execute`:
///      the guard read and the `lockdown()` write are ONE server-side operation,
///      which is what removes the TOCTOU window a mempool-watching drainer needs.
///      That endpoint's condition schema is exactly `{operator, value}` — there
///      is no output index, no tuple path, no member selector anywhere in it.
///
///      Permit2's `allowance()` returns `(uint160 amount, uint48 expiration,
///      uint48 nonce)`. Pointing the guard straight at it therefore cannot work
///      and does not fail loudly: the condition evaluator finds no scalar to
///      compare, reports `observedValue: undefined`, evaluates `gt 0` as false,
///      and SKIPS the write. Observed on Sepolia — an armed, unlimited,
///      correctly-detected Permit2 slot was left fully armed while the run
///      logged a tidy `revoke.skipped ... reason=guard slot already zero`.
///      A guard that silently declines to fire is worse than no guard.
///
///      So the guard reads THIS contract instead, and the action still calls
///      canonical Permit2. Both remain inside the same check-and-execute, so the
///      atomicity property is untouched — this only changes which view function
///      the server reads, never when it reads it.
///
///      Properties that make this safe to leave deployed forever:
///        - No owner, no admin, no upgrade path, no storage, no state to rot.
///        - Nothing payable; it can neither hold nor move a token.
///        - `PERMIT2` is a compile-time constant, so the helper can never be
///          re-pointed at an attacker's contract to fake a live allowance and
///          bait a revoke.
///        - Pure pass-through: it reads canonical Permit2 at call time, so it
///          cannot go stale or disagree with the slot the action zeroes.
contract Permit2AllowanceView {
    /// @notice The canonical Permit2, at the same address on every chain
    ///         (deterministic deployment, salt 0).
    /// @dev Public so that anyone verifying this deployment can read back the
    ///      address it delegates to, rather than taking the source on trust.
    IPermit2Allowance public constant PERMIT2 =
        IPermit2Allowance(0x000000000022D473030F116dDEE9F6B43aC78BA3);

    /// @notice The raw `amount` member of the Permit2 allowance slot.
    /// @dev Diagnostic, NOT the guard. It answers "what does the slot say",
    ///      which is the number the broken tuple guard was reaching for and the
    ///      one an operator reproduces by hand with `cast call`. Read alongside
    ///      `liveAmountOf`, a non-zero here with a zero there is a precise
    ///      statement: granted, but expired.
    function amountOf(address owner, address token, address spender)
        external
        view
        returns (uint160 amount)
    {
        // unused-return: dropping `expiration` and `nonce` is not an oversight,
        // it is the entire function. Returning them would recreate the tuple
        // that the condition evaluator cannot read a member from.
        // slither-disable-next-line unused-return
        (amount,,) = PERMIT2.allowance(owner, token, spender);
    }

    /// @notice The amount this spender can actually move RIGHT NOW — zero once
    ///         the grant has expired.
    /// @dev THIS is what guards the revoke, and the choice is deliberate.
    ///
    ///      A slot with a live amount but a past expiration is not a threat:
    ///      Permit2's `_transfer` reverts with `AllowanceExpired` before moving
    ///      anything, so `lockdown()` on it would spend gas zeroing a number
    ///      nobody can spend. The watcher already refuses to batch expired slots
    ///      (src/watcher.ts classifies them `expired` and clears them), so
    ///      folding the same test into the guard makes the server-side re-read
    ///      agree with the client-side decision instead of being laxer than it —
    ///      and it closes the one case the watcher cannot cover, where the grant
    ///      expires in the seconds between detection and execution.
    ///
    ///      Strictly `>`, matching AllowanceTransfer's own
    ///      `if (block.timestamp > allowed.expiration) revert AllowanceExpired`.
    ///      A `>=` here would call an allowance dead one second before Permit2
    ///      does, and "dead" is the answer that cancels the revoke.
    ///
    ///      block.timestamp is load-bearing on purpose and is not a manipulation
    ///      surface here: the comparison is against an expiry measured in days,
    ///      the worst a proposer's few seconds of leeway can buy is one wasted or
    ///      one skipped no-op lockdown, and this function moves nothing.
    function liveAmountOf(address owner, address token, address spender)
        external
        view
        returns (uint160)
    {
        // unused-return: `nonce` is deliberately dropped — see amountOf.
        // slither-disable-next-line unused-return
        (uint160 amount, uint48 expiration,) = PERMIT2.allowance(owner, token, spender);
        // timestamp: see the note above. Comparing against block.timestamp IS
        // the liveness question, and it is the same comparison Permit2 itself
        // makes before allowing a transfer.
        // slither-disable-next-line timestamp
        if (block.timestamp > expiration) return 0;
        return amount;
    }
}
