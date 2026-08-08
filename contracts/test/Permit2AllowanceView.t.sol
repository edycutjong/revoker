// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {Permit2AllowanceView} from "../src/Permit2AllowanceView.sol";

/// @notice Stand-in for canonical Permit2's allowance ledger.
/// @dev Only the getter under test, with the exact 3-value return shape that
///      broke the guard in the first place. Written as a mock rather than
///      forked so these tests need no RPC, no key and no network — the same bar
///      the TypeScript suite holds to.
contract MockPermit2 {
    struct PackedAllowance {
        uint160 amount;
        uint48 expiration;
        uint48 nonce;
    }

    mapping(address => mapping(address => mapping(address => PackedAllowance))) internal _slots;

    function setAllowance(
        address user,
        address token,
        address spender,
        uint160 amount,
        uint48 expiration,
        uint48 nonce
    ) external {
        _slots[user][token][spender] =
            PackedAllowance({amount: amount, expiration: expiration, nonce: nonce});
    }

    function allowance(address user, address token, address spender)
        external
        view
        returns (uint160, uint48, uint48)
    {
        PackedAllowance memory slot = _slots[user][token][spender];
        return (slot.amount, slot.expiration, slot.nonce);
    }
}

/// @notice Pins the flattening itself.
///
///         The bug these tests exist to prevent a repeat of was not a wrong
///         number — it was NO number: a guard pointed at a tuple-returning
///         getter produced `observedValue: undefined`, so `gt 0` was false and
///         a live, unlimited Permit2 grant was left armed while the log claimed
///         the slot was already zero. Every assertion below is about the guard
///         returning one unambiguous scalar, and the right one.
contract Permit2AllowanceViewTest is Test {
    Permit2AllowanceView internal view_;
    MockPermit2 internal permit2;

    address internal constant PERMIT2_ADDRESS = 0x000000000022D473030F116dDEE9F6B43aC78BA3;

    address internal owner;
    address internal token;
    address internal spender;

    /// @dev Permit2's unlimited sentinel is `type(uint160).max`, NOT uint256 max.
    uint160 internal constant UNLIMITED = type(uint160).max;

    uint48 internal constant EXPIRATION = 1_817_728_584; // the Sepolia fixture's own expiry
    uint48 internal constant NONCE = 7;

    function setUp() public {
        owner = makeAddr("owner");
        token = makeAddr("token");
        spender = makeAddr("spender");

        // The helper hardcodes canonical Permit2, which is exactly the property
        // that stops it being re-pointed at a liar — so the mock has to be put
        // AT that address rather than injected. Code is etched; storage at the
        // target starts empty and is written through the etched setter below.
        MockPermit2 template = new MockPermit2();
        vm.etch(PERMIT2_ADDRESS, address(template).code);
        permit2 = MockPermit2(PERMIT2_ADDRESS);

        view_ = new Permit2AllowanceView();

        // Anything below the expiry, so "live" is the default and each expiry
        // test states its own warp explicitly.
        vm.warp(1_700_000_000);
    }

    function _arm(uint160 amount, uint48 expiration) internal {
        permit2.setAllowance(owner, token, spender, amount, expiration, NONCE);
    }

    // ---- the delegation target ---------------------------------------------

    function test_readsCanonicalPermit2AndNothingElse() public view {
        // If this address ever drifts, the guard is reading some other
        // contract's idea of the allowance while the action still zeroes the
        // real one — a guard that cannot fail closed.
        assertEq(address(view_.PERMIT2()), PERMIT2_ADDRESS, "must delegate to canonical Permit2");
    }

    // ---- amountOf: the raw member ------------------------------------------

    function test_amountOfReturnsTheAmountMemberNotExpirationOrNonce() public {
        // Three deliberately distinct values: reading the wrong tuple member
        // returns a plausible non-zero number, so `gt 0` would still pass and
        // the mistake would only surface as a revoke that fired on garbage.
        _arm(1234, EXPIRATION);

        assertEq(view_.amountOf(owner, token, spender), 1234, "must return amount");
    }

    function test_amountOfIsZeroForAZeroedSlot() public {
        _arm(0, EXPIRATION);

        assertEq(view_.amountOf(owner, token, spender), 0, "zeroed slot must read zero");
    }

    function test_amountOfIsZeroForASlotThatWasNeverWritten() public view {
        // Nothing armed at all. Permit2 returns a zero struct, and this must not
        // dress that up as an exposure.
        assertEq(view_.amountOf(owner, token, spender), 0, "unwritten slot must read zero");
    }

    function test_amountOfIgnoresExpiryOnPurpose() public {
        // The diagnostic half of the pair: it reports what the slot SAYS. A
        // non-zero here beside a zero from liveAmountOf is how an operator tells
        // "granted but expired" apart from "never granted".
        _arm(500, EXPIRATION);
        vm.warp(uint256(EXPIRATION) + 1);

        assertEq(view_.amountOf(owner, token, spender), 500, "raw amount survives expiry");
        assertEq(view_.liveAmountOf(owner, token, spender), 0, "live amount does not");
    }

    function test_unlimitedSentinelSurvivesTheFlattening() public {
        // The value the live demo actually carries. Any truncation to uint128 or
        // a bad cast turns Permit2's unlimited grant into a bounded-looking
        // number, and the rule that scores it stops firing.
        _arm(UNLIMITED, EXPIRATION);

        assertEq(view_.amountOf(owner, token, spender), UNLIMITED, "amountOf must not truncate");
        assertEq(view_.liveAmountOf(owner, token, spender), UNLIMITED, "liveAmountOf must not truncate");
    }

    // ---- liveAmountOf: the guard -------------------------------------------

    function test_liveAmountOfReturnsAmountWhileLive() public {
        _arm(UNLIMITED, EXPIRATION);

        // The whole point: one scalar, strictly greater than zero, so the
        // `gt 0` condition fires and lockdown() runs.
        assertGt(view_.liveAmountOf(owner, token, spender), 0, "live grant must guard as non-zero");
    }

    function test_liveAmountOfIsZeroForAZeroedSlot() public {
        // Someone else revoked first. The guard must report zero so the batch is
        // skipped and no gas is spent.
        _arm(0, EXPIRATION);

        assertEq(view_.liveAmountOf(owner, token, spender), 0, "zeroed slot must not guard live");
    }

    function test_liveAmountOfIsZeroOnceExpired() public {
        _arm(UNLIMITED, EXPIRATION);
        vm.warp(uint256(EXPIRATION) + 1);

        assertEq(view_.liveAmountOf(owner, token, spender), 0, "expired grant is not an exposure");
    }

    function test_liveAmountOfIsStillLiveOnTheExpirationSecondItself() public {
        // The boundary, and it is strict on purpose: AllowanceTransfer reverts
        // on `block.timestamp > expiration`, so at exactly `expiration` the
        // spender can STILL move tokens. A `>=` here would stand the agent down
        // one second early, in the one second an attacker would want it to.
        _arm(UNLIMITED, EXPIRATION);
        vm.warp(EXPIRATION);

        assertEq(
            view_.liveAmountOf(owner, token, spender), UNLIMITED, "expiration second is still live"
        );
    }

    // ---- slot keying --------------------------------------------------------

    function test_slotsAreKeyedByTheWholeOwnerTokenSpenderTriple() public {
        _arm(UNLIMITED, EXPIRATION);

        address otherOwner = makeAddr("otherOwner");
        address otherToken = makeAddr("otherToken");
        address otherSpender = makeAddr("otherSpender");

        // Reading a neighbouring triple must not leak this one's exposure: a
        // guard that did would fire lockdown for a wallet with nothing at risk,
        // and — worse — would report an unrelated wallet's grant as safe.
        assertEq(view_.liveAmountOf(otherOwner, token, spender), 0, "other owner must read zero");
        assertEq(view_.liveAmountOf(owner, otherToken, spender), 0, "other token must read zero");
        assertEq(view_.liveAmountOf(owner, token, otherSpender), 0, "other spender must read zero");
        assertEq(view_.amountOf(otherOwner, otherToken, otherSpender), 0, "unrelated triple is zero");

        // ...and the original is untouched by all that reading.
        assertEq(view_.liveAmountOf(owner, token, spender), UNLIMITED, "own slot must be unchanged");
    }

    // ---- the property, over the whole input space ---------------------------

    function testFuzz_liveAmountIsTheAmountUntilTheInstantItIsNot(
        uint160 amount,
        uint48 expiration,
        uint48 nowSeconds
    ) public {
        vm.assume(nowSeconds > 0);
        _arm(amount, expiration);
        vm.warp(nowSeconds);

        uint160 expected = nowSeconds > expiration ? 0 : amount;

        assertEq(view_.liveAmountOf(owner, token, spender), expected, "guard must match Permit2");
        // The raw read never has an opinion about time.
        assertEq(view_.amountOf(owner, token, spender), amount, "raw read is time-independent");
    }
}
