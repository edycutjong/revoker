// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {MockUSDC} from "../src/MockUSDC.sol";
import {RoachMotelSpender} from "../src/RoachMotelSpender.sol";

/// @notice Tests the security claim itself: once the approval is revoked, the
///         drainer is inert. Not that it reverts — that it succeeds and takes
///         nothing, which is the outcome the demo puts on-chain.
contract RevokerTest is Test {
    MockUSDC internal usdc;
    RoachMotelSpender internal spender;

    address internal victim;
    address internal attacker = address(this); // deploys the spender, so owner

    uint256 internal constant BALANCE = 10_000e6;

    function setUp() public {
        victim = makeAddr("victim");
        usdc = new MockUSDC();
        spender = new RoachMotelSpender();
        usdc.mint(victim, BALANCE);
    }

    function _approveMax() internal {
        vm.prank(victim);
        usdc.approve(address(spender), type(uint256).max);
    }

    // ---- the core claim ----------------------------------------------------

    function test_drainSucceedsWhileApprovalIsLive() public {
        _approveMax();

        uint256 taken = spender.drain(address(usdc), victim);

        assertEq(taken, BALANCE, "drain should take the full balance");
        assertEq(usdc.balanceOf(victim), 0, "victim should be emptied");
        assertEq(usdc.balanceOf(attacker), BALANCE, "attacker should hold the funds");
    }

    function test_drainTakesNothingAfterRevoke() public {
        _approveMax();

        // The revoke, exactly as Revoker performs it.
        vm.prank(victim);
        usdc.approve(address(spender), 0);

        uint256 taken = spender.drain(address(usdc), victim);

        // The call SUCCEEDS — it does not revert and is not blocked.
        // It simply has nothing left to take. That distinction is the project.
        assertEq(taken, 0, "drain must take nothing after revoke");
        assertEq(usdc.balanceOf(victim), BALANCE, "victim balance must be untouched");
        assertEq(usdc.balanceOf(attacker), 0, "attacker must gain nothing");
    }

    function test_drainEmitsDrainFailedAfterRevoke() public {
        _approveMax();
        vm.prank(victim);
        usdc.approve(address(spender), 0);

        vm.expectEmit(true, true, false, true);
        emit RoachMotelSpender.DrainFailed(address(usdc), victim, "allowance revoked");
        spender.drain(address(usdc), victim);
    }

    /// @dev A partial revoke is still a real reduction in exposure.
    function test_boundedApprovalCapsWhatCanBeTaken() public {
        vm.prank(victim);
        usdc.approve(address(spender), 100e6);

        uint256 taken = spender.drain(address(usdc), victim);

        assertEq(taken, 100e6, "drain is capped by the allowance");
        assertEq(usdc.balanceOf(victim), BALANCE - 100e6, "rest of the balance survives");
    }

    // ---- exposure reporting ------------------------------------------------

    function test_exposureIsMinOfAllowanceAndBalance() public {
        vm.prank(victim);
        usdc.approve(address(spender), 500e6);
        assertEq(spender.exposureOf(address(usdc), victim), 500e6, "allowance is the binding limit");

        _approveMax();
        assertEq(spender.exposureOf(address(usdc), victim), BALANCE, "balance is the binding limit");
    }

    function test_exposureIsZeroAfterRevoke() public {
        _approveMax();
        vm.prank(victim);
        usdc.approve(address(spender), 0);

        assertEq(spender.exposureOf(address(usdc), victim), 0, "no exposure after revoke");
    }

    // ---- access control ----------------------------------------------------

    function test_drainIsOwnerOnly() public {
        _approveMax();

        vm.prank(makeAddr("stranger"));
        vm.expectRevert(RoachMotelSpender.NotOwner.selector);
        spender.drain(address(usdc), victim);
    }

    // ---- ERC-20 semantics the rules depend on ------------------------------

    function test_infiniteAllowanceIsNotDecremented() public {
        _approveMax();
        spender.drain(address(usdc), victim);

        assertEq(
            usdc.allowance(victim, address(spender)),
            type(uint256).max,
            "MAX allowance must remain MAX after a transferFrom"
        );
    }

    function test_boundedAllowanceIsDecremented() public {
        vm.prank(victim);
        usdc.approve(address(spender), 100e6);
        spender.drain(address(usdc), victim);

        assertEq(usdc.allowance(victim, address(spender)), 0, "bounded allowance is spent down");
    }

    function test_transferFromRevertsBeyondAllowance() public {
        vm.prank(victim);
        usdc.approve(address(spender), 1e6);

        vm.prank(address(spender));
        vm.expectRevert(abi.encodeWithSelector(MockUSDC.InsufficientAllowance.selector, 1e6, 2e6));
        usdc.transferFrom(victim, attacker, 2e6);
    }

    function testFuzz_revokeAlwaysZeroesExposure(uint256 allowance) public {
        vm.assume(allowance > 0);
        vm.prank(victim);
        usdc.approve(address(spender), allowance);

        vm.prank(victim);
        usdc.approve(address(spender), 0);

        assertEq(spender.exposureOf(address(usdc), victim), 0, "revoke must always zero exposure");
        assertEq(spender.drain(address(usdc), victim), 0, "drain must always take zero");
    }
}
