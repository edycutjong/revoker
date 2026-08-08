// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {MockUSDC} from "../src/MockUSDC.sol";

/// @notice Exhaustive coverage of the ERC-20 fixture, including every revert
///         path. The threat rules reason about allowance semantics, so those
///         semantics are pinned rather than assumed.
contract MockUSDCTest is Test {
    MockUSDC internal usdc;

    address internal alice;
    address internal bob;
    address internal carol;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    function setUp() public {
        usdc = new MockUSDC();
        alice = makeAddr("alice");
        bob = makeAddr("bob");
        carol = makeAddr("carol");
    }

    // ---- metadata ----------------------------------------------------------

    function test_metadata() public view {
        assertEq(usdc.name(), "Mock USD Coin");
        assertEq(usdc.symbol(), "mUSDC");
        assertEq(usdc.decimals(), 6);
        assertEq(usdc.totalSupply(), 0);
    }

    // ---- mint --------------------------------------------------------------

    function test_mintIncreasesBalanceAndSupply() public {
        vm.expectEmit(true, true, false, true);
        emit Transfer(address(0), alice, 1_000e6);
        usdc.mint(alice, 1_000e6);

        assertEq(usdc.balanceOf(alice), 1_000e6);
        assertEq(usdc.totalSupply(), 1_000e6);
    }

    function test_mintAccumulates() public {
        usdc.mint(alice, 100e6);
        usdc.mint(alice, 50e6);
        assertEq(usdc.balanceOf(alice), 150e6);
        assertEq(usdc.totalSupply(), 150e6);
    }

    // ---- approve -----------------------------------------------------------

    function test_approveSetsAllowanceAndEmits() public {
        vm.expectEmit(true, true, false, true);
        emit Approval(alice, bob, 500e6);

        vm.prank(alice);
        assertTrue(usdc.approve(bob, 500e6));
        assertEq(usdc.allowance(alice, bob), 500e6);
    }

    function test_approveOverwritesRatherThanAccumulates() public {
        vm.startPrank(alice);
        usdc.approve(bob, 500e6);
        usdc.approve(bob, 10e6);
        vm.stopPrank();

        assertEq(usdc.allowance(alice, bob), 10e6, "approve must overwrite");
    }

    function test_approveZeroIsTheRevoke() public {
        vm.startPrank(alice);
        usdc.approve(bob, type(uint256).max);
        usdc.approve(bob, 0);
        vm.stopPrank();

        assertEq(usdc.allowance(alice, bob), 0);
    }

    /// @dev Allowances are per (owner, spender) — revoking one must not touch another.
    function test_allowancesAreIsolatedPerSpender() public {
        vm.startPrank(alice);
        usdc.approve(bob, 100e6);
        usdc.approve(carol, 200e6);
        usdc.approve(bob, 0);
        vm.stopPrank();

        assertEq(usdc.allowance(alice, bob), 0);
        assertEq(usdc.allowance(alice, carol), 200e6, "revoking bob must not affect carol");
    }

    // ---- transfer ----------------------------------------------------------

    function test_transferMovesBalance() public {
        usdc.mint(alice, 100e6);

        vm.expectEmit(true, true, false, true);
        emit Transfer(alice, bob, 40e6);

        vm.prank(alice);
        assertTrue(usdc.transfer(bob, 40e6));

        assertEq(usdc.balanceOf(alice), 60e6);
        assertEq(usdc.balanceOf(bob), 40e6);
    }

    function test_transferRevertsOnInsufficientBalance() public {
        usdc.mint(alice, 10e6);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(MockUSDC.InsufficientBalance.selector, 10e6, 11e6));
        usdc.transfer(bob, 11e6);
    }

    function test_transferOfZeroIsAllowed() public {
        vm.prank(alice);
        assertTrue(usdc.transfer(bob, 0));
    }

    // ---- transferFrom ------------------------------------------------------

    function test_transferFromSpendsAllowance() public {
        usdc.mint(alice, 100e6);
        vm.prank(alice);
        usdc.approve(bob, 60e6);

        vm.prank(bob);
        assertTrue(usdc.transferFrom(alice, carol, 25e6));

        assertEq(usdc.allowance(alice, bob), 35e6, "allowance is decremented");
        assertEq(usdc.balanceOf(carol), 25e6);
    }

    function test_transferFromRevertsOnInsufficientAllowance() public {
        usdc.mint(alice, 100e6);
        vm.prank(alice);
        usdc.approve(bob, 5e6);

        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(MockUSDC.InsufficientAllowance.selector, 5e6, 6e6));
        usdc.transferFrom(alice, carol, 6e6);
    }

    function test_transferFromRevertsOnInsufficientBalance() public {
        usdc.mint(alice, 1e6);
        vm.prank(alice);
        usdc.approve(bob, type(uint256).max);

        // Allowance is unlimited, so the balance check is what must stop this.
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(MockUSDC.InsufficientBalance.selector, 1e6, 2e6));
        usdc.transferFrom(alice, carol, 2e6);
    }

    function test_transferFromWithNoAllowanceReverts() public {
        usdc.mint(alice, 100e6);

        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(MockUSDC.InsufficientAllowance.selector, 0, 1));
        usdc.transferFrom(alice, carol, 1);
    }

    /// @dev The special case the `unlimited-to-unverified` rule exists for.
    function test_maxAllowanceIsNeverDecremented() public {
        usdc.mint(alice, 100e6);
        vm.prank(alice);
        usdc.approve(bob, type(uint256).max);

        vm.startPrank(bob);
        usdc.transferFrom(alice, carol, 30e6);
        usdc.transferFrom(alice, carol, 30e6);
        vm.stopPrank();

        assertEq(usdc.allowance(alice, bob), type(uint256).max, "MAX must stay MAX");
        assertEq(usdc.balanceOf(carol), 60e6);
    }

    function testFuzz_transferPreservesTotalSupply(uint128 minted, uint128 sent) public {
        vm.assume(sent <= minted);
        usdc.mint(alice, minted);

        vm.prank(alice);
        usdc.transfer(bob, sent);

        assertEq(usdc.balanceOf(alice) + usdc.balanceOf(bob), minted);
        assertEq(usdc.totalSupply(), minted);
    }

    function testFuzz_approveThenRevokeAlwaysZeroes(uint256 amount) public {
        vm.startPrank(alice);
        usdc.approve(bob, amount);
        usdc.approve(bob, 0);
        vm.stopPrank();

        assertEq(usdc.allowance(alice, bob), 0);
    }
}
