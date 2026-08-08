// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {MockUSDC} from "../src/MockUSDC.sol";
import {RoachMotelSpender} from "../src/RoachMotelSpender.sol";

/// @dev An ERC-20 that reports failure by RETURNING FALSE rather than
///      reverting. Real tokens do this, and it is the only way to reach the
///      spender's TransferFromFailed path — an unchecked return value here
///      would let a "successful" drain silently move nothing.
contract SilentlyFailingToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function setAllowance(address owner, address spender, uint256 value) external {
        allowance[owner][spender] = value;
    }

    function transferFrom(address, address, uint256) external pure returns (bool) {
        return false;
    }
}

contract RoachMotelSpenderTest is Test {
    MockUSDC internal usdc;
    RoachMotelSpender internal spender;

    address internal victim;
    address internal owner = address(this);

    event Drained(address indexed token, address indexed victim, uint256 amount);
    event DrainFailed(address indexed token, address indexed victim, string reason);

    function setUp() public {
        usdc = new MockUSDC();
        spender = new RoachMotelSpender();
        victim = makeAddr("victim");
    }

    // ---- construction ------------------------------------------------------

    function test_deployerIsOwner() public view {
        assertEq(spender.owner(), owner);
    }

    // ---- the successful drain ---------------------------------------------

    function test_drainTakesTheFullExposure() public {
        usdc.mint(victim, 500e6);
        vm.prank(victim);
        usdc.approve(address(spender), type(uint256).max);

        vm.expectEmit(true, true, false, true);
        emit Drained(address(usdc), victim, 500e6);

        assertEq(spender.drain(address(usdc), victim), 500e6);
        assertEq(usdc.balanceOf(owner), 500e6);
    }

    function test_drainIsCappedByAllowance() public {
        usdc.mint(victim, 500e6);
        vm.prank(victim);
        usdc.approve(address(spender), 20e6);

        assertEq(spender.drain(address(usdc), victim), 20e6);
        assertEq(usdc.balanceOf(victim), 480e6);
    }

    // ---- the failure paths (each is a distinct branch) ---------------------

    function test_drainFailsWhenAllowanceRevoked() public {
        usdc.mint(victim, 500e6);
        vm.prank(victim);
        usdc.approve(address(spender), 0);

        vm.expectEmit(true, true, false, true);
        emit DrainFailed(address(usdc), victim, "allowance revoked");

        assertEq(spender.drain(address(usdc), victim), 0);
        assertEq(usdc.balanceOf(victim), 500e6);
    }

    /// @dev Approved, but there is nothing to take — a distinct branch from a
    ///      revoked allowance, and a distinct message in the audit trail.
    function test_drainFailsWhenVictimBalanceEmpty() public {
        vm.prank(victim);
        usdc.approve(address(spender), type(uint256).max);

        vm.expectEmit(true, true, false, true);
        emit DrainFailed(address(usdc), victim, "victim balance empty");

        assertEq(spender.drain(address(usdc), victim), 0);
    }

    function test_drainRevertsWhenTransferFromReturnsFalse() public {
        SilentlyFailingToken token = new SilentlyFailingToken();
        token.mint(victim, 100e6);
        token.setAllowance(victim, address(spender), type(uint256).max);

        // Unchecked, this would report a successful drain that moved nothing.
        vm.expectRevert(RoachMotelSpender.TransferFromFailed.selector);
        spender.drain(address(token), victim);
    }

    // ---- access control ----------------------------------------------------

    function test_drainRejectsNonOwner() public {
        usdc.mint(victim, 100e6);
        vm.prank(victim);
        usdc.approve(address(spender), type(uint256).max);

        vm.prank(makeAddr("stranger"));
        vm.expectRevert(RoachMotelSpender.NotOwner.selector);
        spender.drain(address(usdc), victim);
    }

    function test_victimCannotDrainThemselves() public {
        usdc.mint(victim, 100e6);
        vm.prank(victim);
        usdc.approve(address(spender), type(uint256).max);

        vm.prank(victim);
        vm.expectRevert(RoachMotelSpender.NotOwner.selector);
        spender.drain(address(usdc), victim);
    }

    // ---- exposure reporting ------------------------------------------------

    function test_exposureIsAllowanceWhenAllowanceIsSmaller() public {
        usdc.mint(victim, 500e6);
        vm.prank(victim);
        usdc.approve(address(spender), 10e6);

        assertEq(spender.exposureOf(address(usdc), victim), 10e6);
    }

    function test_exposureIsBalanceWhenBalanceIsSmaller() public {
        usdc.mint(victim, 7e6);
        vm.prank(victim);
        usdc.approve(address(spender), type(uint256).max);

        assertEq(spender.exposureOf(address(usdc), victim), 7e6);
    }

    function test_exposureIsZeroWithoutApproval() public {
        usdc.mint(victim, 500e6);
        assertEq(spender.exposureOf(address(usdc), victim), 0);
    }

    function test_exposureIsReadOnly() public {
        usdc.mint(victim, 500e6);
        vm.prank(victim);
        usdc.approve(address(spender), type(uint256).max);

        spender.exposureOf(address(usdc), victim);

        assertEq(usdc.balanceOf(victim), 500e6, "a read must not move funds");
        assertEq(usdc.allowance(victim, address(spender)), type(uint256).max);
    }

    function testFuzz_exposureIsAlwaysMinOfAllowanceAndBalance(uint128 balance, uint128 allowance)
        public
    {
        usdc.mint(victim, balance);
        vm.prank(victim);
        usdc.approve(address(spender), allowance);

        uint256 expected = allowance < balance ? allowance : balance;
        assertEq(spender.exposureOf(address(usdc), victim), expected);
    }

    function testFuzz_drainNeverTakesMoreThanExposure(uint128 balance, uint128 allowance) public {
        usdc.mint(victim, balance);
        vm.prank(victim);
        usdc.approve(address(spender), allowance);

        uint256 exposure = spender.exposureOf(address(usdc), victim);
        assertEq(spender.drain(address(usdc), victim), exposure);
        assertEq(usdc.balanceOf(victim), uint256(balance) - exposure);
    }
}
