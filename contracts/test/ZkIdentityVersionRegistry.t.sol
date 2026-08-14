// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ZkIdentityVersionRegistry} from "../src/ZkIdentityVersionRegistry.sol";

contract V2VerifierStub {}

contract ZkIdentityVersionRegistryTest is Test {
    ZkIdentityVersionRegistry internal registry;
    V2VerifierStub internal verifier;

    bytes32 internal constant CIRCUIT_ID = keccak256("ubi2.zk-identity.v2.packed-status.research-1");
    bytes32 internal constant ISSUER_KEY_ID = keccak256("issuer-key-1");
    bytes32 internal constant ROOT_10 = keccak256("status-root-10");
    bytes32 internal constant ROOT_11 = keccak256("status-root-11");
    address internal constant OTHER = address(0xBEEF);

    function setUp() public {
        registry = new ZkIdentityVersionRegistry(address(this));
        verifier = new V2VerifierStub();
    }

    function test_RegistersImmutableCircuitAndAcceptsExactIssuerRootTuple() public {
        registry.registerCircuit(CIRCUIT_ID, address(verifier));
        registry.authorizeIssuer(CIRCUIT_ID, ISSUER_KEY_ID);
        registry.publishStatusRoot(CIRCUIT_ID, ISSUER_KEY_ID, 10, ROOT_10);

        (address pinnedVerifier, bytes32 codehash, bool active) = registry.circuits(CIRCUIT_ID);
        assertEq(pinnedVerifier, address(verifier));
        assertEq(codehash, address(verifier).codehash);
        assertTrue(active);
        assertTrue(registry.isAccepted(CIRCUIT_ID, address(verifier), ISSUER_KEY_ID, ROOT_10, 10));
        registry.requireAccepted(CIRCUIT_ID, address(verifier), ISSUER_KEY_ID, ROOT_10, 10);
        assertEq(registry.statusRootEpoch(CIRCUIT_ID, ISSUER_KEY_ID, ROOT_10), 10);
        assertTrue(registry.isRootAccepted(CIRCUIT_ID, address(verifier), ISSUER_KEY_ID, ROOT_10));
        assertEq(registry.requireRootAccepted(CIRCUIT_ID, ISSUER_KEY_ID, ROOT_10), address(verifier));

        assertFalse(registry.isAccepted(CIRCUIT_ID, OTHER, ISSUER_KEY_ID, ROOT_10, 10));
        assertFalse(registry.isAccepted(bytes32(uint256(1)), address(verifier), ISSUER_KEY_ID, ROOT_10, 10));
        assertFalse(registry.isAccepted(CIRCUIT_ID, address(verifier), bytes32(uint256(1)), ROOT_10, 10));
        assertFalse(registry.isAccepted(CIRCUIT_ID, address(verifier), ISSUER_KEY_ID, ROOT_11, 10));
        assertFalse(registry.isAccepted(CIRCUIT_ID, address(verifier), ISSUER_KEY_ID, ROOT_10, 11));
    }

    function test_PublishedRootsOverlapUntilExactRevocation() public {
        _registerThroughRoot10();
        registry.publishStatusRoot(CIRCUIT_ID, ISSUER_KEY_ID, 11, ROOT_11);

        assertTrue(registry.isAccepted(CIRCUIT_ID, address(verifier), ISSUER_KEY_ID, ROOT_10, 10));
        assertTrue(registry.isAccepted(CIRCUIT_ID, address(verifier), ISSUER_KEY_ID, ROOT_11, 11));

        registry.revokeStatusRoot(CIRCUIT_ID, ISSUER_KEY_ID, 10);
        assertFalse(registry.isAccepted(CIRCUIT_ID, address(verifier), ISSUER_KEY_ID, ROOT_10, 10));
        assertFalse(registry.isRootAccepted(CIRCUIT_ID, address(verifier), ISSUER_KEY_ID, ROOT_10));
        assertTrue(registry.isAccepted(CIRCUIT_ID, address(verifier), ISSUER_KEY_ID, ROOT_11, 11));
    }

    function test_StatusEpochsIncreaseAndRootsCannotBeReused() public {
        _registerThroughRoot10();

        vm.expectRevert(abi.encodeWithSelector(ZkIdentityVersionRegistry.StatusEpochNotIncreasing.selector, 10, 10));
        registry.publishStatusRoot(CIRCUIT_ID, ISSUER_KEY_ID, 10, ROOT_11);

        vm.expectRevert(abi.encodeWithSelector(ZkIdentityVersionRegistry.StatusRootAlreadyPublished.selector, ROOT_10));
        registry.publishStatusRoot(CIRCUIT_ID, ISSUER_KEY_ID, 11, ROOT_10);
    }

    function test_CircuitAndIssuerRetirementAreFailClosedAndIrreversible() public {
        _registerThroughRoot10();
        registry.retireIssuer(CIRCUIT_ID, ISSUER_KEY_ID);
        assertFalse(registry.isAccepted(CIRCUIT_ID, address(verifier), ISSUER_KEY_ID, ROOT_10, 10));

        vm.expectRevert(
            abi.encodeWithSelector(
                ZkIdentityVersionRegistry.IssuerAlreadyRegistered.selector, CIRCUIT_ID, ISSUER_KEY_ID
            )
        );
        registry.authorizeIssuer(CIRCUIT_ID, ISSUER_KEY_ID);

        bytes32 nextIssuer = keccak256("issuer-key-2");
        registry.authorizeIssuer(CIRCUIT_ID, nextIssuer);
        registry.retireCircuit(CIRCUIT_ID);
        vm.expectRevert(abi.encodeWithSelector(ZkIdentityVersionRegistry.CircuitInactive.selector, CIRCUIT_ID));
        registry.retireCircuit(CIRCUIT_ID);

        V2VerifierStub replacement = new V2VerifierStub();
        vm.expectRevert(abi.encodeWithSelector(ZkIdentityVersionRegistry.CircuitAlreadyRegistered.selector, CIRCUIT_ID));
        registry.registerCircuit(CIRCUIT_ID, address(replacement));
    }

    function test_CodehashDriftFailsClosed() public {
        _registerThroughRoot10();
        vm.etch(address(verifier), hex"00");
        assertFalse(registry.isAccepted(CIRCUIT_ID, address(verifier), ISSUER_KEY_ID, ROOT_10, 10));
    }

    function test_InvalidAndUnknownStateIsRejected() public {
        vm.expectRevert(ZkIdentityVersionRegistry.InvalidCircuitId.selector);
        registry.registerCircuit(bytes32(0), address(verifier));
        vm.expectRevert(ZkIdentityVersionRegistry.InvalidVerifier.selector);
        registry.registerCircuit(CIRCUIT_ID, OTHER);

        registry.registerCircuit(CIRCUIT_ID, address(verifier));
        vm.expectRevert(ZkIdentityVersionRegistry.InvalidIssuerKeyId.selector);
        registry.authorizeIssuer(CIRCUIT_ID, bytes32(0));
        registry.authorizeIssuer(CIRCUIT_ID, ISSUER_KEY_ID);
        vm.expectRevert(ZkIdentityVersionRegistry.InvalidStatusRoot.selector);
        registry.publishStatusRoot(CIRCUIT_ID, ISSUER_KEY_ID, 1, bytes32(0));
        vm.expectRevert(
            abi.encodeWithSelector(ZkIdentityVersionRegistry.UnknownStatusRoot.selector, CIRCUIT_ID, ISSUER_KEY_ID, 1)
        );
        registry.revokeStatusRoot(CIRCUIT_ID, ISSUER_KEY_ID, 1);
        vm.expectRevert(ZkIdentityVersionRegistry.UnacceptedIdentityState.selector);
        registry.requireAccepted(CIRCUIT_ID, address(verifier), ISSUER_KEY_ID, ROOT_10, 10);
    }

    function test_UnknownTransitionsAndDoubleRevocationFailClosed() public {
        vm.expectRevert(abi.encodeWithSelector(ZkIdentityVersionRegistry.UnknownCircuit.selector, CIRCUIT_ID));
        registry.authorizeIssuer(CIRCUIT_ID, ISSUER_KEY_ID);

        registry.registerCircuit(CIRCUIT_ID, address(verifier));
        vm.expectRevert(
            abi.encodeWithSelector(ZkIdentityVersionRegistry.UnknownIssuer.selector, CIRCUIT_ID, ISSUER_KEY_ID)
        );
        registry.publishStatusRoot(CIRCUIT_ID, ISSUER_KEY_ID, 10, ROOT_10);

        registry.authorizeIssuer(CIRCUIT_ID, ISSUER_KEY_ID);
        registry.publishStatusRoot(CIRCUIT_ID, ISSUER_KEY_ID, 10, ROOT_10);
        registry.revokeStatusRoot(CIRCUIT_ID, ISSUER_KEY_ID, 10);
        vm.expectRevert(
            abi.encodeWithSelector(
                ZkIdentityVersionRegistry.StatusRootAlreadyRevoked.selector, CIRCUIT_ID, ISSUER_KEY_ID, 10
            )
        );
        registry.revokeStatusRoot(CIRCUIT_ID, ISSUER_KEY_ID, 10);
    }

    function test_OnlyOwnerCanMutateGovernanceState() public {
        vm.prank(OTHER);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, OTHER));
        registry.registerCircuit(CIRCUIT_ID, address(verifier));
    }

    function test_OwnershipTransferRequiresAcceptance() public {
        registry.transferOwnership(OTHER);
        assertEq(registry.owner(), address(this));
        assertEq(registry.pendingOwner(), OTHER);

        vm.prank(OTHER);
        registry.acceptOwnership();
        assertEq(registry.owner(), OTHER);
        assertEq(registry.pendingOwner(), address(0));
    }

    function _registerThroughRoot10() private {
        registry.registerCircuit(CIRCUIT_ID, address(verifier));
        registry.authorizeIssuer(CIRCUIT_ID, ISSUER_KEY_ID);
        registry.publishStatusRoot(CIRCUIT_ID, ISSUER_KEY_ID, 10, ROOT_10);
    }
}
