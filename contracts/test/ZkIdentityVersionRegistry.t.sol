// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ZkIdentityEncoding} from "../src/ZkIdentityEncoding.sol";
import {ZkIdentityVersionRegistry} from "../src/ZkIdentityVersionRegistry.sol";

contract V2VerifierStub {}

contract ZkIdentityVersionRegistryTest is Test {
    ZkIdentityVersionRegistry internal registry;
    V2VerifierStub internal verifier;

    bytes32 internal constant CIRCUIT_ID = keccak256("ubi2.zk-identity.v2.packed-status.research-1");
    bytes32 internal constant ISSUER_KEY_ID = keccak256("issuer-key-1");
    bytes32 internal constant ROOT_10 = keccak256("status-root-10");
    bytes32 internal constant ROOT_11 = keccak256("status-root-11");
    bytes32 internal constant STATUS_PROVIDER_HASH = 0x116175bf9d7293d67f2e7b7309631a6b8c1cb2eef79f38ef33e45ab0968a8a55;
    bytes32 internal constant STATUS_LIST_HASH = 0xe8261aa0634bc9f1544375a820c195025e7a45b6e29f0ba57769964d92205726;
    bytes32 internal constant DYNAMIC_STATUS_ROOT = 0x217f00d353043696f123b4919b74ba57900770ce0f80414db45d0e52cbbf2ccf;
    bytes32 internal constant DYNAMIC_POLICY_HASH = 0x554b29b8540ffafa1fa4bc6e54847f887d03b4b9b29449ba2418cbc7f9fa3381;
    uint32 internal constant STATUS_PUBLISHED_AT = 1_786_492_800;
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

    function test_RegistersCanonicalDynamicStatusPolicyAndRetiresIrreversibly() public {
        vm.warp(uint256(STATUS_PUBLISHED_AT) + 1);
        bytes32 policyHash = registry.registerDynamicStatusPolicy(
            STATUS_PROVIDER_HASH, STATUS_LIST_HASH, DYNAMIC_STATUS_ROOT, STATUS_PUBLISHED_AT, 86_400
        );
        assertEq(policyHash, DYNAMIC_POLICY_HASH);
        assertEq(
            registry.dynamicStatusPolicyHash(STATUS_PROVIDER_HASH, STATUS_LIST_HASH, DYNAMIC_STATUS_ROOT, 86_400),
            DYNAMIC_POLICY_HASH
        );

        (
            bytes32 providerIdHash,
            bytes32 listVersionHash,
            bytes32 statusRoot,
            uint32 publishedAt,
            uint32 maximumAgeSeconds,
            bool registered,
            bool active
        ) = registry.dynamicStatusPolicies(policyHash);
        assertEq(providerIdHash, STATUS_PROVIDER_HASH);
        assertEq(listVersionHash, STATUS_LIST_HASH);
        assertEq(statusRoot, DYNAMIC_STATUS_ROOT);
        assertEq(publishedAt, STATUS_PUBLISHED_AT);
        assertEq(maximumAgeSeconds, 86_400);
        assertTrue(registered);
        assertTrue(active);

        (publishedAt, maximumAgeSeconds, registered, active) = registry.dynamicStatusPolicyState(policyHash);
        assertEq(publishedAt, STATUS_PUBLISHED_AT);
        assertEq(maximumAgeSeconds, 86_400);
        assertTrue(registered);
        assertTrue(active);

        registry.retireDynamicStatusPolicy(policyHash);
        (,,, active) = registry.dynamicStatusPolicyState(policyHash);
        assertFalse(active);

        vm.expectRevert(
            abi.encodeWithSelector(ZkIdentityVersionRegistry.DynamicStatusPolicyAlreadyRetired.selector, policyHash)
        );
        registry.retireDynamicStatusPolicy(policyHash);
        vm.expectRevert(
            abi.encodeWithSelector(ZkIdentityVersionRegistry.DynamicStatusPolicyAlreadyRegistered.selector, policyHash)
        );
        registry.registerDynamicStatusPolicy(
            STATUS_PROVIDER_HASH, STATUS_LIST_HASH, DYNAMIC_STATUS_ROOT, STATUS_PUBLISHED_AT, 86_400
        );
    }

    function test_DynamicStatusPolicyRegistrationRejectsInvalidMetadataAndTime() public {
        vm.warp(uint256(STATUS_PUBLISHED_AT));
        vm.expectRevert(ZkIdentityVersionRegistry.InvalidDynamicStatusPublicationTime.selector);
        registry.registerDynamicStatusPolicy(STATUS_PROVIDER_HASH, STATUS_LIST_HASH, DYNAMIC_STATUS_ROOT, 0, 86_400);
        vm.expectRevert(ZkIdentityVersionRegistry.InvalidDynamicStatusPublicationTime.selector);
        registry.registerDynamicStatusPolicy(
            STATUS_PROVIDER_HASH, STATUS_LIST_HASH, DYNAMIC_STATUS_ROOT, STATUS_PUBLISHED_AT + 1, 86_400
        );
        vm.expectRevert(ZkIdentityEncoding.InvalidDynamicStatusPolicy.selector);
        registry.registerDynamicStatusPolicy(
            bytes32(0), STATUS_LIST_HASH, DYNAMIC_STATUS_ROOT, STATUS_PUBLISHED_AT, 86_400
        );
        vm.expectRevert(ZkIdentityEncoding.InvalidDynamicStatusPolicy.selector);
        registry.registerDynamicStatusPolicy(
            STATUS_PROVIDER_HASH, STATUS_LIST_HASH, DYNAMIC_STATUS_ROOT, STATUS_PUBLISHED_AT, 31_536_001
        );

        vm.expectRevert(
            abi.encodeWithSelector(ZkIdentityVersionRegistry.UnknownDynamicStatusPolicy.selector, DYNAMIC_POLICY_HASH)
        );
        registry.retireDynamicStatusPolicy(DYNAMIC_POLICY_HASH);
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

        vm.warp(uint256(STATUS_PUBLISHED_AT));
        vm.prank(OTHER);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, OTHER));
        registry.registerDynamicStatusPolicy(
            STATUS_PROVIDER_HASH, STATUS_LIST_HASH, DYNAMIC_STATUS_ROOT, STATUS_PUBLISHED_AT, 86_400
        );
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
