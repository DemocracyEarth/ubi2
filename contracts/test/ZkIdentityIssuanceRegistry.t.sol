// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ZkIdentityEncoding} from "../src/ZkIdentityEncoding.sol";
import {ZkIdentityIssuanceRegistry} from "../src/ZkIdentityIssuanceRegistry.sol";

contract IssuanceAuthorityHarness {
    function allocate(
        ZkIdentityIssuanceRegistry registry,
        bytes32 issuerKeyId,
        bytes32 duplicateKey,
        uint256 credentialCommitment,
        uint32 expectedStatusId,
        uint32 expectedEpoch
    ) external returns (uint32, uint32) {
        return registry.allocateCredential(
            issuerKeyId, duplicateKey, credentialCommitment, expectedStatusId, expectedEpoch
        );
    }
}

contract StatusPublisherHarness {
    function publish(
        ZkIdentityIssuanceRegistry registry,
        bytes32 issuerKeyId,
        uint64 expectedNextStatusId,
        bytes32 root
    ) external returns (uint32) {
        return registry.publishStatusSnapshot(issuerKeyId, expectedNextStatusId, root);
    }
}

contract ZkIdentityIssuanceRegistryHarness is ZkIdentityIssuanceRegistry {
    constructor(address initialOwner) ZkIdentityIssuanceRegistry(initialOwner) {}

    function setLatestStatusSnapshotId(bytes32 issuerKeyId, uint32 snapshotId) external {
        latestStatusSnapshotId[issuerKeyId] = snapshotId;
    }
}

contract ZkIdentityIssuanceRegistryTest is Test {
    uint256 internal constant BN254_SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    bytes32 internal constant ISSUER_KEY_ID = keccak256("issuer-key-1");
    bytes32 internal constant ISSUER_KEY_ID_2 = keccak256("issuer-key-2");
    bytes32 internal constant DUPLICATE_KEY_1 = keccak256("issuance-duplicate-1");
    bytes32 internal constant DUPLICATE_KEY_2 = keccak256("issuance-duplicate-2");
    uint256 internal constant COMMITMENT_1 = 123_456_789;
    uint256 internal constant COMMITMENT_2 = 987_654_321;
    bytes32 internal constant STATUS_ROOT_1 = bytes32(uint256(111_111));
    bytes32 internal constant STATUS_ROOT_2 = bytes32(uint256(222_222));
    address internal constant OTHER = address(0xBEEF);

    ZkIdentityIssuanceRegistryHarness internal registry;
    IssuanceAuthorityHarness internal authority;
    StatusPublisherHarness internal publisher;

    event CredentialAllocated(
        bytes32 indexed issuerKeyId, uint32 indexed statusId, uint256 indexed credentialCommitment, uint32 issuedAtEpoch
    );
    event StatusSnapshotPublished(
        bytes32 indexed issuerKeyId,
        uint32 indexed snapshotId,
        bytes32 indexed root,
        uint32 activatedThroughStatusId,
        uint64 publishedAt,
        address publisher
    );

    function setUp() public {
        vm.chainId(84_532);
        vm.warp(230 * 90 days + 1);
        registry = new ZkIdentityIssuanceRegistryHarness(address(this));
        authority = new IssuanceAuthorityHarness();
        publisher = new StatusPublisherHarness();
        registry.registerIssuerKey(ISSUER_KEY_ID);
        registry.authorizeIssuanceAuthority(ISSUER_KEY_ID, address(authority));
        registry.authorizeStatusPublisher(ISSUER_KEY_ID, address(publisher));
    }

    function test_PublishesAllocationBoundStatusSnapshot() public {
        _allocate(DUPLICATE_KEY_1, COMMITMENT_1, 1, 230);

        vm.expectEmit(true, true, true, true, address(registry));
        emit StatusSnapshotPublished(ISSUER_KEY_ID, 1, STATUS_ROOT_1, 1, uint64(block.timestamp), address(publisher));
        uint32 snapshotId = _publish(2, STATUS_ROOT_1);
        assertEq(snapshotId, 1);
        assertEq(registry.latestStatusSnapshotId(ISSUER_KEY_ID), 1);
        assertEq(registry.statusSnapshotIdForRoot(ISSUER_KEY_ID, STATUS_ROOT_1), 1);

        (bytes32 root, uint32 activatedThroughStatusId, uint64 publishedAt, bool revoked) =
            registry.statusSnapshots(ISSUER_KEY_ID, 1);
        assertEq(root, STATUS_ROOT_1);
        assertEq(activatedThroughStatusId, 1);
        assertEq(publishedAt, block.timestamp);
        assertFalse(revoked);
        assertTrue(registry.isStatusSnapshotAccepted(ISSUER_KEY_ID, 1, STATUS_ROOT_1));
        assertFalse(registry.isStatusSnapshotAccepted(ISSUER_KEY_ID, 1, STATUS_ROOT_2));
    }

    function test_AllocationRaceAndEmptyRegistryFailWithoutConsumingRoot() public {
        vm.expectRevert(
            abi.encodeWithSelector(ZkIdentityIssuanceRegistry.NoAllocatedCredentials.selector, ISSUER_KEY_ID)
        );
        _publish(1, STATUS_ROOT_1);

        _allocate(DUPLICATE_KEY_1, COMMITMENT_1, 1, 230);
        vm.expectRevert(
            abi.encodeWithSelector(ZkIdentityIssuanceRegistry.UnexpectedNextStatusId.selector, uint64(2), uint64(1))
        );
        _publish(1, STATUS_ROOT_1);
        assertEq(registry.statusSnapshotIdForRoot(ISSUER_KEY_ID, STATUS_ROOT_1), 0);

        _publish(2, STATUS_ROOT_1);
    }

    function test_SnapshotsOverlapUntilExactGovernanceRevocation() public {
        _allocate(DUPLICATE_KEY_1, COMMITMENT_1, 1, 230);
        _publish(2, STATUS_ROOT_1);
        _allocate(DUPLICATE_KEY_2, COMMITMENT_2, 2, 230);
        _publish(3, STATUS_ROOT_2);

        (bytes32 root, uint32 activatedThroughStatusId,,) = registry.statusSnapshots(ISSUER_KEY_ID, 2);
        assertEq(root, STATUS_ROOT_2);
        assertEq(activatedThroughStatusId, 2);
        assertTrue(registry.isStatusSnapshotAccepted(ISSUER_KEY_ID, 1, STATUS_ROOT_1));
        assertTrue(registry.isStatusSnapshotAccepted(ISSUER_KEY_ID, 2, STATUS_ROOT_2));

        registry.revokeStatusSnapshot(ISSUER_KEY_ID, 1);
        assertFalse(registry.isStatusSnapshotAccepted(ISSUER_KEY_ID, 1, STATUS_ROOT_1));
        assertTrue(registry.isStatusSnapshotAccepted(ISSUER_KEY_ID, 2, STATUS_ROOT_2));
        vm.expectRevert(
            abi.encodeWithSelector(
                ZkIdentityIssuanceRegistry.StatusSnapshotAlreadyRevoked.selector, ISSUER_KEY_ID, uint32(1)
            )
        );
        registry.revokeStatusSnapshot(ISSUER_KEY_ID, 1);

        vm.expectRevert(
            abi.encodeWithSelector(ZkIdentityIssuanceRegistry.StatusRootAlreadyPublished.selector, STATUS_ROOT_1)
        );
        _publish(3, STATUS_ROOT_1);
    }

    function test_StatusPublisherAuthorizationAndCodehashFailClosed() public {
        vm.prank(OTHER);
        vm.expectRevert(
            abi.encodeWithSelector(ZkIdentityIssuanceRegistry.UnknownStatusPublisher.selector, ISSUER_KEY_ID, OTHER)
        );
        registry.publishStatusSnapshot(ISSUER_KEY_ID, 1, STATUS_ROOT_1);

        registry.retireStatusPublisher(ISSUER_KEY_ID, address(publisher));
        vm.expectRevert(
            abi.encodeWithSelector(
                ZkIdentityIssuanceRegistry.StatusPublisherInactive.selector, ISSUER_KEY_ID, address(publisher)
            )
        );
        _publish(1, STATUS_ROOT_1);

        StatusPublisherHarness nextPublisher = new StatusPublisherHarness();
        registry.authorizeStatusPublisher(ISSUER_KEY_ID, address(nextPublisher));
        bytes32 expected = address(nextPublisher).codehash;
        vm.etch(address(nextPublisher), hex"00");
        vm.expectRevert(
            abi.encodeWithSelector(
                ZkIdentityIssuanceRegistry.StatusPublisherCodehashChanged.selector,
                expected,
                address(nextPublisher).codehash
            )
        );
        vm.prank(address(nextPublisher));
        registry.publishStatusSnapshot(ISSUER_KEY_ID, 1, STATUS_ROOT_1);
    }

    function test_StatusSnapshotRejectsInvalidRootsAndPublicationTimeOverflow() public {
        _allocate(DUPLICATE_KEY_1, COMMITMENT_1, 1, 230);
        vm.expectRevert(ZkIdentityIssuanceRegistry.InvalidStatusRoot.selector);
        _publish(2, bytes32(0));
        vm.expectRevert(ZkIdentityIssuanceRegistry.InvalidStatusRoot.selector);
        _publish(2, bytes32(BN254_SCALAR_FIELD));

        vm.warp(uint256(type(uint64).max) + 1);
        vm.expectRevert(ZkIdentityIssuanceRegistry.StatusPublicationTimeOverflow.selector);
        _publish(2, STATUS_ROOT_1);
    }

    function test_StatusSnapshotIdOverflowFailsWithoutConsumingRoot() public {
        _allocate(DUPLICATE_KEY_1, COMMITMENT_1, 1, 230);
        registry.setLatestStatusSnapshotId(ISSUER_KEY_ID, type(uint32).max);

        vm.expectRevert(
            abi.encodeWithSelector(ZkIdentityIssuanceRegistry.StatusSnapshotIdOverflow.selector, ISSUER_KEY_ID)
        );
        _publish(2, STATUS_ROOT_1);
        assertEq(registry.statusSnapshotIdForRoot(ISSUER_KEY_ID, STATUS_ROOT_1), 0);
    }

    function test_IssuerRetirementRejectsPublicationButStillAllowsSnapshotRevocation() public {
        _allocate(DUPLICATE_KEY_1, COMMITMENT_1, 1, 230);
        _publish(2, STATUS_ROOT_1);
        registry.retireIssuerKey(ISSUER_KEY_ID);

        assertFalse(registry.isStatusSnapshotAccepted(ISSUER_KEY_ID, 1, STATUS_ROOT_1));
        vm.expectRevert(abi.encodeWithSelector(ZkIdentityIssuanceRegistry.IssuerKeyInactive.selector, ISSUER_KEY_ID));
        _publish(2, STATUS_ROOT_2);
        registry.revokeStatusSnapshot(ISSUER_KEY_ID, 1);
        (,,, bool revoked) = registry.statusSnapshots(ISSUER_KEY_ID, 1);
        assertTrue(revoked);
    }

    function test_ConstructorPinsOwnershipEpochAndIssuanceDomain() public view {
        assertEq(registry.owner(), address(this));
        assertEq(registry.currentEpoch(), 230);
        assertEq(registry.EPOCH(), 90 days);
        assertEq(registry.issuanceDomain(), ZkIdentityEncoding.issuanceDomainHash(block.chainid, address(registry)));

        (bool registered, bool active, uint64 nextStatusId) = registry.issuerKeys(ISSUER_KEY_ID);
        assertTrue(registered);
        assertTrue(active);
        assertEq(nextStatusId, 1);
        (bytes32 codehash, bool authorityRegistered, bool authorityActive) =
            registry.issuanceAuthorities(ISSUER_KEY_ID, address(authority));
        assertEq(codehash, address(authority).codehash);
        assertTrue(authorityRegistered);
        assertTrue(authorityActive);
    }

    function test_AllocatesMonotonicSlotsAndRecordsOpaqueCommitments() public {
        vm.expectEmit(true, true, true, true, address(registry));
        emit CredentialAllocated(ISSUER_KEY_ID, 1, COMMITMENT_1, 230);
        (uint32 statusId, uint32 epoch) = _allocate(DUPLICATE_KEY_1, COMMITMENT_1, 1, 230);
        assertEq(statusId, 1);
        assertEq(epoch, 230);

        (statusId, epoch) = _allocate(DUPLICATE_KEY_2, COMMITMENT_2, 2, 230);
        assertEq(statusId, 2);
        assertEq(epoch, 230);
        (,, uint64 nextStatusId) = registry.issuerKeys(ISSUER_KEY_ID);
        assertEq(nextStatusId, 3);

        ZkIdentityIssuanceRegistry.Issuance memory issuance = registry.issuanceForDuplicateKey(DUPLICATE_KEY_1);
        assertEq(issuance.issuerKeyId, ISSUER_KEY_ID);
        assertEq(issuance.credentialCommitment, COMMITMENT_1);
        assertEq(issuance.statusId, 1);
        assertEq(issuance.issuedAtEpoch, 230);
        assertTrue(registry.isDuplicateKeyUsed(DUPLICATE_KEY_1));
        assertTrue(registry.credentialCommitmentUsed(COMMITMENT_1));
        assertEq(registry.credentialCommitmentAt(ISSUER_KEY_ID, 1), COMMITMENT_1);
    }

    function test_DuplicateKeyIsGlobalAcrossIssuerKeys() public {
        _allocate(DUPLICATE_KEY_1, COMMITMENT_1, 1, 230);
        registry.registerIssuerKey(ISSUER_KEY_ID_2);
        registry.authorizeIssuanceAuthority(ISSUER_KEY_ID_2, address(authority));

        vm.expectRevert(
            abi.encodeWithSelector(
                ZkIdentityIssuanceRegistry.DuplicateKeyAlreadyUsed.selector, ISSUER_KEY_ID, uint32(1)
            )
        );
        authority.allocate(registry, ISSUER_KEY_ID_2, DUPLICATE_KEY_1, COMMITMENT_2, 1, 230);
    }

    function test_CredentialCommitmentCannotBeReused() public {
        _allocate(DUPLICATE_KEY_1, COMMITMENT_1, 1, 230);
        vm.expectRevert(ZkIdentityIssuanceRegistry.CredentialCommitmentAlreadyUsed.selector);
        _allocate(DUPLICATE_KEY_2, COMMITMENT_1, 2, 230);
    }

    function test_RacedSlotOrEpochFailsWithoutConsumingRequest() public {
        vm.expectRevert(
            abi.encodeWithSelector(ZkIdentityIssuanceRegistry.UnexpectedStatusId.selector, uint32(1), uint32(2))
        );
        _allocate(DUPLICATE_KEY_1, COMMITMENT_1, 2, 230);
        assertFalse(registry.isDuplicateKeyUsed(DUPLICATE_KEY_1));

        vm.expectRevert(
            abi.encodeWithSelector(
                ZkIdentityIssuanceRegistry.UnexpectedIssuanceEpoch.selector, uint32(230), uint32(229)
            )
        );
        _allocate(DUPLICATE_KEY_1, COMMITMENT_1, 1, 229);
        assertFalse(registry.isDuplicateKeyUsed(DUPLICATE_KEY_1));

        _allocate(DUPLICATE_KEY_1, COMMITMENT_1, 1, 230);
    }

    function test_RejectsInvalidDuplicateKeyAndCommitmentFields() public {
        vm.expectRevert(ZkIdentityIssuanceRegistry.InvalidDuplicateKey.selector);
        _allocate(bytes32(0), COMMITMENT_1, 1, 230);
        vm.expectRevert(ZkIdentityIssuanceRegistry.InvalidCredentialCommitment.selector);
        _allocate(DUPLICATE_KEY_1, 0, 1, 230);
        vm.expectRevert(ZkIdentityIssuanceRegistry.InvalidCredentialCommitment.selector);
        _allocate(DUPLICATE_KEY_1, BN254_SCALAR_FIELD, 1, 230);
    }

    function test_OnlyActiveAuthorizedCallerMayAllocate() public {
        vm.prank(OTHER);
        vm.expectRevert(
            abi.encodeWithSelector(ZkIdentityIssuanceRegistry.UnknownIssuanceAuthority.selector, ISSUER_KEY_ID, OTHER)
        );
        registry.allocateCredential(ISSUER_KEY_ID, DUPLICATE_KEY_1, COMMITMENT_1, 1, 230);

        registry.retireIssuanceAuthority(ISSUER_KEY_ID, address(authority));
        vm.expectRevert(
            abi.encodeWithSelector(
                ZkIdentityIssuanceRegistry.IssuanceAuthorityInactive.selector, ISSUER_KEY_ID, address(authority)
            )
        );
        _allocate(DUPLICATE_KEY_1, COMMITMENT_1, 1, 230);
    }

    function test_IssuerAndAuthorityLifecycleIsAdditiveAndFailClosed() public {
        registry.retireIssuanceAuthority(ISSUER_KEY_ID, address(authority));
        vm.expectRevert(
            abi.encodeWithSelector(
                ZkIdentityIssuanceRegistry.IssuanceAuthorityAlreadyRegistered.selector,
                ISSUER_KEY_ID,
                address(authority)
            )
        );
        registry.authorizeIssuanceAuthority(ISSUER_KEY_ID, address(authority));

        registry.retireIssuerKey(ISSUER_KEY_ID);
        vm.expectRevert(abi.encodeWithSelector(ZkIdentityIssuanceRegistry.IssuerKeyInactive.selector, ISSUER_KEY_ID));
        _allocate(DUPLICATE_KEY_1, COMMITMENT_1, 1, 230);
        vm.expectRevert(
            abi.encodeWithSelector(ZkIdentityIssuanceRegistry.IssuerKeyAlreadyRegistered.selector, ISSUER_KEY_ID)
        );
        registry.registerIssuerKey(ISSUER_KEY_ID);
    }

    function test_AuthorizedContractCodehashDriftFailsClosed() public {
        bytes32 expected = address(authority).codehash;
        vm.etch(address(authority), hex"00");
        bytes32 actual = address(authority).codehash;
        vm.prank(address(authority));
        vm.expectRevert(
            abi.encodeWithSelector(
                ZkIdentityIssuanceRegistry.IssuanceAuthorityCodehashChanged.selector, expected, actual
            )
        );
        registry.allocateCredential(ISSUER_KEY_ID, DUPLICATE_KEY_1, COMMITMENT_1, 1, 230);
    }

    function test_EoaAuthorityIsPinnedToCodeFreeAccount() public {
        registry.authorizeIssuanceAuthority(ISSUER_KEY_ID, OTHER);
        vm.prank(OTHER);
        registry.allocateCredential(ISSUER_KEY_ID, DUPLICATE_KEY_1, COMMITMENT_1, 1, 230);

        address nextAuthority = address(0xCAFE);
        registry.authorizeIssuanceAuthority(ISSUER_KEY_ID, nextAuthority);
        vm.etch(nextAuthority, hex"00");
        vm.prank(nextAuthority);
        vm.expectRevert(
            abi.encodeWithSelector(
                ZkIdentityIssuanceRegistry.IssuanceAuthorityCodehashChanged.selector, bytes32(0), nextAuthority.codehash
            )
        );
        registry.allocateCredential(ISSUER_KEY_ID, DUPLICATE_KEY_2, COMMITMENT_2, 2, 230);
    }

    function test_DuplicateKeyIsNotEmitted() public {
        vm.recordLogs();
        _allocate(DUPLICATE_KEY_1, COMMITMENT_1, 1, 230);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 1);
        for (uint256 i = 0; i < logs[0].topics.length; ++i) {
            assertNotEq(logs[0].topics[i], DUPLICATE_KEY_1);
        }
        assertNotEq(keccak256(logs[0].data), keccak256(abi.encode(DUPLICATE_KEY_1)));
    }

    function test_AdminFunctionsAreOwnerOnlyAndValidateInputs() public {
        vm.prank(OTHER);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, OTHER));
        registry.registerIssuerKey(ISSUER_KEY_ID_2);

        vm.prank(OTHER);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, OTHER));
        registry.authorizeStatusPublisher(ISSUER_KEY_ID, OTHER);

        vm.expectRevert(ZkIdentityIssuanceRegistry.InvalidIssuerKeyId.selector);
        registry.registerIssuerKey(bytes32(0));
        vm.expectRevert(ZkIdentityIssuanceRegistry.InvalidIssuanceAuthority.selector);
        registry.authorizeIssuanceAuthority(ISSUER_KEY_ID, address(0));
        vm.expectRevert(abi.encodeWithSelector(ZkIdentityIssuanceRegistry.UnknownIssuerKey.selector, ISSUER_KEY_ID_2));
        registry.authorizeIssuanceAuthority(ISSUER_KEY_ID_2, OTHER);
        vm.expectRevert(
            abi.encodeWithSelector(ZkIdentityIssuanceRegistry.UnknownIssuanceAuthority.selector, ISSUER_KEY_ID, OTHER)
        );
        registry.retireIssuanceAuthority(ISSUER_KEY_ID, OTHER);
        vm.expectRevert(ZkIdentityIssuanceRegistry.InvalidStatusPublisher.selector);
        registry.authorizeStatusPublisher(ISSUER_KEY_ID, address(0));
        vm.expectRevert(abi.encodeWithSelector(ZkIdentityIssuanceRegistry.UnknownIssuerKey.selector, ISSUER_KEY_ID_2));
        registry.authorizeStatusPublisher(ISSUER_KEY_ID_2, OTHER);
        vm.expectRevert(
            abi.encodeWithSelector(ZkIdentityIssuanceRegistry.UnknownStatusPublisher.selector, ISSUER_KEY_ID, OTHER)
        );
        registry.retireStatusPublisher(ISSUER_KEY_ID, OTHER);
        vm.expectRevert(
            abi.encodeWithSelector(ZkIdentityIssuanceRegistry.UnknownStatusSnapshot.selector, ISSUER_KEY_ID, uint32(1))
        );
        registry.revokeStatusSnapshot(ISSUER_KEY_ID, 1);
    }

    function test_OwnershipTransferRequiresAcceptance() public {
        registry.transferOwnership(OTHER);
        assertEq(registry.owner(), address(this));
        assertEq(registry.pendingOwner(), OTHER);
        vm.prank(OTHER);
        registry.acceptOwnership();
        assertEq(registry.owner(), OTHER);
    }

    function test_CurrentEpochFailsClosedOnUint32Overflow() public {
        vm.warp((uint256(type(uint32).max) + 1) * 90 days);
        vm.expectRevert(ZkIdentityIssuanceRegistry.IssuanceEpochOverflow.selector);
        registry.currentEpoch();
    }

    function test_FinalUint32SlotAllocatesOnceThenExhausts() public {
        // Boundary injection: `issuerKeys` is storage slot 2 and its two bools
        // precede the packed uint64 counter. Avoids billions of setup calls.
        bytes32 issuerStorageSlot = keccak256(abi.encode(ISSUER_KEY_ID, uint256(2)));
        uint256 packedIssuer = uint256(1) | (uint256(1) << 8) | (uint256(type(uint32).max) << 16);
        vm.store(address(registry), issuerStorageSlot, bytes32(packedIssuer));

        _allocate(DUPLICATE_KEY_1, COMMITMENT_1, type(uint32).max, 230);
        (,, uint64 nextStatusId) = registry.issuerKeys(ISSUER_KEY_ID);
        assertEq(nextStatusId, uint64(type(uint32).max) + 1);
        _publish(uint64(type(uint32).max) + 1, STATUS_ROOT_1);
        (, uint32 activatedThroughStatusId,,) = registry.statusSnapshots(ISSUER_KEY_ID, 1);
        assertEq(activatedThroughStatusId, type(uint32).max);

        vm.expectRevert(abi.encodeWithSelector(ZkIdentityIssuanceRegistry.StatusSlotsExhausted.selector, ISSUER_KEY_ID));
        _allocate(DUPLICATE_KEY_2, COMMITMENT_2, type(uint32).max, 230);
    }

    function _publish(uint64 expectedNextStatusId, bytes32 root) private returns (uint32) {
        return publisher.publish(registry, ISSUER_KEY_ID, expectedNextStatusId, root);
    }

    function _allocate(bytes32 duplicateKey, uint256 commitment, uint32 statusId, uint32 epoch)
        private
        returns (uint32, uint32)
    {
        return authority.allocate(registry, ISSUER_KEY_ID, duplicateKey, commitment, statusId, epoch);
    }
}
