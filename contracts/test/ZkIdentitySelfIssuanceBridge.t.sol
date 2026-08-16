// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {ZkIdentityIssuanceRegistry} from "../src/ZkIdentityIssuanceRegistry.sol";
import {ZkIdentitySelfIssuanceBridge} from "../src/ZkIdentitySelfIssuanceBridge.sol";

contract ZkIdentitySelfIssuanceBridgeTest is Test {
    bytes32 internal constant ISSUER_KEY_ID = keccak256("issuer-key:self:testnet:v1");
    bytes32 internal constant SELF_CONFIG_ID = keccak256("self-config:production:v1");
    bytes32 internal constant DUPLICATE_KEY_1 = keccak256("registry-scoped-self-nullifier:1");
    bytes32 internal constant DUPLICATE_KEY_2 = keccak256("registry-scoped-self-nullifier:2");
    uint256 internal constant AUTHORITY_KEY = 0xA11CE;
    uint256 internal constant WRONG_AUTHORITY_KEY = 0xB0B;
    uint256 internal constant SUBJECT_KEY = 0xCAFE;
    uint256 internal constant COMMITMENT_1 = 123_456_789;
    uint256 internal constant COMMITMENT_2 = 987_654_321;

    bytes32 internal constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 internal constant NAME_HASH = keccak256("ProofOfHumanitySelfIssuance");
    bytes32 internal constant VERSION_HASH = keccak256("1");
    bytes32 internal constant AUTHORIZATION_TYPEHASH = keccak256(
        "SelfIssuanceAuthorization(address subject,bytes32 duplicateKey,uint256 credentialCommitment,bytes32 issuerKeyId,uint32 expectedStatusId,uint32 expectedEpoch,uint64 deadline,bytes32 selfConfigId)"
    );

    ZkIdentityIssuanceRegistry internal registry;
    ZkIdentitySelfIssuanceBridge internal bridge;
    address internal authority;
    address internal subject;

    event CredentialAllocated(
        bytes32 indexed issuerKeyId, uint32 indexed statusId, uint256 indexed credentialCommitment, uint32 issuedAtEpoch
    );
    event SelfCredentialIssued(
        bytes32 indexed issuerKeyId, uint32 indexed statusId, uint256 indexed credentialCommitment, uint32 issuedAtEpoch
    );

    function setUp() public {
        vm.chainId(84_532);
        vm.warp(230 * 90 days + 1);
        authority = vm.addr(AUTHORITY_KEY);
        subject = vm.addr(SUBJECT_KEY);

        registry = new ZkIdentityIssuanceRegistry(address(this));
        registry.registerIssuerKey(ISSUER_KEY_ID);
        bridge = new ZkIdentitySelfIssuanceBridge(registry, ISSUER_KEY_ID, authority, SELF_CONFIG_ID);
        registry.authorizeIssuanceAuthority(ISSUER_KEY_ID, address(bridge));
    }

    function test_ConstructorPinsEveryTrustInput() public view {
        assertEq(address(bridge.registry()), address(registry));
        assertEq(bridge.issuerKeyId(), ISSUER_KEY_ID);
        assertEq(bridge.verificationAuthority(), authority);
        assertEq(bridge.selfConfigId(), SELF_CONFIG_ID);
        assertEq(bridge.AUTHORIZATION_TYPEHASH(), AUTHORIZATION_TYPEHASH);
        assertEq(bridge.MAX_AUTHORIZATION_LIFETIME(), 10 minutes);
        assertEq(
            bridge.domainSeparator(),
            keccak256(abi.encode(EIP712_DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(bridge)))
        );
    }

    function test_ValidAuthorizationAllocatesExactSlotAndEpoch() public {
        ZkIdentitySelfIssuanceBridge.SelfIssuanceAuthorization memory authorization =
            _authorization(DUPLICATE_KEY_1, COMMITMENT_1, 1, 230);
        bytes memory signature = _sign(authorization, AUTHORITY_KEY);

        vm.expectEmit(true, true, true, true, address(registry));
        emit CredentialAllocated(ISSUER_KEY_ID, 1, COMMITMENT_1, 230);
        vm.expectEmit(true, true, true, true, address(bridge));
        emit SelfCredentialIssued(ISSUER_KEY_ID, 1, COMMITMENT_1, 230);
        vm.prank(subject);
        (uint32 statusId, uint32 epoch) = bridge.issue(authorization, signature);

        assertEq(statusId, 1);
        assertEq(epoch, 230);
        assertTrue(registry.isDuplicateKeyUsed(DUPLICATE_KEY_1));
        assertEq(registry.credentialCommitmentAt(ISSUER_KEY_ID, 1), COMMITMENT_1);
    }

    function test_HashMatchesCanonicalEip712Encoding() public view {
        ZkIdentitySelfIssuanceBridge.SelfIssuanceAuthorization memory authorization =
            _authorization(DUPLICATE_KEY_1, COMMITMENT_1, 1, 230);
        assertEq(bridge.hashAuthorization(authorization), _digest(authorization, block.chainid, address(bridge)));
    }

    function test_OnlyProofBoundSubjectMaySubmit() public {
        ZkIdentitySelfIssuanceBridge.SelfIssuanceAuthorization memory authorization =
            _authorization(DUPLICATE_KEY_1, COMMITMENT_1, 1, 230);
        bytes memory signature = _sign(authorization, AUTHORITY_KEY);

        address caller = address(0xBEEF);
        vm.prank(caller);
        vm.expectRevert(abi.encodeWithSelector(ZkIdentitySelfIssuanceBridge.SubjectMismatch.selector, subject, caller));
        bridge.issue(authorization, signature);
        assertFalse(registry.isDuplicateKeyUsed(DUPLICATE_KEY_1));
    }

    function test_RejectsWrongSignerAndAnySignedFieldTampering() public {
        ZkIdentitySelfIssuanceBridge.SelfIssuanceAuthorization memory authorization =
            _authorization(DUPLICATE_KEY_1, COMMITMENT_1, 1, 230);

        address wrongAuthority = vm.addr(WRONG_AUTHORITY_KEY);
        vm.prank(subject);
        vm.expectRevert(
            abi.encodeWithSelector(ZkIdentitySelfIssuanceBridge.UnauthorizedVerificationSigner.selector, wrongAuthority)
        );
        bridge.issue(authorization, _sign(authorization, WRONG_AUTHORITY_KEY));

        bytes memory validSignature = _sign(authorization, AUTHORITY_KEY);
        authorization.credentialCommitment = COMMITMENT_2;
        address recovered = ECDSARecover.recover(bridge.hashAuthorization(authorization), validSignature);
        vm.prank(subject);
        vm.expectRevert(
            abi.encodeWithSelector(ZkIdentitySelfIssuanceBridge.UnauthorizedVerificationSigner.selector, recovered)
        );
        bridge.issue(authorization, validSignature);
        assertFalse(registry.isDuplicateKeyUsed(DUPLICATE_KEY_1));
    }

    function test_SignatureCannotCrossChainOrBridge() public {
        ZkIdentitySelfIssuanceBridge.SelfIssuanceAuthorization memory authorization =
            _authorization(DUPLICATE_KEY_1, COMMITMENT_1, 1, 230);
        bytes memory wrongChainSignature = _signFor(authorization, AUTHORITY_KEY, 1, address(bridge));
        address wrongChainRecovered = ECDSARecover.recover(bridge.hashAuthorization(authorization), wrongChainSignature);
        vm.prank(subject);
        vm.expectRevert(
            abi.encodeWithSelector(
                ZkIdentitySelfIssuanceBridge.UnauthorizedVerificationSigner.selector, wrongChainRecovered
            )
        );
        bridge.issue(authorization, wrongChainSignature);

        bytes memory wrongBridgeSignature = _signFor(authorization, AUTHORITY_KEY, block.chainid, address(0xBEEF));
        address wrongBridgeRecovered =
            ECDSARecover.recover(bridge.hashAuthorization(authorization), wrongBridgeSignature);
        vm.prank(subject);
        vm.expectRevert(
            abi.encodeWithSelector(
                ZkIdentitySelfIssuanceBridge.UnauthorizedVerificationSigner.selector, wrongBridgeRecovered
            )
        );
        bridge.issue(authorization, wrongBridgeSignature);
    }

    function test_RejectsExpiredWrongIssuerAndWrongVerifierConfiguration() public {
        ZkIdentitySelfIssuanceBridge.SelfIssuanceAuthorization memory authorization =
            _authorization(DUPLICATE_KEY_1, COMMITMENT_1, 1, 230);
        authorization.deadline = uint64(block.timestamp - 1);
        vm.prank(subject);
        vm.expectRevert(
            abi.encodeWithSelector(
                ZkIdentitySelfIssuanceBridge.AuthorizationExpired.selector, authorization.deadline, block.timestamp
            )
        );
        bridge.issue(authorization, _sign(authorization, AUTHORITY_KEY));

        authorization = _authorization(DUPLICATE_KEY_1, COMMITMENT_1, 1, 230);
        authorization.deadline = uint64(block.timestamp + 10 minutes + 1);
        vm.prank(subject);
        vm.expectRevert(
            abi.encodeWithSelector(
                ZkIdentitySelfIssuanceBridge.AuthorizationDeadlineTooFar.selector,
                authorization.deadline,
                block.timestamp + 10 minutes
            )
        );
        bridge.issue(authorization, _sign(authorization, AUTHORITY_KEY));

        authorization = _authorization(DUPLICATE_KEY_1, COMMITMENT_1, 1, 230);
        authorization.issuerKeyId = keccak256("other issuer");
        vm.prank(subject);
        vm.expectRevert(
            abi.encodeWithSelector(
                ZkIdentitySelfIssuanceBridge.AuthorizationIssuerKeyMismatch.selector,
                ISSUER_KEY_ID,
                authorization.issuerKeyId
            )
        );
        bridge.issue(authorization, _sign(authorization, AUTHORITY_KEY));

        authorization = _authorization(DUPLICATE_KEY_1, COMMITMENT_1, 1, 230);
        authorization.selfConfigId = keccak256("other Self config");
        vm.prank(subject);
        vm.expectRevert(
            abi.encodeWithSelector(
                ZkIdentitySelfIssuanceBridge.AuthorizationSelfConfigMismatch.selector,
                SELF_CONFIG_ID,
                authorization.selfConfigId
            )
        );
        bridge.issue(authorization, _sign(authorization, AUTHORITY_KEY));
    }

    function test_RegistryRejectsDuplicateAndStaleSlotWithoutPartialConsumption() public {
        ZkIdentitySelfIssuanceBridge.SelfIssuanceAuthorization memory first =
            _authorization(DUPLICATE_KEY_1, COMMITMENT_1, 1, 230);
        vm.prank(subject);
        bridge.issue(first, _sign(first, AUTHORITY_KEY));

        ZkIdentitySelfIssuanceBridge.SelfIssuanceAuthorization memory stale =
            _authorization(DUPLICATE_KEY_2, COMMITMENT_2, 1, 230);
        vm.prank(subject);
        vm.expectRevert(
            abi.encodeWithSelector(ZkIdentityIssuanceRegistry.UnexpectedStatusId.selector, uint32(2), uint32(1))
        );
        bridge.issue(stale, _sign(stale, AUTHORITY_KEY));
        assertFalse(registry.isDuplicateKeyUsed(DUPLICATE_KEY_2));

        stale.expectedStatusId = 2;
        vm.prank(subject);
        bridge.issue(stale, _sign(stale, AUTHORITY_KEY));

        ZkIdentitySelfIssuanceBridge.SelfIssuanceAuthorization memory duplicate =
            _authorization(DUPLICATE_KEY_1, 111, 3, 230);
        vm.prank(subject);
        vm.expectRevert(
            abi.encodeWithSelector(
                ZkIdentityIssuanceRegistry.DuplicateKeyAlreadyUsed.selector, ISSUER_KEY_ID, uint32(1)
            )
        );
        bridge.issue(duplicate, _sign(duplicate, AUTHORITY_KEY));
    }

    function test_DuplicateKeyIsAbsentFromEveryLog() public {
        ZkIdentitySelfIssuanceBridge.SelfIssuanceAuthorization memory authorization =
            _authorization(DUPLICATE_KEY_1, COMMITMENT_1, 1, 230);
        vm.recordLogs();
        vm.prank(subject);
        bridge.issue(authorization, _sign(authorization, AUTHORITY_KEY));

        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 2);
        for (uint256 i = 0; i < logs.length; ++i) {
            for (uint256 j = 0; j < logs[i].topics.length; ++j) {
                assertNotEq(logs[i].topics[j], DUPLICATE_KEY_1);
            }
            assertNotEq(keccak256(logs[i].data), keccak256(abi.encode(DUPLICATE_KEY_1)));
        }
    }

    function test_ConstructorRejectsInvalidOrInactiveTrustInputs() public {
        vm.expectRevert(ZkIdentitySelfIssuanceBridge.InvalidRegistry.selector);
        new ZkIdentitySelfIssuanceBridge(
            ZkIdentityIssuanceRegistry(address(0)), ISSUER_KEY_ID, authority, SELF_CONFIG_ID
        );
        vm.expectRevert(ZkIdentitySelfIssuanceBridge.InvalidIssuerKeyId.selector);
        new ZkIdentitySelfIssuanceBridge(registry, bytes32(0), authority, SELF_CONFIG_ID);
        vm.expectRevert(ZkIdentitySelfIssuanceBridge.InvalidVerificationAuthority.selector);
        new ZkIdentitySelfIssuanceBridge(registry, ISSUER_KEY_ID, address(0), SELF_CONFIG_ID);
        vm.expectRevert(ZkIdentitySelfIssuanceBridge.InvalidSelfConfigId.selector);
        new ZkIdentitySelfIssuanceBridge(registry, ISSUER_KEY_ID, authority, bytes32(0));

        bytes32 unknownIssuer = keccak256("unknown issuer");
        vm.expectRevert(abi.encodeWithSelector(ZkIdentitySelfIssuanceBridge.InactiveIssuerKey.selector, unknownIssuer));
        new ZkIdentitySelfIssuanceBridge(registry, unknownIssuer, authority, SELF_CONFIG_ID);
    }

    function _authorization(bytes32 duplicateKey, uint256 commitment, uint32 statusId, uint32 epoch)
        private
        view
        returns (ZkIdentitySelfIssuanceBridge.SelfIssuanceAuthorization memory)
    {
        return ZkIdentitySelfIssuanceBridge.SelfIssuanceAuthorization({
            subject: subject,
            duplicateKey: duplicateKey,
            credentialCommitment: commitment,
            issuerKeyId: ISSUER_KEY_ID,
            expectedStatusId: statusId,
            expectedEpoch: epoch,
            deadline: uint64(block.timestamp + 10 minutes),
            selfConfigId: SELF_CONFIG_ID
        });
    }

    function _sign(ZkIdentitySelfIssuanceBridge.SelfIssuanceAuthorization memory authorization, uint256 key)
        private
        view
        returns (bytes memory)
    {
        return _signFor(authorization, key, block.chainid, address(bridge));
    }

    function _signFor(
        ZkIdentitySelfIssuanceBridge.SelfIssuanceAuthorization memory authorization,
        uint256 key,
        uint256 signingChainId,
        address signingBridge
    ) private view returns (bytes memory) {
        bytes32 digest = _digest(authorization, signingChainId, signingBridge);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    function _digest(
        ZkIdentitySelfIssuanceBridge.SelfIssuanceAuthorization memory authorization,
        uint256 signingChainId,
        address signingBridge
    ) private pure returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                AUTHORIZATION_TYPEHASH,
                authorization.subject,
                authorization.duplicateKey,
                authorization.credentialCommitment,
                authorization.issuerKeyId,
                authorization.expectedStatusId,
                authorization.expectedEpoch,
                authorization.deadline,
                authorization.selfConfigId
            )
        );
        bytes32 domainSeparator =
            keccak256(abi.encode(EIP712_DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, signingChainId, signingBridge));
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }
}

/// @dev Tiny wrapper keeps the test's expected recovered signer explicit while
///      exercising the production bridge's OpenZeppelin ECDSA path.
library ECDSARecover {
    function recover(bytes32 digest, bytes memory signature) internal pure returns (address) {
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }
        return ecrecover(digest, v, r, s);
    }
}
