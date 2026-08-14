// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {ZkIdentityEncoding} from "../src/ZkIdentityEncoding.sol";

contract ZkIdentityEncodingHarness {
    function privateCredentialFingerprint(ZkIdentityEncoding.PrivateCredential memory credential)
        external
        pure
        returns (bytes32)
    {
        return ZkIdentityEncoding.privateCredentialFingerprint(credential);
    }

    function nullifierScopeHash(ZkIdentityEncoding.NullifierScope memory scope) external pure returns (bytes32) {
        return ZkIdentityEncoding.nullifierScopeHash(scope);
    }

    function presentationBindingHash(ZkIdentityEncoding.PresentationBinding memory binding)
        external
        pure
        returns (bytes32)
    {
        return ZkIdentityEncoding.presentationBindingHash(binding);
    }

    function dynamicStatusPolicyHash(ZkIdentityEncoding.DynamicStatusPolicy memory policy)
        external
        pure
        returns (bytes32)
    {
        return ZkIdentityEncoding.dynamicStatusPolicyHash(policy);
    }

    function scopedNullifierPreimage(uint256 holderSecret, ZkIdentityEncoding.NullifierScope memory scope)
        external
        pure
        returns (uint256[6] memory)
    {
        return ZkIdentityEncoding.scopedNullifierPreimage(holderSecret, scope);
    }

    function decodePublicSignals(uint256[] memory signals)
        external
        pure
        returns (ZkIdentityEncoding.PublicSignals memory)
    {
        return ZkIdentityEncoding.decodePublicSignals(signals);
    }
}

/// @notice Parity vectors mirrored by the TypeScript SDK and `ubi2-zkpoh` Rust tests.
contract ZkIdentityEncodingTest is Test {
    ZkIdentityEncodingHarness internal harness;

    bytes32 internal constant ISSUER_KEY_ID = 0x02bc3d3958ba083a8c814e7961433903dd91b59f2af591138467a1202da88d21;
    bytes32 internal constant STATUS_ID = 0x84a8b6c45e1e6baf59f05ec3b1fb2317d2ec4b773c7f64d0b8c83d63ba2b3f3a;
    bytes32 internal constant POLICY_HASH = 0x3f71ddd64fc1edef180756674529dd32b2c90f7288d2f0ced062e781a0cda3a2;

    function setUp() public {
        harness = new ZkIdentityEncodingHarness();
    }

    function _scope() internal pure returns (ZkIdentityEncoding.NullifierScope memory) {
        return ZkIdentityEncoding.NullifierScope({
            mode: 1,
            chainId: 84532,
            verifier: 0x1111111111111111111111111111111111111111,
            consumer: 0x2222222222222222222222222222222222222222,
            context: keccak256("membership:season-1"),
            policyHash: POLICY_HASH
        });
    }

    function _signals() internal pure returns (uint256[] memory signals) {
        signals = new uint256[](18);
        signals[0] = 1;
        signals[1] = 148470164970938473527131569574145738248;
        signals[2] = 143106528634218877324650955020395841930;
        signals[3] = 3635849571425045330628617071914858755;
        signals[4] = 294515953839665300979725696144129953057;
        signals[5] = 56743338650715011814192789619580272247;
        signals[6] = 283811814910439300292750339907545096601;
        signals[7] = 84332592671497082657127333409566874930;
        signals[8] = 237646548228780080072226119388672926626;
        signals[9] = 335934530153236393154503107393022614242;
        signals[10] = 104498824908571987640421674469385365408;
        signals[11] = 148368269012998052364797751201271282309;
        signals[12] = 126559033271166220203394870356863420182;
        signals[13] = 4242424242;
        signals[14] = 292300327466180583640736966543256603931186508595;
        signals[15] = 1;
        signals[16] = 230;
        signals[17] = 0;
    }

    function test_PrivateCredentialFingerprint_Parity() public view {
        ZkIdentityEncoding.PrivateCredential memory credential = ZkIdentityEncoding.PrivateCredential({
            issuerKeyId: ISSUER_KEY_ID,
            statusId: STATUS_ID,
            holderSecret: 123456789,
            credentialBlinding: 987654321,
            dateOfBirth: 19900403,
            nationality: bytes3("ARG"),
            issuingState: bytes3("ARG"),
            expiryDate: 20310709,
            documentClass: 1,
            assurance: 2,
            issuedAtEpoch: 230
        });
        assertEq(
            harness.privateCredentialFingerprint(credential),
            0x5f3113cae53c94a863c5362d229137c767d996e444283541f19b13aac89e7f11
        );
    }

    function test_NullifierScopeAndPreimage_Parity() public view {
        ZkIdentityEncoding.NullifierScope memory scope = _scope();
        assertEq(harness.nullifierScopeHash(scope), 0x6f9eb06ffea41fade00efe22ab9a7a855f366218cd9248acb84e7578a4f90716);
        uint256[6] memory preimage = harness.scopedNullifierPreimage(123456789, scope);
        uint256[6] memory expected = [
            uint256(3753063511814324395807447140844095217),
            uint256(39595397136107903161255285981469469429),
            uint256(1),
            uint256(123456789),
            uint256(148368269012998052364797751201271282309),
            uint256(126559033271166220203394870356863420182)
        ];
        for (uint256 i = 0; i < expected.length; ++i) {
            assertEq(preimage[i], expected[i]);
        }
    }

    function test_PresentationBindingHash_Parity() public view {
        bytes32 binding = harness.presentationBindingHash(
            ZkIdentityEncoding.PresentationBinding({
                policyHash: POLICY_HASH,
                chainId: 84532,
                verifier: 0x1111111111111111111111111111111111111111,
                consumer: 0x2222222222222222222222222222222222222222,
                subject: 0x3333333333333333333333333333333333333333,
                context: keccak256("membership:season-1"),
                challenge: keccak256("challenge-1"),
                epoch: 230
            })
        );
        assertEq(binding, 0xfcbaa318d3aba026a8827d332ec45ae24e9dbdd9ca6029b6fd3741b4e670e7a0);
    }

    function test_PresentationBinding_RejectsZeroTrustDomains() public {
        ZkIdentityEncoding.PresentationBinding memory binding = ZkIdentityEncoding.PresentationBinding({
            policyHash: POLICY_HASH,
            chainId: 84532,
            verifier: address(0),
            consumer: 0x2222222222222222222222222222222222222222,
            subject: 0x3333333333333333333333333333333333333333,
            context: keccak256("membership:season-1"),
            challenge: keccak256("challenge-1"),
            epoch: 230
        });
        vm.expectRevert(ZkIdentityEncoding.InvalidPresentationBinding.selector);
        harness.presentationBindingHash(binding);
    }

    function test_DynamicStatusPolicyHash_Parity() public view {
        bytes32 policyHash = harness.dynamicStatusPolicyHash(
            ZkIdentityEncoding.DynamicStatusPolicy({
                providerIdHash: 0x116175bf9d7293d67f2e7b7309631a6b8c1cb2eef79f38ef33e45ab0968a8a55,
                listVersionHash: 0xe8261aa0634bc9f1544375a820c195025e7a45b6e29f0ba57769964d92205726,
                statusRoot: 0x217f00d353043696f123b4919b74ba57900770ce0f80414db45d0e52cbbf2ccf,
                maximumAgeSeconds: 86_400
            })
        );
        assertEq(policyHash, 0x554b29b8540ffafa1fa4bc6e54847f887d03b4b9b29449ba2418cbc7f9fa3381);
    }

    function test_DynamicStatusPolicyHash_RejectsInvalidMetadata() public {
        ZkIdentityEncoding.DynamicStatusPolicy memory policy = ZkIdentityEncoding.DynamicStatusPolicy({
            providerIdHash: bytes32(0),
            listVersionHash: bytes32(uint256(2)),
            statusRoot: bytes32(uint256(3)),
            maximumAgeSeconds: 86_400
        });
        vm.expectRevert(ZkIdentityEncoding.InvalidDynamicStatusPolicy.selector);
        harness.dynamicStatusPolicyHash(policy);

        policy.providerIdHash = bytes32(uint256(1));
        policy.maximumAgeSeconds = 59;
        vm.expectRevert(ZkIdentityEncoding.InvalidDynamicStatusPolicy.selector);
        harness.dynamicStatusPolicyHash(policy);
    }

    function test_NullifierPreimage_RejectsNonCanonicalHolderSecret() public {
        vm.expectRevert(ZkIdentityEncoding.InvalidHolderSecret.selector);
        harness.scopedNullifierPreimage(0, _scope());

        vm.expectRevert(ZkIdentityEncoding.InvalidHolderSecret.selector);
        harness.scopedNullifierPreimage(
            21888242871839275222246405745257275088548364400416034343698204186575808495617, _scope()
        );
    }

    function test_NullifierScope_RejectsUnsupportedModeAndZeroConsumer() public {
        ZkIdentityEncoding.NullifierScope memory scope = _scope();
        scope.mode = 3;
        vm.expectRevert(ZkIdentityEncoding.InvalidNullifierScope.selector);
        harness.nullifierScopeHash(scope);

        scope = _scope();
        scope.consumer = address(0);
        vm.expectRevert(ZkIdentityEncoding.InvalidNullifierScope.selector);
        harness.nullifierScopeHash(scope);
    }

    function test_PublicSignals_DecodeLosslessly() public view {
        ZkIdentityEncoding.PublicSignals memory decoded = harness.decodePublicSignals(_signals());
        assertEq(decoded.circuitId, keccak256("circuit:v2-spike:1"));
        assertEq(decoded.issuerKeyId, ISSUER_KEY_ID);
        assertEq(decoded.activeRoot, keccak256("active-root:testnet:230"));
        assertEq(decoded.policyHash, POLICY_HASH);
        assertEq(decoded.presentationBindingHash, 0xfcbaa318d3aba026a8827d332ec45ae24e9dbdd9ca6029b6fd3741b4e670e7a0);
        assertEq(decoded.nullifierScopeHash, 0x6f9eb06ffea41fade00efe22ab9a7a855f366218cd9248acb84e7578a4f90716);
        assertEq(decoded.scopedNullifier, 4242424242);
        assertEq(decoded.subject, 0x3333333333333333333333333333333333333333);
        assertTrue(decoded.result);
        assertEq(decoded.credentialEpoch, 230);
        assertEq(decoded.statusEpoch, 0);
    }

    function test_PublicSignals_RejectNonCanonicalField() public {
        uint256[] memory signals = _signals();
        signals[13] = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        vm.expectRevert(abi.encodeWithSelector(ZkIdentityEncoding.NonCanonicalField.selector, 13));
        harness.decodePublicSignals(signals);
    }

    function test_PublicSignals_RejectNonBooleanResult() public {
        uint256[] memory signals = _signals();
        signals[15] = 2;
        vm.expectRevert(ZkIdentityEncoding.InvalidResult.selector);
        harness.decodePublicSignals(signals);
    }

    function test_PublicSignals_RejectZeroSubject() public {
        uint256[] memory signals = _signals();
        signals[14] = 0;
        vm.expectRevert(ZkIdentityEncoding.InvalidSubject.selector);
        harness.decodePublicSignals(signals);
    }

    function test_PublicSignals_RejectWideOrZeroIdentifier() public {
        uint256[] memory signals = _signals();
        signals[1] = uint256(type(uint128).max) + 1;
        vm.expectRevert(abi.encodeWithSelector(ZkIdentityEncoding.InvalidIdentifier.selector, 1));
        harness.decodePublicSignals(signals);

        signals = _signals();
        signals[7] = 0;
        signals[8] = 0;
        vm.expectRevert(abi.encodeWithSelector(ZkIdentityEncoding.InvalidIdentifier.selector, 7));
        harness.decodePublicSignals(signals);
    }
}
