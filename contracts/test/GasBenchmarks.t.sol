// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {ProofOfHumanity, HumanityVoucher} from "../src/ProofOfHumanity.sol";
import {
    PredicateVerifier,
    PredicateAttestation,
    IPredicateProver,
    IPredicateProverReplay
} from "../src/PredicateVerifier.sol";
import {V2PackedStatusGroth16Verifier} from "../src/research/V2PackedStatusGroth16Verifier.sol";
import {V2DynamicStatusGroth16Verifier} from "../src/research/V2DynamicStatusGroth16Verifier.sol";
import {IZkIdentityGroth16Verifier, ZkIdentityPredicateProver} from "../src/ZkIdentityPredicateProver.sol";
import {ZkIdentityEncoding} from "../src/ZkIdentityEncoding.sol";
import {ZkIdentityIssuanceRegistry} from "../src/ZkIdentityIssuanceRegistry.sol";
import {ZkIdentitySelfIssuanceBridge} from "../src/ZkIdentitySelfIssuanceBridge.sol";
import {ZkIdentityVersionRegistry} from "../src/ZkIdentityVersionRegistry.sol";
import {V2PackedStatusFixture} from "./fixtures/V2PackedStatusFixture.sol";
import {V2DynamicStatusFixture} from "./fixtures/V2DynamicStatusFixture.sol";

contract GasPredicateProver is IPredicateProver, IPredicateProverReplay {
    address internal _subject;
    bytes32 internal _predicate;
    uint32 internal _epoch;

    function setOutput(address subject, bytes32 predicate, uint32 epoch) external {
        _subject = subject;
        _predicate = predicate;
        _epoch = epoch;
    }

    function verifyPredicate(bytes calldata, uint256[] calldata, bytes calldata)
        external
        view
        returns (address, bytes32, bool, uint32)
    {
        return (_subject, _predicate, true, _epoch);
    }

    function proofReplayIdentifier(uint256[] calldata) external pure returns (bytes32) {
        return bytes32(uint256(1));
    }
}

/// @notice Isolated release benchmarks. Setup, hashing, and signing are excluded
/// from metering so `.gas-snapshot` records the target external call only.
contract GasBenchmarksTest is Test {
    ProofOfHumanity internal poh;
    PredicateVerifier internal pv;
    GasPredicateProver internal prover;

    uint256 internal constant ISSUER_PK = 0xA11CE;
    uint256 internal constant NULLIFIER = uint256(keccak256("gas-benchmark-human"));
    bytes32 internal constant PREDICATE = keccak256("age>=18");
    bytes32 internal constant CONTEXT = keccak256("gas-benchmark-context");

    address internal issuer;
    address internal human;

    function setUp() public {
        vm.warp(1_700_000_000);
        issuer = vm.addr(ISSUER_PK);
        human = makeAddr("human");
        poh = new ProofOfHumanity(address(this), issuer);
        pv = new PredicateVerifier(address(this), issuer);
        prover = new GasPredicateProver();
    }

    function test_Gas_Mint() public {
        vm.pauseGasMetering();
        HumanityVoucher memory voucher = _voucher(poh.currentEpoch());
        bytes memory signature = _signVoucher(voucher);
        vm.resumeGasMetering();
        poh.mintWithVoucher(voucher, signature);
        vm.pauseGasMetering();
    }

    function test_Gas_Refresh() public {
        vm.pauseGasMetering();
        HumanityVoucher memory initial = _voucher(poh.currentEpoch());
        poh.mintWithVoucher(initial, _signVoucher(initial));
        HumanityVoucher memory refresh = _voucher(initial.epoch + 1);
        bytes memory signature = _signVoucher(refresh);
        vm.resumeGasMetering();
        poh.mintWithVoucher(refresh, signature);
        vm.pauseGasMetering();
    }

    function test_Gas_Consume() public {
        vm.pauseGasMetering();
        PredicateAttestation memory att = PredicateAttestation({
            consumer: address(this),
            context: CONTEXT,
            predicate: PREDICATE,
            result: true,
            subject: human,
            epoch: pv.currentEpoch(),
            nonce: 1
        });
        bytes memory signature = _signAttestation(att);
        vm.resumeGasMetering();
        pv.consume(att, signature, human);
        vm.pauseGasMetering();
    }

    function test_Gas_ConsumeWithProof() public {
        vm.pauseGasMetering();
        pv.setPredicateProver(prover);
        prover.setOutput(human, PREDICATE, pv.currentEpoch());
        bytes memory proof = hex"c0ffee";
        uint256[] memory publicSignals = new uint256[](0);
        bytes memory context = abi.encode(CONTEXT);
        vm.resumeGasMetering();
        pv.consumeWithProof(proof, publicSignals, context, PREDICATE, human);
        vm.pauseGasMetering();
    }

    function _voucher(uint32 epoch) private view returns (HumanityVoucher memory) {
        return HumanityVoucher({to: human, nullifier: NULLIFIER, epoch: epoch});
    }

    function _signVoucher(HumanityVoucher memory voucher) private view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ISSUER_PK, poh.hashVoucher(voucher));
        return abi.encodePacked(r, s, v);
    }

    function _signAttestation(PredicateAttestation memory att) private view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ISSUER_PK, pv.hashAttestation(att));
        return abi.encodePacked(r, s, v);
    }
}

/// @notice Kept separate so adding the v2 selector does not perturb the v1
///         benchmark contract's dispatcher gas.
contract V2VerifierGasBenchmarkTest is Test {
    V2PackedStatusGroth16Verifier internal verifier;

    function setUp() public {
        verifier = new V2PackedStatusGroth16Verifier();
    }

    function test_Gas_V2PackedStatusGroth16Verify() public {
        vm.pauseGasMetering();
        uint256[8] memory proof = V2PackedStatusFixture.proof();
        uint256[5] memory publicInputs = V2PackedStatusFixture.publicInputs();
        vm.resumeGasMetering();
        bool verified = verifier.verifyProof(proof, publicInputs);
        vm.pauseGasMetering();
        assertTrue(verified);
    }
}

/// @notice Measures the one-time registry write separately from passport-proof
///         verification and off-chain credential signing.
contract V2IssuanceGasBenchmarkTest is Test {
    bytes32 internal constant ISSUER_KEY_ID = keccak256("issuer-key-gas");
    bytes32 internal constant DUPLICATE_KEY = keccak256("issuance-duplicate-gas");
    uint256 internal constant CREDENTIAL_COMMITMENT = 123_456_789;

    ZkIdentityIssuanceRegistry internal registry;

    function setUp() public {
        vm.warp(230 * 90 days + 1);
        registry = new ZkIdentityIssuanceRegistry(address(this));
        registry.registerIssuerKey(ISSUER_KEY_ID);
        registry.authorizeIssuanceAuthority(ISSUER_KEY_ID, address(this));
    }

    function test_Gas_V2AllocateCredential() public {
        vm.pauseGasMetering();
        uint32 epoch = registry.currentEpoch();
        vm.resumeGasMetering();
        registry.allocateCredential(ISSUER_KEY_ID, DUPLICATE_KEY, CREDENTIAL_COMMITMENT, 1, epoch);
        vm.pauseGasMetering();
    }
}

/// @notice Measures EIP-712 authority recovery plus the one-time registry write.
///         Self proof verification and duplicate-key derivation remain off-chain.
contract V2SelfIssuanceGasBenchmarkTest is Test {
    bytes32 internal constant ISSUER_KEY_ID = keccak256("issuer-key-self-gas");
    bytes32 internal constant SELF_CONFIG_ID = keccak256("self-config-gas");
    bytes32 internal constant DUPLICATE_KEY = keccak256("self-duplicate-gas");
    uint256 internal constant CREDENTIAL_COMMITMENT = 123_456_789;
    uint256 internal constant AUTHORITY_KEY = 0xA11CE;
    uint256 internal constant SUBJECT_KEY = 0xCAFE;

    ZkIdentityIssuanceRegistry internal registry;
    ZkIdentitySelfIssuanceBridge internal bridge;
    address internal subject;

    function setUp() public {
        vm.chainId(84_532);
        vm.warp(230 * 90 days + 1);
        subject = vm.addr(SUBJECT_KEY);
        registry = new ZkIdentityIssuanceRegistry(address(this));
        registry.registerIssuerKey(ISSUER_KEY_ID);
        bridge = new ZkIdentitySelfIssuanceBridge(registry, ISSUER_KEY_ID, vm.addr(AUTHORITY_KEY), SELF_CONFIG_ID);
        registry.authorizeIssuanceAuthority(ISSUER_KEY_ID, address(bridge));
    }

    function test_Gas_V2SelfIssueCredential() public {
        vm.pauseGasMetering();
        ZkIdentitySelfIssuanceBridge.SelfIssuanceAuthorization memory authorization =
            ZkIdentitySelfIssuanceBridge.SelfIssuanceAuthorization({
                subject: subject,
                duplicateKey: DUPLICATE_KEY,
                credentialCommitment: CREDENTIAL_COMMITMENT,
                issuerKeyId: ISSUER_KEY_ID,
                expectedStatusId: 1,
                expectedEpoch: registry.currentEpoch(),
                deadline: uint64(block.timestamp + 10 minutes),
                selfConfigId: SELF_CONFIG_ID
            });
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(AUTHORITY_KEY, bridge.hashAuthorization(authorization));
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.prank(subject);
        vm.resumeGasMetering();
        bridge.issue(authorization, signature);
        vm.pauseGasMetering();
    }
}

contract V2DynamicStatusVerifierGasBenchmarkTest is Test {
    V2DynamicStatusGroth16Verifier internal verifier;

    function setUp() public {
        verifier = new V2DynamicStatusGroth16Verifier();
    }

    function test_Gas_V2DynamicStatusGroth16Verify() public {
        vm.pauseGasMetering();
        uint256[8] memory proof = V2DynamicStatusFixture.proof();
        uint256[18] memory publicInputs = V2DynamicStatusFixture.publicInputs();
        vm.resumeGasMetering();
        bool verified = verifier.verifyProof(proof, publicInputs);
        vm.pauseGasMetering();
        assertTrue(verified);
    }
}

contract GasZkIdentityGroth16Verifier is IZkIdentityGroth16Verifier {
    function verifyProof(uint256[8] calldata proof, uint256[18] calldata publicSignals) external pure returns (bool) {
        return proof[0] == 1 && publicSignals[0] == 1;
    }
}

/// @notice Measures host + 18-signal adapter + registry + replay storage. Stub
///         calls isolate adapter overhead; the deterministic research verifier
///         gives an end-to-end gas observation but is not a production setup.
contract V2AdapterGasBenchmarkTest is Test {
    bytes32 internal constant CIRCUIT_ID = keccak256("ubi2.zk-identity.v2.adapter-gas-fixture-1");
    bytes32 internal constant ISSUER_KEY_ID = keccak256("issuer-key-gas");
    bytes32 internal constant ACTIVE_ROOT = keccak256("active-root-gas");
    bytes32 internal constant POLICY_HASH = keccak256("age-range-policy-gas");
    bytes32 internal constant STATUS_PROVIDER_HASH = keccak256("self:ofac");
    bytes32 internal constant STATUS_LIST_HASH = keccak256("2026-08-14");
    bytes32 internal constant DYNAMIC_STATUS_ROOT = keccak256("dynamic-status-root-gas");
    bytes32 internal constant ACTION_CONTEXT = keccak256("membership:gas");
    bytes32 internal constant CHALLENGE = keccak256("challenge:gas");
    address internal constant FIXTURE_CONSUMER = 0x2222222222222222222222222222222222222222;
    address internal constant FIXTURE_SUBJECT = 0x3333333333333333333333333333333333333333;
    address internal constant EXPECTED_HOST = 0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f;
    bytes32 internal constant FIXTURE_ACTION_CONTEXT =
        0x9d3469716e75d7b16c109c886f96fef85b6e9dc7b1e3139c864e5e664a00a98b;
    bytes32 internal constant FIXTURE_CHALLENGE = 0xc65bfcbace59e23335df2a1f460660814b3f85710ddbcd922d5f458f4e150b34;
    uint32 internal constant FIXTURE_PUBLISHED_AT = 1_788_480_000;

    PredicateVerifier internal predicateVerifier;
    ZkIdentityVersionRegistry internal registry;
    GasZkIdentityGroth16Verifier internal rawVerifier;
    V2DynamicStatusGroth16Verifier internal dynamicStatusVerifier;
    ZkIdentityPredicateProver internal adapter;
    address internal subject;
    bytes32 internal dynamicPolicyHash;
    uint32 internal dynamicStatusPublishedAt;
    bytes32 internal researchPolicyHash;

    function setUp() public {
        vm.chainId(84_532);
        vm.warp(uint256(FIXTURE_PUBLISHED_AT) + 60);
        subject = makeAddr("v2-adapter-gas-subject");
        predicateVerifier = new PredicateVerifier(address(this), makeAddr("v2-adapter-gas-issuer"));
        assertEq(address(predicateVerifier), EXPECTED_HOST);
        registry = new ZkIdentityVersionRegistry(address(this));
        rawVerifier = new GasZkIdentityGroth16Verifier();
        dynamicStatusVerifier = new V2DynamicStatusGroth16Verifier();
        registry.registerCircuit(CIRCUIT_ID, address(rawVerifier));
        registry.authorizeIssuer(CIRCUIT_ID, ISSUER_KEY_ID);
        registry.publishStatusRoot(CIRCUIT_ID, ISSUER_KEY_ID, 1, ACTIVE_ROOT);
        registry.publishStatusRoot(CIRCUIT_ID, ISSUER_KEY_ID, 2, DYNAMIC_STATUS_ROOT);
        dynamicStatusPublishedAt = uint32(block.timestamp - 60);
        dynamicPolicyHash = registry.registerDynamicStatusPolicy(
            STATUS_PROVIDER_HASH, STATUS_LIST_HASH, DYNAMIC_STATUS_ROOT, dynamicStatusPublishedAt, 3_600
        );

        uint256[18] memory fixtureSignals = V2DynamicStatusFixture.publicInputs();
        bytes32 researchCircuitId = _join(fixtureSignals[1], fixtureSignals[2]);
        bytes32 researchIssuerKeyId = _join(fixtureSignals[3], fixtureSignals[4]);
        bytes32 researchRoot = _join(fixtureSignals[5], fixtureSignals[6]);
        registry.registerCircuit(researchCircuitId, address(dynamicStatusVerifier));
        registry.authorizeIssuer(researchCircuitId, researchIssuerKeyId);
        registry.publishStatusRoot(researchCircuitId, researchIssuerKeyId, 1, researchRoot);
        researchPolicyHash = registry.registerDynamicStatusPolicy(
            keccak256("self:ofac"), keccak256("research:fixture-1"), researchRoot, FIXTURE_PUBLISHED_AT, 86_400
        );
        assertEq(researchPolicyHash, _join(fixtureSignals[7], fixtureSignals[8]));
        adapter = new ZkIdentityPredicateProver(address(predicateVerifier), registry);
        predicateVerifier.setPredicateProver(adapter);
    }

    function test_Gas_V2AdapterConsumeWithStubVerifier() public {
        vm.pauseGasMetering();
        uint256[] memory publicSignals = _signals(ACTIVE_ROOT, POLICY_HASH, 0);
        uint256[8] memory proofWords;
        proofWords[0] = 1;
        bytes memory proof = abi.encode(proofWords);
        bytes memory context = abi.encode(ACTION_CONTEXT, CHALLENGE, uint8(1));
        vm.resumeGasMetering();
        bool verified = predicateVerifier.consumeWithProof(proof, publicSignals, context, POLICY_HASH, subject);
        vm.pauseGasMetering();
        assertTrue(verified);
    }

    function test_Gas_V2AdapterConsumeDynamicStatusWithStubVerifier() public {
        vm.pauseGasMetering();
        uint256[] memory publicSignals = _signals(DYNAMIC_STATUS_ROOT, dynamicPolicyHash, dynamicStatusPublishedAt);
        uint256[8] memory proofWords;
        proofWords[0] = 1;
        bytes memory proof = abi.encode(proofWords);
        bytes memory context = abi.encode(ACTION_CONTEXT, CHALLENGE, uint8(1));
        vm.resumeGasMetering();
        bool verified = predicateVerifier.consumeWithProof(proof, publicSignals, context, dynamicPolicyHash, subject);
        vm.pauseGasMetering();
        assertTrue(verified);
    }

    function test_Gas_V2AdapterConsumeDynamicStatusWithRealVerifier() public {
        vm.pauseGasMetering();
        uint256[18] memory fixedSignals = V2DynamicStatusFixture.publicInputs();
        uint256[] memory publicSignals = new uint256[](18);
        for (uint256 i = 0; i < 18; ++i) {
            publicSignals[i] = fixedSignals[i];
        }
        bytes memory proof = abi.encode(V2DynamicStatusFixture.proof());
        bytes memory context = abi.encode(FIXTURE_ACTION_CONTEXT, FIXTURE_CHALLENGE, uint8(1));
        vm.prank(FIXTURE_CONSUMER);
        vm.resumeGasMetering();
        bool verified =
            predicateVerifier.consumeWithProof(proof, publicSignals, context, researchPolicyHash, FIXTURE_SUBJECT);
        vm.pauseGasMetering();
        assertTrue(verified);
    }

    function _signals(bytes32 signalActiveRoot, bytes32 signalPolicyHash, uint32 statusEpoch)
        private
        view
        returns (uint256[] memory signals)
    {
        signals = new uint256[](18);
        signals[0] = 1;
        _writeIdentifier(signals, 1, CIRCUIT_ID);
        _writeIdentifier(signals, 3, ISSUER_KEY_ID);
        _writeIdentifier(signals, 5, signalActiveRoot);
        _writeIdentifier(signals, 7, signalPolicyHash);

        bytes32 binding = ZkIdentityEncoding.presentationBindingHash(
            ZkIdentityEncoding.PresentationBinding({
                policyHash: signalPolicyHash,
                chainId: block.chainid,
                verifier: address(predicateVerifier),
                consumer: address(this),
                subject: subject,
                context: ACTION_CONTEXT,
                challenge: CHALLENGE,
                epoch: predicateVerifier.currentEpoch()
            })
        );
        _writeIdentifier(signals, 9, binding);
        bytes32 scope = ZkIdentityEncoding.nullifierScopeHash(
            ZkIdentityEncoding.NullifierScope({
                mode: 1,
                chainId: block.chainid,
                verifier: address(predicateVerifier),
                consumer: address(this),
                context: ACTION_CONTEXT,
                policyHash: signalPolicyHash
            })
        );
        _writeIdentifier(signals, 11, scope);
        signals[13] = 1;
        signals[14] = uint160(subject);
        signals[15] = 1;
        signals[16] = predicateVerifier.currentEpoch();
        signals[17] = statusEpoch;
    }

    function _writeIdentifier(uint256[] memory signals, uint256 highIndex, bytes32 value) private pure {
        (signals[highIndex], signals[highIndex + 1]) = ZkIdentityEncoding.splitBytes32(value);
    }

    function _join(uint256 high, uint256 low) private pure returns (bytes32) {
        return bytes32((high << 128) | low);
    }
}
