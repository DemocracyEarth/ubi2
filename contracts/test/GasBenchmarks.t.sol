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
import {IZkIdentityGroth16Verifier, ZkIdentityPredicateProver} from "../src/ZkIdentityPredicateProver.sol";
import {ZkIdentityEncoding} from "../src/ZkIdentityEncoding.sol";
import {ZkIdentityVersionRegistry} from "../src/ZkIdentityVersionRegistry.sol";
import {V2PackedStatusFixture} from "./fixtures/V2PackedStatusFixture.sol";

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

contract GasZkIdentityGroth16Verifier is IZkIdentityGroth16Verifier {
    function verifyProof(uint256[8] calldata proof, uint256[18] calldata publicSignals) external pure returns (bool) {
        return proof[0] == 1 && publicSignals[0] == 1;
    }
}

/// @notice Measures host + 18-signal adapter + registry + replay storage with a
///         stub raw verifier. Add the final 18-input pairing cost only when the
///         reviewed circuit and ceremony artifact exist.
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

    PredicateVerifier internal predicateVerifier;
    ZkIdentityVersionRegistry internal registry;
    GasZkIdentityGroth16Verifier internal rawVerifier;
    ZkIdentityPredicateProver internal adapter;
    address internal subject;
    bytes32 internal dynamicPolicyHash;
    uint32 internal dynamicStatusPublishedAt;

    function setUp() public {
        vm.warp(1_700_000_000);
        subject = makeAddr("v2-adapter-gas-subject");
        predicateVerifier = new PredicateVerifier(address(this), makeAddr("v2-adapter-gas-issuer"));
        registry = new ZkIdentityVersionRegistry(address(this));
        rawVerifier = new GasZkIdentityGroth16Verifier();
        registry.registerCircuit(CIRCUIT_ID, address(rawVerifier));
        registry.authorizeIssuer(CIRCUIT_ID, ISSUER_KEY_ID);
        registry.publishStatusRoot(CIRCUIT_ID, ISSUER_KEY_ID, 1, ACTIVE_ROOT);
        dynamicStatusPublishedAt = uint32(block.timestamp - 60);
        dynamicPolicyHash = registry.registerDynamicStatusPolicy(
            STATUS_PROVIDER_HASH, STATUS_LIST_HASH, DYNAMIC_STATUS_ROOT, dynamicStatusPublishedAt, 3_600
        );
        adapter = new ZkIdentityPredicateProver(address(predicateVerifier), registry);
        predicateVerifier.setPredicateProver(adapter);
    }

    function test_Gas_V2AdapterConsumeWithStubVerifier() public {
        vm.pauseGasMetering();
        uint256[] memory publicSignals = _signals(POLICY_HASH, 0);
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
        uint256[] memory publicSignals = _signals(dynamicPolicyHash, dynamicStatusPublishedAt);
        uint256[8] memory proofWords;
        proofWords[0] = 1;
        bytes memory proof = abi.encode(proofWords);
        bytes memory context = abi.encode(ACTION_CONTEXT, CHALLENGE, uint8(1));
        vm.resumeGasMetering();
        bool verified = predicateVerifier.consumeWithProof(proof, publicSignals, context, dynamicPolicyHash, subject);
        vm.pauseGasMetering();
        assertTrue(verified);
    }

    function _signals(bytes32 signalPolicyHash, uint32 statusEpoch) private view returns (uint256[] memory signals) {
        signals = new uint256[](18);
        signals[0] = 1;
        _writeIdentifier(signals, 1, CIRCUIT_ID);
        _writeIdentifier(signals, 3, ISSUER_KEY_ID);
        _writeIdentifier(signals, 5, ACTIVE_ROOT);
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
}
