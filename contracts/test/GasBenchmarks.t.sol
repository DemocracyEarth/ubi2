// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {ProofOfHumanity, HumanityVoucher} from "../src/ProofOfHumanity.sol";
import {PredicateVerifier, PredicateAttestation, IPredicateProver} from "../src/PredicateVerifier.sol";
import {V2PackedStatusGroth16Verifier} from "../src/research/V2PackedStatusGroth16Verifier.sol";
import {V2PackedStatusFixture} from "./fixtures/V2PackedStatusFixture.sol";

contract GasPredicateProver is IPredicateProver {
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
