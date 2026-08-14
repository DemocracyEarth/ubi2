// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {
    PredicateVerifier,
    PredicateAttestation,
    IPredicateProver,
    IPredicateProverReplay
} from "../src/PredicateVerifier.sol";

contract PrivacyPredicateProver is IPredicateProver, IPredicateProverReplay {
    bytes32 public constant REPLAY_IDENTIFIER = bytes32(uint256(1));
    address internal _subject;
    bytes32 internal _predicate;
    bool internal _result;
    uint32 internal _epoch;

    function setOutput(address subject, bytes32 predicate, bool result, uint32 epoch) external {
        _subject = subject;
        _predicate = predicate;
        _result = result;
        _epoch = epoch;
    }

    function verifyPredicate(bytes calldata, uint256[] calldata, bytes calldata)
        external
        view
        returns (address, bytes32, bool, uint32)
    {
        return (_subject, _predicate, _result, _epoch);
    }

    function proofReplayIdentifier(uint256[] calldata) external pure returns (bytes32) {
        return REPLAY_IDENTIFIER;
    }
}

contract PredicatePrivacyTest is Test {
    PredicateVerifier internal pv;
    PrivacyPredicateProver internal prover;

    uint256 internal constant ISSUER_PK = 0xA11CE;
    bytes32 internal constant PREDICATE = keccak256("age>=18");
    bytes32 internal constant CONTEXT = keccak256("privacy-test-context");

    // Representative private credential values that must never cross the
    // on-chain boundary. Only the derived predicate boolean may do so.
    bytes32 internal constant EXACT_AGE = bytes32(uint256(37));
    bytes32 internal constant EXACT_DATE_OF_BIRTH = bytes32(uint256(19_900_123));
    bytes32 internal constant NATIONALITY = "ARG";

    address internal owner;
    address internal issuer;
    address internal human;
    address internal consumer;

    function setUp() public {
        vm.warp(1_700_000_000);
        owner = makeAddr("owner");
        issuer = vm.addr(ISSUER_PK);
        human = makeAddr("human");
        consumer = makeAddr("consumer");
        pv = new PredicateVerifier(owner, issuer);
        prover = new PrivacyPredicateProver();
    }

    function test_AttestationLeaksOnlyBooleanInCalldataLogsAndStorage() public {
        PredicateAttestation memory att = PredicateAttestation({
            consumer: consumer,
            context: CONTEXT,
            predicate: PREDICATE,
            result: true,
            subject: human,
            epoch: pv.currentEpoch(),
            nonce: 1
        });
        bytes memory signature = _sign(att);
        bytes memory callData = abi.encodeCall(pv.consume, (att, signature, human));
        _assertNoPrivateValues(callData);

        vm.record();
        vm.recordLogs();
        vm.prank(consumer);
        assertTrue(pv.consume(att, signature, human));

        assertTrue(pv.consumed(pv.replayKey(att)));
        _assertLogsContainNoPrivateValues(vm.getRecordedLogs());
        _assertRecordedStorageContainsNoPrivateValues(address(pv));
    }

    function test_ProofLeaksOnlyBooleanInCalldataLogsAndStorage() public {
        vm.prank(owner);
        pv.setPredicateProver(prover);
        prover.setOutput(human, PREDICATE, true, pv.currentEpoch());

        bytes memory proof = hex"c0ffee";
        uint256[] memory publicSignals = new uint256[](0);
        bytes memory context = abi.encode(CONTEXT);
        bytes memory callData = abi.encodeCall(pv.consumeWithProof, (proof, publicSignals, context, PREDICATE, human));
        _assertNoPrivateValues(callData);

        vm.record();
        vm.recordLogs();
        vm.prank(consumer);
        assertTrue(pv.consumeWithProof(proof, publicSignals, context, PREDICATE, human));

        bytes32 replayKey = pv.proofReplayKey(consumer, prover.REPLAY_IDENTIFIER());
        assertTrue(pv.consumed(replayKey));
        _assertLogsContainNoPrivateValues(vm.getRecordedLogs());
        _assertRecordedStorageContainsNoPrivateValues(address(pv));
        _assertRecordedStorageContainsNoPrivateValues(address(prover));
    }

    function _sign(PredicateAttestation memory att) private view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ISSUER_PK, pv.hashAttestation(att));
        return abi.encodePacked(r, s, v);
    }

    function _assertLogsContainNoPrivateValues(Vm.Log[] memory logs) private pure {
        for (uint256 i = 0; i < logs.length; i++) {
            for (uint256 j = 0; j < logs[i].topics.length; j++) {
                assertNotEq(logs[i].topics[j], EXACT_AGE);
                assertNotEq(logs[i].topics[j], EXACT_DATE_OF_BIRTH);
                assertNotEq(logs[i].topics[j], NATIONALITY);
            }
            _assertNoPrivateValues(logs[i].data);
        }
    }

    function _assertRecordedStorageContainsNoPrivateValues(address target) private view {
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(target);
        for (uint256 i = 0; i < reads.length; i++) {
            _assertSlotAndValueArePrivateValueFree(target, reads[i]);
        }
        for (uint256 i = 0; i < writes.length; i++) {
            _assertSlotAndValueArePrivateValueFree(target, writes[i]);
        }
    }

    function _assertSlotAndValueArePrivateValueFree(address target, bytes32 slot) private view {
        assertNotEq(slot, EXACT_AGE);
        assertNotEq(slot, EXACT_DATE_OF_BIRTH);
        assertNotEq(slot, NATIONALITY);
        bytes32 value = vm.load(target, slot);
        assertNotEq(value, EXACT_AGE);
        assertNotEq(value, EXACT_DATE_OF_BIRTH);
        assertNotEq(value, NATIONALITY);
    }

    function _assertNoPrivateValues(bytes memory blob) private pure {
        if (blob.length >= 32) {
            for (uint256 i = 0; i <= blob.length - 32; i++) {
                bytes32 word;
                assembly ("memory-safe") {
                    word := mload(add(add(blob, 0x20), i))
                }
                assertNotEq(word, EXACT_AGE);
                assertNotEq(word, EXACT_DATE_OF_BIRTH);
                assertNotEq(word, NATIONALITY);
            }
        }
        assertFalse(_contains(blob, bytes("ARG")));
    }

    function _contains(bytes memory haystack, bytes memory needle) private pure returns (bool) {
        if (needle.length == 0) return true;
        if (needle.length > haystack.length) return false;
        for (uint256 i = 0; i <= haystack.length - needle.length; i++) {
            bool matches = true;
            for (uint256 j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    matches = false;
                    break;
                }
            }
            if (matches) return true;
        }
        return false;
    }
}
