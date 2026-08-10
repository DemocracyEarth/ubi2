// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {PredicateVerifier, PredicateAttestation} from "../src/PredicateVerifier.sol";

contract PredicateVerifierTest is Test {
    PredicateVerifier internal pv;

    // Issuer key pair (known private key => real EIP-712 signatures via vm.sign).
    uint256 internal constant ISSUER_PK = 0xA11CE;
    uint256 internal constant NEW_ISSUER_PK = 0xB0B;
    uint256 internal constant IMPOSTOR_PK = 0xBAD;
    address internal issuer;
    address internal newIssuer;

    address internal owner;
    address internal alice; // the presenting human (subject)
    address internal consumer; // a stand-in consuming contract/app

    // Canonical predicate ids (descriptor grammar).
    bytes32 internal constant PRED_AGE18 = keccak256("age>=18");
    bytes32 internal constant PRED_AGE21 = keccak256("age>=21");
    bytes32 internal constant CTX = keccak256("proposal-42");

    uint256 internal constant EPOCH = 90 days;

    function setUp() public {
        issuer = vm.addr(ISSUER_PK);
        newIssuer = vm.addr(NEW_ISSUER_PK);
        owner = makeAddr("owner");
        alice = makeAddr("alice");
        consumer = makeAddr("consumer");

        vm.warp(1_700_000_000);
        pv = new PredicateVerifier(owner, issuer);
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    function _att(bool result) internal view returns (PredicateAttestation memory) {
        return PredicateAttestation({
            consumer: consumer,
            context: CTX,
            predicate: PRED_AGE18,
            result: result,
            subject: alice,
            epoch: pv.currentEpoch(),
            nonce: 1
        });
    }

    function _sign(uint256 pk, PredicateAttestation memory att) internal view returns (bytes memory) {
        bytes32 digest = pv.hashAttestation(att);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    /*//////////////////////////////////////////////////////////////
                          CONSTRUCTOR / CONSTANTS
    //////////////////////////////////////////////////////////////*/

    function test_Constructor_SetsOwnerIssuer() public view {
        assertEq(pv.owner(), owner);
        assertEq(pv.issuer(), issuer);
    }

    function test_Constructor_RevertsOnZeroIssuer() public {
        vm.expectRevert(PredicateVerifier.InvalidIssuer.selector);
        new PredicateVerifier(owner, address(0));
    }

    function test_Constants_EpochAndValidity() public view {
        assertEq(pv.EPOCH(), 90 days);
        assertEq(pv.VALIDITY_EPOCHS(), 4);
    }

    /// @notice The PINNED typehash must be byte-identical to the TS/viem signer.
    function test_TypehashIsPinned() public view {
        assertEq(
            pv.PREDICATE_TYPEHASH(),
            keccak256(
                "PredicateAttestation(address consumer,bytes32 context,bytes32 predicate,bool result,address subject,uint32 epoch,uint256 nonce)"
            )
        );
    }

    function test_PredicateId_MatchesKeccak() public view {
        assertEq(pv.predicateId("age>=18"), PRED_AGE18);
        assertEq(pv.predicateId("age>=21"), PRED_AGE21);
        assertEq(pv.predicateId("nationality=ARG"), keccak256("nationality=ARG"));
        assertEq(pv.predicateId("sanctions-clear"), keccak256("sanctions-clear"));
    }

    /*//////////////////////////////////////////////////////////////
                                ADMIN
    //////////////////////////////////////////////////////////////*/

    function test_SetIssuer_OnlyOwner() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", alice));
        pv.setIssuer(newIssuer);
    }

    function test_SetIssuer_RevertsOnZero() public {
        vm.prank(owner);
        vm.expectRevert(PredicateVerifier.InvalidIssuer.selector);
        pv.setIssuer(address(0));
    }

    function test_SetIssuer_UpdatesAndEmits() public {
        vm.expectEmit(true, true, false, true, address(pv));
        emit PredicateVerifier.IssuerUpdated(issuer, newIssuer);
        vm.prank(owner);
        pv.setIssuer(newIssuer);
        assertEq(pv.issuer(), newIssuer);
    }

    /*//////////////////////////////////////////////////////////////
                            CONSUME (HAPPY)
    //////////////////////////////////////////////////////////////*/

    function test_Consume_HappyPath_ReturnsResultAndMarksSpent() public {
        PredicateAttestation memory att = _att(true);
        bytes memory sig = _sign(ISSUER_PK, att);

        bytes32 key = pv.replayKey(att);
        assertFalse(pv.consumed(key));

        vm.expectEmit(true, true, true, true, address(pv));
        emit PredicateVerifier.PredicateConsumed(consumer, alice, PRED_AGE18, CTX, true);

        vm.prank(consumer);
        bool result = pv.consume(att, sig, alice);

        assertTrue(result);
        assertTrue(pv.consumed(key));
    }

    /// @notice A signed `result == false` is a valid attestation; it just returns false.
    function test_Consume_ReturnsFalseResult() public {
        PredicateAttestation memory att = _att(false);
        bytes memory sig = _sign(ISSUER_PK, att);
        vm.prank(consumer);
        assertFalse(pv.consume(att, sig, alice));
    }

    /*//////////////////////////////////////////////////////////////
                            CONSUME (REJECTS)
    //////////////////////////////////////////////////////////////*/

    function test_Consume_Revert_WrongConsumer() public {
        // att.consumer is `consumer`, but a different contract calls.
        PredicateAttestation memory att = _att(true);
        bytes memory sig = _sign(ISSUER_PK, att);
        vm.prank(makeAddr("other-consumer"));
        vm.expectRevert(PredicateVerifier.ConsumerMismatch.selector);
        pv.consume(att, sig, alice);
    }

    function test_Consume_Revert_WrongSubject() public {
        // presenter != att.subject.
        PredicateAttestation memory att = _att(true);
        bytes memory sig = _sign(ISSUER_PK, att);
        vm.prank(consumer);
        vm.expectRevert(PredicateVerifier.SubjectMismatch.selector);
        pv.consume(att, sig, makeAddr("mallory"));
    }

    function test_Consume_Revert_BadIssuerSig() public {
        // Signed by someone who is not the issuer.
        PredicateAttestation memory att = _att(true);
        bytes memory sig = _sign(IMPOSTOR_PK, att);
        vm.prank(consumer);
        vm.expectRevert(PredicateVerifier.InvalidSigner.selector);
        pv.consume(att, sig, alice);
    }

    function test_Consume_Revert_TamperedResult() public {
        // Flip the boolean AFTER signing => digest changes => recovered != issuer.
        PredicateAttestation memory att = _att(false);
        bytes memory sig = _sign(ISSUER_PK, att);
        att.result = true;
        vm.prank(consumer);
        vm.expectRevert(PredicateVerifier.InvalidSigner.selector);
        pv.consume(att, sig, alice);
    }

    function test_Consume_Revert_TamperedPredicate() public {
        PredicateAttestation memory att = _att(true);
        bytes memory sig = _sign(ISSUER_PK, att);
        att.predicate = PRED_AGE21;
        vm.prank(consumer);
        vm.expectRevert(PredicateVerifier.InvalidSigner.selector);
        pv.consume(att, sig, alice);
    }

    function test_Consume_Revert_TamperedContext() public {
        PredicateAttestation memory att = _att(true);
        bytes memory sig = _sign(ISSUER_PK, att);
        att.context = keccak256("proposal-99");
        vm.prank(consumer);
        vm.expectRevert(PredicateVerifier.InvalidSigner.selector);
        pv.consume(att, sig, alice);
    }

    function test_Consume_Revert_TamperedEpoch() public {
        PredicateAttestation memory att = _att(true);
        bytes memory sig = _sign(ISSUER_PK, att);
        att.epoch++;
        vm.prank(consumer);
        vm.expectRevert(PredicateVerifier.InvalidSigner.selector);
        pv.consume(att, sig, alice);
    }

    function test_Consume_Revert_AttestationSignedForAnotherChain() public {
        PredicateAttestation memory att = _att(true);
        bytes memory chainASignature = _sign(ISSUER_PK, att);

        vm.chainId(block.chainid + 1);
        vm.prank(consumer);
        vm.expectRevert(PredicateVerifier.InvalidSigner.selector);
        pv.consume(att, chainASignature, alice);
    }

    function test_Consume_Revert_StaleEpoch() public {
        PredicateAttestation memory att = _att(true);
        bytes memory sig = _sign(ISSUER_PK, att);

        // Still fresh at exactly signedEpoch + VALIDITY_EPOCHS.
        vm.warp(block.timestamp + 4 * EPOCH);
        vm.prank(consumer);
        // (fresh here; consume would succeed — use check to avoid spending)
        assertTrue(pv.check(att, sig, alice, consumer));

        // One epoch past the window => stale.
        vm.warp(block.timestamp + EPOCH);
        vm.prank(consumer);
        vm.expectRevert(PredicateVerifier.StaleEpoch.selector);
        pv.consume(att, sig, alice);
    }

    function test_Consume_Revert_ReplayedNonce() public {
        PredicateAttestation memory att = _att(true);
        bytes memory sig = _sign(ISSUER_PK, att);

        vm.prank(consumer);
        pv.consume(att, sig, alice);

        // Same (subject, consumer, context, nonce) => spent.
        vm.prank(consumer);
        vm.expectRevert(PredicateVerifier.AttestationReplayed.selector);
        pv.consume(att, sig, alice);
    }

    function test_Consume_DifferentNonce_NotReplay() public {
        PredicateAttestation memory att = _att(true);
        bytes memory sig = _sign(ISSUER_PK, att);
        vm.prank(consumer);
        pv.consume(att, sig, alice);

        // A fresh nonce is a distinct single-use key.
        PredicateAttestation memory att2 = _att(true);
        att2.nonce = 2;
        bytes memory sig2 = _sign(ISSUER_PK, att2);
        vm.prank(consumer);
        assertTrue(pv.consume(att2, sig2, alice));
    }

    /*//////////////////////////////////////////////////////////////
                              CHECK (VIEW)
    //////////////////////////////////////////////////////////////*/

    function test_Check_ReturnsResult_NoStateWrite() public {
        PredicateAttestation memory att = _att(true);
        bytes memory sig = _sign(ISSUER_PK, att);
        bytes32 key = pv.replayKey(att);

        assertTrue(pv.check(att, sig, alice, consumer));
        // No replay-state write: calling twice is fine and nothing is marked spent.
        assertTrue(pv.check(att, sig, alice, consumer));
        assertFalse(pv.consumed(key));

        vm.prank(consumer);
        pv.consume(att, sig, alice);
        // check() deliberately ignores replay state even after consume().
        assertTrue(pv.check(att, sig, alice, consumer));
    }

    function test_Check_Revert_WrongConsumerArg() public {
        PredicateAttestation memory att = _att(true);
        bytes memory sig = _sign(ISSUER_PK, att);
        vm.expectRevert(PredicateVerifier.ConsumerMismatch.selector);
        pv.check(att, sig, alice, makeAddr("other-consumer"));
    }

    function test_Check_Revert_BadIssuerSig() public {
        PredicateAttestation memory att = _att(true);
        bytes memory sig = _sign(IMPOSTOR_PK, att);
        vm.expectRevert(PredicateVerifier.InvalidSigner.selector);
        pv.check(att, sig, alice, consumer);
    }

    /*//////////////////////////////////////////////////////////////
                          UNLINKABILITY / BINDING
    //////////////////////////////////////////////////////////////*/

    /// @notice An attestation minted for consumer A cannot be presented at consumer
    ///         B — per-consumer binding is what makes proofs unlinkable across
    ///         consumers.
    function test_Consume_AttestationBoundToOneConsumer() public {
        PredicateAttestation memory att = _att(true);
        bytes memory sig = _sign(ISSUER_PK, att); // bound to `consumer`

        address consumerB = makeAddr("consumerB");
        vm.prank(consumerB);
        vm.expectRevert(PredicateVerifier.ConsumerMismatch.selector);
        pv.consume(att, sig, alice);
    }

    function test_IssuerRotation_OldSigRejected() public {
        vm.prank(owner);
        pv.setIssuer(newIssuer);

        PredicateAttestation memory att = _att(true);
        bytes memory oldSig = _sign(ISSUER_PK, att);
        vm.prank(consumer);
        vm.expectRevert(PredicateVerifier.InvalidSigner.selector);
        pv.consume(att, oldSig, alice);

        // New issuer works.
        bytes memory newSig = _sign(NEW_ISSUER_PK, att);
        vm.prank(consumer);
        assertTrue(pv.consume(att, newSig, alice));
    }
}
