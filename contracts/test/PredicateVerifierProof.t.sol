// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {PredicateVerifier, IPredicateProver} from "../src/PredicateVerifier.sol";

/// @dev A stand-in prover for the ADR-0009 proof path. Returns a settable
///      `(subject, predicate, result, epoch)` tuple so the verifier's shared checks
///      (predicate match, subject binding, freshness, anti-replay) can be tested
///      independently of any real ZK circuit. `setRevert(true)` simulates a bad proof.
contract MockPredicateProver is IPredicateProver {
    address public sSubject;
    bytes32 public sPredicate;
    bool public sResult;
    uint32 public sEpoch;
    bool public sRevert;

    function set(address subject_, bytes32 predicate_, bool result_, uint32 epoch_) external {
        sSubject = subject_;
        sPredicate = predicate_;
        sResult = result_;
        sEpoch = epoch_;
    }

    function setRevert(bool r) external {
        sRevert = r;
    }

    function verifyPredicate(bytes calldata, uint256[] calldata, bytes calldata)
        external
        view
        returns (address, bytes32, bool, uint32)
    {
        require(!sRevert, "bad proof");
        return (sSubject, sPredicate, sResult, sEpoch);
    }
}

contract PredicateVerifierProofTest is Test {
    PredicateVerifier internal pv;
    MockPredicateProver internal mock;

    address internal owner = makeAddr("owner");
    address internal issuer = makeAddr("issuer");
    address internal human = makeAddr("human");
    address internal consumerA = makeAddr("consumerA");
    address internal consumerB = makeAddr("consumerB");

    bytes32 internal constant AGE18 = keccak256("age>=18");
    bytes32 internal constant AGE21 = keccak256("age>=21");

    bytes internal proof = hex"c0ffee";
    uint256[] internal signals; // empty; the mock ignores it
    bytes internal ctx = abi.encode(uint256(0xABCD));

    event PredicateProverUpdated(address indexed previousProver, address indexed newProver);
    event PredicateProven(
        address indexed consumer, address indexed subject, bytes32 indexed predicate, bytes32 contextHash, bool result
    );

    function setUp() public {
        vm.warp(2000 days); // deterministic epoch math (currentEpoch ~= 22, room to go stale)
        pv = new PredicateVerifier(owner, issuer);
        mock = new MockPredicateProver();
    }

    function _wireFreshTrueAge18() internal {
        vm.prank(owner);
        pv.setPredicateProver(mock);
        mock.set(human, AGE18, true, pv.currentEpoch());
    }

    /*//////////////////////////////////////////////////////////////  setPredicateProver  */

    function test_SetProver_OnlyOwner() public {
        vm.prank(human);
        vm.expectRevert(abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", human));
        pv.setPredicateProver(mock);
    }

    function test_SetProver_SetsSwapsUnsets_AndEmits() public {
        vm.expectEmit(true, true, false, false);
        emit PredicateProverUpdated(address(0), address(mock));
        vm.prank(owner);
        pv.setPredicateProver(mock);
        assertEq(address(pv.prover()), address(mock));

        MockPredicateProver mock2 = new MockPredicateProver();
        vm.prank(owner);
        pv.setPredicateProver(mock2);
        assertEq(address(pv.prover()), address(mock2));

        vm.prank(owner);
        pv.setPredicateProver(IPredicateProver(address(0)));
        assertEq(address(pv.prover()), address(0));
    }

    /*//////////////////////////////////////////////////////////////  consumeWithProof  */

    function test_ConsumeWithProof_RevertsWhenProverUnset() public {
        vm.prank(consumerA);
        vm.expectRevert(PredicateVerifier.PredicateProverUnset.selector);
        pv.consumeWithProof(proof, signals, ctx, AGE18, human);
    }

    function test_ConsumeWithProof_HappyPath_ReturnsResult_Emits_Spends() public {
        _wireFreshTrueAge18();

        vm.expectEmit(true, true, true, true);
        emit PredicateProven(consumerA, human, AGE18, keccak256(ctx), true);
        vm.prank(consumerA);
        bool r = pv.consumeWithProof(proof, signals, ctx, AGE18, human);
        assertTrue(r);

        // spent: replay reverts
        vm.prank(consumerA);
        vm.expectRevert(PredicateVerifier.ProofReplayed.selector);
        pv.consumeWithProof(proof, signals, ctx, AGE18, human);
    }

    function test_ConsumeWithProof_FalseResultAlsoConsumes() public {
        vm.prank(owner);
        pv.setPredicateProver(mock);
        mock.set(human, AGE18, false, pv.currentEpoch());

        vm.prank(consumerA);
        bool r = pv.consumeWithProof(proof, signals, ctx, AGE18, human);
        assertFalse(r); // the boolean can be false; it is still a valid, spent proof
    }

    function test_ConsumeWithProof_Revert_WrongPredicate() public {
        _wireFreshTrueAge18(); // prover proves AGE18
        vm.prank(consumerA);
        vm.expectRevert(PredicateVerifier.WrongPredicate.selector);
        pv.consumeWithProof(proof, signals, ctx, AGE21, human); // consumer required AGE21
    }

    function test_ConsumeWithProof_Revert_WrongSubject() public {
        _wireFreshTrueAge18();
        vm.prank(consumerA);
        vm.expectRevert(PredicateVerifier.SubjectMismatch.selector);
        pv.consumeWithProof(proof, signals, ctx, AGE18, makeAddr("notHuman"));
    }

    function test_ConsumeWithProof_Revert_StaleEpoch() public {
        vm.prank(owner);
        pv.setPredicateProver(mock);
        // VALIDITY_EPOCHS = 4; stale when currentEpoch > epoch + 4
        mock.set(human, AGE18, true, pv.currentEpoch() - 5);
        vm.prank(consumerA);
        vm.expectRevert(PredicateVerifier.StaleEpoch.selector);
        pv.consumeWithProof(proof, signals, ctx, AGE18, human);
    }

    function test_ConsumeWithProof_Revert_BadProofBubbles() public {
        vm.prank(owner);
        pv.setPredicateProver(mock);
        mock.set(human, AGE18, true, pv.currentEpoch());
        mock.setRevert(true); // the prover rejects the proof
        vm.prank(consumerA);
        vm.expectRevert(bytes("bad proof"));
        pv.consumeWithProof(proof, signals, ctx, AGE18, human);
    }

    function test_ConsumeWithProof_DifferentContext_NotReplay() public {
        _wireFreshTrueAge18();
        vm.prank(consumerA);
        pv.consumeWithProof(proof, signals, ctx, AGE18, human);

        bytes memory ctx2 = abi.encode(uint256(0xBEEF));
        vm.prank(consumerA);
        bool r = pv.consumeWithProof(proof, signals, ctx2, AGE18, human);
        assertTrue(r); // same human+consumer, different context => allowed
    }

    function test_ConsumeWithProof_DifferentConsumer_NotReplay() public {
        _wireFreshTrueAge18();
        vm.prank(consumerA);
        pv.consumeWithProof(proof, signals, ctx, AGE18, human);

        // same (subject, context) but a different consumer keeps its own replay slot
        vm.prank(consumerB);
        bool r = pv.consumeWithProof(proof, signals, ctx, AGE18, human);
        assertTrue(r);
    }

    /*//////////////////////////////////////////////////////////////  checkProof (stateless)  */

    function test_CheckProof_ReturnsResult_NoStateWrite() public {
        _wireFreshTrueAge18();

        bool r = pv.checkProof(proof, signals, ctx, AGE18, human);
        assertTrue(r);
        assertTrue(pv.checkProof(proof, signals, ctx, AGE18, human));

        // it did NOT spend — a subsequent consume for the same key still succeeds
        vm.prank(consumerA);
        bool r2 = pv.consumeWithProof(proof, signals, ctx, AGE18, human);
        assertTrue(r2);
    }

    function test_CheckProof_RevertsIdentically() public {
        // unset
        vm.expectRevert(PredicateVerifier.PredicateProverUnset.selector);
        pv.checkProof(proof, signals, ctx, AGE18, human);

        _wireFreshTrueAge18();
        vm.expectRevert(PredicateVerifier.WrongPredicate.selector);
        pv.checkProof(proof, signals, ctx, AGE21, human);
        vm.expectRevert(PredicateVerifier.SubjectMismatch.selector);
        pv.checkProof(proof, signals, ctx, AGE18, makeAddr("notHuman"));

        mock.set(human, AGE18, true, pv.currentEpoch() - 5);
        vm.expectRevert(PredicateVerifier.StaleEpoch.selector);
        pv.checkProof(proof, signals, ctx, AGE18, human);

        mock.set(human, AGE18, true, pv.currentEpoch());
        mock.setRevert(true);
        vm.expectRevert(bytes("bad proof"));
        pv.checkProof(proof, signals, ctx, AGE18, human);
    }
}
