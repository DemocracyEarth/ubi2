// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {ProofOfHumanity, HumanityVoucher} from "../src/ProofOfHumanity.sol";
import {PredicateVerifier, PredicateAttestation} from "../src/PredicateVerifier.sol";
import {SybilResistantVote} from "../src/SybilResistantVote.sol";

/// @notice End-to-end proof of the predicate-layer thesis: a unique valid human
///         casts a vote gated on an `age>=18` predicate that reveals ONLY the
///         boolean — no age/nationality/sanctions value on-chain.
contract SybilResistantVoteTest is Test {
    ProofOfHumanity internal poh;
    PredicateVerifier internal pv;
    SybilResistantVote internal ballot;

    // Same issuer key signs both the mint voucher and the predicate attestation.
    uint256 internal constant ISSUER_PK = 0xA11CE;
    uint256 internal constant IMPOSTOR_PK = 0xBAD;
    address internal issuer;

    address internal owner;
    address internal alice;
    address internal bob;
    address internal relayer;

    uint256 internal constant NULL_A = uint256(keccak256("nullifier-a"));
    uint256 internal constant NULL_B = uint256(keccak256("nullifier-b"));

    bytes32 internal constant PRED_AGE18 = keccak256("age>=18");
    bytes32 internal constant PRED_AGE21 = keccak256("age>=21");
    bytes32 internal constant CTX = keccak256("proposal-42");

    bytes32 internal constant PREDICATE_TYPEHASH = keccak256(
        "PredicateAttestation(address consumer,bytes32 context,bytes32 predicate,bool result,address subject,uint32 epoch,uint256 nonce)"
    );

    uint256 internal constant EPOCH = 90 days;

    // Cached in setUp so signing needs NO real external call (only the `vm.sign`
    // cheatcode). This keeps an inline `_sign(...)` argument from consuming a
    // preceding `vm.prank` / `vm.expectRevert`, which cheatcodes skip.
    bytes32 internal pvDomainSeparator;

    function setUp() public {
        issuer = vm.addr(ISSUER_PK);
        owner = makeAddr("owner");
        alice = makeAddr("alice");
        bob = makeAddr("bob");
        relayer = makeAddr("relayer");

        vm.warp(1_700_000_000);
        poh = new ProofOfHumanity(owner, issuer);
        pv = new PredicateVerifier(owner, issuer);
        ballot = new SybilResistantVote(poh, pv, PRED_AGE18, CTX);
        pvDomainSeparator = pv.domainSeparator();
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    function _mint(address to, uint256 nullifier) internal returns (uint256) {
        HumanityVoucher memory v = HumanityVoucher({to: to, nullifier: nullifier, epoch: poh.currentEpoch()});
        bytes32 digest = poh.hashVoucher(v);
        (uint8 vv, bytes32 r, bytes32 s) = vm.sign(ISSUER_PK, digest);
        vm.prank(relayer);
        return poh.mintWithVoucher(v, abi.encodePacked(r, s, vv));
    }

    function _att(address subject, bytes32 predicate, bytes32 context, bool result, uint256 nonce)
        internal
        view
        returns (PredicateAttestation memory)
    {
        return PredicateAttestation({
            consumer: address(ballot),
            context: context,
            predicate: predicate,
            result: result,
            subject: subject,
            epoch: pv.currentEpoch(),
            nonce: nonce
        });
    }

    /// @dev Computes the EIP-712 digest locally (no external call to `pv`) so an
    ///      inline `_sign(...)` argument can't consume a preceding cheatcode. The
    ///      digest is asserted equal to `pv.hashAttestation` in a dedicated test.
    function _digest(PredicateAttestation memory att) internal view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                PREDICATE_TYPEHASH,
                att.consumer,
                att.context,
                att.predicate,
                att.result,
                att.subject,
                att.epoch,
                att.nonce
            )
        );
        return keccak256(abi.encodePacked(hex"1901", pvDomainSeparator, structHash));
    }

    function _sign(uint256 pk, PredicateAttestation memory att) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, _digest(att));
        return abi.encodePacked(r, s, v);
    }

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    function test_Constructor_WiresDependencies() public view {
        assertEq(address(ballot.poh()), address(poh));
        assertEq(address(ballot.predicateVerifier()), address(pv));
        assertEq(ballot.requiredPredicate(), PRED_AGE18);
        assertEq(ballot.context(), CTX);
        assertEq(ballot.yesVotes(), 0);
        assertEq(ballot.noVotes(), 0);
    }

    /// @notice The locally-derived EIP-712 digest (what an off-chain viem signer
    ///         computes) must equal the verifier's on-chain hash — the pinned
    ///         typehash + domain make the proof portable across the stack.
    function test_DigestMatchesOnChainHash() public view {
        PredicateAttestation memory att = _att(alice, PRED_AGE18, CTX, true, 7);
        assertEq(_digest(att), pv.hashAttestation(att));
    }

    function test_Constructor_RevertsOnZeroDep() public {
        vm.expectRevert(SybilResistantVote.ZeroAddress.selector);
        new SybilResistantVote(ProofOfHumanity(address(0)), pv, PRED_AGE18, CTX);
        vm.expectRevert(SybilResistantVote.ZeroAddress.selector);
        new SybilResistantVote(poh, PredicateVerifier(address(0)), PRED_AGE18, CTX);
    }

    /*//////////////////////////////////////////////////////////////
                              HAPPY PATH
    //////////////////////////////////////////////////////////////*/

    function test_Vote_HappyPath_GatedByPredicate() public {
        uint256 tokenId = _mint(alice, NULL_A);
        PredicateAttestation memory att = _att(alice, PRED_AGE18, CTX, true, 1);
        bytes memory sig = _sign(ISSUER_PK, att);

        vm.expectEmit(true, true, false, true, address(ballot));
        emit SybilResistantVote.Voted(tokenId, alice, true);

        vm.prank(alice);
        ballot.vote(tokenId, true, att, sig);

        assertEq(ballot.yesVotes(), 1);
        assertEq(ballot.noVotes(), 0);
        assertTrue(ballot.voted(tokenId));
    }

    function test_Vote_NoTally() public {
        uint256 tokenId = _mint(alice, NULL_A);
        PredicateAttestation memory att = _att(alice, PRED_AGE18, CTX, true, 1);
        vm.prank(alice);
        ballot.vote(tokenId, false, att, _sign(ISSUER_PK, att));
        assertEq(ballot.noVotes(), 1);
        assertEq(ballot.yesVotes(), 0);
    }

    function test_Vote_TwoDistinctHumans() public {
        uint256 idA = _mint(alice, NULL_A);
        uint256 idB = _mint(bob, NULL_B);

        PredicateAttestation memory attA = _att(alice, PRED_AGE18, CTX, true, 1);
        vm.prank(alice);
        ballot.vote(idA, true, attA, _sign(ISSUER_PK, attA));

        // Bob also satisfies the predicate (result=true) but casts a NO vote
        // (support=false) — the vote choice is independent of the predicate.
        PredicateAttestation memory attB = _att(bob, PRED_AGE18, CTX, true, 1);
        vm.prank(bob);
        ballot.vote(idB, false, attB, _sign(ISSUER_PK, attB));

        assertEq(ballot.yesVotes(), 1);
        assertEq(ballot.noVotes(), 1);
    }

    /// @notice The whole point: only the boolean crosses on-chain. No age,
    ///         nationality or sanctions value appears in this contract's state or
    ///         the emitted event topics/data. We assert the tally is exactly the
    ///         counters (no attribute storage exists to inspect) and the event
    ///         carries only (tokenId, voter, support).
    function test_Vote_RevealsOnlyBoolean() public {
        uint256 tokenId = _mint(alice, NULL_A);
        PredicateAttestation memory att = _att(alice, PRED_AGE18, CTX, true, 1);
        bytes memory sig = _sign(ISSUER_PK, att);

        vm.recordLogs();
        vm.prank(alice);
        ballot.vote(tokenId, true, att, sig);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        // Find the Voted event; assert its payload is only the support bool.
        bytes32 votedSig = keccak256("Voted(uint256,address,bool)");
        bool found;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].emitter == address(ballot) && logs[i].topics[0] == votedSig) {
                found = true;
                // data is only the non-indexed `support` bool (32 bytes).
                assertEq(logs[i].data.length, 32);
                assertEq(abi.decode(logs[i].data, (bool)), true);
            }
        }
        assertTrue(found);
    }

    /*//////////////////////////////////////////////////////////////
                        SYBIL / HUMANITY GATES
    //////////////////////////////////////////////////////////////*/

    function test_Vote_Revert_NonHuman_NoToken() public {
        // bob holds no token; ownerOf reverts (ERC721NonexistentToken).
        PredicateAttestation memory att = _att(bob, PRED_AGE18, CTX, true, 1);
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSignature("ERC721NonexistentToken(uint256)", uint256(1)));
        ballot.vote(1, true, att, _sign(ISSUER_PK, att));
    }

    function test_Vote_Revert_NotTokenHolder() public {
        uint256 tokenId = _mint(alice, NULL_A);
        // bob tries to vote with alice's token.
        PredicateAttestation memory att = _att(bob, PRED_AGE18, CTX, true, 1);
        vm.prank(bob);
        vm.expectRevert(SybilResistantVote.NotTokenHolder.selector);
        ballot.vote(tokenId, true, att, _sign(ISSUER_PK, att));
    }

    function test_Vote_Revert_ExpiredSBT() public {
        uint256 tokenId = _mint(alice, NULL_A);
        // Warp past the SBT validity window (VALIDITY_EPOCHS = 4).
        vm.warp(block.timestamp + 5 * EPOCH);

        // Fresh attestation for the current epoch so the predicate gate isn't what fails.
        PredicateAttestation memory att = _att(alice, PRED_AGE18, CTX, true, 1);
        vm.prank(alice);
        vm.expectRevert(SybilResistantVote.HumanNotValid.selector);
        ballot.vote(tokenId, true, att, _sign(ISSUER_PK, att));
    }

    function test_Vote_Revert_DoubleVote() public {
        uint256 tokenId = _mint(alice, NULL_A);

        PredicateAttestation memory att1 = _att(alice, PRED_AGE18, CTX, true, 1);
        vm.prank(alice);
        ballot.vote(tokenId, true, att1, _sign(ISSUER_PK, att1));

        // Second vote with a fresh nonce still blocked by the per-token flag.
        PredicateAttestation memory att2 = _att(alice, PRED_AGE18, CTX, true, 2);
        vm.prank(alice);
        vm.expectRevert(SybilResistantVote.AlreadyVoted.selector);
        ballot.vote(tokenId, false, att2, _sign(ISSUER_PK, att2));

        assertEq(ballot.yesVotes(), 1);
        assertEq(ballot.noVotes(), 0);
    }

    /*//////////////////////////////////////////////////////////////
                        PREDICATE GATES
    //////////////////////////////////////////////////////////////*/

    function test_Vote_Revert_WrongPredicate() public {
        uint256 tokenId = _mint(alice, NULL_A);
        // Proves age>=21, but this ballot requires age>=18.
        PredicateAttestation memory att = _att(alice, PRED_AGE21, CTX, true, 1);
        vm.prank(alice);
        vm.expectRevert(SybilResistantVote.WrongPredicate.selector);
        ballot.vote(tokenId, true, att, _sign(ISSUER_PK, att));
    }

    function test_Vote_Revert_WrongContext() public {
        uint256 tokenId = _mint(alice, NULL_A);
        PredicateAttestation memory att = _att(alice, PRED_AGE18, keccak256("proposal-99"), true, 1);
        vm.prank(alice);
        vm.expectRevert(SybilResistantVote.WrongContext.selector);
        ballot.vote(tokenId, true, att, _sign(ISSUER_PK, att));
    }

    function test_Vote_Revert_PredicateFalse() public {
        uint256 tokenId = _mint(alice, NULL_A);
        // Issuer honestly attests the human is NOT 18+ (result=false).
        PredicateAttestation memory att = _att(alice, PRED_AGE18, CTX, false, 1);
        vm.prank(alice);
        vm.expectRevert(SybilResistantVote.PredicateNotSatisfied.selector);
        ballot.vote(tokenId, true, att, _sign(ISSUER_PK, att));
    }

    function test_Vote_Revert_WrongConsumerBinding() public {
        uint256 tokenId = _mint(alice, NULL_A);
        // Attestation bound to a different consumer address than the ballot.
        PredicateAttestation memory att = _att(alice, PRED_AGE18, CTX, true, 1);
        att.consumer = makeAddr("other-consumer");
        vm.prank(alice);
        vm.expectRevert(PredicateVerifier.ConsumerMismatch.selector);
        ballot.vote(tokenId, true, att, _sign(ISSUER_PK, att));
    }

    function test_Vote_Revert_WrongSubjectBinding() public {
        uint256 tokenId = _mint(alice, NULL_A);
        // Attestation subject is bob, but alice presents it (holder of the token).
        PredicateAttestation memory att = _att(bob, PRED_AGE18, CTX, true, 1);
        vm.prank(alice);
        vm.expectRevert(PredicateVerifier.SubjectMismatch.selector);
        ballot.vote(tokenId, true, att, _sign(ISSUER_PK, att));
    }

    function test_Vote_Revert_BadIssuerSig() public {
        uint256 tokenId = _mint(alice, NULL_A);
        PredicateAttestation memory att = _att(alice, PRED_AGE18, CTX, true, 1);
        vm.prank(alice);
        vm.expectRevert(PredicateVerifier.InvalidSigner.selector);
        ballot.vote(tokenId, true, att, _sign(IMPOSTOR_PK, att));
    }

    function test_Vote_Revert_StaleAttestationEpoch() public {
        uint256 tokenId = _mint(alice, NULL_A);
        // Build an attestation pinned to the current epoch, then warp the
        // attestation past its freshness window while keeping the SBT valid by
        // also refreshing... instead: mint fresh SBT each epoch is complex, so
        // sign a stale-epoch attestation directly.
        PredicateAttestation memory att = _att(alice, PRED_AGE18, CTX, true, 1);
        att.epoch = pv.currentEpoch() - (pv.VALIDITY_EPOCHS() + 1); // already stale
        vm.prank(alice);
        vm.expectRevert(PredicateVerifier.StaleEpoch.selector);
        ballot.vote(tokenId, true, att, _sign(ISSUER_PK, att));
    }

    function test_Vote_Revert_ReplayedAttestation() public {
        uint256 idA = _mint(alice, NULL_A);
        PredicateAttestation memory att = _att(alice, PRED_AGE18, CTX, true, 1);
        bytes memory sig = _sign(ISSUER_PK, att);

        vm.prank(alice);
        ballot.vote(idA, true, att, sig);

        // Even if alice somehow got a second token, replaying the SAME attestation
        // (same nonce) is rejected by the verifier's anti-replay before double-vote.
        // Here we re-present it directly to the verifier to isolate the replay path.
        vm.prank(address(ballot));
        vm.expectRevert(PredicateVerifier.AttestationReplayed.selector);
        pv.consume(att, sig, alice);
    }
}
