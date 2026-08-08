// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ProofOfHumanity} from "./ProofOfHumanity.sol";
import {PredicateVerifier, PredicateAttestation} from "./PredicateVerifier.sol";

/// @title Sybil-Resistant Vote
/// @notice A minimal demo consumer that proves the predicate-layer thesis
///         end-to-end: a single yes/no proposal vote gated on (1) a valid,
///         unique {ProofOfHumanity} SBT — one human, one vote — and (2) an
///         issuer-attested predicate (e.g. `age>=18`), revealing ONLY the
///         boolean. No age, nationality, sanctions value or any personal
///         attribute is stored, logged or passed on-chain: the tally is just
///         two counters plus a per-token voted flag.
/// @dev The token id supplies Sybil resistance (uniqueness) while the
///      {PredicateAttestation} supplies the eligibility predicate. The two are
///      bound to the SAME human because `poh.ownerOf(tokenId) == msg.sender` and
///      the verifier requires `att.subject == msg.sender`.
contract SybilResistantVote {
    /*//////////////////////////////////////////////////////////////
                              IMMUTABLES
    //////////////////////////////////////////////////////////////*/

    /// @notice The base unique-human SBT. Supplies Sybil resistance.
    ProofOfHumanity public immutable poh;

    /// @notice The predicate checkpoint that verifies + spends attestations.
    PredicateVerifier public immutable predicateVerifier;

    /// @notice The exact predicate every voter must satisfy, as
    ///         `keccak256(bytes(descriptor))` (e.g. of "age>=18").
    bytes32 public immutable requiredPredicate;

    /// @notice This proposal's context tag. The attestation must be bound to it,
    ///         so an attestation minted for another proposal cannot be reused here.
    bytes32 public immutable context;

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Yes votes.
    uint256 public yesVotes;

    /// @notice No votes.
    uint256 public noVotes;

    /// @notice One-human-one-vote: whether a given SBT has already voted.
    mapping(uint256 tokenId => bool) public voted;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted on a counted vote. Reveals only who voted (by token) and
    ///         their yes/no choice — never the predicate's underlying attribute.
    event Voted(uint256 indexed tokenId, address indexed voter, bool support);

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @dev Caller is not the current holder of `tokenId`.
    error NotTokenHolder();
    /// @dev The SBT is outside its validity window (expired credential).
    error HumanNotValid();
    /// @dev This SBT already voted on this proposal.
    error AlreadyVoted();
    /// @dev The attestation proves a different predicate than {requiredPredicate}.
    error WrongPredicate();
    /// @dev The attestation is bound to a different context than this proposal.
    error WrongContext();
    /// @dev The issuer attested `result == false` (predicate does not hold).
    error PredicateNotSatisfied();
    /// @dev A constructor dependency was the zero address.
    error ZeroAddress();

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @param poh_               The base Proof-of-Humanity SBT.
    /// @param pv_                The predicate verifier checkpoint.
    /// @param requiredPredicate_ The predicate id every voter must prove.
    /// @param context_           This proposal's context tag.
    constructor(ProofOfHumanity poh_, PredicateVerifier pv_, bytes32 requiredPredicate_, bytes32 context_) {
        if (address(poh_) == address(0) || address(pv_) == address(0)) revert ZeroAddress();
        poh = poh_;
        predicateVerifier = pv_;
        requiredPredicate = requiredPredicate_;
        context = context_;
    }

    /*//////////////////////////////////////////////////////////////
                                  VOTE
    //////////////////////////////////////////////////////////////*/

    /// @notice Cast a Sybil-resistant, predicate-gated vote on the proposal.
    /// @dev Order of checks (fail-closed, all before any state write):
    ///      1. `msg.sender` holds `tokenId` (Sybil identity binding).
    ///      2. the SBT is still valid (unexpired credential).
    ///      3. `tokenId` has not voted (one human, one vote).
    ///      4. the attestation is for THIS predicate and THIS context.
    ///      5. {PredicateVerifier.consume} verifies the issuer signature, binds
    ///         `subject == msg.sender` and `consumer == this`, checks freshness,
    ///         and spends the nonce (anti-replay) — returning the boolean, which
    ///         must be `true`.
    ///      Only then is the vote counted. The attestation's `result` is the
    ///      sole identity-derived value that ever touches this contract, and it
    ///      is never persisted.
    /// @param tokenId   The caller's Proof-of-Humanity token.
    /// @param support   `true` for yes, `false` for no.
    /// @param att       The issuer-signed predicate attestation.
    /// @param signature The issuer's EIP-712 signature over `att`.
    function vote(uint256 tokenId, bool support, PredicateAttestation calldata att, bytes calldata signature) external {
        // (1) Unique-human binding: caller must hold the token.
        if (poh.ownerOf(tokenId) != msg.sender) revert NotTokenHolder();
        // (2) The credential must still be within its validity window.
        if (!poh.isValid(tokenId)) revert HumanNotValid();
        // (3) One human, one vote.
        if (voted[tokenId]) revert AlreadyVoted();

        // (4) The attestation must be for exactly this predicate + proposal.
        if (att.predicate != requiredPredicate) revert WrongPredicate();
        if (att.context != context) revert WrongContext();

        // (5) Verify + spend the attestation (binds subject == caller,
        //     consumer == this, checks freshness, anti-replay). Reveals only the bool.
        bool ok = predicateVerifier.consume(att, signature, msg.sender);
        if (!ok) revert PredicateNotSatisfied();

        // Record the vote (mark BEFORE tally is fine; consume already spent the nonce).
        voted[tokenId] = true;
        if (support) {
            yesVotes++;
        } else {
            noVotes++;
        }

        emit Voted(tokenId, msg.sender, support);
    }
}
