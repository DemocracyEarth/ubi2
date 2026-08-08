// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/**
 * CROSS-STACK TEST FIXTURES for the predicate layer (LANE B copy).
 *
 * These are the App/SDK lane's self-contained mirror of the Solidity lane's
 * `PredicateVerifier.sol` + `SybilResistantVote.sol`, kept here so
 * `test/predicate.crossstack.ts` can drive a REAL on-chain predicate-gated vote
 * on anvil and assert the App/SDK EIP-712 encoding is accepted byte-for-byte —
 * WITHOUT depending on the contracts package having landed yet.
 *
 * The `PREDICATE_TYPEHASH` string and the `EIP712("ProofOfHumanityPredicate","1")`
 * domain below come from the SAME pinned spec string as `app/lib/predicate.ts`, so
 * the digest matches regardless of which lane compiled the verifier. When the
 * Solidity lane lands, this fixture and `contracts/src/PredicateVerifier.sol` must
 * stay byte-identical on those two facts (the test would fail otherwise).
 */

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @notice The v1 predicate proof — the issuer's signed assertion that `subject`
///         satisfies `predicate` (as boolean `result`) for one `consumer` in one
///         `context`. Carries NO personal attribute — only the boolean + binding.
struct PredicateAttestation {
    address consumer;
    bytes32 context;
    bytes32 predicate;
    bool result;
    address subject;
    uint32 epoch;
    uint256 nonce;
}

/// @notice The unique-human SBT surface the demo consumer reads.
interface IProofOfHumanity {
    function ownerOf(uint256 tokenId) external view returns (address);
    function isValid(uint256 tokenId) external view returns (bool);
}

/// @title Design seam for the FUTURE trustless (holder-side ZK) predicate path.
/// @notice In v2 the issuer signature is replaced by a holder-generated ZK proof
///         over the held HumanCredential, verified here instead of `ECDSA.recover`.
///         The `consume`/`check` ABI does not change — this is an additive drop-in.
/// @dev INTENTIONALLY UNIMPLEMENTED in v1. Declared only to fix the ABI seam.
interface IPredicateProver {
    function proveAndCheck(bytes calldata proof, PredicateAttestation calldata att) external view returns (bool);
}

/// @title PredicateVerifier (v1, issuer-attested)
/// @notice Recovers the issuer from an EIP-712 `PredicateAttestation` and enforces
///         consumer / subject / freshness binding, with anti-replay on `consume`.
contract PredicateVerifier is Ownable, EIP712 {
    bytes32 public constant PREDICATE_TYPEHASH = keccak256(
        "PredicateAttestation(address consumer,bytes32 context,bytes32 predicate,bool result,address subject,uint32 epoch,uint256 nonce)"
    );

    /// @notice Validity epoch length + window — mirrors the ProofOfHumanity SBT.
    uint256 public constant EPOCH = 90 days;
    uint32 public constant VALIDITY_EPOCHS = 4;

    address public issuer;

    /// @notice Spent anti-replay keys: keccak(subject, consumer, context, nonce).
    mapping(bytes32 => bool) public used;

    error InvalidIssuer();
    error InvalidSigner();
    error WrongConsumer();
    error WrongSubject();
    error FutureEpoch();
    error StaleEpoch();
    error ReplayedNonce();

    event IssuerUpdated(address indexed previous, address indexed next);

    constructor(address initialOwner, address initialIssuer)
        Ownable(initialOwner)
        EIP712("ProofOfHumanityPredicate", "1")
    {
        if (initialIssuer == address(0)) revert InvalidIssuer();
        issuer = initialIssuer;
        emit IssuerUpdated(address(0), initialIssuer);
    }

    function setIssuer(address newIssuer) external onlyOwner {
        if (newIssuer == address(0)) revert InvalidIssuer();
        emit IssuerUpdated(issuer, newIssuer);
        issuer = newIssuer;
    }

    function currentEpoch() public view returns (uint32) {
        return uint32(block.timestamp / EPOCH);
    }

    function _structHash(PredicateAttestation calldata a) private pure returns (bytes32) {
        return keccak256(
            abi.encode(PREDICATE_TYPEHASH, a.consumer, a.context, a.predicate, a.result, a.subject, a.epoch, a.nonce)
        );
    }

    /// @notice EIP-712 digest of `att` — must equal the SDK's `hashPredicateAttestation`.
    function hashAttestation(PredicateAttestation calldata att) external view returns (bytes32) {
        return _hashTypedDataV4(_structHash(att));
    }

    function domainSeparator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    /// @dev Shared validation: signature, consumer/subject binding, freshness.
    function _verify(PredicateAttestation calldata att, bytes calldata sig, address presenter, address consumer)
        private
        view
        returns (bool)
    {
        address signer = ECDSA.recover(_hashTypedDataV4(_structHash(att)), sig);
        if (signer != issuer) revert InvalidSigner();
        if (att.consumer != consumer) revert WrongConsumer();
        if (att.subject != presenter) revert WrongSubject();
        uint32 nowE = currentEpoch();
        if (att.epoch > nowE) revert FutureEpoch();
        if (uint256(nowE) > uint256(att.epoch) + VALIDITY_EPOCHS) revert StaleEpoch();
        return att.result;
    }

    /// @notice Stateless check (no replay-state write) — for view/off-chain gates.
    function check(PredicateAttestation calldata att, bytes calldata sig, address presenter, address consumer)
        external
        view
        returns (bool)
    {
        return _verify(att, sig, presenter, consumer);
    }

    /// @notice Stateful consume: validates against `msg.sender` (the calling consumer)
    ///         and burns the anti-replay key. Reverts on reuse.
    function consume(PredicateAttestation calldata att, bytes calldata sig, address presenter)
        external
        returns (bool)
    {
        bool result = _verify(att, sig, presenter, msg.sender);
        bytes32 key = keccak256(abi.encode(att.subject, att.consumer, att.context, att.nonce));
        if (used[key]) revert ReplayedNonce();
        used[key] = true;
        return result;
    }
}

/// @title ConsumerProbe — a minimal stateful consumer used ONLY by the cross-stack
///        test to exercise `PredicateVerifier.consume` directly (anti-replay +
///        consumer binding) without the SybilResistantVote one-vote-per-token guard
///        masking the verifier-level `ReplayedNonce`.
contract ConsumerProbe {
    PredicateVerifier public immutable pv;

    constructor(PredicateVerifier _pv) {
        pv = _pv;
    }

    function probe(PredicateAttestation calldata att, bytes calldata sig, address presenter) external returns (bool) {
        return pv.consume(att, sig, presenter);
    }
}

/// @title SybilResistantVote — demo consumer proving the whole thesis end-to-end.
/// @notice One unique human, one vote, gated on a predicate — revealing only the
///         boolean. No age / nationality / OFAC value ever reaches on-chain state.
contract SybilResistantVote {
    IProofOfHumanity public immutable poh;
    PredicateVerifier public immutable pv;
    bytes32 public immutable requiredPredicate;
    bytes32 public immutable context;

    mapping(uint256 => bool) public voted;
    uint256 public yesVotes;
    uint256 public noVotes;

    error NotHuman();
    error InvalidHuman();
    error AlreadyVoted();
    error WrongPredicate();
    error WrongContext();
    error PredicateFailed();

    event Voted(uint256 indexed tokenId, bool support);

    constructor(IProofOfHumanity _poh, PredicateVerifier _pv, bytes32 _requiredPredicate, bytes32 _context) {
        poh = _poh;
        pv = _pv;
        requiredPredicate = _requiredPredicate;
        context = _context;
    }

    function vote(uint256 tokenId, bool support, PredicateAttestation calldata att, bytes calldata sig) external {
        // Unique valid human, bound to the caller.
        if (poh.ownerOf(tokenId) != msg.sender) revert NotHuman();
        if (!poh.isValid(tokenId)) revert InvalidHuman();
        if (voted[tokenId]) revert AlreadyVoted();

        // The proof must be for THIS predicate + context.
        if (att.predicate != requiredPredicate) revert WrongPredicate();
        if (att.context != context) revert WrongContext();

        // Consume it — the verifier binds consumer(msg.sender)/subject/freshness + anti-replay.
        if (!pv.consume(att, sig, msg.sender)) revert PredicateFailed();

        voted[tokenId] = true;
        if (support) {
            yesVotes++;
        } else {
            noVotes++;
        }
        emit Voted(tokenId, support);
    }
}
