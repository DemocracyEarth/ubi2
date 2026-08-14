// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/*//////////////////////////////////////////////////////////////
                        SHARED TYPES
//////////////////////////////////////////////////////////////*/

/// @notice The v1 predicate "proof": an issuer-signed attestation that a verified
///         human satisfies (or does not satisfy) a single yes/no predicate about
///         their identity — revealing ONLY the resulting boolean, never the
///         underlying age / nationality / sanctions value.
/// @dev In v1 the issuer (the same trusted party that mints the base
///      Proof-of-Humanity SBT) is the prover: it holds/re-verifies the human's
///      private off-chain `HumanCredential`, evaluates the predicate, and signs
///      this attestation. The attestation is bound to ONE `consumer` +
///      `context` + `subject`, which is exactly what makes it unlinkable across
///      consumers: two consumers see two independent signatures over two
///      different `consumer` addresses and cannot correlate them.
///
///      The trustless v2 replaces the issuer signature with a holder-side ZK
///      proof (see {IPredicateProver}); the on-chain consumer surface is
///      identical, so v2 is an additive, non-breaking upgrade.
///
/// @param consumer  The verifying contract/app the proof is minted for. Binds
///                  the attestation to one consumer ⇒ unlinkable across
///                  consumers. Enforced `== msg.sender` in {consume}.
/// @param context   Consumer-defined scope (e.g. a proposal id, a session tag).
///                  The consumer decides its meaning; the verifier only binds to
///                  it (and folds it into the anti-replay key).
/// @param predicate `keccak256(<canonical descriptor>)` — the predicate being
///                  proven. See the descriptor grammar in {PredicateVerifier}.
/// @param result    The boolean the issuer computed from the human's credential
///                  (`true` = predicate holds). This is the ONLY identity-derived
///                  bit that ever crosses on-chain.
/// @param subject   The presenting human's address. Binds the attestation to the
///                  presenter; enforced `== presenter` in {consume}.
/// @param epoch     The coarse validity epoch the credential was verified in
///                  (`block.timestamp / EPOCH`). Checked for freshness — carries
///                  no exact date.
/// @param nonce     Anti-replay salt chosen per request. The tuple
///                  `(subject, consumer, context, nonce)` is single-use.
struct PredicateAttestation {
    address consumer;
    bytes32 context;
    bytes32 predicate;
    bool result;
    address subject;
    uint32 epoch;
    uint256 nonce;
}

/*//////////////////////////////////////////////////////////////
                        INTERFACES
//////////////////////////////////////////////////////////////*/

/// @title Design seam for the FUTURE fully-trustless predicate path (v2).
/// @notice In v1 a consumer trusts the issuer's signature over a
///         {PredicateAttestation}. In the trustless v2 the human keeps a private
///         credential and, at presentation time, produces a zero-knowledge proof
///         that the credential satisfies the predicate — the verifier checks the
///         proof on-chain and never sees, nor trusts anyone about, the
///         underlying attribute. A `consumeWithProof(bytes proof, ...)`
///         entrypoint would call {verifyPredicate} on an implementation of this
///         interface and then apply the EXACT same binding + freshness +
///         anti-replay logic that {PredicateVerifier.consume} uses today.
/// @dev INTENTIONALLY UNIMPLEMENTED in v1. Declared only to fix the ABI seam so
///      the trustless path is additive and non-breaking. Like the attestation,
///      it extracts only the (subject, predicate, boolean result, epoch) —
///      never any personal attribute value. A v2 proof would additionally bind a
///      per-context pseudonym (nullifier) so one human cannot present twice for
///      the same context, replacing the issuer-chosen `nonce`.
interface IPredicateProver {
    /// @param proof         The opaque ZK proof bytes (e.g. a Groth16 proof).
    /// @param publicSignals The proof's public inputs.
    /// @param context       Host-created `abi.encode(consumer, applicationContext)`
    ///                      envelope. The presenter never supplies the consumer.
    /// @return subject   The address the proof is bound to.
    /// @return predicate The `keccak256(descriptor)` proven.
    /// @return result    The boolean the predicate evaluates to.
    /// @return epoch     The credential epoch the proof attests freshness for.
    function verifyPredicate(bytes calldata proof, uint256[] calldata publicSignals, bytes calldata context)
        external
        view
        returns (address subject, bytes32 predicate, bool result, uint32 epoch);
}

/// @title Replay identifier extension for stateful predicate consumption
/// @notice Returns the proof-system-specific, consumer-scoped identifier that
///         must be spent after a proof verifies. For v2 this is the scoped
///         nullifier public signal, so changing the presenting wallet cannot
///         create a second slot for the same human and scope.
/// @dev Kept separate from {IPredicateProver} so the forever verification
///      interface remains proof-system agnostic. Every prover configured for
///      stateful {PredicateVerifier.consumeWithProof} MUST implement it.
interface IPredicateProverReplay {
    function proofReplayIdentifier(uint256[] calldata publicSignals) external view returns (bytes32);
}

/*//////////////////////////////////////////////////////////////
                        PREDICATE VERIFIER
//////////////////////////////////////////////////////////////*/

/// @title Predicate Verifier (v1, issuer-attested)
/// @notice On-chain checkpoint for privacy-preserving identity predicates. A
///         verified human proves a single yes/no predicate (age ≥ N, nationality
///         = X, sanctions-clear) to a specific consumer, revealing ONLY the
///         boolean result — no age, nationality, sanctions value or any other
///         attribute is ever stored, logged or passed on-chain.
/// @dev Trust model (v1): the `issuer` — the same trusted party that signs the
///      base {ProofOfHumanity} mint voucher — evaluates the predicate off-chain
///      against the human's private `HumanCredential` and EIP-712-signs a
///      {PredicateAttestation}. Consumers call {consume} to atomically verify +
///      spend that attestation. The EIP-712 domain is bound to `chainId` and
///      this contract's address, so an attestation is valid on exactly one chain
///      for exactly one deployment.
///
///      DESCRIPTOR GRAMMAR (the `predicate` field is `keccak256(bytes(descriptor))`):
///        - "age>=<N>"          e.g. "age>=18", "age>=21"   (integer minimum age)
///        - "nationality=<A3>"  e.g. "nationality=ARG"      (ISO 3166-1 alpha-3)
///        - "sanctions-clear"                               (OFAC / sanctions clear)
///      Descriptors are canonical: no spaces, lowercase keyword, uppercase A3
///      code. The verifier is descriptor-agnostic — it binds to the hash the
///      issuer signed and lets each consumer require the exact hash it needs.
///
///      The v2 trustless drop-in is fixed by {IPredicateProver}.
contract PredicateVerifier is Ownable, EIP712 {
    using ECDSA for bytes32;

    struct ProofClaims {
        address subject;
        bytes32 predicate;
        bool result;
        uint32 epoch;
    }

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice EIP-712 type hash of {PredicateAttestation}. PINNED — must be
    ///         byte-identical to the TS/viem signer and any v2 prover.
    /// @dev Type string (field order is load-bearing):
    ///      "PredicateAttestation(address consumer,bytes32 context,bytes32 predicate,bool result,address subject,uint32 epoch,uint256 nonce)".
    bytes32 public constant PREDICATE_TYPEHASH = keccak256(
        "PredicateAttestation(address consumer,bytes32 context,bytes32 predicate,bool result,address subject,uint32 epoch,uint256 nonce)"
    );

    /// @notice Domain separator for proof-system replay identifiers.
    bytes32 public constant PROOF_REPLAY_DOMAIN = keccak256("org.proofofhumanity.predicate-proof-replay");

    /// @notice Length of a validity epoch. `currentEpoch() = block.timestamp / EPOCH`.
    ///         Mirrors {ProofOfHumanity.EPOCH} so credential + attestation epochs align.
    uint256 public constant EPOCH = 90 days;

    /// @notice How many epochs an attestation stays fresh after its signed epoch.
    ///         `VALIDITY_EPOCHS = 4` epochs of 90 days is ~1 year. Mirrors the SBT.
    uint32 public constant VALIDITY_EPOCHS = 4;

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Address whose EIP-712 signature authorizes attestations. Rotatable
    ///         to a threshold multisig via {setIssuer}. Same key/pattern as the
    ///         {ProofOfHumanity} mint issuer.
    address public issuer;

    /// @notice Spent anti-replay keys. `true` once an attestation with a given
    ///         `(subject, consumer, context, nonce)` tuple has been consumed.
    mapping(bytes32 replayKey => bool spent) public consumed;

    /// @notice The active holder-side ZK predicate prover (ADR-0009 seam). When set,
    ///         {consumeWithProof} accepts a proof INSTEAD of an issuer signature — the
    ///         trust root for that path moves from {issuer} to the prover's verifier.
    ///         Unset (`address(0)`) disables the proof path (issuer path only). This is
    ///         what keeps THIS deployed verifier final: upgrading v1 → v1.5 → v2 is a
    ///         {setPredicateProver} swap, never a redeploy or a consumer migration.
    IPredicateProver public prover;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when an attestation is successfully consumed. Carries only
    ///         the binding fields + the boolean result — never any attribute.
    event PredicateConsumed(
        address indexed consumer, address indexed subject, bytes32 indexed predicate, bytes32 context, bool result
    );

    /// @notice Emitted when the authorized attestation issuer is set or rotated.
    event IssuerUpdated(address indexed previousIssuer, address indexed newIssuer);

    /// @notice Emitted when the ZK predicate prover is set, swapped, or unset.
    event PredicateProverUpdated(address indexed previousProver, address indexed newProver);

    /// @notice Emitted when a predicate is proven via {consumeWithProof}. Carries only
    ///         the binding fields + boolean — never any attribute. `contextHash` is
    ///         `keccak256(context)` (the presentation context is opaque to this contract).
    event PredicateProven(
        address indexed consumer, address indexed subject, bytes32 indexed predicate, bytes32 contextHash, bool result
    );

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @dev The recovered attestation signer is not the current {issuer}.
    error InvalidSigner();
    /// @dev The issuer may not be the zero address.
    error InvalidIssuer();
    /// @dev `att.consumer` does not match the calling consumer (`msg.sender` /
    ///      the `consumer` argument of {check}).
    error ConsumerMismatch();
    /// @dev `att.subject` does not match the presenting human (`presenter`).
    error SubjectMismatch();
    /// @dev `att.epoch` is outside the freshness window (too old).
    error StaleEpoch();
    /// @dev This `(subject, consumer, context, nonce)` tuple was already consumed.
    error AttestationReplayed();
    /// @dev {consumeWithProof}/{checkProof} called while no {prover} is set.
    error PredicateProverUnset();
    /// @dev The proven predicate does not match the `requiredPredicate` the consumer asked for.
    error WrongPredicate();
    /// @dev This prover-authenticated scoped identifier was already consumed for the consumer.
    error ProofReplayed();
    /// @dev The active prover does not expose a non-zero, authenticated replay identifier.
    error InvalidProofReplayIdentifier();

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @param initialOwner  Admin who can rotate the issuer (Ownable owner).
    /// @param initialIssuer Address whose signatures authorize attestations.
    constructor(address initialOwner, address initialIssuer)
        Ownable(initialOwner)
        EIP712("ProofOfHumanityPredicate", "1")
    {
        if (initialIssuer == address(0)) revert InvalidIssuer();
        issuer = initialIssuer;
        emit IssuerUpdated(address(0), initialIssuer);
    }

    /*//////////////////////////////////////////////////////////////
                                ADMIN
    //////////////////////////////////////////////////////////////*/

    /// @notice Rotate the authorized attestation issuer (e.g. to a threshold multisig).
    /// @dev Only the owner. Attestations signed by the previous issuer stop working.
    function setIssuer(address newIssuer) external onlyOwner {
        if (newIssuer == address(0)) revert InvalidIssuer();
        address previous = issuer;
        issuer = newIssuer;
        emit IssuerUpdated(previous, newIssuer);
    }

    /// @notice Set, swap, or unset the holder-side ZK predicate prover (ADR-0009 seam).
    /// @dev Only the owner (the same multisig that rotates the issuer). Pass
    ///      `address(0)` to disable the proof path. A prover only affects consumers that
    ///      opt into {consumeWithProof}; it can NEVER touch the base SBT, the nullifier
    ///      set, or UBI eligibility. Swapping the prover is how the trust model upgrades
    ///      (v1 issuer → v1.5 Self-ZK → v2 anonymous credential) with no redeploy.
    function setPredicateProver(IPredicateProver newProver) external onlyOwner {
        address previous = address(prover);
        prover = newProver;
        emit PredicateProverUpdated(previous, address(newProver));
    }

    /*//////////////////////////////////////////////////////////////
                          CONSUME / CHECK
    //////////////////////////////////////////////////////////////*/

    /// @notice Verify and SPEND a predicate attestation. Called by the consuming
    ///         contract as part of a gated action. Reverts fail-closed on any
    ///         binding, freshness, signature or replay violation; otherwise marks
    ///         the attestation spent and returns the proven boolean.
    /// @dev Binding: the attestation must name this exact caller (`att.consumer ==
    ///      msg.sender`) and this exact human (`att.subject == presenter`). The
    ///      anti-replay key folds in `context`, so the same human may present
    ///      distinct attestations for distinct contexts, but never the same one
    ///      twice.
    /// @param att       The issuer-signed attestation.
    /// @param signature The issuer's EIP-712 signature over `att`.
    /// @param presenter The human presenting the attestation (the consumer passes
    ///                  its own `msg.sender`).
    /// @return result   `att.result` — the ONLY identity-derived bit revealed.
    function consume(PredicateAttestation calldata att, bytes calldata signature, address presenter)
        external
        returns (bool result)
    {
        // Full stateless validation (signer + consumer==msg.sender + subject + freshness).
        _validate(att, signature, msg.sender, presenter);

        // Anti-replay: single-use per (subject, consumer, context, nonce).
        bytes32 key = _replayKey(att);
        if (consumed[key]) revert AttestationReplayed();
        consumed[key] = true;

        emit PredicateConsumed(att.consumer, att.subject, att.predicate, att.context, att.result);
        return att.result;
    }

    /// @notice Stateless view twin of {consume}: runs the SAME signer + binding +
    ///         freshness checks but performs NO replay-state write, for read-only
    ///         / off-chain gates that don't need single-use semantics.
    /// @dev Because it cannot read `msg.sender` meaningfully across an external
    ///      staticcall, the intended `consumer` is passed explicitly and bound
    ///      against `att.consumer`. Does NOT consult or set {consumed}. Reverts
    ///      identically to {consume} on any binding/freshness/signature failure.
    /// @param att       The issuer-signed attestation.
    /// @param signature The issuer's EIP-712 signature over `att`.
    /// @param presenter The human the attestation must be bound to.
    /// @param consumer  The consumer the attestation must be bound to.
    /// @return result   `att.result`.
    function check(PredicateAttestation calldata att, bytes calldata signature, address presenter, address consumer)
        external
        view
        returns (bool result)
    {
        _validate(att, signature, consumer, presenter);
        return att.result;
    }

    /*//////////////////////////////////////////////////////////////
                    CONSUME / CHECK — proof path (ADR-0009)
    //////////////////////////////////////////////////////////////*/

    /// @notice Verify and SPEND a holder-side ZK predicate proof — the trustless twin
    ///         of {consume}. Instead of an issuer signature, the active {prover}
    ///         cryptographically attests `(subject, predicate, result, epoch)` from a
    ///         proof the human generated on their own device. Reverts fail-closed on any
    ///         predicate / binding / freshness / replay violation.
    /// @dev The host wraps the opaque application `context` with `msg.sender`
    ///      before calling the prover, so the proof is bound to the actual consumer.
    ///      Anti-replay spends the prover-authenticated scoped identifier; in v2
    ///      that nullifier stays stable across wallet/challenge changes and varies
    ///      across consumer/context/policy scopes. Reveals ONLY the boolean.
    /// @param proof             Opaque proof bytes (e.g. a Groth16 proof).
    /// @param publicSignals     The proof's public inputs.
    /// @param context           Consumer-scoped presentation context.
    /// @param requiredPredicate The predicate the consumer requires (`keccak256(descriptor)`).
    /// @param presenter         The presenting human (the consumer passes its `msg.sender`).
    /// @return result           The proven boolean — the ONLY identity-derived bit revealed.
    function consumeWithProof(
        bytes calldata proof,
        uint256[] calldata publicSignals,
        bytes calldata context,
        bytes32 requiredPredicate,
        address presenter
    ) external returns (bool result) {
        address subject;
        (subject, result) = _validateProof(proof, publicSignals, context, requiredPredicate, presenter, msg.sender);

        bytes32 replayIdentifier;
        try IPredicateProverReplay(address(prover)).proofReplayIdentifier(publicSignals) returns (bytes32 value) {
            replayIdentifier = value;
        } catch {
            revert InvalidProofReplayIdentifier();
        }
        if (replayIdentifier == bytes32(0)) revert InvalidProofReplayIdentifier();

        bytes32 key = _proofReplayKey(msg.sender, replayIdentifier);
        if (consumed[key]) revert ProofReplayed();
        consumed[key] = true;

        emit PredicateProven(msg.sender, subject, requiredPredicate, keccak256(context), result);
        return result;
    }

    /// @notice Stateless view twin of {consumeWithProof}: same prover + predicate +
    ///         binding + freshness checks, NO replay-state write. For read-only /
    ///         off-chain gates that don't need single-use semantics.
    function checkProof(
        bytes calldata proof,
        uint256[] calldata publicSignals,
        bytes calldata context,
        bytes32 requiredPredicate,
        address presenter
    ) external view returns (bool result) {
        (, result) = _validateProof(proof, publicSignals, context, requiredPredicate, presenter, msg.sender);
    }

    /// @notice Explicit-consumer view twin for off-chain calls and integrations
    ///         that cannot make the intended consumer the `eth_call` sender.
    /// @dev Performs no replay-state read or write. The consumer is still
    ///      cryptographically forwarded to the prover and bound by its proof.
    function checkProofFor(
        bytes calldata proof,
        uint256[] calldata publicSignals,
        bytes calldata context,
        bytes32 requiredPredicate,
        address presenter,
        address consumer
    ) external view returns (bool result) {
        if (consumer == address(0)) revert ConsumerMismatch();
        (, result) = _validateProof(proof, publicSignals, context, requiredPredicate, presenter, consumer);
    }

    /// @dev Shared proof-path verification: run the {prover}, then enforce the SAME
    ///      predicate-match / subject-binding / freshness invariants the issuer path
    ///      uses. Pure w.r.t. replay state. Reverts if no prover is set.
    function _validateProof(
        bytes calldata proof,
        uint256[] calldata publicSignals,
        bytes calldata context,
        bytes32 requiredPredicate,
        address presenter,
        address consumer
    ) private view returns (address subject, bool result) {
        ProofClaims memory claims = _proofClaims(proof, publicSignals, context, consumer);

        if (claims.predicate != requiredPredicate) revert WrongPredicate();
        if (claims.subject != presenter) revert SubjectMismatch();
        if (!_isFresh(claims.epoch)) revert StaleEpoch();
        return (claims.subject, claims.result);
    }

    function _proofClaims(
        bytes calldata proof,
        uint256[] calldata publicSignals,
        bytes calldata context,
        address consumer
    ) private view returns (ProofClaims memory claims) {
        IPredicateProver p = prover;
        if (address(p) == address(0)) revert PredicateProverUnset();

        // The host, not the presenter, creates this envelope. A prover can now
        // bind the proof to the actual consuming contract without changing the
        // forever `verifyPredicate` ABI.
        bytes memory proverContext = abi.encode(consumer, context);
        (claims.subject, claims.predicate, claims.result, claims.epoch) =
            p.verifyPredicate(proof, publicSignals, proverContext);
    }

    /// @dev Anti-replay key for the proof path. The prover authenticates the
    ///      identifier; v2 returns a scoped nullifier that deliberately remains
    ///      stable when the holder changes wallets or refreshes a challenge.
    function _proofReplayKey(address consumer, bytes32 replayIdentifier) private pure returns (bytes32) {
        return keccak256(abi.encode(PROOF_REPLAY_DOMAIN, consumer, replayIdentifier));
    }

    /// @dev Shared verification: recover the issuer over the EIP-712 digest and
    ///      enforce every binding + freshness invariant. Pure w.r.t. replay state.
    function _validate(PredicateAttestation calldata att, bytes calldata signature, address consumer, address presenter)
        private
        view
    {
        if (att.consumer != consumer) revert ConsumerMismatch();
        if (att.subject != presenter) revert SubjectMismatch();
        if (!_isFresh(att.epoch)) revert StaleEpoch();

        address signer = ECDSA.recover(_hashTypedDataV4(_structHash(att)), signature);
        if (signer != issuer) revert InvalidSigner();
    }

    /// @dev The anti-replay key: single-use per (subject, consumer, context, nonce).
    function _replayKey(PredicateAttestation calldata att) private pure returns (bytes32) {
        return keccak256(abi.encode(att.subject, att.consumer, att.context, att.nonce));
    }

    /// @dev EIP-712 struct hash of an attestation (field order matches the typehash).
    function _structHash(PredicateAttestation calldata att) private pure returns (bytes32) {
        return keccak256(
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
    }

    /// @dev Freshness: within `VALIDITY_EPOCHS` of the signed epoch. Mirrors
    ///      {ProofOfHumanity._isValid}.
    function _isFresh(uint32 epoch) private view returns (bool) {
        return uint256(currentEpoch()) <= uint256(epoch) + VALIDITY_EPOCHS;
    }

    /*//////////////////////////////////////////////////////////////
                                VIEWS
    //////////////////////////////////////////////////////////////*/

    /// @notice The current coarse validity epoch, `block.timestamp / EPOCH`.
    function currentEpoch() public view returns (uint32) {
        return uint32(block.timestamp / EPOCH);
    }

    /// @notice The EIP-712 digest a signer must sign for `att` (helper for the
    ///         off-chain issuer / tests). MUST equal the viem-computed hash.
    function hashAttestation(PredicateAttestation calldata att) external view returns (bytes32) {
        return _hashTypedDataV4(_structHash(att));
    }

    /// @notice The anti-replay key for `att` (helper for tooling / tests).
    function replayKey(PredicateAttestation calldata att) external pure returns (bytes32) {
        return _replayKey(att);
    }

    /// @notice The state key consumed for an authenticated proof replay identifier.
    function proofReplayKey(address consumer, bytes32 replayIdentifier) external pure returns (bytes32) {
        return _proofReplayKey(consumer, replayIdentifier);
    }

    /// @notice The EIP-712 domain separator for this contract/chain.
    function domainSeparator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    /// @notice Canonical predicate id for a descriptor string (see the grammar in
    ///         the contract docs), i.e. `keccak256(bytes(descriptor))`. Pure
    ///         helper so consumers/tests derive the same id the issuer signs.
    function predicateId(string calldata descriptor) external pure returns (bytes32) {
        return keccak256(bytes(descriptor));
    }
}
