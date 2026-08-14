// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IPredicateProver, IPredicateProverReplay} from "./PredicateVerifier.sol";
import {ZkIdentityEncoding} from "./ZkIdentityEncoding.sol";
import {ZkIdentityVersionRegistry} from "./ZkIdentityVersionRegistry.sol";

/// @notice Minimal interface expected from the final 18-public-signal Groth16 verifier.
interface IZkIdentityGroth16Verifier {
    function verifyProof(uint256[8] calldata proof, uint256[18] calldata publicSignals) external view returns (bool);
}

/// @title Governed v2 ZK identity predicate-prover adapter
/// @notice Strictly decodes the pinned 18-signal layout, authenticates every EVM
///         presentation binding, resolves an accepted verifier/issuer/root tuple,
///         and verifies the proof before returning the forever-interface result.
/// @dev PRE-DEPLOYMENT DESIGN. No production 18-signal circuit or ceremony
///      artifact exists yet, so this contract MUST NOT be configured on a live
///      PredicateVerifier. The application context is ABI-encoded as
///      `(bytes32 actionContext, bytes32 challenge, uint8 nullifierMode)`.
contract ZkIdentityPredicateProver is IPredicateProver, IPredicateProverReplay {
    address public immutable predicateVerifier;
    ZkIdentityVersionRegistry public immutable registry;

    error InvalidPredicateVerifier();
    error InvalidRegistry();
    error OnlyPredicateVerifier();
    error InvalidProofEncoding();
    error InvalidProofContext();
    error PresentationBindingMismatch();
    error NullifierScopeMismatch();
    error DynamicStatusUnsupported();
    error InvalidProof();

    constructor(address predicateVerifier_, ZkIdentityVersionRegistry registry_) {
        if (predicateVerifier_ == address(0) || predicateVerifier_.code.length == 0) {
            revert InvalidPredicateVerifier();
        }
        if (address(registry_) == address(0) || address(registry_).code.length == 0) revert InvalidRegistry();
        predicateVerifier = predicateVerifier_;
        registry = registry_;
    }

    /// @inheritdoc IPredicateProver
    /// @dev `context` is the host-created `abi.encode(consumer, applicationContext)`
    ///      envelope. Only the configured PredicateVerifier may supply it.
    function verifyPredicate(bytes calldata proof, uint256[] calldata publicSignals, bytes calldata context)
        external
        view
        returns (address subject, bytes32 predicate, bool result, uint32 epoch)
    {
        if (msg.sender != predicateVerifier) revert OnlyPredicateVerifier();
        ZkIdentityEncoding.PublicSignals memory decoded = ZkIdentityEncoding.decodePublicSignals(publicSignals);
        // Signal 17 is reserved for short-lived dynamic status. Its time unit,
        // policy-specific maximum age and root-publication relationship are not
        // ratified yet, so accepting a non-zero value would invent freshness.
        if (decoded.statusEpoch != 0) revert DynamicStatusUnsupported();
        _validateContextBindings(decoded, context);
        address verifier = registry.requireRootAccepted(decoded.circuitId, decoded.issuerKeyId, decoded.activeRoot);
        _verifyProof(verifier, proof, publicSignals);

        return (decoded.subject, decoded.policyHash, decoded.result, decoded.credentialEpoch);
    }

    function _validateContextBindings(ZkIdentityEncoding.PublicSignals memory decoded, bytes calldata context)
        private
        view
    {
        (address consumer, bytes memory applicationContext) = abi.decode(context, (address, bytes));
        if (consumer == address(0) || applicationContext.length != 3 * 32) revert InvalidProofContext();
        (bytes32 actionContext, bytes32 challenge, uint8 nullifierMode) =
            abi.decode(applicationContext, (bytes32, bytes32, uint8));
        if (challenge == bytes32(0) || (nullifierMode != 1 && nullifierMode != 2)) revert InvalidProofContext();

        bytes32 expectedBinding = ZkIdentityEncoding.presentationBindingHash(
            ZkIdentityEncoding.PresentationBinding({
                policyHash: decoded.policyHash,
                chainId: block.chainid,
                verifier: predicateVerifier,
                consumer: consumer,
                subject: decoded.subject,
                context: actionContext,
                challenge: challenge,
                epoch: decoded.credentialEpoch
            })
        );
        if (decoded.presentationBindingHash != expectedBinding) revert PresentationBindingMismatch();

        bytes32 expectedScope = ZkIdentityEncoding.nullifierScopeHash(
            ZkIdentityEncoding.NullifierScope({
                mode: nullifierMode,
                chainId: block.chainid,
                verifier: predicateVerifier,
                consumer: consumer,
                context: actionContext,
                policyHash: decoded.policyHash
            })
        );
        if (decoded.nullifierScopeHash != expectedScope) revert NullifierScopeMismatch();
    }

    function _verifyProof(address verifier, bytes calldata proof, uint256[] calldata publicSignals) private view {
        if (proof.length != 8 * 32) revert InvalidProofEncoding();
        uint256[8] memory proofWords = abi.decode(proof, (uint256[8]));
        uint256[18] memory signalWords;
        for (uint256 i = 0; i < signalWords.length; ++i) {
            signalWords[i] = publicSignals[i];
        }

        try IZkIdentityGroth16Verifier(verifier).verifyProof(proofWords, signalWords) returns (bool verified) {
            if (!verified) revert InvalidProof();
        } catch {
            revert InvalidProof();
        }
    }

    /// @inheritdoc IPredicateProverReplay
    function proofReplayIdentifier(uint256[] calldata publicSignals) external pure returns (bytes32) {
        ZkIdentityEncoding.PublicSignals memory decoded = ZkIdentityEncoding.decodePublicSignals(publicSignals);
        return bytes32(decoded.scopedNullifier);
    }
}
