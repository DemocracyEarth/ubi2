// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @dev Tuple layout must match contracts/src/PredicateVerifier.sol. The
/// cross-stack test deploys the production verifier; this fixture exists only
/// to provide a second consuming contract for direct anti-replay checks.
struct PredicateAttestation {
    address consumer;
    bytes32 context;
    bytes32 predicate;
    bool result;
    address subject;
    uint32 epoch;
    uint256 nonce;
}

interface IPredicateVerifier {
    function consume(PredicateAttestation calldata att, bytes calldata signature, address presenter)
        external
        returns (bool);
}

contract ConsumerProbe {
    IPredicateVerifier public immutable VERIFIER;

    constructor(IPredicateVerifier verifier_) {
        VERIFIER = verifier_;
    }

    function probe(PredicateAttestation calldata att, bytes calldata signature, address presenter)
        external
        returns (bool)
    {
        return VERIFIER.consume(att, signature, presenter);
    }
}
