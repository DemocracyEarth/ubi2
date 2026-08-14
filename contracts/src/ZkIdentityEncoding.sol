// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title Canonical v2 ZK identity wire encodings
/// @notice Pins the EVM ABI and public-signal layouts shared by the SDK, circuit
///         fixtures, and future `IPredicateProver` adapters.
/// @dev This library intentionally does NOT choose the SNARK-native credential
///      commitment or nullifier hash. ADR-0010 keeps those behind a measured
///      cryptographic gate. The diagnostic Keccak fingerprint below must never
///      become a public presentation identifier.
library ZkIdentityEncoding {
    uint256 internal constant BN254_SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    uint16 internal constant PRIVATE_CREDENTIAL_VERSION = 1;
    uint16 internal constant NULLIFIER_SCOPE_VERSION = 1;
    uint16 internal constant PRESENTATION_VERSION = 1;
    uint16 internal constant PUBLIC_SIGNALS_VERSION = 1;
    uint256 internal constant PUBLIC_SIGNAL_COUNT = 18;

    bytes32 internal constant PRIVATE_CREDENTIAL_DOMAIN = keccak256("org.proofofhumanity.zk-private-credential");
    bytes32 internal constant NULLIFIER_SCOPE_DOMAIN = keccak256("org.proofofhumanity.zk-nullifier-scope");
    bytes32 internal constant NULLIFIER_PREIMAGE_DOMAIN = keccak256("org.proofofhumanity.zk-nullifier-scope:derive");
    bytes32 internal constant PRESENTATION_DOMAIN = keccak256("org.proofofhumanity.zk-presentation");

    uint256 internal constant IDX_LAYOUT_VERSION = 0;
    uint256 internal constant IDX_CIRCUIT_ID_HI = 1;
    uint256 internal constant IDX_ISSUER_KEY_ID_HI = 3;
    uint256 internal constant IDX_ACTIVE_ROOT_HI = 5;
    uint256 internal constant IDX_POLICY_HASH_HI = 7;
    uint256 internal constant IDX_BINDING_HASH_HI = 9;
    uint256 internal constant IDX_NULLIFIER_SCOPE_HASH_HI = 11;
    uint256 internal constant IDX_SCOPED_NULLIFIER = 13;
    uint256 internal constant IDX_SUBJECT = 14;
    uint256 internal constant IDX_RESULT = 15;
    uint256 internal constant IDX_CREDENTIAL_EPOCH = 16;
    uint256 internal constant IDX_STATUS_EPOCH = 17;

    struct PrivateCredential {
        bytes32 issuerKeyId;
        bytes32 statusId;
        uint256 holderSecret;
        uint256 credentialBlinding;
        uint32 dateOfBirth;
        bytes3 nationality;
        bytes3 issuingState;
        uint32 expiryDate;
        uint8 documentClass;
        uint8 assurance;
        uint32 issuedAtEpoch;
    }

    struct NullifierScope {
        uint8 mode;
        uint256 chainId;
        address verifier;
        address consumer;
        bytes32 context;
        bytes32 policyHash;
    }

    struct PublicSignals {
        bytes32 circuitId;
        bytes32 issuerKeyId;
        bytes32 activeRoot;
        bytes32 policyHash;
        bytes32 presentationBindingHash;
        bytes32 nullifierScopeHash;
        uint256 scopedNullifier;
        address subject;
        bool result;
        uint32 credentialEpoch;
        uint32 statusEpoch;
    }

    struct PresentationBinding {
        bytes32 policyHash;
        uint256 chainId;
        address verifier;
        address consumer;
        address subject;
        bytes32 context;
        bytes32 challenge;
        uint32 epoch;
    }

    error NonCanonicalField(uint256 index);
    error UnsupportedPublicSignalLayout();
    error InvalidPublicSignalLength();
    error InvalidIdentifier(uint256 highIndex);
    error InvalidHolderSecret();
    error InvalidNullifierScope();
    error InvalidSubject();
    error InvalidResult();
    error InvalidEpoch(uint256 index);
    error InvalidPresentationBinding();

    /// @notice Diagnostic parity fingerprint of the private credential ABI.
    /// @dev Never publish or use this stable value as a presentation identifier.
    function privateCredentialFingerprint(PrivateCredential memory credential) internal pure returns (bytes32) {
        // `PrivateCredential` is an all-static tuple, so encoding it after the two
        // domain fields is byte-identical to listing each member inline. Keeping
        // the tuple grouped also compiles when `forge coverage` disables the
        // optimizer; the flattened 13-argument form exhausts the legacy stack.
        return keccak256(abi.encode(PRIVATE_CREDENTIAL_DOMAIN, PRIVATE_CREDENTIAL_VERSION, credential));
    }

    /// @notice Stable consumer scope for a scoped-nullifier derivation.
    /// @dev Subject, challenge and epoch are deliberately excluded so changing
    ///      them cannot create another one-per-scope slot.
    function nullifierScopeHash(NullifierScope memory scope) internal pure returns (bytes32) {
        if (
            (scope.mode != 1 && scope.mode != 2) || scope.chainId == 0 || scope.verifier == address(0)
                || scope.consumer == address(0) || scope.policyHash == bytes32(0)
        ) revert InvalidNullifierScope();
        return keccak256(
            abi.encode(
                NULLIFIER_SCOPE_DOMAIN,
                NULLIFIER_SCOPE_VERSION,
                scope.mode,
                scope.chainId,
                scope.verifier,
                scope.consumer,
                scope.context,
                scope.policyHash
            )
        );
    }

    /// @notice Hash every EVM presentation binding using the SDK-pinned ABI.
    /// @dev The adapter recomputes this from host-authenticated consumer data;
    ///      the presenter cannot substitute another chain, verifier or consumer.
    function presentationBindingHash(PresentationBinding memory binding) internal pure returns (bytes32) {
        if (
            binding.policyHash == bytes32(0) || binding.chainId == 0 || binding.verifier == address(0)
                || binding.consumer == address(0) || binding.subject == address(0)
        ) revert InvalidPresentationBinding();
        return keccak256(
            abi.encode(
                PRESENTATION_DOMAIN,
                PRESENTATION_VERSION,
                binding.policyHash,
                binding.chainId,
                binding.verifier,
                binding.consumer,
                binding.subject,
                binding.context,
                binding.challenge,
                binding.epoch
            )
        );
    }

    /// @notice Ordered field preimage a measured circuit-native hash will consume.
    function scopedNullifierPreimage(uint256 holderSecret, NullifierScope memory scope)
        internal
        pure
        returns (uint256[6] memory preimage)
    {
        if (holderSecret == 0 || holderSecret >= BN254_SCALAR_FIELD) revert InvalidHolderSecret();
        (uint256 domainHi, uint256 domainLo) = splitBytes32(NULLIFIER_PREIMAGE_DOMAIN);
        (uint256 scopeHi, uint256 scopeLo) = splitBytes32(nullifierScopeHash(scope));
        preimage = [domainHi, domainLo, uint256(NULLIFIER_SCOPE_VERSION), holderSecret, scopeHi, scopeLo];
    }

    /// @notice Losslessly split a bytes32 into 128-bit field-safe limbs, high first.
    function splitBytes32(bytes32 value) internal pure returns (uint256 high, uint256 low) {
        high = uint256(value) >> 128;
        low = uint256(value) & type(uint128).max;
    }

    /// @notice Strictly decode the fixed 18-signal v1 layout.
    /// @dev Rejects rather than reducing non-canonical BN254 field elements.
    function decodePublicSignals(uint256[] memory signals) internal pure returns (PublicSignals memory decoded) {
        if (signals.length != PUBLIC_SIGNAL_COUNT) revert InvalidPublicSignalLength();
        for (uint256 i = 0; i < PUBLIC_SIGNAL_COUNT; ++i) {
            if (signals[i] >= BN254_SCALAR_FIELD) revert NonCanonicalField(i);
        }
        if (signals[IDX_LAYOUT_VERSION] != PUBLIC_SIGNALS_VERSION) revert UnsupportedPublicSignalLayout();

        decoded.circuitId = _joinIdentifier(signals, IDX_CIRCUIT_ID_HI);
        decoded.issuerKeyId = _joinIdentifier(signals, IDX_ISSUER_KEY_ID_HI);
        decoded.activeRoot = _joinIdentifier(signals, IDX_ACTIVE_ROOT_HI);
        decoded.policyHash = _joinIdentifier(signals, IDX_POLICY_HASH_HI);
        decoded.presentationBindingHash = _joinIdentifier(signals, IDX_BINDING_HASH_HI);
        decoded.nullifierScopeHash = _joinIdentifier(signals, IDX_NULLIFIER_SCOPE_HASH_HI);

        if (signals[IDX_SCOPED_NULLIFIER] == 0) revert InvalidIdentifier(IDX_SCOPED_NULLIFIER);
        if (signals[IDX_SUBJECT] == 0 || signals[IDX_SUBJECT] > type(uint160).max) revert InvalidSubject();
        if (signals[IDX_RESULT] > 1) revert InvalidResult();
        if (signals[IDX_CREDENTIAL_EPOCH] > type(uint32).max) revert InvalidEpoch(IDX_CREDENTIAL_EPOCH);
        if (signals[IDX_STATUS_EPOCH] > type(uint32).max) revert InvalidEpoch(IDX_STATUS_EPOCH);

        decoded.scopedNullifier = signals[IDX_SCOPED_NULLIFIER];
        decoded.subject = address(uint160(signals[IDX_SUBJECT]));
        decoded.result = signals[IDX_RESULT] == 1;
        decoded.credentialEpoch = uint32(signals[IDX_CREDENTIAL_EPOCH]);
        decoded.statusEpoch = uint32(signals[IDX_STATUS_EPOCH]);
    }

    function _joinIdentifier(uint256[] memory signals, uint256 highIndex) private pure returns (bytes32 value) {
        uint256 high = signals[highIndex];
        uint256 low = signals[highIndex + 1];
        if (high > type(uint128).max || low > type(uint128).max || (high == 0 && low == 0)) {
            revert InvalidIdentifier(highIndex);
        }
        value = bytes32((high << 128) | low);
    }
}
