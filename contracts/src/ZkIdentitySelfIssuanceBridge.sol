// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ZkIdentityIssuanceRegistry} from "./ZkIdentityIssuanceRegistry.sol";

/// @title Self passport proof to private ZK credential issuance bridge
/// @notice Allocates one registry slot after an immutable verification authority
///         authenticates the exact result of a Self passport proof.
/// @dev TRANSITIONAL TRUST BOUNDARY. The bridge does not verify the Self Groth16
///      proof onchain. The configured authority must run the pinned Self verifier,
///      derive `duplicateKey` from its raw nullifier and the registry issuance
///      domain, and sign only the proof-bound holder commitment and subject.
///      Rotation deploys and authorizes a new immutable bridge.
contract ZkIdentitySelfIssuanceBridge is EIP712 {
    struct SelfIssuanceAuthorization {
        address subject;
        bytes32 duplicateKey;
        uint256 credentialCommitment;
        bytes32 issuerKeyId;
        uint32 expectedStatusId;
        uint32 expectedEpoch;
        uint64 deadline;
        bytes32 selfConfigId;
    }

    bytes32 public constant AUTHORIZATION_TYPEHASH = keccak256(
        "SelfIssuanceAuthorization(address subject,bytes32 duplicateKey,uint256 credentialCommitment,bytes32 issuerKeyId,uint32 expectedStatusId,uint32 expectedEpoch,uint64 deadline,bytes32 selfConfigId)"
    );
    uint256 public constant MAX_AUTHORIZATION_LIFETIME = 10 minutes;

    ZkIdentityIssuanceRegistry public immutable registry;
    bytes32 public immutable issuerKeyId;
    address public immutable verificationAuthority;
    bytes32 public immutable selfConfigId;

    error InvalidRegistry();
    error InvalidIssuerKeyId();
    error InactiveIssuerKey(bytes32 issuerKeyId);
    error InvalidVerificationAuthority();
    error InvalidSelfConfigId();
    error SubjectMismatch(address expected, address caller);
    error AuthorizationExpired(uint64 deadline, uint256 currentTimestamp);
    error AuthorizationDeadlineTooFar(uint64 deadline, uint256 maximumDeadline);
    error AuthorizationIssuerKeyMismatch(bytes32 expected, bytes32 provided);
    error AuthorizationSelfConfigMismatch(bytes32 expected, bytes32 provided);
    error UnauthorizedVerificationSigner(address recovered);

    event SelfCredentialIssued(
        bytes32 indexed issuerKeyId, uint32 indexed statusId, uint256 indexed credentialCommitment, uint32 issuedAtEpoch
    );

    constructor(
        ZkIdentityIssuanceRegistry registry_,
        bytes32 issuerKeyId_,
        address verificationAuthority_,
        bytes32 selfConfigId_
    ) EIP712("ProofOfHumanitySelfIssuance", "1") {
        if (address(registry_) == address(0) || address(registry_).code.length == 0) {
            revert InvalidRegistry();
        }
        if (issuerKeyId_ == bytes32(0)) revert InvalidIssuerKeyId();
        if (verificationAuthority_ == address(0)) revert InvalidVerificationAuthority();
        if (selfConfigId_ == bytes32(0)) revert InvalidSelfConfigId();

        (bool registered, bool active,) = registry_.issuerKeys(issuerKeyId_);
        if (!registered || !active) revert InactiveIssuerKey(issuerKeyId_);

        registry = registry_;
        issuerKeyId = issuerKeyId_;
        verificationAuthority = verificationAuthority_;
        selfConfigId = selfConfigId_;
    }

    /// @notice Consume a short-lived verification authorization and allocate
    ///         the exact registry slot and epoch signed by the authority.
    /// @dev The subject must submit its own transaction. This prevents a leaked
    ///      authorization from being exercised by another wallet. Smart accounts
    ///      can call directly; delegated relaying is deliberately not supported.
    function issue(SelfIssuanceAuthorization calldata authorization, bytes calldata signature)
        external
        returns (uint32 statusId, uint32 issuedAtEpoch)
    {
        if (authorization.subject != msg.sender) revert SubjectMismatch(authorization.subject, msg.sender);
        if (authorization.issuerKeyId != issuerKeyId) {
            revert AuthorizationIssuerKeyMismatch(issuerKeyId, authorization.issuerKeyId);
        }
        if (authorization.selfConfigId != selfConfigId) {
            revert AuthorizationSelfConfigMismatch(selfConfigId, authorization.selfConfigId);
        }
        if (authorization.deadline == 0 || block.timestamp > authorization.deadline) {
            revert AuthorizationExpired(authorization.deadline, block.timestamp);
        }
        uint256 maximumDeadline = block.timestamp + MAX_AUTHORIZATION_LIFETIME;
        if (authorization.deadline > maximumDeadline) {
            revert AuthorizationDeadlineTooFar(authorization.deadline, maximumDeadline);
        }

        address recovered = ECDSA.recover(_hashTypedDataV4(_authorizationStructHash(authorization)), signature);
        if (recovered != verificationAuthority) revert UnauthorizedVerificationSigner(recovered);

        (statusId, issuedAtEpoch) = registry.allocateCredential(
            issuerKeyId,
            authorization.duplicateKey,
            authorization.credentialCommitment,
            authorization.expectedStatusId,
            authorization.expectedEpoch
        );
        emit SelfCredentialIssued(issuerKeyId, statusId, authorization.credentialCommitment, issuedAtEpoch);
    }

    function hashAuthorization(SelfIssuanceAuthorization calldata authorization) external view returns (bytes32) {
        return _hashTypedDataV4(_authorizationStructHash(authorization));
    }

    function domainSeparator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    function _authorizationStructHash(SelfIssuanceAuthorization calldata authorization) private pure returns (bytes32) {
        return keccak256(
            abi.encode(
                AUTHORIZATION_TYPEHASH,
                authorization.subject,
                authorization.duplicateKey,
                authorization.credentialCommitment,
                authorization.issuerKeyId,
                authorization.expectedStatusId,
                authorization.expectedEpoch,
                authorization.deadline,
                authorization.selfConfigId
            )
        );
    }
}
