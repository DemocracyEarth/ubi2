// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {ZkIdentityEncoding} from "./ZkIdentityEncoding.sol";

/// @title ZK Identity one-time issuance and packed-status slot registry
/// @notice Allocates one monotonic status slot to one opaque credential
///         commitment after an authorized passport bridge supplies a unique,
///         registry-scoped duplicate key.
/// @dev PRE-DEPLOYMENT DESIGN. This registry does not verify passport truth or
///      derive duplicate keys. The authorized issuance authority must verify a
///      Self/passport proof and bind the proof-derived duplicate key to
///      `issuanceDomain`. A duplicate key is global across every issuer key in
///      this registry, while status slots are scoped by issuer key and never
///      reused. The duplicate key is intentionally omitted from events.
contract ZkIdentityIssuanceRegistry is Ownable2Step {
    uint256 public constant EPOCH = 90 days;
    uint256 private constant BN254_SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    struct IssuerKey {
        bool registered;
        bool active;
        uint64 nextStatusId;
    }

    struct IssuanceAuthority {
        bytes32 codehash;
        bool registered;
        bool active;
    }

    struct Issuance {
        bytes32 issuerKeyId;
        uint256 credentialCommitment;
        uint32 statusId;
        uint32 issuedAtEpoch;
    }

    bytes32 public immutable issuanceDomain;

    mapping(bytes32 issuerKeyId => IssuerKey) public issuerKeys;
    mapping(bytes32 issuerKeyId => mapping(address authority => IssuanceAuthority)) public issuanceAuthorities;
    mapping(bytes32 duplicateKey => Issuance) private _issuances;
    mapping(uint256 credentialCommitment => bool) public credentialCommitmentUsed;
    mapping(bytes32 issuerKeyId => mapping(uint32 statusId => uint256 credentialCommitment)) public
        credentialCommitmentAt;

    error InvalidIssuerKeyId();
    error IssuerKeyAlreadyRegistered(bytes32 issuerKeyId);
    error UnknownIssuerKey(bytes32 issuerKeyId);
    error IssuerKeyInactive(bytes32 issuerKeyId);
    error InvalidIssuanceAuthority();
    error IssuanceAuthorityAlreadyRegistered(bytes32 issuerKeyId, address authority);
    error UnknownIssuanceAuthority(bytes32 issuerKeyId, address authority);
    error IssuanceAuthorityInactive(bytes32 issuerKeyId, address authority);
    error IssuanceAuthorityCodehashChanged(bytes32 expected, bytes32 actual);
    error InvalidDuplicateKey();
    error DuplicateKeyAlreadyUsed(bytes32 issuerKeyId, uint32 statusId);
    error InvalidCredentialCommitment();
    error CredentialCommitmentAlreadyUsed();
    error UnexpectedStatusId(uint32 expected, uint32 provided);
    error UnexpectedIssuanceEpoch(uint32 expected, uint32 provided);
    error StatusSlotsExhausted(bytes32 issuerKeyId);
    error IssuanceEpochOverflow();

    event IssuerKeyRegistered(bytes32 indexed issuerKeyId);
    event IssuerKeyRetired(bytes32 indexed issuerKeyId);
    event IssuanceAuthorityAuthorized(
        bytes32 indexed issuerKeyId, address indexed authority, bytes32 authorityCodehash
    );
    event IssuanceAuthorityRetired(bytes32 indexed issuerKeyId, address indexed authority);
    event CredentialAllocated(
        bytes32 indexed issuerKeyId, uint32 indexed statusId, uint256 indexed credentialCommitment, uint32 issuedAtEpoch
    );

    constructor(address initialOwner) Ownable(initialOwner) {
        issuanceDomain = ZkIdentityEncoding.issuanceDomainHash(block.chainid, address(this));
    }

    /// @notice Add one credential-signing key namespace. Registration and
    ///         retirement are irreversible; rotation uses a new key identifier.
    function registerIssuerKey(bytes32 issuerKeyId) external onlyOwner {
        if (issuerKeyId == bytes32(0)) revert InvalidIssuerKeyId();
        IssuerKey storage issuer = issuerKeys[issuerKeyId];
        if (issuer.registered) revert IssuerKeyAlreadyRegistered(issuerKeyId);

        issuer.registered = true;
        issuer.active = true;
        issuer.nextStatusId = 1;
        emit IssuerKeyRegistered(issuerKeyId);
    }

    function retireIssuerKey(bytes32 issuerKeyId) external onlyOwner {
        IssuerKey storage issuer = _activeIssuerKey(issuerKeyId);
        issuer.active = false;
        emit IssuerKeyRetired(issuerKeyId);
    }

    /// @notice Authorize an EOA, Safe or passport bridge to allocate slots for
    ///         one issuer key. Contract bytecode is pinned at authorization.
    /// @dev A proxy's codehash does not pin its implementation. Governance must
    ///      separately constrain it or authorize an immutable implementation.
    function authorizeIssuanceAuthority(bytes32 issuerKeyId, address authority) external onlyOwner {
        _activeIssuerKey(issuerKeyId);
        if (authority == address(0)) revert InvalidIssuanceAuthority();
        IssuanceAuthority storage authorization = issuanceAuthorities[issuerKeyId][authority];
        if (authorization.registered) revert IssuanceAuthorityAlreadyRegistered(issuerKeyId, authority);

        bytes32 codehash = authority.code.length == 0 ? bytes32(0) : authority.codehash;
        authorization.codehash = codehash;
        authorization.registered = true;
        authorization.active = true;
        emit IssuanceAuthorityAuthorized(issuerKeyId, authority, codehash);
    }

    function retireIssuanceAuthority(bytes32 issuerKeyId, address authority) external onlyOwner {
        _activeIssuerKey(issuerKeyId);
        IssuanceAuthority storage authorization = _activeIssuanceAuthority(issuerKeyId, authority);
        authorization.active = false;
        emit IssuanceAuthorityRetired(issuerKeyId, authority);
    }

    /// @notice Consume a proof-derived duplicate key and allocate the next slot.
    /// @param duplicateKey A nonzero, issuance-domain-bound proof output. It must
    ///        not be a raw passport identifier or raw Self nullifier.
    /// @param credentialCommitment The nonzero canonical BN254 commitment the
    ///        issuer authenticates. It never appears in presentations.
    /// @param expectedStatusId The next slot observed before constructing the
    ///        signed credential; a race fails closed rather than misbinding it.
    /// @param expectedEpoch The current coarse epoch bound into the credential.
    function allocateCredential(
        bytes32 issuerKeyId,
        bytes32 duplicateKey,
        uint256 credentialCommitment,
        uint32 expectedStatusId,
        uint32 expectedEpoch
    ) external returns (uint32 statusId, uint32 issuedAtEpoch) {
        IssuerKey storage issuer = _activeIssuerKey(issuerKeyId);
        IssuanceAuthority storage authorization = _activeIssuanceAuthority(issuerKeyId, msg.sender);
        _requireAuthorityCodehash(authorization);

        if (duplicateKey == bytes32(0)) revert InvalidDuplicateKey();
        Issuance storage previous = _issuances[duplicateKey];
        if (previous.statusId != 0) revert DuplicateKeyAlreadyUsed(previous.issuerKeyId, previous.statusId);
        if (credentialCommitment == 0 || credentialCommitment >= BN254_SCALAR_FIELD) {
            revert InvalidCredentialCommitment();
        }
        if (credentialCommitmentUsed[credentialCommitment]) revert CredentialCommitmentAlreadyUsed();

        uint64 nextStatusId = issuer.nextStatusId;
        if (nextStatusId > type(uint32).max) revert StatusSlotsExhausted(issuerKeyId);
        statusId = uint32(nextStatusId);
        if (expectedStatusId != statusId) revert UnexpectedStatusId(statusId, expectedStatusId);

        issuedAtEpoch = currentEpoch();
        if (expectedEpoch != issuedAtEpoch) revert UnexpectedIssuanceEpoch(issuedAtEpoch, expectedEpoch);

        issuer.nextStatusId = nextStatusId + 1;
        _issuances[duplicateKey] = Issuance({
            issuerKeyId: issuerKeyId,
            credentialCommitment: credentialCommitment,
            statusId: statusId,
            issuedAtEpoch: issuedAtEpoch
        });
        credentialCommitmentUsed[credentialCommitment] = true;
        credentialCommitmentAt[issuerKeyId][statusId] = credentialCommitment;

        emit CredentialAllocated(issuerKeyId, statusId, credentialCommitment, issuedAtEpoch);
    }

    function currentEpoch() public view returns (uint32 epoch) {
        uint256 wideEpoch = block.timestamp / EPOCH;
        if (wideEpoch > type(uint32).max) revert IssuanceEpochOverflow();
        epoch = uint32(wideEpoch);
    }

    /// @notice Lookup requires knowing the non-emitted duplicate key.
    function issuanceForDuplicateKey(bytes32 duplicateKey) external view returns (Issuance memory) {
        return _issuances[duplicateKey];
    }

    function isDuplicateKeyUsed(bytes32 duplicateKey) external view returns (bool) {
        return _issuances[duplicateKey].statusId != 0;
    }

    function _activeIssuerKey(bytes32 issuerKeyId) private view returns (IssuerKey storage issuer) {
        issuer = issuerKeys[issuerKeyId];
        if (!issuer.registered) revert UnknownIssuerKey(issuerKeyId);
        if (!issuer.active) revert IssuerKeyInactive(issuerKeyId);
    }

    function _activeIssuanceAuthority(bytes32 issuerKeyId, address authority)
        private
        view
        returns (IssuanceAuthority storage authorization)
    {
        authorization = issuanceAuthorities[issuerKeyId][authority];
        if (!authorization.registered) revert UnknownIssuanceAuthority(issuerKeyId, authority);
        if (!authorization.active) revert IssuanceAuthorityInactive(issuerKeyId, authority);
    }

    function _requireAuthorityCodehash(IssuanceAuthority storage authorization) private view {
        bytes32 expected = authorization.codehash;
        bytes32 actual = msg.sender.code.length == 0 ? bytes32(0) : msg.sender.codehash;
        if (actual != expected) revert IssuanceAuthorityCodehashChanged(expected, actual);
    }
}
