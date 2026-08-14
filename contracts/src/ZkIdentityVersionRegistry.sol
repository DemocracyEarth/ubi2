// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";

/// @title ZK Identity verifier-version and status-root registry
/// @notice Fail-closed governance surface for the tuple a v2 adapter must
///         accept: circuit version, immutable verifier bytecode, issuer key,
///         status root and status epoch.
/// @dev PRE-DEPLOYMENT DESIGN. The owner is expected to be a timelock-controlled
///      multisig in production. Circuit and issuer registrations are additive;
///      retirement is irreversible. Multiple published roots may overlap until
///      governance explicitly revokes them, avoiding an implicit in-flight-proof
///      race. Freshness policy is intentionally enforced by the adapter or
///      consumer, not inferred by this registry.
contract ZkIdentityVersionRegistry is Ownable2Step {
    struct CircuitVersion {
        address verifier;
        bytes32 verifierCodehash;
        bool active;
    }

    struct IssuerAuthorization {
        bool registered;
        bool active;
    }

    struct StatusRoot {
        bytes32 root;
        bool revoked;
    }

    mapping(bytes32 circuitId => CircuitVersion) public circuits;
    mapping(bytes32 circuitId => mapping(bytes32 issuerKeyId => IssuerAuthorization)) public issuers;
    mapping(bytes32 circuitId => mapping(bytes32 issuerKeyId => uint32)) public latestStatusEpoch;
    mapping(bytes32 circuitId => mapping(bytes32 issuerKeyId => mapping(uint32 epoch => StatusRoot))) public
        statusRoots;
    mapping(bytes32 circuitId => mapping(bytes32 issuerKeyId => mapping(bytes32 root => bool))) public publishedRoots;
    mapping(bytes32 circuitId => mapping(bytes32 issuerKeyId => mapping(bytes32 root => uint32 epoch))) public
        statusRootEpoch;

    error InvalidCircuitId();
    error InvalidVerifier();
    error CircuitAlreadyRegistered(bytes32 circuitId);
    error UnknownCircuit(bytes32 circuitId);
    error CircuitInactive(bytes32 circuitId);
    error InvalidIssuerKeyId();
    error IssuerAlreadyRegistered(bytes32 circuitId, bytes32 issuerKeyId);
    error UnknownIssuer(bytes32 circuitId, bytes32 issuerKeyId);
    error IssuerInactive(bytes32 circuitId, bytes32 issuerKeyId);
    error InvalidStatusRoot();
    error StatusEpochNotIncreasing(uint32 latest, uint32 proposed);
    error StatusRootAlreadyPublished(bytes32 root);
    error UnknownStatusRoot(bytes32 circuitId, bytes32 issuerKeyId, uint32 epoch);
    error StatusRootAlreadyRevoked(bytes32 circuitId, bytes32 issuerKeyId, uint32 epoch);
    error UnacceptedIdentityState();

    event CircuitRegistered(bytes32 indexed circuitId, address indexed verifier, bytes32 verifierCodehash);
    event CircuitRetired(bytes32 indexed circuitId);
    event IssuerAuthorized(bytes32 indexed circuitId, bytes32 indexed issuerKeyId);
    event IssuerRetired(bytes32 indexed circuitId, bytes32 indexed issuerKeyId);
    event StatusRootPublished(
        bytes32 indexed circuitId, bytes32 indexed issuerKeyId, uint32 indexed epoch, bytes32 root
    );
    event StatusRootRevoked(bytes32 indexed circuitId, bytes32 indexed issuerKeyId, uint32 indexed epoch);

    constructor(address initialOwner) Ownable(initialOwner) {}

    function registerCircuit(bytes32 circuitId, address verifier) external onlyOwner {
        if (circuitId == bytes32(0)) revert InvalidCircuitId();
        if (verifier == address(0) || verifier.code.length == 0) revert InvalidVerifier();
        if (circuits[circuitId].verifier != address(0)) revert CircuitAlreadyRegistered(circuitId);

        bytes32 codehash = verifier.codehash;
        circuits[circuitId] = CircuitVersion({verifier: verifier, verifierCodehash: codehash, active: true});
        emit CircuitRegistered(circuitId, verifier, codehash);
    }

    function retireCircuit(bytes32 circuitId) external onlyOwner {
        CircuitVersion storage circuit = _activeCircuit(circuitId);
        circuit.active = false;
        emit CircuitRetired(circuitId);
    }

    function authorizeIssuer(bytes32 circuitId, bytes32 issuerKeyId) external onlyOwner {
        _activeCircuit(circuitId);
        if (issuerKeyId == bytes32(0)) revert InvalidIssuerKeyId();
        IssuerAuthorization storage issuer = issuers[circuitId][issuerKeyId];
        if (issuer.registered) revert IssuerAlreadyRegistered(circuitId, issuerKeyId);

        issuer.registered = true;
        issuer.active = true;
        emit IssuerAuthorized(circuitId, issuerKeyId);
    }

    function retireIssuer(bytes32 circuitId, bytes32 issuerKeyId) external onlyOwner {
        _activeCircuit(circuitId);
        IssuerAuthorization storage issuer = _activeIssuer(circuitId, issuerKeyId);
        issuer.active = false;
        emit IssuerRetired(circuitId, issuerKeyId);
    }

    function publishStatusRoot(bytes32 circuitId, bytes32 issuerKeyId, uint32 epoch, bytes32 root) external onlyOwner {
        _activeCircuit(circuitId);
        _activeIssuer(circuitId, issuerKeyId);
        if (root == bytes32(0)) revert InvalidStatusRoot();

        uint32 latest = latestStatusEpoch[circuitId][issuerKeyId];
        if (epoch <= latest) revert StatusEpochNotIncreasing(latest, epoch);
        if (publishedRoots[circuitId][issuerKeyId][root]) revert StatusRootAlreadyPublished(root);

        latestStatusEpoch[circuitId][issuerKeyId] = epoch;
        publishedRoots[circuitId][issuerKeyId][root] = true;
        statusRootEpoch[circuitId][issuerKeyId][root] = epoch;
        statusRoots[circuitId][issuerKeyId][epoch] = StatusRoot({root: root, revoked: false});
        emit StatusRootPublished(circuitId, issuerKeyId, epoch, root);
    }

    function revokeStatusRoot(bytes32 circuitId, bytes32 issuerKeyId, uint32 epoch) external onlyOwner {
        _activeCircuit(circuitId);
        _activeIssuer(circuitId, issuerKeyId);
        StatusRoot storage status = statusRoots[circuitId][issuerKeyId][epoch];
        if (status.root == bytes32(0)) revert UnknownStatusRoot(circuitId, issuerKeyId, epoch);
        if (status.revoked) revert StatusRootAlreadyRevoked(circuitId, issuerKeyId, epoch);

        status.revoked = true;
        emit StatusRootRevoked(circuitId, issuerKeyId, epoch);
    }

    function isAccepted(bytes32 circuitId, address verifier, bytes32 issuerKeyId, bytes32 root, uint32 epoch)
        public
        view
        returns (bool)
    {
        CircuitVersion storage circuit = circuits[circuitId];
        if (!circuit.active || circuit.verifier != verifier || verifier.codehash != circuit.verifierCodehash) {
            return false;
        }

        IssuerAuthorization storage issuer = issuers[circuitId][issuerKeyId];
        if (!issuer.active) return false;

        StatusRoot storage status = statusRoots[circuitId][issuerKeyId][epoch];
        return status.root == root && root != bytes32(0) && !status.revoked;
    }

    function requireAccepted(bytes32 circuitId, address verifier, bytes32 issuerKeyId, bytes32 root, uint32 epoch)
        external
        view
    {
        if (!isAccepted(circuitId, verifier, issuerKeyId, root, epoch)) revert UnacceptedIdentityState();
    }

    /// @notice Whether an exact root remains accepted without requiring the
    ///         presentation circuit to expose the governance publication epoch.
    /// @dev The product public-signal layout uses its final slot for optional
    ///      dynamic-status freshness, so root-version lookup belongs here.
    function isRootAccepted(bytes32 circuitId, address verifier, bytes32 issuerKeyId, bytes32 root)
        public
        view
        returns (bool)
    {
        uint32 epoch = statusRootEpoch[circuitId][issuerKeyId][root];
        return epoch != 0 && isAccepted(circuitId, verifier, issuerKeyId, root, epoch);
    }

    /// @notice Resolve the verifier for an accepted circuit/issuer/root tuple.
    /// @dev Reverts fail-closed on retired circuits or issuers, revoked/unknown
    ///      roots, and verifier bytecode drift.
    function requireRootAccepted(bytes32 circuitId, bytes32 issuerKeyId, bytes32 root)
        external
        view
        returns (address verifier)
    {
        verifier = circuits[circuitId].verifier;
        if (!isRootAccepted(circuitId, verifier, issuerKeyId, root)) revert UnacceptedIdentityState();
    }

    function _activeCircuit(bytes32 circuitId) private view returns (CircuitVersion storage circuit) {
        circuit = circuits[circuitId];
        if (circuit.verifier == address(0)) revert UnknownCircuit(circuitId);
        if (!circuit.active) revert CircuitInactive(circuitId);
    }

    function _activeIssuer(bytes32 circuitId, bytes32 issuerKeyId)
        private
        view
        returns (IssuerAuthorization storage issuer)
    {
        issuer = issuers[circuitId][issuerKeyId];
        if (!issuer.registered) revert UnknownIssuer(circuitId, issuerKeyId);
        if (!issuer.active) revert IssuerInactive(circuitId, issuerKeyId);
    }
}
