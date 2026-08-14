// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {PredicateVerifier} from "../src/PredicateVerifier.sol";
import {ZkIdentityEncoding} from "../src/ZkIdentityEncoding.sol";
import {IZkIdentityGroth16Verifier, ZkIdentityPredicateProver} from "../src/ZkIdentityPredicateProver.sol";
import {ZkIdentityVersionRegistry} from "../src/ZkIdentityVersionRegistry.sol";

contract MockZkIdentityGroth16Verifier is IZkIdentityGroth16Verifier {
    function verifyProof(uint256[8] calldata proof, uint256[18] calldata publicSignals) external pure returns (bool) {
        return proof[0] == 1 && publicSignals[0] == 1;
    }
}

contract ZkIdentityPredicateProverTest is Test {
    PredicateVerifier internal predicateVerifier;
    ZkIdentityVersionRegistry internal registry;
    MockZkIdentityGroth16Verifier internal rawVerifier;
    ZkIdentityPredicateProver internal adapter;

    bytes32 internal constant CIRCUIT_ID = keccak256("ubi2.zk-identity.v2.adapter-fixture-1");
    bytes32 internal constant ISSUER_KEY_ID = keccak256("issuer-key-1");
    bytes32 internal constant ACTIVE_ROOT = keccak256("active-root-10");
    bytes32 internal constant POLICY_HASH = keccak256("age-range-policy");
    bytes32 internal constant ACTION_CONTEXT = keccak256("membership:season-1");
    bytes32 internal constant CHALLENGE = keccak256("challenge-1");
    uint256 internal constant SCOPED_NULLIFIER = 4242424242;

    address internal issuer = makeAddr("issuer");
    address internal subject = makeAddr("subject");
    address internal consumer = makeAddr("consumer");
    address internal otherConsumer = makeAddr("otherConsumer");

    function setUp() public {
        vm.chainId(84532);
        vm.warp(1_700_000_000);
        predicateVerifier = new PredicateVerifier(address(this), issuer);
        registry = new ZkIdentityVersionRegistry(address(this));
        rawVerifier = new MockZkIdentityGroth16Verifier();
        registry.registerCircuit(CIRCUIT_ID, address(rawVerifier));
        registry.authorizeIssuer(CIRCUIT_ID, ISSUER_KEY_ID);
        registry.publishStatusRoot(CIRCUIT_ID, ISSUER_KEY_ID, 10, ACTIVE_ROOT);
        adapter = new ZkIdentityPredicateProver(address(predicateVerifier), registry);
        predicateVerifier.setPredicateProver(adapter);
    }

    function test_VerifiesGovernedBoundProofAndSpendsScopedNullifier() public {
        uint256[] memory signals = _signals(subject, consumer, ACTION_CONTEXT, CHALLENGE, 1, SCOPED_NULLIFIER);

        vm.prank(consumer);
        assertTrue(
            predicateVerifier.consumeWithProof(
                _proof(), signals, _applicationContext(ACTION_CONTEXT, CHALLENGE, 1), POLICY_HASH, subject
            )
        );

        assertTrue(predicateVerifier.consumed(predicateVerifier.proofReplayKey(consumer, bytes32(SCOPED_NULLIFIER))));
    }

    function test_ChangedSubjectCannotBypassScopedNullifierReplay() public {
        uint256[] memory first = _signals(subject, consumer, ACTION_CONTEXT, CHALLENGE, 1, SCOPED_NULLIFIER);
        vm.prank(consumer);
        predicateVerifier.consumeWithProof(
            _proof(), first, _applicationContext(ACTION_CONTEXT, CHALLENGE, 1), POLICY_HASH, subject
        );

        address nextWallet = makeAddr("nextWallet");
        bytes32 nextChallenge = keccak256("challenge-2");
        uint256[] memory second = _signals(nextWallet, consumer, ACTION_CONTEXT, nextChallenge, 1, SCOPED_NULLIFIER);
        vm.prank(consumer);
        vm.expectRevert(PredicateVerifier.ProofReplayed.selector);
        predicateVerifier.consumeWithProof(
            _proof(), second, _applicationContext(ACTION_CONTEXT, nextChallenge, 1), POLICY_HASH, nextWallet
        );
    }

    function test_ConsumerChainContextChallengeAndModeAreBound() public {
        uint256[] memory signals = _signals(subject, consumer, ACTION_CONTEXT, CHALLENGE, 1, SCOPED_NULLIFIER);

        vm.prank(otherConsumer);
        vm.expectRevert(ZkIdentityPredicateProver.PresentationBindingMismatch.selector);
        predicateVerifier.consumeWithProof(
            _proof(), signals, _applicationContext(ACTION_CONTEXT, CHALLENGE, 1), POLICY_HASH, subject
        );

        vm.chainId(1);
        vm.prank(consumer);
        vm.expectRevert(ZkIdentityPredicateProver.PresentationBindingMismatch.selector);
        predicateVerifier.consumeWithProof(
            _proof(), signals, _applicationContext(ACTION_CONTEXT, CHALLENGE, 1), POLICY_HASH, subject
        );
        vm.chainId(84532);

        vm.prank(consumer);
        vm.expectRevert(ZkIdentityPredicateProver.PresentationBindingMismatch.selector);
        predicateVerifier.consumeWithProof(
            _proof(), signals, _applicationContext(keccak256("other-context"), CHALLENGE, 1), POLICY_HASH, subject
        );

        vm.prank(consumer);
        vm.expectRevert(ZkIdentityPredicateProver.PresentationBindingMismatch.selector);
        predicateVerifier.consumeWithProof(
            _proof(),
            signals,
            _applicationContext(ACTION_CONTEXT, keccak256("other-challenge"), 1),
            POLICY_HASH,
            subject
        );

        vm.prank(consumer);
        vm.expectRevert(ZkIdentityPredicateProver.NullifierScopeMismatch.selector);
        predicateVerifier.consumeWithProof(
            _proof(), signals, _applicationContext(ACTION_CONTEXT, CHALLENGE, 2), POLICY_HASH, subject
        );
    }

    function test_RejectsMalformedContextAndProof() public {
        uint256[] memory signals = _signals(subject, consumer, ACTION_CONTEXT, CHALLENGE, 1, SCOPED_NULLIFIER);

        vm.prank(consumer);
        vm.expectRevert(ZkIdentityPredicateProver.InvalidProofContext.selector);
        predicateVerifier.consumeWithProof(_proof(), signals, hex"1234", POLICY_HASH, subject);

        vm.prank(consumer);
        vm.expectRevert(ZkIdentityPredicateProver.InvalidProofContext.selector);
        predicateVerifier.consumeWithProof(
            _proof(), signals, _applicationContext(ACTION_CONTEXT, bytes32(0), 1), POLICY_HASH, subject
        );

        vm.prank(consumer);
        vm.expectRevert(ZkIdentityPredicateProver.InvalidProofEncoding.selector);
        predicateVerifier.consumeWithProof(
            hex"01", signals, _applicationContext(ACTION_CONTEXT, CHALLENGE, 1), POLICY_HASH, subject
        );

        uint256[8] memory invalidProof;
        vm.prank(consumer);
        vm.expectRevert(ZkIdentityPredicateProver.InvalidProof.selector);
        predicateVerifier.consumeWithProof(
            abi.encode(invalidProof), signals, _applicationContext(ACTION_CONTEXT, CHALLENGE, 1), POLICY_HASH, subject
        );
    }

    function test_RejectsTamperedSignalsAndGovernanceState() public {
        uint256[] memory signals = _signals(subject, consumer, ACTION_CONTEXT, CHALLENGE, 1, SCOPED_NULLIFIER);
        signals[9] ^= 1;
        vm.prank(consumer);
        vm.expectRevert(ZkIdentityPredicateProver.PresentationBindingMismatch.selector);
        predicateVerifier.consumeWithProof(
            _proof(), signals, _applicationContext(ACTION_CONTEXT, CHALLENGE, 1), POLICY_HASH, subject
        );

        signals = _signals(subject, consumer, ACTION_CONTEXT, CHALLENGE, 1, SCOPED_NULLIFIER);
        registry.revokeStatusRoot(CIRCUIT_ID, ISSUER_KEY_ID, 10);
        vm.prank(consumer);
        vm.expectRevert(ZkIdentityVersionRegistry.UnacceptedIdentityState.selector);
        predicateVerifier.consumeWithProof(
            _proof(), signals, _applicationContext(ACTION_CONTEXT, CHALLENGE, 1), POLICY_HASH, subject
        );
    }

    function test_DynamicStatusFailsClosedUntilFreshnessPolicyIsRatified() public {
        uint256[] memory signals = _signals(subject, consumer, ACTION_CONTEXT, CHALLENGE, 1, SCOPED_NULLIFIER);
        signals[17] = 1;

        vm.prank(consumer);
        vm.expectRevert(ZkIdentityPredicateProver.DynamicStatusUnsupported.selector);
        predicateVerifier.consumeWithProof(
            _proof(), signals, _applicationContext(ACTION_CONTEXT, CHALLENGE, 1), POLICY_HASH, subject
        );
    }

    function test_CheckProofForBindsExplicitConsumerWithoutSpending() public view {
        uint256[] memory signals = _signals(subject, consumer, ACTION_CONTEXT, CHALLENGE, 1, SCOPED_NULLIFIER);
        bytes memory context = _applicationContext(ACTION_CONTEXT, CHALLENGE, 1);
        assertTrue(predicateVerifier.checkProofFor(_proof(), signals, context, POLICY_HASH, subject, consumer));
        assertFalse(predicateVerifier.consumed(predicateVerifier.proofReplayKey(consumer, bytes32(SCOPED_NULLIFIER))));
    }

    function test_DirectAdapterCallsFailClosed() public {
        uint256[] memory signals = _signals(subject, consumer, ACTION_CONTEXT, CHALLENGE, 1, SCOPED_NULLIFIER);
        vm.expectRevert(ZkIdentityPredicateProver.OnlyPredicateVerifier.selector);
        adapter.verifyPredicate(
            _proof(), signals, abi.encode(consumer, _applicationContext(ACTION_CONTEXT, CHALLENGE, 1))
        );
    }

    function test_ConstructorRejectsMissingHostOrRegistryCode() public {
        vm.expectRevert(ZkIdentityPredicateProver.InvalidPredicateVerifier.selector);
        new ZkIdentityPredicateProver(address(0), registry);

        vm.expectRevert(ZkIdentityPredicateProver.InvalidPredicateVerifier.selector);
        new ZkIdentityPredicateProver(makeAddr("not-a-host-contract"), registry);

        vm.expectRevert(ZkIdentityPredicateProver.InvalidRegistry.selector);
        new ZkIdentityPredicateProver(
            address(predicateVerifier), ZkIdentityVersionRegistry(makeAddr("not-a-registry-contract"))
        );
    }

    function _signals(
        address signalSubject,
        address signalConsumer,
        bytes32 actionContext,
        bytes32 challenge,
        uint8 nullifierMode,
        uint256 scopedNullifier
    ) internal view returns (uint256[] memory signals) {
        signals = new uint256[](18);
        signals[0] = 1;
        _writeIdentifier(signals, 1, CIRCUIT_ID);
        _writeIdentifier(signals, 3, ISSUER_KEY_ID);
        _writeIdentifier(signals, 5, ACTIVE_ROOT);
        _writeIdentifier(signals, 7, POLICY_HASH);

        bytes32 binding = ZkIdentityEncoding.presentationBindingHash(
            ZkIdentityEncoding.PresentationBinding({
                policyHash: POLICY_HASH,
                chainId: block.chainid,
                verifier: address(predicateVerifier),
                consumer: signalConsumer,
                subject: signalSubject,
                context: actionContext,
                challenge: challenge,
                epoch: predicateVerifier.currentEpoch()
            })
        );
        _writeIdentifier(signals, 9, binding);

        bytes32 scope = ZkIdentityEncoding.nullifierScopeHash(
            ZkIdentityEncoding.NullifierScope({
                mode: nullifierMode,
                chainId: block.chainid,
                verifier: address(predicateVerifier),
                consumer: signalConsumer,
                context: actionContext,
                policyHash: POLICY_HASH
            })
        );
        _writeIdentifier(signals, 11, scope);
        signals[13] = scopedNullifier;
        signals[14] = uint160(signalSubject);
        signals[15] = 1;
        signals[16] = predicateVerifier.currentEpoch();
        signals[17] = 0;
    }

    function _writeIdentifier(uint256[] memory signals, uint256 highIndex, bytes32 value) internal pure {
        (signals[highIndex], signals[highIndex + 1]) = ZkIdentityEncoding.splitBytes32(value);
    }

    function _proof() internal pure returns (bytes memory) {
        uint256[8] memory proof;
        proof[0] = 1;
        return abi.encode(proof);
    }

    function _applicationContext(bytes32 actionContext, bytes32 challenge, uint8 nullifierMode)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encode(actionContext, challenge, nullifierMode);
    }
}
