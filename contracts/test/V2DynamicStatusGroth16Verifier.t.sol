// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {PredicateVerifier} from "../src/PredicateVerifier.sol";
import {ZkIdentityPredicateProver} from "../src/ZkIdentityPredicateProver.sol";
import {ZkIdentityVersionRegistry} from "../src/ZkIdentityVersionRegistry.sol";
import {V2DynamicStatusGroth16Verifier} from "../src/research/V2DynamicStatusGroth16Verifier.sol";
import {V2DynamicStatusFixture} from "./fixtures/V2DynamicStatusFixture.sol";

contract V2DynamicStatusGroth16VerifierTest is Test {
    uint256 internal constant BASE_FIELD =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 internal constant SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    V2DynamicStatusGroth16Verifier internal verifier;

    function setUp() public {
        verifier = new V2DynamicStatusGroth16Verifier();
    }

    function test_VerifiesExactEighteenSignalArkworksFixture() public view {
        assertTrue(verifier.verifyProof(V2DynamicStatusFixture.proof(), V2DynamicStatusFixture.publicInputs()));
    }

    function test_EveryPublicSignalIsCryptographicallyBound() public view {
        for (uint256 i = 0; i < 18; ++i) {
            uint256[18] memory inputs = V2DynamicStatusFixture.publicInputs();
            inputs[i] += 1;
            assertFalse(verifier.verifyProof(V2DynamicStatusFixture.proof(), inputs), "modified signal accepted");
        }
    }

    function test_RejectsModifiedOrNonCanonicalProofAndSignals() public view {
        uint256[8] memory proof = V2DynamicStatusFixture.proof();
        proof[0] += 1;
        assertFalse(verifier.verifyProof(proof, V2DynamicStatusFixture.publicInputs()));

        proof = V2DynamicStatusFixture.proof();
        proof[2] = BASE_FIELD;
        assertFalse(verifier.verifyProof(proof, V2DynamicStatusFixture.publicInputs()));

        uint256[18] memory inputs = V2DynamicStatusFixture.publicInputs();
        inputs[17] = SCALAR_FIELD;
        assertFalse(verifier.verifyProof(V2DynamicStatusFixture.proof(), inputs));
    }

    function test_RuntimeFitsTheEip170Limit() public view {
        assertLt(address(verifier).code.length, 24_576);
    }
}

contract V2DynamicStatusEndToEndTest is Test {
    address internal constant FIXTURE_CONSUMER = 0x2222222222222222222222222222222222222222;
    address internal constant FIXTURE_SUBJECT = 0x3333333333333333333333333333333333333333;
    address internal constant EXPECTED_HOST = 0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f;
    bytes32 internal constant ACTION_CONTEXT = 0x9d3469716e75d7b16c109c886f96fef85b6e9dc7b1e3139c864e5e664a00a98b;
    bytes32 internal constant CHALLENGE = 0xc65bfcbace59e23335df2a1f460660814b3f85710ddbcd922d5f458f4e150b34;
    uint32 internal constant PUBLISHED_AT = 1_788_480_000;

    PredicateVerifier internal predicateVerifier;
    ZkIdentityVersionRegistry internal registry;
    V2DynamicStatusGroth16Verifier internal rawVerifier;
    ZkIdentityPredicateProver internal adapter;
    bytes32 internal policyHash;

    function setUp() public {
        vm.chainId(84_532);
        vm.warp(uint256(PUBLISHED_AT) + 60);

        predicateVerifier = new PredicateVerifier(address(this), makeAddr("research-fixture-issuer"));
        assertEq(address(predicateVerifier), EXPECTED_HOST, "fixture binding assumes the first CREATE address");
        registry = new ZkIdentityVersionRegistry(address(this));
        rawVerifier = new V2DynamicStatusGroth16Verifier();

        uint256[18] memory inputs = V2DynamicStatusFixture.publicInputs();
        bytes32 circuitId = _join(inputs[1], inputs[2]);
        bytes32 issuerKeyId = _join(inputs[3], inputs[4]);
        bytes32 activeRoot = _join(inputs[5], inputs[6]);
        policyHash = _join(inputs[7], inputs[8]);

        registry.registerCircuit(circuitId, address(rawVerifier));
        registry.authorizeIssuer(circuitId, issuerKeyId);
        registry.publishStatusRoot(circuitId, issuerKeyId, 1, activeRoot);
        bytes32 registeredPolicy = registry.registerDynamicStatusPolicy(
            keccak256("self:ofac"), keccak256("research:fixture-1"), activeRoot, PUBLISHED_AT, 86_400
        );
        assertEq(registeredPolicy, policyHash);

        adapter = new ZkIdentityPredicateProver(address(predicateVerifier), registry);
        predicateVerifier.setPredicateProver(adapter);
        assertEq(predicateVerifier.currentEpoch(), 230);
    }

    function test_RealProofTraversesRegistryAdapterHostAndReplayStorage() public {
        uint256[] memory signals = _dynamicSignals();
        vm.prank(FIXTURE_CONSUMER);
        assertTrue(
            predicateVerifier.consumeWithProof(
                abi.encode(V2DynamicStatusFixture.proof()),
                signals,
                abi.encode(ACTION_CONTEXT, CHALLENGE, uint8(1)),
                policyHash,
                FIXTURE_SUBJECT
            )
        );

        bytes32 replayId = bytes32(V2DynamicStatusFixture.publicInputs()[13]);
        assertTrue(predicateVerifier.consumed(predicateVerifier.proofReplayKey(FIXTURE_CONSUMER, replayId)));
    }

    function test_RealProofCannotBeReplayed() public {
        uint256[] memory signals = _dynamicSignals();
        bytes memory proof = abi.encode(V2DynamicStatusFixture.proof());
        bytes memory context = abi.encode(ACTION_CONTEXT, CHALLENGE, uint8(1));
        vm.startPrank(FIXTURE_CONSUMER);
        predicateVerifier.consumeWithProof(proof, signals, context, policyHash, FIXTURE_SUBJECT);
        vm.expectRevert(PredicateVerifier.ProofReplayed.selector);
        predicateVerifier.consumeWithProof(proof, signals, context, policyHash, FIXTURE_SUBJECT);
        vm.stopPrank();
    }

    function _dynamicSignals() private pure returns (uint256[] memory signals) {
        uint256[18] memory fixedSignals = V2DynamicStatusFixture.publicInputs();
        signals = new uint256[](18);
        for (uint256 i = 0; i < 18; ++i) {
            signals[i] = fixedSignals[i];
        }
    }

    function _join(uint256 high, uint256 low) private pure returns (bytes32) {
        return bytes32((high << 128) | low);
    }
}
