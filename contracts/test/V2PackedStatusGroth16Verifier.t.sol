// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {V2PackedStatusGroth16Verifier} from "../src/research/V2PackedStatusGroth16Verifier.sol";
import {V2PackedStatusFixture} from "./fixtures/V2PackedStatusFixture.sol";

contract V2PackedStatusGroth16VerifierTest is Test {
    V2PackedStatusGroth16Verifier internal verifier;

    function setUp() public {
        verifier = new V2PackedStatusGroth16Verifier();
    }

    function test_VerifiesArkworksFixtureThroughEvmPrecompiles() public view {
        assertTrue(verifier.verifyProof(V2PackedStatusFixture.proof(), V2PackedStatusFixture.publicInputs()));
    }

    function test_RejectsModifiedPublicInput() public view {
        uint256[5] memory inputs = V2PackedStatusFixture.publicInputs();
        inputs[0] += 1;
        assertFalse(verifier.verifyProof(V2PackedStatusFixture.proof(), inputs));
    }

    function test_RejectsModifiedProof() public view {
        uint256[8] memory proof = V2PackedStatusFixture.proof();
        proof[0] += 1;
        assertFalse(verifier.verifyProof(proof, V2PackedStatusFixture.publicInputs()));
    }

    function test_RejectsNonCanonicalProofCoordinateAndPublicInput() public view {
        uint256[8] memory proof = V2PackedStatusFixture.proof();
        proof[2] = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        assertFalse(verifier.verifyProof(proof, V2PackedStatusFixture.publicInputs()));

        uint256[5] memory inputs = V2PackedStatusFixture.publicInputs();
        inputs[4] = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        assertFalse(verifier.verifyProof(V2PackedStatusFixture.proof(), inputs));
    }
}
