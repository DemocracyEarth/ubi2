import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const EXPECTED_SCHEMA = "org.proofofhumanity.v2-dynamic-status-evm-fixture/1";
const PUBLIC_INPUT_COUNT = 18;
const DECIMAL = /^(0|[1-9][0-9]*)$/;

const inputPath = process.argv[2];
if (!inputPath) {
  throw new Error("usage: node contracts/scripts/generate-v2-dynamic-status-research.mjs <fixture.json>");
}

const report = JSON.parse(readFileSync(resolve(inputPath), "utf8"));
if (
  report.schema !== EXPECTED_SCHEMA ||
  report.warning !== "research fixture only; deterministic toxic-waste setup is public and not deployable" ||
  report.public_input_count !== PUBLIC_INPUT_COUNT ||
  report.public_inputs?.length !== PUBLIC_INPUT_COUNT ||
  report.gamma_abc_g1?.length !== PUBLIC_INPUT_COUNT + 1 ||
  report.proof_verified !== true
) {
  throw new Error("fixture metadata does not match the reviewed 18-signal research profile");
}

const requireDecimal = (value, label) => {
  if (typeof value !== "string" || !DECIMAL.test(value)) {
    throw new Error(`${label} must be an unsigned canonical decimal string`);
  }
  return value;
};

const g1 = (point, label) => [
  requireDecimal(point?.x, `${label}.x`),
  requireDecimal(point?.y, `${label}.y`),
];
const g2 = (point, label) => [
  requireDecimal(point?.x_imaginary, `${label}.x_imaginary`),
  requireDecimal(point?.x_real, `${label}.x_real`),
  requireDecimal(point?.y_imaginary, `${label}.y_imaginary`),
  requireDecimal(point?.y_real, `${label}.y_real`),
];

const alpha = g1(report.alpha_g1, "alpha_g1");
const beta = g2(report.beta_g2, "beta_g2");
const gamma = g2(report.gamma_g2, "gamma_g2");
const delta = g2(report.delta_g2, "delta_g2");
const proof = [
  ...g1(report.proof?.a, "proof.a"),
  ...g2(report.proof?.b, "proof.b"),
  ...g1(report.proof?.c, "proof.c"),
];
const publicInputs = report.public_inputs.map((value, index) => requireDecimal(value, `public_inputs[${index}]`));
const ic = report.gamma_abc_g1.map((point, index) => g1(point, `gamma_abc_g1[${index}]`));

const icCases = ic
  .map(
    ([x, y], index) => `        if (index == ${index}) {
            return (
                ${x},
                ${y}
            );
        }`,
  )
  .join("\n");

const verifier = `// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title Dynamic-status 18-signal Groth16 research verifier
/// @notice Verifies the deterministic sanctions-clear research fixture emitted
///         by \`tools/v2-crypto-bench --dynamic-status-evm-fixture\`.
/// @dev RESEARCH ONLY. The deterministic setup seed and toxic waste are public,
///      the circuit has not been audited, and this bytecode MUST NOT be deployed
///      or registered by a live PredicateVerifier.
contract V2DynamicStatusGroth16Verifier {
    uint256 internal constant BASE_FIELD =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 internal constant SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 internal constant EC_ADD_GAS = 2_000;
    uint256 internal constant EC_MUL_GAS = 10_000;
    uint256 internal constant PAIRING_GAS = 250_000;

    function verifyProof(uint256[8] calldata proof, uint256[18] calldata publicInputs) external view returns (bool) {
        for (uint256 i = 0; i < proof.length; ++i) {
            if (proof[i] >= BASE_FIELD) return false;
        }
        for (uint256 i = 0; i < publicInputs.length; ++i) {
            if (publicInputs[i] >= SCALAR_FIELD) return false;
        }

        (uint256 vkX, uint256 vkY, bool accumulated) = _accumulatePublicInputs(publicInputs);
        if (!accumulated) return false;

        uint256[24] memory pairs;
        pairs[0] = proof[0];
        pairs[1] = _negateY(proof[1]);
        pairs[2] = proof[2];
        pairs[3] = proof[3];
        pairs[4] = proof[4];
        pairs[5] = proof[5];

        pairs[6] = ${alpha[0]};
        pairs[7] = ${alpha[1]};
        pairs[8] = ${beta[0]};
        pairs[9] = ${beta[1]};
        pairs[10] = ${beta[2]};
        pairs[11] = ${beta[3]};

        pairs[12] = vkX;
        pairs[13] = vkY;
        pairs[14] = ${gamma[0]};
        pairs[15] = ${gamma[1]};
        pairs[16] = ${gamma[2]};
        pairs[17] = ${gamma[3]};

        pairs[18] = proof[6];
        pairs[19] = proof[7];
        pairs[20] = ${delta[0]};
        pairs[21] = ${delta[1]};
        pairs[22] = ${delta[2]};
        pairs[23] = ${delta[3]};

        return _pairing(pairs);
    }

    function _accumulatePublicInputs(uint256[18] calldata publicInputs)
        private
        view
        returns (uint256 vkX, uint256 vkY, bool success)
    {
        (vkX, vkY) = _ic(0);
        for (uint256 i = 0; i < publicInputs.length; ++i) {
            (uint256 icX, uint256 icY) = _ic(i + 1);
            (uint256 mulX, uint256 mulY, bool multiplied) = _ecMul(icX, icY, publicInputs[i]);
            if (!multiplied) return (0, 0, false);
            (vkX, vkY, success) = _ecAdd(vkX, vkY, mulX, mulY);
            if (!success) return (0, 0, false);
        }
        return (vkX, vkY, true);
    }

    function _ic(uint256 index) private pure returns (uint256 x, uint256 y) {
${icCases}
        revert("invalid IC index");
    }

    function _ecMul(uint256 x, uint256 y, uint256 scalar)
        private
        view
        returns (uint256 resultX, uint256 resultY, bool success)
    {
        uint256[3] memory input = [x, y, scalar];
        uint256[2] memory output;
        assembly ("memory-safe") {
            success := staticcall(EC_MUL_GAS, 0x07, input, 0x60, output, 0x40)
        }
        return (output[0], output[1], success);
    }

    function _ecAdd(uint256 x1, uint256 y1, uint256 x2, uint256 y2)
        private
        view
        returns (uint256 resultX, uint256 resultY, bool success)
    {
        uint256[4] memory input = [x1, y1, x2, y2];
        uint256[2] memory output;
        assembly ("memory-safe") {
            success := staticcall(EC_ADD_GAS, 0x06, input, 0x80, output, 0x40)
        }
        return (output[0], output[1], success);
    }

    function _pairing(uint256[24] memory input) private view returns (bool) {
        uint256[1] memory output;
        bool success;
        assembly ("memory-safe") {
            success := staticcall(PAIRING_GAS, 0x08, input, 0x300, output, 0x20)
        }
        return success && output[0] == 1;
    }

    function _negateY(uint256 y) private pure returns (uint256) {
        return y == 0 ? 0 : BASE_FIELD - y;
    }
}
`;

const solidityArray = (values) => values.map((value, index) => `${index === 0 ? "uint256(" : ""}${value}${index === 0 ? ")" : ""}`).join(",\n            ");
const fixture = `// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @dev Generated from the deterministic public-toxic-waste research setup.
///      Never use this proof or setup artifact in production.
library V2DynamicStatusFixture {
    function proof() internal pure returns (uint256[8] memory value) {
        value = [
            ${solidityArray(proof)}
        ];
    }

    function publicInputs() internal pure returns (uint256[18] memory value) {
        value = [
            ${solidityArray(publicInputs)}
        ];
    }
}
`;

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const contractsDirectory = resolve(scriptDirectory, "..");
writeFileSync(join(contractsDirectory, "src/research/V2DynamicStatusGroth16Verifier.sol"), verifier);
writeFileSync(join(contractsDirectory, "test/fixtures/V2DynamicStatusFixture.sol"), fixture);
