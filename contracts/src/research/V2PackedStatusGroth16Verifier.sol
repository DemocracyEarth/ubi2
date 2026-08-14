// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title Packed-status Groth16 EVM benchmark verifier
/// @notice Verifies the deterministic five-public-input research fixture from
///         `tools/v2-crypto-bench --packed-evm-fixture` through the EIP-196/197
///         BN254 precompiles.
/// @dev RESEARCH ONLY. The setup seed and toxic waste are public, the measured
///      relation omits the product's pinned 18-signal presentation ABI, and the
///      contract has not been audited. It MUST NOT be deployed or accepted by
///      `PredicateVerifier`. A production verifier must be generated from the
///      final reviewed circuit and ceremony artifacts.
contract V2PackedStatusGroth16Verifier {
    uint256 internal constant BASE_FIELD =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 internal constant SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Post-Istanbul BN254 prices are 150 (add), 6,000 (mul), and 181,000
    // (four-pair check). Fixed headroom bounds malformed-input gas grief.
    uint256 internal constant EC_ADD_GAS = 2_000;
    uint256 internal constant EC_MUL_GAS = 10_000;
    uint256 internal constant PAIRING_GAS = 250_000;

    /// @notice Proof word order is A(x,y), B(x_imaginary,x_real,
    ///         y_imaginary,y_real), C(x,y), matching EIP-197's `a*i + b`
    ///         extension-field encoding.
    function verifyProof(uint256[8] calldata proof, uint256[5] calldata publicInputs) external view returns (bool) {
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

        pairs[6] = 21658410556490094431016308636861247605233882419307565210506060126025787947870;
        pairs[7] = 18744269980691058832321786876697556992405616482607283160378570216475284167106;
        pairs[8] = 11267019709809010579921299880827778753229647076572030860441239220117311578890;
        pairs[9] = 18353812417622532601225169175357274176470942944670498357200015555246095177524;
        pairs[10] = 1930987713356461858363903337943408694505313704033385891582999748375840879989;
        pairs[11] = 17782909838147685148354795733302937815872681976116294640497482972267968779643;

        pairs[12] = vkX;
        pairs[13] = vkY;
        pairs[14] = 21557204883182652253857819118507010983942411779132281524692798028001555562809;
        pairs[15] = 13390162027044455635046190440720942451305581736721103797532763277837298712973;
        pairs[16] = 10725404032823005177561132446005578761726576644296262541445297570050962554154;
        pairs[17] = 4676768855769953601906460082151083424369325152104474549366997050861314258397;

        pairs[18] = proof[6];
        pairs[19] = proof[7];
        pairs[20] = 19449924112566067421592008737165133515311146688045215030571047620448249826835;
        pairs[21] = 13221903361530910251672795462101498681383163938542918079366746456625813942715;
        pairs[22] = 20666900539611537683977163954540147669359770318428318728622744644076492909876;
        pairs[23] = 1194815299459605734062463639587937856812348170038432285370336894385716808839;

        return _pairing(pairs);
    }

    function _accumulatePublicInputs(uint256[5] calldata publicInputs)
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
        if (index == 0) {
            return (
                21886579544451573950530484669767991423954339639242454820425805294804593538322,
                1484979957957748429315002198187794165656871510339543104966340031454146889358
            );
        }
        if (index == 1) {
            return (
                10378739940415559778536538855684551693496060506244530798957615674873058051321,
                31425343574788017937785161277444678590382766653732328975952145801878072131
            );
        }
        if (index == 2) {
            return (
                574160001095367445489425938708841496640995341164540404598835604012487940902,
                7345323690953491442081492573741751525668994866769734863282860871758932022822
            );
        }
        if (index == 3) {
            return (
                8690604403489415171759271999545727594276290234589509873034134790427565712589,
                10499942046767081443938894818478634064202781838603746250394938711935013598651
            );
        }
        if (index == 4) {
            return (
                9931614549645031509643357762725172788904343382149989335142599416567077088610,
                11942699573559157101824149287785752363103921000249590735051790037553181359723
            );
        }
        return (
            17234148376735771660032237320603013369012235332672066124146430124462915607205,
            13309824229338613473144509653382228467890642122587311223268122188553999237019
        );
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
