// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title Dynamic-status 18-signal Groth16 research verifier
/// @notice Verifies the deterministic sanctions-clear research fixture emitted
///         by `tools/v2-crypto-bench --dynamic-status-evm-fixture`.
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

        pairs[6] = 8005723860705952485109408441639372068821195900291661855535862428722754669344;
        pairs[7] = 10905537318090532365242381748573090391408527266973311274657232466885028173822;
        pairs[8] = 21743363498514904928700588647105892594700320799047757728088207220757841698021;
        pairs[9] = 7363677217177389626782355837002530704202599466904976042624358988902101506621;
        pairs[10] = 3906904756227236839560331473212755456215803376037003842666976611766182860335;
        pairs[11] = 10404789351174118145548841165564752933660626857956792280403136969189000903601;

        pairs[12] = vkX;
        pairs[13] = vkY;
        pairs[14] = 6758701179450225156304289533394766997350452912349600107434363411475597897144;
        pairs[15] = 16095347022725238269264164117499879111811386177584881120486586021277312181973;
        pairs[16] = 16456176174934377803314603496191557613547386742734540912532255487530597668437;
        pairs[17] = 21525324550063361821931503950374140295668094248118070630162336275041689344395;

        pairs[18] = proof[6];
        pairs[19] = proof[7];
        pairs[20] = 4391059644397889219605976250134685029447024695478539715654508540792400711733;
        pairs[21] = 13694617537551278011117612951722005522296935709922762982285941015401160650691;
        pairs[22] = 15243352539973739820638193809246457071181041243929630592414377784872551620692;
        pairs[23] = 8757924504846639921409748069792406166648015079580181763668461448691315693085;

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
        if (index == 0) {
            return (
                20650725564032935736681228587513929651752764526867457981595017646061226387265,
                8756450213503051883979656454486805324773066000690880953042100456608020554247
            );
        }
        if (index == 1) {
            return (
                3162719418020760888652205578081093522781217260324702595408445214216820350299,
                18110213402718963104893595213094169832338849808631273444927249265505641074901
            );
        }
        if (index == 2) {
            return (
                15783415570095330322254215930804436195308218307738564245336601282492540742131,
                16243635799280537967261927200071402701361011487756921197204282634448735108860
            );
        }
        if (index == 3) {
            return (
                12731549998932813875685502190532143571152233628751347423839780332690403288682,
                7468461186788234222138029974292165766351238792667742176434447794134473289595
            );
        }
        if (index == 4) {
            return (
                11452815631417658157894427066692915042440176892901663655506573038192501439146,
                11224355601202594715661943121732641708574762221191887705331757440128982262690
            );
        }
        if (index == 5) {
            return (
                14601681557690849462260489467436750103737363311727529100527319135314823727911,
                16321412180672684918573972928524133725297323616971764849832022449146962034100
            );
        }
        if (index == 6) {
            return (
                13037873787175267929139448544009297409853445363688678093448566120551579403264,
                741463036820012425791854086686744484510457774106962481290589437944259903121
            );
        }
        if (index == 7) {
            return (
                5362905236847993451484354991322332722765855125231516746437660168584399358280,
                6181782499944478349134397766152402156345355206020681268302058396262962794068
            );
        }
        if (index == 8) {
            return (
                21655369200610746829676425569646240862415732655758949704589691856221316210562,
                8311423484367493672307853103074927974493685750205933889877681351015584450342
            );
        }
        if (index == 9) {
            return (
                9212987029735932601759147579173273299860257462606618420945362581588584527920,
                8850687111477883642223019218863735508576668888149268659191224318643415970187
            );
        }
        if (index == 10) {
            return (
                12004824526308085334447848433059044411981527592415716976242008208184920426570,
                20931902749424618960841789775863908366158884243331627892865975074890863096683
            );
        }
        if (index == 11) {
            return (
                21871548462014494122443396522130046885224715207505637639496356505936428238102,
                16811305812587291516756505294603686432977013610418827716077709732030178463347
            );
        }
        if (index == 12) {
            return (
                16056448972020603152818833839008331025896707585887601311679021694830464131600,
                4364685048790383168477130591075615765614021367908728077736303080418092265700
            );
        }
        if (index == 13) {
            return (
                12663845169966477192307031223036842351996437665202955851655068867223705613689,
                19257259273337949225834162119294378126028392756552226523992630281270762038153
            );
        }
        if (index == 14) {
            return (
                20123137100659845520708149144569624109927306589360564281412040887835795969336,
                5490863729416821422559621905499962851460924468900911820130414277371029555599
            );
        }
        if (index == 15) {
            return (
                16508586995475431934877990248125102023366956211839429508761762258583189106316,
                4277813479691655120638716182501528253675075339139292536820606688859182186033
            );
        }
        if (index == 16) {
            return (
                12657690066112131193391096363817111033220717064710808272840840824815593676005,
                2772763515855877220168853684604383030399485768816089410271845199646255987684
            );
        }
        if (index == 17) {
            return (
                4381365543273016121594795172172830819941531626773836400403067707248144949427,
                13217508720683116386514992568186279230110989662295271380866765660907222614385
            );
        }
        if (index == 18) {
            return (
                5330385495138595845829196118890164644116260537142452761976548597836178556976,
                2369783941696709193573122169576701139689739367872623477112128779067411175132
            );
        }
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
