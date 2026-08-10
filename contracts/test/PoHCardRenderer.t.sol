// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {ProofOfHumanity, HumanityVoucher} from "../src/ProofOfHumanity.sol";
import {PoHCardRenderer} from "../src/PoHCardRenderer.sol";

/// @notice Tests the fully on-chain MINIMAL PoH card renderer and its wiring into
///         {ProofOfHumanity.tokenURI} (the optional `"image"` field).
contract PoHCardRendererTest is Test {
    ProofOfHumanity internal poh;
    PoHCardRenderer internal renderer;

    uint256 internal constant ISSUER_PK = 0xA11CE;
    address internal issuer;
    address internal owner;
    address internal alice;
    address internal relayer;

    uint256 internal constant NULL_A = uint256(keccak256("nullifier-a"));

    function setUp() public {
        issuer = vm.addr(ISSUER_PK);
        owner = makeAddr("owner");
        alice = makeAddr("alice");
        relayer = makeAddr("relayer");

        vm.warp(1_700_000_000);
        poh = new ProofOfHumanity(owner, issuer);
        renderer = new PoHCardRenderer();
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    function _voucher(address to, uint256 nullifier) internal view returns (HumanityVoucher memory) {
        return HumanityVoucher({to: to, nullifier: nullifier, epoch: poh.currentEpoch()});
    }

    function _mint(HumanityVoucher memory v) internal returns (uint256) {
        bytes32 digest = poh.hashVoucher(v);
        (uint8 vv, bytes32 r, bytes32 s) = vm.sign(ISSUER_PK, digest);
        bytes memory sig = abi.encodePacked(r, s, vv);
        vm.prank(relayer);
        return poh.mintWithVoucher(v, sig);
    }

    /*//////////////////////////////////////////////////////////////
                            ADMIN WIRING
    //////////////////////////////////////////////////////////////*/

    function test_SetCardRenderer_OnlyOwner() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", alice));
        poh.setCardRenderer(address(renderer));
    }

    function test_SetCardRenderer_UpdatesAndEmits() public {
        vm.expectEmit(true, true, true, true, address(poh));
        emit ProofOfHumanity.CardRendererUpdated(address(0), address(renderer));
        vm.prank(owner);
        poh.setCardRenderer(address(renderer));
        assertEq(poh.cardRenderer(), address(renderer));
    }

    /*//////////////////////////////////////////////////////////////
                        tokenURI IMAGE FIELD
    //////////////////////////////////////////////////////////////*/

    function test_TokenURI_OmitsImageWhenRendererUnset() public {
        uint256 id = _mint(_voucher(alice, NULL_A));
        string memory json = _decodeJsonUri(poh.tokenURI(id));
        assertFalse(_contains(json, '"image"'), "image must be absent when no renderer");
        // JSON still valid & complete.
        assertTrue(_contains(json, '"name":"Proof of Humanity #1"'));
        assertTrue(_contains(json, '"attributes":['));
    }

    function test_TokenURI_IncludesMinimalCardWhenRendererSet() public {
        vm.prank(owner);
        poh.setCardRenderer(address(renderer));

        uint256 id = _mint(_voucher(alice, NULL_A));
        string memory json = _decodeJsonUri(poh.tokenURI(id));

        // The image is a base64 SVG data-URI embedded in valid JSON.
        assertTrue(_contains(json, '"image":"data:image/svg+xml;base64,'), "missing image data-uri");

        string memory svg = _decodeImageSvg(json);
        assertTrue(_contains(svg, "<svg"), "not an svg");
        assertTrue(_contains(svg, "</svg>"), "svg not closed");
        // Minimal-card chrome present.
        assertTrue(_contains(svg, "Proof of Humanity"), "missing title");
        assertTrue(_contains(svg, "HUMAN ID"), "missing human id label");
        assertTrue(_contains(svg, "ZERO-KNOWLEDGE"), "missing section header");
        assertTrue(_contains(svg, "Unique human"), "missing unique-human row");
        assertTrue(_contains(svg, "Personal data on-chain"), "missing on-chain row");
        assertTrue(_contains(svg, "#FF6B8A"), "missing brand gradient stop");

        // NO personal data anywhere on the minimal card.
        _assertNoPersonalData(svg);
    }

    /*//////////////////////////////////////////////////////////////
                        RENDERER UNIT (pure)
    //////////////////////////////////////////////////////////////*/

    function test_Render_MinimalCardChrome() public view {
        string memory uri = renderer.render(7, NULL_A);
        assertTrue(_startsWith(uri, "data:image/svg+xml;base64,"));
        string memory svg = string(_base64Decode(_afterPrefix(uri, "data:image/svg+xml;base64,")));

        // The full locked minimal card is present.
        assertTrue(_contains(svg, "ZERO-KNOWLEDGE"));
        assertTrue(_contains(svg, "PROVABLE ON DEMAND"));
        assertTrue(_contains(svg, "Unique human"));
        assertTrue(_contains(svg, "Personal data on-chain"));
        assertTrue(_contains(svg, "None"));
        assertTrue(_contains(svg, "Age 18+"));
        assertTrue(_contains(svg, "Nationality"));
        assertTrue(_contains(svg, "Sanctions"));
        assertTrue(_contains(svg, unicode"ONE HUMAN · ONE CREDENTIAL · SOULBOUND"));
        assertTrue(_contains(svg, "#FFE24B"));
        assertTrue(_contains(svg, "HUMAN ID"));

        // NO personal-attribute values (the whole point of the pivot).
        _assertNoPersonalData(svg);
    }

    function test_Render_HumanIdShortHex() public view {
        // nullifier with known top-16 (0x7A3F) and bottom-16 (0xC9E2) bits.
        uint256 nullifier = (uint256(0x7A3F) << 240) | uint256(0xC9E2);
        string memory svg =
            string(_base64Decode(_afterPrefix(renderer.render(1, nullifier), "data:image/svg+xml;base64,")));
        // HUMAN ID = 0x<top4>…<bottom4>, uppercase, matching the locked design.
        assertTrue(_contains(svg, unicode"0x7A3F…C9E2"), "missing/incorrect HUMAN ID");
    }

    function test_Render_HumanIdZeroNullifier() public view {
        string memory svg = string(_base64Decode(_afterPrefix(renderer.render(1, 0), "data:image/svg+xml;base64,")));
        assertTrue(_contains(svg, unicode"0x0000…0000"), "zero nullifier id");
    }

    /*//////////////////////////////////////////////////////////////
                          STRING / BASE64 UTILS
    //////////////////////////////////////////////////////////////*/

    /// @dev Assert none of the retired personal-attribute values leak into `svg`.
    function _assertNoPersonalData(string memory svg) internal pure {
        assertFalse(_contains(svg, "DISCLOSED ATTRIBUTES"), "stale attributes header");
        assertFalse(_contains(svg, "Argentina"), "leaked nationality");
        assertFalse(_contains(svg, "Female"), "leaked gender");
        assertFalse(_contains(svg, "Male"), "leaked gender");
        assertFalse(_contains(svg, "Gender"), "leaked gender label");
        assertFalse(_contains(svg, "or older"), "leaked age");
        assertFalse(_contains(svg, "Legal age"), "leaked age label");
    }

    function _startsWith(string memory s, string memory prefix) internal pure returns (bool) {
        bytes memory bs = bytes(s);
        bytes memory bp = bytes(prefix);
        if (bp.length > bs.length) return false;
        for (uint256 i = 0; i < bp.length; i++) {
            if (bs[i] != bp[i]) return false;
        }
        return true;
    }

    function _contains(string memory haystack, string memory needle) internal pure returns (bool) {
        return _indexOf(bytes(haystack), bytes(needle)) != type(uint256).max;
    }

    /// @dev First index of `n` in `h`, or type(uint256).max if absent.
    function _indexOf(bytes memory h, bytes memory n) internal pure returns (uint256) {
        if (n.length == 0) return 0;
        if (n.length > h.length) return type(uint256).max;
        for (uint256 i = 0; i <= h.length - n.length; i++) {
            bool ok = true;
            for (uint256 j = 0; j < n.length; j++) {
                if (h[i + j] != n[j]) {
                    ok = false;
                    break;
                }
            }
            if (ok) return i;
        }
        return type(uint256).max;
    }

    /// @dev Everything after `prefix` in `s` (assumes `s` starts with `prefix`).
    function _afterPrefix(string memory s, string memory prefix) internal pure returns (bytes memory) {
        bytes memory b = bytes(s);
        uint256 start = bytes(prefix).length;
        bytes memory out = new bytes(b.length - start);
        for (uint256 i = start; i < b.length; i++) {
            out[i - start] = b[i];
        }
        return out;
    }

    /// @dev Strip `data:application/json;base64,` and decode to the JSON string.
    function _decodeJsonUri(string memory uri) internal pure returns (string memory) {
        return string(_base64Decode(_afterPrefix(uri, "data:application/json;base64,")));
    }

    /// @dev From a decoded metadata JSON, extract the `"image"` SVG data-URI base64
    ///      payload and decode it to the raw SVG string.
    function _decodeImageSvg(string memory json) internal pure returns (string memory) {
        bytes memory j = bytes(json);
        bytes memory marker = bytes('"image":"data:image/svg+xml;base64,');
        uint256 at = _indexOf(j, marker);
        require(at != type(uint256).max, "no image marker");
        uint256 start = at + marker.length;
        // The base64 payload runs until the closing double-quote.
        uint256 end = start;
        while (end < j.length && j[end] != '"') {
            end++;
        }
        bytes memory payload = new bytes(end - start);
        for (uint256 i = start; i < end; i++) {
            payload[i - start] = j[i];
        }
        return string(_base64Decode(payload));
    }

    function _base64Decode(bytes memory data) internal pure returns (bytes memory) {
        uint256 len = data.length;
        if (len == 0) return new bytes(0);
        require(len % 4 == 0, "bad base64 length");

        bytes memory table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        uint8[128] memory inv;
        for (uint8 i = 0; i < 64; i++) {
            inv[uint8(table[i])] = i;
        }

        uint256 pad;
        if (data[len - 1] == "=") pad++;
        if (data[len - 2] == "=") pad++;

        uint256 outLen = (len / 4) * 3 - pad;
        bytes memory out = new bytes(outLen);
        uint256 o;
        for (uint256 i = 0; i < len; i += 4) {
            uint256 chunk = (uint256(inv[uint8(data[i])]) << 18) | (uint256(inv[uint8(data[i + 1])]) << 12)
                | (uint256(inv[uint8(data[i + 2])]) << 6) | uint256(inv[uint8(data[i + 3])]);
            if (o < outLen) out[o++] = bytes1(uint8(chunk >> 16));
            if (o < outLen) out[o++] = bytes1(uint8(chunk >> 8));
            if (o < outLen) out[o++] = bytes1(uint8(chunk));
        }
        return out;
    }
}
