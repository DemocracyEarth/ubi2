// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {ProofOfHumanity, HumanityVoucher} from "../src/ProofOfHumanity.sol";
import {PoHCardRenderer} from "../src/PoHCardRenderer.sol";

/// @notice Tests the fully on-chain PoH card renderer and its wiring into
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

    uint8 internal constant AGE_18 = 0x02;
    uint8 internal constant SEX_F = 0x46; // 'F'

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
        return HumanityVoucher({
            to: to,
            nullifier: nullifier,
            ageFlags: AGE_18,
            nationality: bytes3("ARG"),
            gender: SEX_F,
            ofacClear: true,
            expiry: uint64(block.timestamp + 365 days)
        });
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

    function test_TokenURI_IncludesCardImageWhenRendererSet() public {
        vm.prank(owner);
        poh.setCardRenderer(address(renderer));

        uint256 id = _mint(_voucher(alice, NULL_A));
        string memory json = _decodeJsonUri(poh.tokenURI(id));

        // The image is a base64 SVG data-URI embedded in valid JSON.
        assertTrue(_contains(json, '"image":"data:image/svg+xml;base64,'), "missing image data-uri");

        string memory svg = _decodeImageSvg(json);
        assertTrue(_contains(svg, "<svg"), "not an svg");
        assertTrue(_contains(svg, "</svg>"), "svg not closed");
        assertTrue(_contains(svg, "Proof of Humanity"), "missing title");
        assertTrue(_contains(svg, "Argentina"), "missing nationality name");
        assertTrue(_contains(svg, "Female"), "missing gender");
        assertTrue(_contains(svg, "18 or older"), "missing legal age");
        assertTrue(_contains(svg, "#FF6B8A"), "missing brand gradient stop");
        // Token id slot rendered as #<decimal>.
        assertTrue(_contains(svg, "#1"), "missing token id");
    }

    /*//////////////////////////////////////////////////////////////
                        RENDERER UNIT (pure)
    //////////////////////////////////////////////////////////////*/

    function test_Render_NotDisclosedTraits() public view {
        string memory uri = renderer.render(7, 0, bytes3(0), 0);
        assertTrue(_startsWith(uri, "data:image/svg+xml;base64,"));
        string memory svg = string(_base64Decode(_afterPrefix(uri, "data:image/svg+xml;base64,")));
        // Undisclosed nationality/age/gender all collapse to "Not disclosed".
        assertTrue(_contains(svg, "Not disclosed"), "expected Not disclosed");
        assertTrue(_contains(svg, "#7"), "missing token id");
        // Static chrome present.
        assertTrue(_contains(svg, "DISCLOSED ATTRIBUTES"));
        assertTrue(_contains(svg, "#FFE24B"));
    }

    function test_Render_AgeUsesHighestBit() public view {
        // 13+ and 18+ set -> highest disclosed threshold shown.
        string memory svg = string(
            _base64Decode(_afterPrefix(renderer.render(1, 0x03, bytes3("ARG"), SEX_F), "data:image/svg+xml;base64,"))
        );
        assertTrue(_contains(svg, "18 or older"));
        assertFalse(_contains(svg, "13 or older"));
    }

    /*//////////////////////////////////////////////////////////////
                          STRING / BASE64 UTILS
    //////////////////////////////////////////////////////////////*/

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
