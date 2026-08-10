// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Base64} from "@openzeppelin/contracts/utils/Base64.sol";

/// @title PoHCardRenderer
/// @notice Pure, fully on-chain renderer for the MINIMAL Proof-of-Humanity NFT
///         card. Given a token's anonymous nullifier it returns the LOCKED card
///         SVG as a `data:image/svg+xml;base64,...` URI, ready to drop into
///         `tokenURI`'s `"image"` field.
/// @dev Deployed as a SEPARATE contract from {ProofOfHumanity} so the SVG art
///      never bloats the token contract. Stateless & pure.
///
///      The card shows NO personal data — no nationality, gender or age values.
///      It is assembled from two immutable static chunks (`_A`, `_B`, copied
///      verbatim from the locked design source `card-minimal-final.svg`) with a
///      single dynamic slot spliced in between them: the `HUMAN ID`, a short hex
///      of the nullifier.
contract PoHCardRenderer {
    /*//////////////////////////////////////////////////////////////
                     STATIC SVG CHUNKS (LOCKED DESIGN)
    //////////////////////////////////////////////////////////////*/

    // SQUARE (1000x1000) so wallet tiles (which center-crop to 1:1) never clip it.
    // Everything up to (and including) the open tag of the HUMAN ID value text; the
    // nullifier hex is spliced in between {_A} and {_B} by {render}.
    string private constant _A =
        unicode'<svg width="1000" height="1000" viewBox="0 0 1000 1000" xmlns="http://www.w3.org/2000/svg" role="img"><title>Proof of Humanity — zero-knowledge</title><defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#FFE24B"/><stop offset="52%" stop-color="#FF9A55"/><stop offset="100%" stop-color="#FF6B8A"/></linearGradient><linearGradient id="ok" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#6EE7B7"/><stop offset="100%" stop-color="#22C55E"/></linearGradient><linearGradient id="card" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#101016"/><stop offset="100%" stop-color="#08080B"/></linearGradient><radialGradient id="glow" cx="50%" cy="27%" r="46%"><stop offset="0%" stop-color="#FF7A66" stop-opacity="0.16"/><stop offset="100%" stop-color="#000000" stop-opacity="0"/></radialGradient></defs><rect width="1000" height="1000" fill="#08080B"/><rect width="1000" height="1000" fill="url(#glow)"/><rect x="24" y="24" width="952" height="952" rx="44" fill="url(#card)" stroke="url(#g)" stroke-width="2"/><path d="M74 60 L79 78 L97 83 L79 88 L74 106 L69 88 L51 83 L69 78 Z" fill="url(#g)" opacity="0.9"/><text x="936" y="74" text-anchor="end" font-family="ui-monospace,Menlo,monospace" font-size="13" letter-spacing="3" fill="#C9A24E">HUMAN ID</text><text x="936" y="100" text-anchor="end" font-family="ui-monospace,Menlo,monospace" font-size="18" fill="#E8E8EC">';

    // Closes the HUMAN ID value, then the emblem, title, the ZERO-KNOWLEDGE section,
    // the three verified rows, the PROVABLE-ON-DEMAND chips and the signature line —
    // all static — through </svg>.
    string private constant _B =
        unicode'</text><path d="M656 250 L578 385 L422 385 L344 250 L422 115 L578 115 Z" fill="none" stroke="url(#g)" stroke-opacity="0.18" stroke-width="1.2" stroke-dasharray="2 9"/><circle cx="500" cy="250" r="146" fill="none" stroke="url(#g)" stroke-opacity="0.26" stroke-width="1" stroke-dasharray="1.5 7"/><circle cx="382" cy="250" r="3.5" fill="url(#g)"/><circle cx="618" cy="250" r="3.5" fill="url(#g)"/><circle cx="500" cy="250" r="118" fill="#0B0B10" stroke="url(#g)" stroke-opacity="0.5" stroke-width="1.5"/><g transform="translate(427,157) scale(0.42)"><path fill="url(#g)" d="M 347.25 181.1 Q 347.25 147.05 334.2 115.65 321.15 84.2 297.1 60.15 273.05 36.05 241.6 23 210.15 10 176.15 9.95 174.897265625 9.9517578125 173.65 9.95 172.40078125 9.9517578125 171.15 9.95 137.1 10 105.65 23 74.25 36.05 50.2 60.15 26.1 84.2 13.1 115.65 0.05 147.05 0 181.1 0.0033203125 182.2296875 0 183.35 0.001953125 184.7263671875 0 186.1 0.05 203.45 4.5 220.25 8.9 237.1 17.4 252.25 25.9 267.4 37.9 279.95 49.95 292.5 64.75 301.65 L 79.75 310.85 79.75 418.7 Q 79.75 420.75 81.2 422.2 82.7 423.65 84.75 423.65 L 242.6 423.65 Q 244.65 423.65 246.1 422.2 247.6 420.75 247.6 418.7 L 247.6 377.15 295.75 377.15 Q 300.7 377.15 305.3 375.25 309.85 373.35 313.4 369.85 316.9 366.35 318.8 361.75 320.7 357.2 320.7 352.25 L 320.7 304.05 351.1 304.05 Q 355.5 304.05 359.45 302.05 363.4 300 365.95 296.45 368.5 292.85 369.2 288.5 369.5890625 285.8658203125 369.2 283.3 369.8205078125 279.015625 368.4 274.95 L 347.25 212.2 347.25 181.1 M 332.3 218 Q 332.3 218.85 332.55 219.6 L 353.95 283.1 Q 353.980859375 283.1904296875 354 283.25 353.620703125 284.544140625 352.85 285.65 351.7 287.25 349.9 288.2 348.2853515625 289.007421875 346.5 289.05 L 310.7 289.05 Q 308.65 289.1 307.15 290.55 305.75 292 305.7 294.05 L 305.7 347.55 Q 305.6390625 350.3458984375 304.55 352.95 303.4 355.7 301.35 357.8 299.25 359.9 296.5 361.05 293.8935546875 362.1400390625 291.05 362.2 L 237.6 362.2 Q 235.55 362.2 234.05 363.65 232.6 365.1 232.6 367.2 L 232.6 408.7 94.75 408.7 94.75 303.05 Q 94.75 301.75 94.1 300.65 93.45 299.5 92.35 298.8 L 74.95 288.15 Q 61.25 279.65 50.1 268.05 38.95 256.45 31.1 242.4 23.2 228.35 19.1 212.75 15.2994140625 198.1578125 14.95 183.05 15.5302734375 152.651171875 27.25 124.4 39.5 94.8 62.2 72.15 84.85 49.45 114.45 37.2 142.941796875 25.38046875 173.65 24.9 204.35625 25.38046875 232.8 37.2 262.45 49.45 285.1 72.15 307.75 94.8 320.05 124.4 331.76171875 152.7470703125 332.3 183.3 L 332.3 218 M 234.25 188.1 Q 234.25 186.15 232.9 184.75 231.5 183.4 229.6 183.35 L 229.25 183.35 Q 227.8 183.45 226.65 184.35 L 176.7 222.2 126.8 184.3 Q 125.9 183.6 124.75 183.4 123.65 183.2 122.55 183.5 121.45 183.85 120.6 184.65 119.8 185.4 119.4 186.5 119.05 187.6 119.2 188.7 119.4 189.85 120.05 190.8 L 172.85 266.35 Q 173.5 267.3 174.55 267.8 175.55 268.35 176.7 268.35 177.85 268.35 178.9 267.8 179.95 267.3 180.6 266.35 L 233.35 190.85 Q 234.25 189.65 234.25 188.1 M 174.4 77.35 Q 173.3 77.95 172.65 79.05 L 123.9 160.15 Q 123 161.75 123.3 163.5 123.65 165.25 125.05 166.35 L 173.85 203.95 Q 175.1 204.95 176.7 204.95 178.3 204.95 179.6 203.95 L 228.35 166.35 Q 229.8 165.25 230.1 163.5 230.45 161.75 229.55 160.15 L 180.75 79.05 Q 180.1 77.95 179.05 77.35 177.95 76.75 176.7 76.75 175.45 76.75 174.4 77.35 M 176.75 136.45 Q 177.6 136.45 178.4 136.8 L 219.8 155.55 Q 221.35 156.25 221.9 157.85 222.5 159.4 221.8 160.95 221.15 162.45 219.55 163.05 217.95 163.65 216.45 162.95 L 178.2 145.65 Q 177.5 145.3 176.7 145.3 175.95 145.3 175.25 145.65 L 137 162.95 Q 135.5 163.65 133.85 163.1 132.3 162.5 131.6 160.95 130.9 159.4 131.5 157.85 132.1 156.25 133.65 155.55 L 175.05 136.8 Q 175.85 136.45 176.75 136.45 Z"/></g><text x="500" y="452" text-anchor="middle" font-family="Helvetica,\'Helvetica Neue\',Arial,sans-serif" font-size="50" font-weight="800" letter-spacing="-1.5" fill="#F5F5F7">Proof of Humanity</text><text x="500" y="489" text-anchor="middle" font-family="Helvetica,\'Helvetica Neue\',Arial,sans-serif" font-size="21" font-weight="600" fill="url(#g)">Verified with Self</text><line x1="152" y1="537" x2="352" y2="537" stroke="url(#g)" stroke-opacity="0.4"/><line x1="648" y1="537" x2="848" y2="537" stroke="url(#g)" stroke-opacity="0.4"/><text x="500" y="542" text-anchor="middle" font-family="Helvetica,Arial,sans-serif" font-size="13" letter-spacing="4.5" fill="#C9A24E">ZERO-KNOWLEDGE PROOF OF HUMANITY</text><rect x="60" y="562" width="880" height="54" rx="15" fill="#0D0D12" stroke="url(#g)" stroke-opacity="0.20"/><rect x="76" y="578" width="28" height="22" rx="3" fill="none" stroke="url(#g)" stroke-width="1.5"/><circle cx="85" cy="586" r="3.6" fill="none" stroke="url(#g)" stroke-width="1.4"/><line x1="93" y1="584" x2="100" y2="584" stroke="url(#g)" stroke-width="1.4"/><line x1="93" y1="590" x2="100" y2="590" stroke="url(#g)" stroke-width="1.4"/><line x1="80" y1="595" x2="100" y2="595" stroke="url(#g)" stroke-width="1.4" stroke-opacity="0.7"/><text x="130" y="596" font-family="Helvetica,Arial,sans-serif" font-size="19" fill="#EAEAEE">Valid passport</text><text x="856" y="596" text-anchor="end" font-family="Helvetica,Arial,sans-serif" font-size="19" fill="#F2F2F4">Verified</text><circle cx="900" cy="589" r="13" fill="none" stroke="url(#ok)" stroke-width="1.7"/><path d="M893 589 l5 5 l9 -9.5" fill="none" stroke="url(#ok)" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round"/><rect x="60" y="624" width="880" height="54" rx="15" fill="#0D0D12" stroke="url(#g)" stroke-opacity="0.20"/><circle cx="90" cy="645" r="6" fill="none" stroke="url(#g)" stroke-width="1.6"/><path d="M78 664 q12 -14 24 0" fill="none" stroke="url(#g)" stroke-width="1.6" stroke-linecap="round"/><text x="130" y="658" font-family="Helvetica,Arial,sans-serif" font-size="19" fill="#EAEAEE">Unique human</text><text x="856" y="658" text-anchor="end" font-family="Helvetica,Arial,sans-serif" font-size="19" fill="#F2F2F4">Verified</text><circle cx="900" cy="651" r="13" fill="none" stroke="url(#ok)" stroke-width="1.7"/><path d="M893 651 l5 5 l9 -9.5" fill="none" stroke="url(#ok)" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round"/><rect x="60" y="686" width="880" height="54" rx="15" fill="#0D0D12" stroke="url(#g)" stroke-opacity="0.20"/><rect x="82" y="712" width="18" height="13" rx="2" fill="none" stroke="url(#g)" stroke-width="1.6"/><path d="M85 712 v-4 a6 6 0 0 1 12 0 v4" fill="none" stroke="url(#g)" stroke-width="1.6"/><text x="130" y="720" font-family="Helvetica,Arial,sans-serif" font-size="19" fill="#EAEAEE">Personal data on-chain</text><text x="856" y="720" text-anchor="end" font-family="Helvetica,Arial,sans-serif" font-size="19" fill="url(#ok)">None</text><circle cx="900" cy="713" r="13" fill="none" stroke="url(#ok)" stroke-width="1.7"/><path d="M893 713 l5 5 l9 -9.5" fill="none" stroke="url(#ok)" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round"/><text x="500" y="782" text-anchor="middle" font-family="Helvetica,Arial,sans-serif" font-size="12" letter-spacing="3.5" fill="#C9A24E">PROVABLE ON DEMAND · NEVER STORED</text><g font-family="Helvetica,Arial,sans-serif" font-size="16" font-weight="500"><rect x="60" y="800" width="280" height="50" rx="25" fill="#12121A" stroke="url(#g)" stroke-opacity="0.5"/><text x="200" y="831" text-anchor="middle" fill="#EDEDF1">Age 18+</text><rect x="360" y="800" width="280" height="50" rx="25" fill="#12121A" stroke="url(#g)" stroke-opacity="0.5"/><text x="500" y="831" text-anchor="middle" fill="#EDEDF1">Nationality</text><rect x="660" y="800" width="280" height="50" rx="25" fill="#12121A" stroke="url(#g)" stroke-opacity="0.5"/><text x="800" y="831" text-anchor="middle" fill="#EDEDF1">Sanctions</text></g><path d="M244 903 l7 6 l-7 5 z" fill="url(#g)"/><path d="M244 903 l-7 6 l7 5 z" fill="url(#g)" opacity="0.55"/><text x="500" y="913" text-anchor="middle" font-family="Helvetica,\'Helvetica Neue\',Arial,sans-serif" font-size="13" font-weight="600" letter-spacing="2" fill="url(#g)">ONE HUMAN · ONE CREDENTIAL · SOULBOUND</text><path d="M756 903 l7 6 l-7 5 z" fill="url(#g)" opacity="0.55"/><path d="M756 903 l-7 6 l7 5 z" fill="url(#g)"/></svg>';

    /*//////////////////////////////////////////////////////////////
                                RENDER
    //////////////////////////////////////////////////////////////*/

    /// @notice Render the LOCKED minimal PoH card for a token.
    /// @param nullifier The token's anonymous Self nullifier; shown truncated as
    ///                  the `HUMAN ID` (`0x` + first 4 + `…` + last 4 hex chars).
    /// @return A `data:image/svg+xml;base64,...` URI of the card.
    /// @dev `tokenId` is part of the {IPoHCardRenderer} seam but the minimal card
    ///      shows no token-id slot, so it is intentionally unused.
    function render(uint256, uint256 nullifier) external pure returns (string memory) {
        string memory svg = string.concat(_A, _humanId(nullifier), _B);
        return string.concat("data:image/svg+xml;base64,", Base64.encode(bytes(svg)));
    }

    /*//////////////////////////////////////////////////////////////
                          DYNAMIC-SLOT HELPER
    //////////////////////////////////////////////////////////////*/

    /// @dev Short anonymous id: `0x` + top-16-bit hex + `…` + bottom-16-bit hex,
    ///      e.g. `0x7A3F…C9E2`. Uppercase hex to match the locked design.
    function _humanId(uint256 nullifier) private pure returns (string memory) {
        return string.concat("0x", _hex4(uint16(nullifier >> 240)), unicode"…", _hex4(uint16(nullifier)));
    }

    /// @dev Render a uint16 as exactly 4 uppercase hex characters.
    function _hex4(uint16 v) private pure returns (string memory) {
        bytes memory HEX = "0123456789ABCDEF";
        bytes memory out = new bytes(4);
        out[0] = HEX[(v >> 12) & 0xF];
        out[1] = HEX[(v >> 8) & 0xF];
        out[2] = HEX[(v >> 4) & 0xF];
        out[3] = HEX[v & 0xF];
        return string(out);
    }
}
