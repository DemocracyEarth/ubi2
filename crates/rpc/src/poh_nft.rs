//! Proof-of-Humanity NFT: the soulbound ERC-721 "Proof of Humanity" (POH) collection answered by the
//! HumanityHub (`0x…5048`), plus the fully on-chain fingerprint card.
//!
//! Spec: `docs/specs/03-proof-of-humanity.md` + `docs/assets/poh-brand.md`. This module is the pure
//! (state-free) ABI + rendering layer, mirroring [`crate::streams`] for the StreamHub. The stateful
//! dispatch (reading `ubi_getHuman` status for `ownerOf`/`balanceOf`/`tokenURI`, emitting the mint/burn
//! `Transfer` logs at the Verified/Revoke lifecycle transitions) lives in `lib.rs` and calls in here.
//!
//! ## The tokenId scheme (stateless, keyed on the address)
//! There is no token table: a human is its own token. `tokenId == the human address as uint160` (i.e.
//! the 20-byte address zero-extended into a `uint256`). So `ownerOf(tokenId)` is just `tokenId` cast
//! back to an address — and it only *exists* (does not revert) while that address's `ubi_getHuman`
//! status is `Verified`. `balanceOf(owner) == 1` iff `owner` is `Verified`, else `0`. One token per
//! verified human, minted on the Pending→Verified transition and burned on Revoke.

use alloy_primitives::{Address as AlloyAddr, U256};
use alloy_sol_types::{sol, SolValue};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;

use ubi2_runtime::HumanStatus;

/// The PoH ERC-721 collection name (ERC-721 Metadata `name()`).
pub const POH_NAME: &str = "Proof of Humanity";
/// The PoH ERC-721 collection symbol (ERC-721 Metadata `symbol()`).
pub const POH_SYMBOL: &str = "POH";

/// The ERC-165 / ERC-721 / ERC-721 Metadata interface ids `supportsInterface` answers `true` for.
/// (Shared values with the StreamHub collection — these are the canonical ERC interface ids.)
pub const IFACE_ERC165: [u8; 4] = [0x01, 0xff, 0xc9, 0xa7];
pub const IFACE_ERC721: [u8; 4] = [0x80, 0xac, 0x58, 0xcd];
pub const IFACE_ERC721_METADATA: [u8; 4] = [0x5b, 0x5e, 0x13, 0x9f];

// ---------------------------------------------------------------------------------------------
// ABI: the ERC-721 view + soulbound-mutator surface. `sol!` derives the 4-byte selectors so wallets
// (MetaMask / viem / ethers) encode them byte-identically to a real Solidity collection.
// ---------------------------------------------------------------------------------------------

sol! {
    /// The "Proof of Humanity" ERC-165 / ERC-721 / ERC-721 Metadata read surface (via `eth_call` to
    /// the HumanityHub), plus the soulbound mutators (which MUST revert).
    interface IPohNft {
        // --- ERC-165 / ERC-721 / ERC-721 Metadata (read, eth_call) ---
        function supportsInterface(bytes4 interfaceId) external view returns (bool);
        function name() external view returns (string);
        function symbol() external view returns (string);
        function balanceOf(address owner) external view returns (uint256);
        function ownerOf(uint256 tokenId) external view returns (address);
        function tokenURI(uint256 tokenId) external view returns (string);

        // --- soulbound: these MUST revert (one token per human, non-transferable) ---
        function transferFrom(address from, address to, uint256 tokenId) external;
        function safeTransferFrom(address from, address to, uint256 tokenId) external;
        function approve(address to, uint256 tokenId) external;
        function setApprovalForAll(address operator, bool approved) external;
    }
}

/// Re-export the generated call types so `lib.rs` can match on selectors without re-deriving them.
pub use IPohNft::{
    approveCall, balanceOfCall, nameCall, ownerOfCall, safeTransferFromCall, setApprovalForAllCall,
    supportsInterfaceCall, symbolCall, tokenURICall, transferFromCall,
};

// ---------------------------------------------------------------------------------------------
// tokenId <-> address (stateless ownership; spec: tokenId = address as uint160).
// ---------------------------------------------------------------------------------------------

/// The token id for `human`: the 20-byte address as a `uint160`, zero-extended to `uint256`.
pub fn token_id_of(human: &AlloyAddr) -> U256 {
    U256::from_be_slice(human.as_slice())
}

/// Recover the address a `tokenId` encodes, or `None` if any bit above bit 159 is set (no such token —
/// a valid PoH token id always fits in 160 bits).
pub fn addr_of_token_id(token_id: U256) -> Option<AlloyAddr> {
    // Reject ids that don't fit in 160 bits (would not be a clean address-as-uint160).
    if token_id >> 160 != U256::ZERO {
        return None;
    }
    let bytes: [u8; 32] = token_id.to_be_bytes();
    let mut a = [0u8; 20];
    a.copy_from_slice(&bytes[12..]);
    Some(AlloyAddr::from(a))
}

// ---------------------------------------------------------------------------------------------
// ABI return encoders (eth_call returns). Mirror `streams::encode_*`.
// ---------------------------------------------------------------------------------------------

/// ABI-encode a `string` return value.
pub fn encode_string(s: &str) -> Vec<u8> {
    s.to_string().abi_encode()
}
/// ABI-encode a `bool` return value.
pub fn encode_bool(b: bool) -> Vec<u8> {
    b.abi_encode()
}
/// ABI-encode a `uint256` return value.
pub fn encode_u256(v: U256) -> Vec<u8> {
    v.abi_encode()
}
/// ABI-encode an `address` return value.
pub fn encode_address(a: AlloyAddr) -> Vec<u8> {
    a.abi_encode()
}

// ---------------------------------------------------------------------------------------------
// On-chain card: the fingerprint mark + tokenURI document.
// ---------------------------------------------------------------------------------------------

/// The fingerprint-in-shield mark path (the `mask#Mask_Mask_1` silhouette from
/// `apps/wallet/public/poh-logo.svg`). Drawn filled with the yellow→pink PoH gradient. The path is in
/// the logo's native coordinate space (~0..369 × 0..423); the card wraps it in a positioning/scaling
/// transform.
const FINGERPRINT_PATH: &str = "M 347.25 181.1 Q 347.25 147.05 334.2 115.65 321.15 84.2 297.1 60.15 273.05 36.05 241.6 23 210.15 10 176.15 9.95 174.897265625 9.9517578125 173.65 9.95 172.40078125 9.9517578125 171.15 9.95 137.1 10 105.65 23 74.25 36.05 50.2 60.15 26.1 84.2 13.1 115.65 0.05 147.05 0 181.1 0.0033203125 182.2296875 0 183.35 0.001953125 184.7263671875 0 186.1 0.05 203.45 4.5 220.25 8.9 237.1 17.4 252.25 25.9 267.4 37.9 279.95 49.95 292.5 64.75 301.65 L 79.75 310.85 79.75 418.7 Q 79.75 420.75 81.2 422.2 82.7 423.65 84.75 423.65 L 242.6 423.65 Q 244.65 423.65 246.1 422.2 247.6 420.75 247.6 418.7 L 247.6 377.15 295.75 377.15 Q 300.7 377.15 305.3 375.25 309.85 373.35 313.4 369.85 316.9 366.35 318.8 361.75 320.7 357.2 320.7 352.25 L 320.7 304.05 351.1 304.05 Q 355.5 304.05 359.45 302.05 363.4 300 365.95 296.45 368.5 292.85 369.2 288.5 369.5890625 285.8658203125 369.2 283.3 369.8205078125 279.015625 368.4 274.95 L 347.25 212.2 347.25 181.1 M 332.3 218 Q 332.3 218.85 332.55 219.6 L 353.95 283.1 Q 353.980859375 283.1904296875 354 283.25 353.620703125 284.544140625 352.85 285.65 351.7 287.25 349.9 288.2 348.2853515625 289.007421875 346.5 289.05 L 310.7 289.05 Q 308.65 289.1 307.15 290.55 305.75 292 305.7 294.05 L 305.7 347.55 Q 305.6390625 350.3458984375 304.55 352.95 303.4 355.7 301.35 357.8 299.25 359.9 296.5 361.05 293.8935546875 362.1400390625 291.05 362.2 L 237.6 362.2 Q 235.55 362.2 234.05 363.65 232.6 365.1 232.6 367.2 L 232.6 408.7 94.75 408.7 94.75 303.05 Q 94.75 301.75 94.1 300.65 93.45 299.5 92.35 298.8 L 74.95 288.15 Q 61.25 279.65 50.1 268.05 38.95 256.45 31.1 242.4 23.2 228.35 19.1 212.75 15.2994140625 198.1578125 14.95 183.05 15.5302734375 152.651171875 27.25 124.4 39.5 94.8 62.2 72.15 84.85 49.45 114.45 37.2 142.941796875 25.38046875 173.65 24.9 204.35625 25.38046875 232.8 37.2 262.45 49.45 285.1 72.15 307.75 94.8 320.05 124.4 331.76171875 152.7470703125 332.3 183.3 L 332.3 218 M 234.25 188.1 Q 234.25 186.15 232.9 184.75 231.5 183.4 229.6 183.35 L 229.25 183.35 Q 227.8 183.45 226.65 184.35 L 176.7 222.2 126.8 184.3 Q 125.9 183.6 124.75 183.4 123.65 183.2 122.55 183.5 121.45 183.85 120.6 184.65 119.8 185.4 119.4 186.5 119.05 187.6 119.2 188.7 119.4 189.85 120.05 190.8 L 172.85 266.35 Q 173.5 267.3 174.55 267.8 175.55 268.35 176.7 268.35 177.85 268.35 178.9 267.8 179.95 267.3 180.6 266.35 L 233.35 190.85 Q 234.25 189.65 234.25 188.1 M 174.4 77.35 Q 173.3 77.95 172.65 79.05 L 123.9 160.15 Q 123 161.75 123.3 163.5 123.65 165.25 125.05 166.35 L 173.85 203.95 Q 175.1 204.95 176.7 204.95 178.3 204.95 179.6 203.95 L 228.35 166.35 Q 229.8 165.25 230.1 163.5 230.45 161.75 229.55 160.15 L 180.75 79.05 Q 180.1 77.95 179.05 77.35 177.95 76.75 176.7 76.75 175.45 76.75 174.4 77.35 M 176.75 136.45 Q 177.6 136.45 178.4 136.8 L 219.8 155.55 Q 221.35 156.25 221.9 157.85 222.5 159.4 221.8 160.95 221.15 162.45 219.55 163.05 217.95 163.65 216.45 162.95 L 178.2 145.65 Q 177.5 145.3 176.7 145.3 175.95 145.3 175.25 145.65 L 137 162.95 Q 135.5 163.65 133.85 163.1 132.3 162.5 131.6 160.95 130.9 159.4 131.5 157.85 132.1 156.25 133.65 155.55 L 175.05 136.8 Q 175.85 136.45 176.75 136.45 Z";

/// Truncate an address to `0x` + first 4 + `…` + last 4 hex chars (e.g. `0xf39F…2266`).
pub fn truncate_addr(a: &AlloyAddr) -> String {
    let full: String = a.as_slice().iter().map(|b| format!("{b:02x}")).collect();
    format!("0x{}…{}", &full[..4], &full[full.len() - 4..])
}

fn hex_addr(a: &AlloyAddr) -> String {
    a.as_slice().iter().map(|b| format!("{b:02x}")).collect()
}

/// XML-escape interpolated text so the SVG/JSON stays well-formed even for hostile inputs.
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

/// JSON-escape a string value (the metadata document is hand-built to keep the image inline cheaply).
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            _ => out.push(c),
        }
    }
    out
}

/// Format a unix second as a short `MMM D, YYYY` UTC label (e.g. `Jun 20, 2024`). Pure integer
/// civil-date math (no chrono dep) so it stays deterministic and self-contained. `0` renders as `—`.
fn fmt_date(unix: u64) -> String {
    if unix == 0 {
        return "—".to_string();
    }
    let days = (unix / 86_400) as i64;
    let (y, m, d) = civil_from_days(days);
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let mon = MONTHS[(m - 1) as usize];
    format!("{mon} {d}, {y}")
}

/// Howard Hinnant's days→civil-date algorithm (proleptic Gregorian), integer-only.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// The read-time values the PoH card needs, derived from a verified [`ubi2_runtime::Human`].
pub struct CardData {
    pub address: AlloyAddr,
    pub status: HumanStatus,
    pub verified_at: u64,
    pub vouches: usize,
    pub reputation: i64,
}

/// Render the PoH SVG card (viewBox `0 0 500 500`): a dark card with the gradient-filled fingerprint
/// mark, "Proof of Humanity", "Verified human", the short address, verified date, vouch count and
/// reputation. Pure string-templating; all interpolated text is XML-escaped.
pub fn render_svg(card: &CardData) -> String {
    let short = xml_escape(&truncate_addr(&card.address));
    let verified = xml_escape(&fmt_date(card.verified_at));
    let vouches = card.vouches;
    let reputation = card.reputation;

    format!(
        r##"<svg width="100%" viewBox="0 0 500 500" role="img" xmlns="http://www.w3.org/2000/svg"><title>Proof of Humanity</title><desc>Verified human {short}, verified {verified}, {vouches} vouches, reputation {reputation}.</desc>
<defs><linearGradient id="poh" gradientUnits="userSpaceOnUse" x1="190" y1="70" x2="310" y2="250"><stop offset="0%" stop-color="#FFFF00"/><stop offset="100%" stop-color="#FF6699"/></linearGradient></defs>
<rect x="0" y="0" width="500" height="500" rx="28" fill="#0b0b0f" stroke="#2a2a36"/>
<g transform="translate(186,52) scale(0.34)"><path fill="url(#poh)" stroke="none" d="{FINGERPRINT_PATH}"/></g>
<text x="250" y="232" text-anchor="middle" font-family="ui-sans-serif,system-ui,sans-serif" font-size="30" font-weight="700" fill="#ffffff">Proof of Humanity</text>
<g transform="translate(250,262)"><rect x="-78" y="-16" width="156" height="30" rx="15" fill="#0d2419" stroke="#009966"/><circle cx="-58" cy="-1" r="4" fill="#009966"/><text x="6" y="4" text-anchor="middle" font-family="ui-sans-serif,system-ui,sans-serif" font-size="14" font-weight="600" fill="#34d399">Verified human</text></g>
<text x="250" y="316" text-anchor="middle" font-family="ui-monospace,Menlo,monospace" font-size="18" fill="#e8e8ec">{short}</text>
<line x1="60" y1="350" x2="440" y2="350" stroke="#1b1b24"/>
<text x="78" y="384" font-size="12" fill="#6f6f78" font-family="ui-sans-serif,system-ui,sans-serif">Verified since</text><text x="78" y="406" font-size="15" fill="#e8e8ec" font-family="ui-sans-serif,system-ui,sans-serif">{verified}</text>
<text x="250" y="384" text-anchor="middle" font-size="12" fill="#6f6f78" font-family="ui-sans-serif,system-ui,sans-serif">Vouches</text><text x="250" y="406" text-anchor="middle" font-size="15" fill="#e8e8ec" font-family="ui-monospace,Menlo,monospace">{vouches}</text>
<text x="422" y="384" text-anchor="end" font-size="12" fill="#6f6f78" font-family="ui-sans-serif,system-ui,sans-serif">Reputation</text><text x="422" y="406" text-anchor="end" font-size="15" fill="#e8e8ec" font-family="ui-monospace,Menlo,monospace">{reputation}</text>
<line x1="60" y1="440" x2="440" y2="440" stroke="#1b1b24"/>
<text x="78" y="470" font-size="12" fill="#6f6f78" font-family="ui-monospace,Menlo,monospace">soulbound · proof of humanity</text><text x="422" y="470" text-anchor="end" font-size="12" fill="#6f6f78" font-family="ui-sans-serif,system-ui,sans-serif">POH</text></svg>"##
    )
}

/// Build the full `tokenURI` data document for `card`: a `data:application/json;base64,…` whose
/// `image` is the inline base64 SVG and whose `attributes` array carries Status / Verified since /
/// Vouches / Reputation. Fully on-chain.
pub fn render_token_uri(card: &CardData) -> String {
    let svg = render_svg(card);
    let svg_b64 = B64.encode(svg.as_bytes());
    let image = format!("data:image/svg+xml;base64,{svg_b64}");

    let full = format!("0x{}", hex_addr(&card.address));
    let short = truncate_addr(&card.address);
    let verified = fmt_date(card.verified_at);

    let name = format!("Proof of Humanity — {short}");
    let description = format!(
        "A soulbound Proof of Humanity token for the verified human {full}. One token per verified, \
         unique human. Fully on-chain on UBI."
    );

    let json = format!(
        r#"{{"name":"{name}","description":"{description}","image":"{image}","attributes":[{{"trait_type":"Status","value":"Verified"}},{{"trait_type":"Address","value":"{addr}"}},{{"display_type":"date","trait_type":"Verified since","value":{verified_at}}},{{"trait_type":"Verified date","value":"{verified}"}},{{"trait_type":"Vouches","value":{vouches}}},{{"trait_type":"Reputation","value":{reputation}}}]}}"#,
        name = json_escape(&name),
        description = json_escape(&description),
        image = image, // base64, no escaping needed
        addr = json_escape(&full),
        verified_at = card.verified_at,
        verified = json_escape(&verified),
        vouches = card.vouches,
        reputation = card.reputation,
    );

    let json_b64 = B64.encode(json.as_bytes());
    format!("data:application/json;base64,{json_b64}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::keccak256;

    fn card(addr: AlloyAddr) -> CardData {
        CardData {
            address: addr,
            status: HumanStatus::Verified,
            verified_at: 1_700_000_000,
            vouches: 2,
            reputation: 7,
        }
    }

    #[test]
    fn selectors_match_solidity() {
        use alloy_sol_types::SolCall;
        assert_eq!(&ownerOfCall::SELECTOR, &keccak256(b"ownerOf(uint256)")[..4]);
        assert_eq!(
            &balanceOfCall::SELECTOR,
            &keccak256(b"balanceOf(address)")[..4]
        );
        assert_eq!(
            &tokenURICall::SELECTOR,
            &keccak256(b"tokenURI(uint256)")[..4]
        );
        assert_eq!(
            &transferFromCall::SELECTOR,
            &keccak256(b"transferFrom(address,address,uint256)")[..4]
        );
    }

    #[test]
    fn token_id_is_address_as_uint160_roundtrip() {
        let a = AlloyAddr::from([0xf3; 20]);
        let id = token_id_of(&a);
        // The id is exactly the address zero-extended (no high bits).
        assert_eq!(id >> 160, U256::ZERO);
        assert_eq!(addr_of_token_id(id), Some(a));
        // An id with bits above 160 is not a valid token.
        let stray = id | (U256::from(1u8) << 200);
        assert_eq!(addr_of_token_id(stray), None);
        // The zero address maps to token id 0.
        assert_eq!(token_id_of(&AlloyAddr::ZERO), U256::ZERO);
    }

    #[test]
    fn svg_contains_brand_and_live_values() {
        let svg = render_svg(&card(AlloyAddr::from([0xf3; 20])));
        assert!(svg.starts_with("<svg") && svg.ends_with("</svg>"));
        assert!(svg.contains("Proof of Humanity"));
        assert!(svg.contains("Verified human"));
        assert!(svg.contains("0xf3f3…f3f3"));
        // The PoH gradient stops are present.
        assert!(svg.contains("#FFFF00") && svg.contains("#FF6699"));
        // The fingerprint mark path is embedded with the gradient fill.
        assert!(svg.contains("url(#poh)"));
        assert!(svg.contains("M 347.25 181.1"));
    }

    #[test]
    fn token_uri_decodes_to_json_with_image_svg_and_brand() {
        let uri = render_token_uri(&card(AlloyAddr::from([0xab; 20])));
        let b64 = uri.strip_prefix("data:application/json;base64,").unwrap();
        let json = String::from_utf8(B64.decode(b64).unwrap()).unwrap();
        assert!(json.contains("Proof of Humanity"));
        assert!(json.contains("0xabababababababababababababababababababab"));
        assert!(json.contains("\"attributes\":["));
        assert!(json.contains("\"Verified\""));
        // The image is an inline base64 SVG carrying the fingerprint mark.
        let img_marker = "\"image\":\"data:image/svg+xml;base64,";
        let start = json.find(img_marker).unwrap() + img_marker.len();
        let rest = &json[start..];
        let end = rest.find('"').unwrap();
        let svg = String::from_utf8(B64.decode(&rest[..end]).unwrap()).unwrap();
        assert!(svg.starts_with("<svg") && svg.contains("Proof of Humanity"));
    }
}
