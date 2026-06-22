//! M2 streaming: StreamHub calldata ABI, the ERC-721 view precompile, and the on-chain SVG card.
//!
//! Spec: `docs/specs/02-streaming.md` (D2, D4, "RPC surface", "Streams as NFTs"). This module is the
//! pure (state-free) ABI + rendering layer; the stateful dispatch (recovering the signer, calling the
//! runtime ops, reading state for `ownerOf`/`balanceOf`/`tokenURI`) lives in `lib.rs` and calls into
//! the helpers here.
//!
//! ## The two-token scheme (D4)
//! Each stream mints **two** soulbound ERC-721 tokens against the StreamHub collection:
//!   * recipient token — `tokenId == streamId`, owner `to`;
//!   * sender receipt   — `tokenId == streamId | SENDER_FLAG` (top bit), owner `from`.
//!
//! `ownerOf`/`tokenURI` decode the flag with [`decode_token_id`]; `balanceOf` counts both sides.

use alloy_primitives::{Address as AlloyAddr, U256};
use alloy_sol_types::{sol, SolCall, SolValue};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;

use ubi2_runtime::{Stream, StreamId, StreamStatus, EMISSION_PERIOD_SECS, UBI};

/// The reserved StreamHub system address (`0x…5742`) — spec D2. Stream ops are EVM txs to it, and it
/// doubles as the ERC-721 collection "ubi2 Streams" (D4).
pub const STREAM_HUB: AlloyAddr = AlloyAddr::new([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x57, 0x42,
]);

/// Top bit of the 256-bit tokenId: set ⇒ the **sender receipt** of stream `tokenId & !SENDER_FLAG`;
/// clear ⇒ the **recipient token** of stream `tokenId`. Spec D4.
pub fn sender_flag() -> U256 {
    U256::from(1u8) << 255
}

/// Which side of a stream a token represents (drives the card badge + the owner).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    /// Recipient token (`tokenId == streamId`) — the "Incoming" claim, owner `to`.
    Incoming,
    /// Sender receipt (`tokenId == streamId | SENDER_FLAG`) — the "Outgoing" record, owner `from`.
    Outgoing,
}

impl Side {
    /// The badge text rendered on the card and used as the `side` substitution.
    pub fn badge(self) -> &'static str {
        match self {
            Side::Incoming => "Incoming",
            Side::Outgoing => "Outgoing",
        }
    }
}

/// Decode a 256-bit tokenId into `(streamId, side)`. The high bit selects the side; the low 64 bits
/// are the stream id. Returns `None` if any bits between bit 64 and bit 254 are set (no such token)
/// or the stream id doesn't fit u64. Pure + deterministic (D4 — ownership is stateless).
pub fn decode_token_id(token_id: U256) -> Option<(StreamId, Side)> {
    let flag = sender_flag();
    let is_sender = (token_id & flag) != U256::ZERO;
    let bare = token_id & !flag; // strip the side flag
                                 // The remaining value must be a clean u64 stream id (no stray high bits).
    if bare > U256::from(u64::MAX) {
        return None;
    }
    let id: u64 = bare.to::<u64>();
    Some((
        id,
        if is_sender {
            Side::Outgoing
        } else {
            Side::Incoming
        },
    ))
}

/// Encode `(streamId, side)` back into the 256-bit tokenId (inverse of [`decode_token_id`]).
pub fn encode_token_id(id: StreamId, side: Side) -> U256 {
    let base = U256::from(id);
    match side {
        Side::Incoming => base,
        Side::Outgoing => base | sender_flag(),
    }
}

// ---------------------------------------------------------------------------------------------
// ABI: StreamHub calldata (writes) + ERC-721 views (reads). `sol!` derives the 4-byte selectors.
// ---------------------------------------------------------------------------------------------

sol! {
    /// StreamHub ops (write, via `eth_sendRawTransaction`) + ERC-721 metadata views (read, via
    /// `eth_call`). Solidity-style signatures so MetaMask / viem / ethers encode them identically.
    interface IStreamHub {
        // --- writes (calldata to StreamHub) ---
        function openStream(address to, uint256 ratePerSec, uint256 deposit) external returns (uint256 id);
        function stopStream(uint256 id) external;

        // --- ERC-165 / ERC-721 / ERC-721 Metadata (read, eth_call) ---
        function supportsInterface(bytes4 interfaceId) external view returns (bool);
        function name() external view returns (string);
        function symbol() external view returns (string);
        function balanceOf(address owner) external view returns (uint256);
        function ownerOf(uint256 tokenId) external view returns (address);
        function tokenURI(uint256 tokenId) external view returns (string);

        // --- soulbound: these MUST revert (no transfer/approve state in M2, spec D4) ---
        function transferFrom(address from, address to, uint256 tokenId) external;
        function safeTransferFrom(address from, address to, uint256 tokenId) external;
        function approve(address to, uint256 tokenId) external;
        function setApprovalForAll(address operator, bool approved) external;
    }
}

/// Re-export the generated call types so `lib.rs` can match on selectors without re-deriving them.
pub use IStreamHub::{
    approveCall, balanceOfCall, nameCall, openStreamCall, ownerOfCall, safeTransferFromCall,
    setApprovalForAllCall, stopStreamCall, supportsInterfaceCall, symbolCall, tokenURICall,
    transferFromCall,
};

/// A decoded StreamHub *write* op, parsed from a tx's calldata (spec D2). The signer (recovered from
/// the tx) is supplied separately as `from`/`caller` by the dispatcher.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StreamOp {
    /// `openStream(to, ratePerSec, deposit)` — open a stream from the tx signer to `to`.
    Open {
        to: AlloyAddr,
        rate: u128,
        deposit: u128,
    },
    /// `stopStream(id)` — stop the stream (only the signer-as-sender may, enforced in the runtime).
    Stop { id: StreamId },
}

/// Why a StreamHub calldata blob could not be turned into a [`StreamOp`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CalldataError {
    /// Calldata shorter than a 4-byte selector.
    TooShort,
    /// Selector did not match any known StreamHub write op.
    UnknownSelector([u8; 4]),
    /// Selector matched but the argument tail failed to ABI-decode.
    BadArgs(String),
    /// A `uint256` argument exceeded the runtime's `u128` base-unit range.
    Overflow(&'static str),
    /// A soulbound transfer/approve selector was sent as a write tx — must revert ("soulbound").
    Soulbound,
}

impl std::fmt::Display for CalldataError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CalldataError::TooShort => write!(f, "calldata too short for a selector"),
            CalldataError::UnknownSelector(s) => {
                write!(f, "unknown StreamHub selector 0x{}", hex4(s))
            }
            CalldataError::BadArgs(e) => write!(f, "bad StreamHub calldata args: {e}"),
            CalldataError::Overflow(which) => {
                write!(f, "{which} exceeds u128 base-unit range")
            }
            CalldataError::Soulbound => write!(f, "soulbound"),
        }
    }
}

fn hex4(s: &[u8; 4]) -> String {
    s.iter().map(|b| format!("{b:02x}")).collect()
}

/// Try to decode a u256 ABI arg into the runtime's `u128` base unit, naming the field on overflow.
fn u256_to_u128(v: U256, which: &'static str) -> Result<u128, CalldataError> {
    v.try_into().map_err(|_| CalldataError::Overflow(which))
}

/// Parse StreamHub calldata (selector + ABI args) into a [`StreamOp`]. Soulbound transfer/approve
/// selectors return [`CalldataError::Soulbound`] so the tx reverts (spec D4). Unknown selectors and
/// malformed args are surfaced distinctly so the RPC can return a precise error.
pub fn parse_calldata(data: &[u8]) -> Result<StreamOp, CalldataError> {
    if data.len() < 4 {
        return Err(CalldataError::TooShort);
    }
    let selector: [u8; 4] = [data[0], data[1], data[2], data[3]];

    match selector {
        s if s == openStreamCall::SELECTOR => {
            let call = openStreamCall::abi_decode(data, true)
                .map_err(|e| CalldataError::BadArgs(e.to_string()))?;
            Ok(StreamOp::Open {
                to: call.to,
                rate: u256_to_u128(call.ratePerSec, "ratePerSec")?,
                deposit: u256_to_u128(call.deposit, "deposit")?,
            })
        }
        s if s == stopStreamCall::SELECTOR => {
            let call = stopStreamCall::abi_decode(data, true)
                .map_err(|e| CalldataError::BadArgs(e.to_string()))?;
            // tokenId-space ids are u64 in the runtime; reject ids that don't fit.
            if call.id > U256::from(u64::MAX) {
                return Err(CalldataError::Overflow("stream id"));
            }
            Ok(StreamOp::Stop {
                id: call.id.to::<u64>(),
            })
        }
        // Soulbound: any transfer/approve selector to StreamHub reverts (D4).
        s if s == transferFromCall::SELECTOR
            || s == safeTransferFromCall::SELECTOR
            || s == approveCall::SELECTOR
            || s == setApprovalForAllCall::SELECTOR =>
        {
            Err(CalldataError::Soulbound)
        }
        other => Err(CalldataError::UnknownSelector(other)),
    }
}

// ---------------------------------------------------------------------------------------------
// ERC-721 view encoding (eth_call returns). All return the ABI-encoded result bytes.
// ---------------------------------------------------------------------------------------------

/// The ERC-165/721/721-Metadata interface ids `supportsInterface` answers `true` for (spec D4).
pub const IFACE_ERC165: [u8; 4] = [0x01, 0xff, 0xc9, 0xa7];
pub const IFACE_ERC721: [u8; 4] = [0x80, 0xac, 0x58, 0xcd];
pub const IFACE_ERC721_METADATA: [u8; 4] = [0x5b, 0x5e, 0x13, 0x9f];

/// ABI-encode a `string` return value (the lone tuple element).
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
// On-chain card: tokenURI document + the SVG (spec "Streams as NFTs").
// ---------------------------------------------------------------------------------------------

/// ubi2 palette + status colors (spec). Centralized so the card and any future surface agree.
struct StatusColors {
    fg: &'static str,
    bg: &'static str,
    stroke: &'static str,
    label: &'static str,
}

fn status_colors(status: StreamStatus) -> StatusColors {
    match status {
        StreamStatus::Active => StatusColors {
            fg: "#6ee7b7",
            bg: "#11271d",
            stroke: "#2f6f57",
            label: "Active",
        },
        StreamStatus::Stopped(_) => StatusColors {
            fg: "#fbbf24",
            bg: "#2a210b",
            stroke: "#7a5a12",
            label: "Stopped",
        },
        StreamStatus::Completed => StatusColors {
            fg: "#9a9aa6",
            bg: "#1b1b24",
            stroke: "#2a2a36",
            label: "Completed",
        },
    }
}

/// Truncate an address to `0x` + first 4 + `…` + last 4 hex chars (e.g. `0xf39F…2266`).
pub fn truncate_addr(a: &AlloyAddr) -> String {
    let full: String = a.as_slice().iter().map(|b| format!("{b:02x}")).collect();
    format!("0x{}…{}", &full[..4], &full[full.len() - 4..])
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

/// Render a `u128` base-unit amount as a fixed-2-decimal UBI string (e.g. `6.50`). Integer math only:
/// `whole.frac` where `frac` is the first two decimal digits (hundredths of a UBI), truncated.
pub fn fmt_ubi(amount: u128) -> String {
    let whole = amount / UBI;
    // hundredths = (amount % UBI) * 100 / UBI
    let hundredths = (amount % UBI).saturating_mul(100) / UBI;
    format!("{whole}.{hundredths:02}")
}

/// Render the per-second `rate` as a UBI/hour string (`rate * 3600` base units, 2 decimals).
pub fn fmt_rate_per_hour(rate: u128) -> String {
    fmt_ubi(rate.saturating_mul(EMISSION_PERIOD_SECS as u128))
}

/// Progress percent `drawn_or_accrued / deposit` as an integer 0..=100 (saturating, deposit>0).
fn pct(streamed: u128, deposit: u128) -> u64 {
    if deposit == 0 {
        return 0;
    }
    let p = streamed.saturating_mul(100) / deposit;
    p.min(100) as u64
}

/// Format a unix second as a short `MMM D · HH:MM` UTC label (e.g. `Jun 20 · 14:05`). Pure integer
/// civil-date math (no chrono dep) so it stays deterministic and self-contained. `started_at == 0`
/// or a `None`/unreachable end renders as the caller-provided fallback.
fn fmt_ts(unix: u64) -> String {
    // days since 1970-01-01 + seconds within the day.
    let days = (unix / 86_400) as i64;
    let secs_of_day = unix % 86_400;
    let hh = secs_of_day / 3_600;
    let mm = (secs_of_day % 3_600) / 60;
    let (y, m, d) = civil_from_days(days);
    let _ = y; // year omitted from the short label by design (MMM D · HH:MM)
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let mon = MONTHS[(m - 1) as usize];
    format!("{mon} {d} · {hh:02}:{mm:02}")
}

/// Howard Hinnant's days→civil-date algorithm (proleptic Gregorian), integer-only.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// All the read-time values the card needs, derived from a [`Stream`] at `now`. The "streamed"
/// amount is the gross accrued-so-far (`accrued(now)`, capped at deposit), which is what both parties
/// should see ticking — not just the already-settled `drawn`.
pub struct CardData {
    pub id: StreamId,
    pub from: AlloyAddr,
    pub to: AlloyAddr,
    pub rate: u128,
    pub deposit: u128,
    pub streamed: u128,
    pub status: StreamStatus,
    pub started_at: u64,
    pub t_end: u64,
    pub side: Side,
}

impl CardData {
    /// Build the card values for `stream` viewed from `side` at wall-clock `now`.
    pub fn new(stream: &Stream, side: Side, now: u64) -> Self {
        CardData {
            id: stream.id,
            from: AlloyAddr::from(stream.from),
            to: AlloyAddr::from(stream.to),
            rate: stream.rate,
            deposit: stream.deposit,
            streamed: stream.accrued(now),
            status: stream.status,
            started_at: stream.started_at,
            t_end: stream.t_end(),
            side,
        }
    }
}

/// Render the approved 500×500 SVG card (viewBox `0 0 680 540`) for `card`. Pure string-templating of
/// the team's reference markup with live values, the side badge, and the integer progress-bar width
/// `round(pct/100 * 432)`. All interpolated text is XML-escaped.
pub fn render_svg(card: &CardData) -> String {
    let sc = status_colors(card.status);
    let id = card.id;
    let side = card.side.badge();
    let from = xml_escape(&truncate_addr(&card.from));
    let to = xml_escape(&truncate_addr(&card.to));
    let rate = xml_escape(&fmt_rate_per_hour(card.rate));
    let streamed = xml_escape(&fmt_ubi(card.streamed));
    let deposit = xml_escape(&fmt_ubi(card.deposit));
    let pct = pct(card.streamed, card.deposit);
    // progress-bar fill width: round(pct/100 * 432) with integer rounding.
    let bar_w = (pct * 432 + 50) / 100;
    let status = sc.label;
    let status_fg = sc.fg;
    let status_bg = sc.bg;
    let status_stroke = sc.stroke;

    // Started: short UTC stamp (or "—" if unset). Ends: the drain instant for an Active stream; for a
    // Stopped stream the stop instant; "ran dry" once Completed; "—" if it never had a finite end.
    let started = if card.started_at == 0 {
        "—".to_string()
    } else {
        xml_escape(&fmt_ts(card.started_at))
    };
    let ends = match card.status {
        StreamStatus::Completed => "ran dry".to_string(),
        StreamStatus::Stopped(at) => xml_escape(&fmt_ts(at)),
        StreamStatus::Active => {
            if card.t_end == 0 || card.t_end < card.started_at {
                "—".to_string()
            } else {
                xml_escape(&fmt_ts(card.t_end))
            }
        }
    };

    format!(
        r##"<svg width="100%" viewBox="0 0 680 540" role="img" xmlns="http://www.w3.org/2000/svg"><title>UBI stream #{id}</title><desc>{from} to {to}, {rate} UBI/hr, {streamed} of {deposit} UBI, {pct}%, {status}.</desc>
<rect x="90" y="20" width="500" height="500" rx="22" fill="#0b0b0f" stroke="#2a2a36"/>
<text x="124" y="80" font-family="ui-sans-serif,system-ui,sans-serif" font-size="30" font-weight="700" fill="#6ee7b7">UBI</text>
<text x="124" y="102" font-family="ui-monospace,Menlo,monospace" font-size="13" fill="#9a9aa6">stream #{id} · {side}</text>
<rect x="454" y="54" width="102" height="30" rx="15" fill="{status_bg}" stroke="{status_stroke}"/><circle cx="472" cy="69" r="4" fill="{status_fg}"/><text x="484" y="73" font-family="ui-sans-serif,system-ui,sans-serif" font-size="13" font-weight="500" fill="{status_fg}">{status}</text>
<line x1="124" y1="120" x2="556" y2="120" stroke="#1b1b24"/>
<text x="124" y="150" font-size="12" fill="#6f6f78" font-family="ui-sans-serif,system-ui,sans-serif">From</text><text x="124" y="173" font-size="15" fill="#e8e8ec" font-family="ui-monospace,Menlo,monospace">{from}</text>
<text x="556" y="150" text-anchor="end" font-size="12" fill="#6f6f78" font-family="ui-sans-serif,system-ui,sans-serif">To</text><text x="556" y="173" text-anchor="end" font-size="15" fill="#e8e8ec" font-family="ui-monospace,Menlo,monospace">{to}</text>
<line x1="250" y1="202" x2="430" y2="202" stroke="#2f6f57" stroke-width="1.5"/><path d="M424 197 L431 202 L424 207" fill="none" stroke="#6ee7b7" stroke-width="1.5"/>
<text x="124" y="296" font-family="ui-monospace,Menlo,monospace" font-size="46" font-weight="700" fill="#ffffff">{streamed}<tspan dx="10" font-size="22" fill="#6ee7b7">UBI</tspan></text>
<text x="124" y="322" font-size="14" fill="#9a9aa6" font-family="ui-sans-serif,system-ui,sans-serif">of {deposit} UBI streamed</text>
<text x="556" y="322" text-anchor="end" font-size="14" font-weight="500" fill="#6ee7b7" font-family="ui-monospace,Menlo,monospace">{pct}%</text>
<rect x="124" y="338" width="432" height="10" rx="5" fill="#1b1b24"/><rect x="124" y="338" width="{bar_w}" height="10" rx="5" fill="#6ee7b7"/>
<text x="124" y="386" font-size="12" fill="#6f6f78" font-family="ui-sans-serif,system-ui,sans-serif">Rate</text><text x="124" y="408" font-size="14" fill="#e8e8ec" font-family="ui-monospace,Menlo,monospace">{rate} UBI / hr</text>
<text x="312" y="386" font-size="12" fill="#6f6f78" font-family="ui-sans-serif,system-ui,sans-serif">Started</text><text x="312" y="408" font-size="14" fill="#e8e8ec" font-family="ui-monospace,Menlo,monospace">{started}</text>
<text x="556" y="386" text-anchor="end" font-size="12" fill="#6f6f78" font-family="ui-sans-serif,system-ui,sans-serif">Ends</text><text x="556" y="408" text-anchor="end" font-size="14" fill="#e8e8ec" font-family="ui-monospace,Menlo,monospace">{ends}</text>
<line x1="124" y1="442" x2="556" y2="442" stroke="#1b1b24"/>
<text x="124" y="470" font-size="12" fill="#6f6f78" font-family="ui-monospace,Menlo,monospace">real-time stream · chain 21826</text><text x="556" y="470" text-anchor="end" font-size="12" fill="#6f6f78" font-family="ui-sans-serif,system-ui,sans-serif">UBI Streams</text></svg>"##
    )
}

/// Build the full `tokenURI` data document for `card`: a `data:application/json;base64,…` whose
/// `image` is the inline base64 SVG and whose `attributes` array matches the spec. Fully on-chain.
pub fn render_token_uri(card: &CardData) -> String {
    let svg = render_svg(card);
    let svg_b64 = B64.encode(svg.as_bytes());
    let image = format!("data:image/svg+xml;base64,{svg_b64}");

    let from_full = format!("0x{}", hex_addr(&card.from));
    let to_full = format!("0x{}", hex_addr(&card.to));
    let status_label = status_colors(card.status).label;
    let pct = pct(card.streamed, card.deposit);

    // Ends attribute: the finite drain instant if known, else the started instant (best effort).
    let ends_unix = match card.status {
        StreamStatus::Stopped(at) => at,
        _ => card.t_end,
    };

    let name = format!("UBI Stream #{}", card.id);
    let description = format!(
        "A real-time UBI stream from {from_full} to {to_full} at {} UBI/hr. Fully on-chain on UBI.",
        fmt_rate_per_hour(card.rate)
    );

    let json = format!(
        r#"{{"name":"{name}","description":"{description}","image":"{image}","attributes":[{{"trait_type":"Status","value":"{status}"}},{{"trait_type":"Side","value":"{side}"}},{{"trait_type":"From","value":"{from}"}},{{"trait_type":"To","value":"{to}"}},{{"trait_type":"Rate","value":"{rate} UBI/hr"}},{{"trait_type":"Deposit","value":"{deposit} UBI"}},{{"trait_type":"Streamed","value":"{streamed} UBI"}},{{"display_type":"boost_percentage","trait_type":"Progress","value":{pct}}},{{"display_type":"date","trait_type":"Started","value":{started}}},{{"display_type":"date","trait_type":"Ends","value":{ends}}}]}}"#,
        name = json_escape(&name),
        description = json_escape(&description),
        image = image, // base64, no escaping needed
        status = json_escape(status_label),
        side = json_escape(card.side.badge()),
        from = json_escape(&from_full),
        to = json_escape(&to_full),
        rate = json_escape(&fmt_rate_per_hour(card.rate)),
        deposit = json_escape(&fmt_ubi(card.deposit)),
        streamed = json_escape(&fmt_ubi(card.streamed)),
        pct = pct,
        started = card.started_at,
        ends = ends_unix,
    );

    let json_b64 = B64.encode(json.as_bytes());
    format!("data:application/json;base64,{json_b64}")
}

fn hex_addr(a: &AlloyAddr) -> String {
    a.as_slice().iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ubi2_runtime::Stream;

    fn sample_stream(status: StreamStatus) -> Stream {
        Stream {
            id: 7,
            from: [0xf3; 20],
            to: [0xab; 20],
            rate: UBI / EMISSION_PERIOD_SECS as u128, // ~1 UBI/hr
            deposit: 24 * UBI,
            drawn: 0,
            started_at: 1_700_000_000,
            status,
        }
    }

    #[test]
    fn selectors_match_solidity() {
        // openStream(address,uint256,uint256) selector via keccak should match the sol!-derived one.
        use alloy_primitives::keccak256;
        let want = &keccak256(b"openStream(address,uint256,uint256)")[..4];
        assert_eq!(&openStreamCall::SELECTOR, want);
        let want_stop = &keccak256(b"stopStream(uint256)")[..4];
        assert_eq!(&stopStreamCall::SELECTOR, want_stop);
    }

    #[test]
    fn token_id_roundtrip_and_flag() {
        let id = 12345u64;
        let recipient = encode_token_id(id, Side::Incoming);
        let sender = encode_token_id(id, Side::Outgoing);
        assert_eq!(recipient, U256::from(id));
        assert_eq!(sender, U256::from(id) | sender_flag());
        assert_eq!(decode_token_id(recipient), Some((id, Side::Incoming)));
        assert_eq!(decode_token_id(sender), Some((id, Side::Outgoing)));
        // A token id with stray middle bits decodes to None.
        let stray = (U256::from(1u8) << 100) | U256::from(5u8);
        assert_eq!(decode_token_id(stray), None);
    }

    #[test]
    fn parse_open_and_stop_calldata() {
        let to = AlloyAddr::from([0x11; 20]);
        let open = openStreamCall {
            to,
            ratePerSec: U256::from(277_777_777_777_777u128),
            deposit: U256::from(24u128) * U256::from(UBI),
        };
        let data = open.abi_encode();
        let parsed = parse_calldata(&data).unwrap();
        assert_eq!(
            parsed,
            StreamOp::Open {
                to,
                rate: 277_777_777_777_777,
                deposit: 24 * UBI,
            }
        );

        let stop = stopStreamCall {
            id: U256::from(9u8),
        };
        let data = stop.abi_encode();
        assert_eq!(parse_calldata(&data).unwrap(), StreamOp::Stop { id: 9 });
    }

    #[test]
    fn transfer_selectors_are_soulbound() {
        let t = transferFromCall {
            from: AlloyAddr::ZERO,
            to: AlloyAddr::ZERO,
            tokenId: U256::from(1u8),
        };
        assert_eq!(
            parse_calldata(&t.abi_encode()).unwrap_err(),
            CalldataError::Soulbound
        );
        let a = approveCall {
            to: AlloyAddr::ZERO,
            tokenId: U256::from(1u8),
        };
        assert_eq!(
            parse_calldata(&a.abi_encode()).unwrap_err(),
            CalldataError::Soulbound
        );
    }

    #[test]
    fn fmt_helpers() {
        assert_eq!(fmt_ubi(0), "0.00");
        assert_eq!(fmt_ubi(UBI), "1.00");
        assert_eq!(fmt_ubi(UBI * 6 + UBI / 2), "6.50");
        assert_eq!(fmt_ubi(24 * UBI), "24.00");
        // ~1 UBI/hr rate renders as ~1.00 UBI/hr (truncated).
        let r = UBI / EMISSION_PERIOD_SECS as u128;
        assert_eq!(fmt_rate_per_hour(r), "0.99"); // 277777777777777 * 3600 = 0.9999..e18
        assert_eq!(truncate_addr(&AlloyAddr::from([0xf3; 20])), "0xf3f3…f3f3");
    }

    #[test]
    fn svg_contains_live_values_and_status() {
        let card = CardData::new(
            &sample_stream(StreamStatus::Active),
            Side::Incoming,
            1_700_000_000 + 6 * EMISSION_PERIOD_SECS,
        );
        let svg = render_svg(&card);
        assert!(svg.starts_with("<svg"));
        assert!(svg.ends_with("</svg>"));
        assert!(svg.contains("stream #7 · Incoming"));
        assert!(svg.contains("Active"));
        assert!(svg.contains("UBI")); // headline unit
                                      // progress bar fill width present and within track.
        assert!(svg.contains("of 24.00 UBI streamed"));
    }

    #[test]
    fn token_uri_decodes_to_json_with_image_svg() {
        let card = CardData::new(
            &sample_stream(StreamStatus::Active),
            Side::Outgoing,
            1_700_000_000 + 6 * EMISSION_PERIOD_SECS,
        );
        let uri = render_token_uri(&card);
        let b64 = uri.strip_prefix("data:application/json;base64,").unwrap();
        let json = String::from_utf8(B64.decode(b64).unwrap()).unwrap();
        assert!(json.contains("\"name\":\"UBI Stream #7\""));
        assert!(json.contains("\"attributes\":["));
        assert!(json.contains("\"Outgoing\""));
        let img_marker = "\"image\":\"data:image/svg+xml;base64,";
        let start = json.find(img_marker).unwrap() + img_marker.len();
        let rest = &json[start..];
        let end = rest.find('"').unwrap();
        let svg_b64 = &rest[..end];
        let svg = String::from_utf8(B64.decode(svg_b64).unwrap()).unwrap();
        assert!(svg.starts_with("<svg") && svg.contains("</svg>"));
    }
}
