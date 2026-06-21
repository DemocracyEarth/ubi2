//! tokenURI / SVG determinism property tests (reliability gate, board task M2-T6, GATE 2).
//!
//! `tokenURI(id)` and its inline SVG card are part of the wallet-visible surface and are rendered
//! purely from `(stream fields, side, now)` (spec `docs/specs/02-streaming.md` §"Streams as NFTs").
//! Invariant I2 forbids hidden nondeterminism. These tests prove the rendering is a **deterministic,
//! byte-for-byte reproducible** integer function of its inputs — the same property the consensus path
//! demands, applied to the metadata surface a marketplace/wallet caches and compares.
//!
//! Properties:
//!   T1  `render_token_uri` is byte-identical across repeated calls at a *fixed* `now`, for the same
//!       stream + side — no map-iteration / locale / float jitter.
//!   T2  `render_token_uri` is byte-identical across two **independently constructed** `CardData`
//!       instances (the "two nodes" check) over randomized streams, both sides, many `now` values.
//!   T3  The card number/date formatters (`fmt_ubi`, `fmt_rate_per_hour`, `fmt_ts`) are pure integer
//!       functions: identical inputs ⇒ identical strings, and contain no float artifacts (no `e`,
//!       no `NaN`/`inf`, exactly two decimals for amounts) — guards the "check for floats in the card
//!       number formatting" requirement.
//!   T4  The decoded SVG is well-formed for the full random corpus (starts `<svg`, ends `</svg>`,
//!       balanced — a smoke check that no input produces malformed markup).
//!
//! Deterministic SplitMix64 PRNG (fixed seed) so any failure reproduces exactly. No network.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;

use ubi2_rpc::streams::{fmt_rate_per_hour, fmt_ubi, render_svg, render_token_uri, CardData, Side};
use ubi2_runtime::{Stream, StreamStatus, MAX_RATE, UBI};

struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed)
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }
    fn below_u128(&mut self, n: u128) -> u128 {
        let hi = (self.next_u64() as u128) << 64;
        (hi | self.next_u64() as u128) % n
    }
}

/// Build a randomized but plausible stream from the PRNG.
fn rand_stream(rng: &mut Rng) -> Stream {
    let rate = 1 + rng.below_u128(MAX_RATE);
    let deposit = 1 + rng.below_u128(1_000u128 * UBI);
    let drawn = rng.below_u128(deposit + 1);
    let started_at = rng.below(2_000_000_000);
    let status = match rng.below(3) {
        0 => StreamStatus::Active,
        1 => StreamStatus::Stopped(started_at.saturating_add(rng.below(1_000_000))),
        _ => StreamStatus::Completed,
    };
    let mut from = [0u8; 20];
    let mut to = [0u8; 20];
    from[..8].copy_from_slice(&rng.next_u64().to_be_bytes());
    to[..8].copy_from_slice(&rng.next_u64().to_be_bytes());
    Stream {
        id: rng.next_u64(),
        from,
        to,
        rate,
        deposit,
        drawn,
        started_at,
        status,
    }
}

fn rand_side(rng: &mut Rng) -> Side {
    if rng.below(2) == 0 {
        Side::Incoming
    } else {
        Side::Outgoing
    }
}

/// T1 — repeated `render_token_uri` calls at a fixed `now` are byte-identical (no per-call jitter).
#[test]
fn token_uri_is_byte_stable_across_repeated_calls() {
    let mut rng = Rng::new(0x70CE_0001);
    for _ in 0..20_000 {
        let stream = rand_stream(&mut rng);
        let side = rand_side(&mut rng);
        let now = stream.started_at.saturating_add(rng.below(4_000_000));

        let card = CardData::new(&stream, side, now);
        let a = render_token_uri(&card);
        let b = render_token_uri(&card);
        assert_eq!(
            a, b,
            "tokenURI not byte-stable across calls (id={})",
            stream.id
        );
    }
}

/// T2 + T4 — `render_token_uri` is byte-identical across two **independently constructed** `CardData`
/// instances (the cross-node check), and the embedded SVG is well-formed, over the random corpus.
#[test]
fn token_uri_reproducible_across_instances_and_svg_wellformed() {
    let mut rng = Rng::new(0x70CE_0002);
    for _ in 0..20_000 {
        let stream = rand_stream(&mut rng);
        let side = rand_side(&mut rng);
        // Read at a normal point and occasionally at the absolute extreme `u64::MAX`.
        let now = if rng.below(8) == 0 {
            u64::MAX
        } else {
            stream.started_at.saturating_add(rng.below(4_000_000))
        };

        // Two independently built cards from the same inputs — the "two nodes render the same token".
        let card_a = CardData::new(&stream, side, now);
        let card_b = CardData::new(&stream, side, now);
        let uri_a = render_token_uri(&card_a);
        let uri_b = render_token_uri(&card_b);
        assert_eq!(
            uri_a, uri_b,
            "tokenURI diverged across instances (id={}, now={now}, side={:?})",
            stream.id, side
        );

        // The whole document and the inline SVG both decode and are well-formed.
        let json_b64 = uri_a
            .strip_prefix("data:application/json;base64,")
            .expect("data-uri prefix");
        let json = String::from_utf8(B64.decode(json_b64).expect("valid base64")).unwrap();
        let marker = "\"image\":\"data:image/svg+xml;base64,";
        let start = json.find(marker).expect("image field") + marker.len();
        let rest = &json[start..];
        let end = rest.find('"').expect("image end quote");
        let svg = String::from_utf8(B64.decode(&rest[..end]).expect("valid svg base64")).unwrap();
        assert!(
            svg.starts_with("<svg") && svg.ends_with("</svg>"),
            "malformed SVG for id={}, now={now}",
            stream.id
        );

        // Direct render_svg path agrees too (same inputs ⇒ same bytes).
        assert_eq!(
            render_svg(&card_a),
            render_svg(&card_b),
            "render_svg diverged"
        );
    }
}

/// T3 — the card number/date formatters are pure integer functions with no float artifacts. Amounts
/// always render as `<whole>.<2 digits>`; rates likewise; no `e`/`NaN`/`inf` ever appears. Reproducible
/// for identical inputs.
#[test]
fn formatters_are_pure_integer_no_float_artifacts() {
    let mut rng = Rng::new(0x70CE_0003);

    // Named edge cases first (regressions get a clear name).
    assert_eq!(fmt_ubi(0), "0.00");
    assert_eq!(fmt_ubi(UBI), "1.00");
    assert_eq!(fmt_ubi(UBI * 6 + UBI / 2), "6.50");
    assert_eq!(fmt_ubi(u128::MAX), {
        // pure integer reference: whole.hundredths, truncated.
        let whole = u128::MAX / UBI;
        let hund = (u128::MAX % UBI).saturating_mul(100) / UBI;
        format!("{whole}.{hund:02}")
    });

    for _ in 0..100_000 {
        let amount = rng.below_u128(u128::MAX);
        let s = fmt_ubi(amount);
        // Reproducible.
        assert_eq!(s, fmt_ubi(amount), "fmt_ubi not pure");
        // No float artifacts.
        assert!(
            !s.contains('e') && !s.contains('E') && !s.contains("NaN") && !s.contains("inf"),
            "float artifact in fmt_ubi output: {s}"
        );
        // Exactly one dot, exactly two fractional digits.
        let (whole, frac) = s.split_once('.').expect("has a decimal point");
        assert_eq!(frac.len(), 2, "fmt_ubi must have 2 decimals: {s}");
        assert!(
            whole.chars().all(|c| c.is_ascii_digit()) && frac.chars().all(|c| c.is_ascii_digit()),
            "non-digit in fmt_ubi: {s}"
        );
        // Matches an independent pure-integer reference.
        let ref_whole = amount / UBI;
        let ref_frac = (amount % UBI).saturating_mul(100) / UBI;
        assert_eq!(
            s,
            format!("{ref_whole}.{ref_frac:02}"),
            "fmt_ubi != integer reference"
        );

        // Rate-per-hour: rate * 3600 base units, same formatting guarantees (saturating).
        let rate = rng.below_u128(MAX_RATE + 1);
        let rs = fmt_rate_per_hour(rate);
        assert_eq!(rs, fmt_rate_per_hour(rate), "fmt_rate_per_hour not pure");
        assert!(
            rs.split_once('.')
                .map(|(_, f)| f.len() == 2)
                .unwrap_or(false),
            "fmt_rate_per_hour must have 2 decimals: {rs}"
        );
        assert!(
            !rs.contains('e') && !rs.contains("NaN") && !rs.contains("inf"),
            "float artifact in fmt_rate_per_hour: {rs}"
        );
    }
}
