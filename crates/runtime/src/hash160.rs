//! Dependency-free SHA-256 + RIPEMD-160 (Bitcoin `hash160`) — the EC-C7 `user_identifier` binding.
//!
//! The runtime crate pulls **no** crypto crate (ADR-0005 D2 — the deterministic consensus core is
//! dependency-free, integer-only, no floats). To bind a Self `vc_and_disclose` proof to its carried
//! `userContextData` on-chain, the runtime must recompute Self's `user_identifier` (public signal 20),
//! which is **not** the submitter address but the Bitcoin-style `hash160` of the FULL `userContextData`
//! byte buffer:
//!
//! ```text
//!   user_identifier = RIPEMD160(SHA256(userContextData))     // 20-byte digest
//! ```
//!
//! Verified bit-for-bit against a genuine Self **staging** proof (EC-C7): the 20-byte digest is used
//! verbatim, **right-aligned** into the 32-byte field element (high 12 bytes zero). Both hashes are
//! implemented here as pure integer Rust (FIPS 180-4 SHA-256; the Dobbertin–Bosselaers–Preneel
//! RIPEMD-160), so two nodes recomputing `user_identifier_hash(ucd)` agree to the bit (I1) with zero
//! new dependencies.

use crate::humanity::Hash;

// ---------------------------------------------------------------------------------------------
// SHA-256 (FIPS 180-4). Big-endian words; 64-byte blocks; 64-bit big-endian length pad.
// ---------------------------------------------------------------------------------------------

const SHA256_H0: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

const SHA256_K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

/// SHA-256 of `data` (FIPS 180-4). Pure integer arithmetic; no allocation beyond the padded message.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = SHA256_H0;

    // Message padding: 0x80, zeros to 56 mod 64, then the 64-bit big-endian bit length.
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, word) in w.iter_mut().enumerate().take(16) {
            let j = i * 4;
            *word = u32::from_be_bytes([chunk[j], chunk[j + 1], chunk[j + 2], chunk[j + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA256_K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

// ---------------------------------------------------------------------------------------------
// RIPEMD-160 (Dobbertin–Bosselaers–Preneel). Little-endian words; two parallel 5-round lines.
// ---------------------------------------------------------------------------------------------

/// Left-line message-word selection `r[j]`.
const RL: [usize; 80] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5,
    2, 14, 11, 8, 3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4,
    13, 3, 7, 15, 14, 5, 6, 2, 4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
];
/// Right-line message-word selection `r'[j]`.
const RR: [usize; 80] = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12,
    4, 9, 1, 2, 15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5,
    12, 2, 13, 9, 7, 10, 14, 12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
];
/// Left-line rotation amounts `s[j]`.
const SL: [u32; 80] = [
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15,
    9, 11, 7, 13, 12, 11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14,
    15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12, 9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
];
/// Right-line rotation amounts `s'[j]`.
const SR: [u32; 80] = [
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12,
    7, 6, 15, 13, 11, 9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14,
    6, 14, 6, 9, 12, 9, 12, 5, 15, 8, 8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
];

/// The round nonlinear function for round `j / 16` (`0..5`).
#[inline]
fn rmd_f(round: usize, x: u32, y: u32, z: u32) -> u32 {
    match round {
        0 => x ^ y ^ z,
        1 => (x & y) | (!x & z),
        2 => (x | !y) ^ z,
        3 => (x & z) | (y & !z),
        _ => x ^ (y | !z),
    }
}

/// The additive constant for the left line at round `j / 16`.
#[inline]
fn rmd_kl(round: usize) -> u32 {
    match round {
        0 => 0x0000_0000,
        1 => 0x5a82_7999,
        2 => 0x6ed9_eba1,
        3 => 0x8f1b_bcdc,
        _ => 0xa953_fd4e,
    }
}

/// The additive constant for the right line at round `j / 16`.
#[inline]
fn rmd_kr(round: usize) -> u32 {
    match round {
        0 => 0x50a2_8be6,
        1 => 0x5c4d_d124,
        2 => 0x6d70_3ef3,
        3 => 0x7a6d_76e9,
        _ => 0x0000_0000,
    }
}

/// RIPEMD-160 of `data`. Pure integer arithmetic; little-endian throughout.
pub fn ripemd160(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [
        0x6745_2301,
        0xefcd_ab89,
        0x98ba_dcfe,
        0x1032_5476,
        0xc3d2_e1f0,
    ];

    // MD-style padding with a 64-bit LITTLE-endian bit length.
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut x = [0u32; 16];
        for (i, word) in x.iter_mut().enumerate() {
            let j = i * 4;
            *word = u32::from_le_bytes([chunk[j], chunk[j + 1], chunk[j + 2], chunk[j + 3]]);
        }

        let (mut al, mut bl, mut cl, mut dl, mut el) = (h[0], h[1], h[2], h[3], h[4]);
        let (mut ar, mut br, mut cr, mut dr, mut er) = (h[0], h[1], h[2], h[3], h[4]);

        for j in 0..80 {
            let round = j / 16;
            // Left line.
            let t = al
                .wrapping_add(rmd_f(round, bl, cl, dl))
                .wrapping_add(x[RL[j]])
                .wrapping_add(rmd_kl(round))
                .rotate_left(SL[j])
                .wrapping_add(el);
            al = el;
            el = dl;
            dl = cl.rotate_left(10);
            cl = bl;
            bl = t;

            // Right line uses the round functions in reverse order (f5,f4,f3,f2,f1).
            let t = ar
                .wrapping_add(rmd_f(4 - round, br, cr, dr))
                .wrapping_add(x[RR[j]])
                .wrapping_add(rmd_kr(round))
                .rotate_left(SR[j])
                .wrapping_add(er);
            ar = er;
            er = dr;
            dr = cr.rotate_left(10);
            cr = br;
            br = t;
        }

        let t = h[1].wrapping_add(cl).wrapping_add(dr);
        h[1] = h[2].wrapping_add(dl).wrapping_add(er);
        h[2] = h[3].wrapping_add(el).wrapping_add(ar);
        h[3] = h[4].wrapping_add(al).wrapping_add(br);
        h[4] = h[0].wrapping_add(bl).wrapping_add(cr);
        h[0] = t;
    }

    let mut out = [0u8; 20];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

/// The Self `vc_and_disclose` `user_identifier` (public signal 20): the Bitcoin-style
/// `RIPEMD160(SHA256(userContextData))` `hash160` of the FULL `userContextData` buffer, the 20-byte
/// digest right-aligned into a 32-byte field element (high 12 bytes zero) — spec 06b §4.4 (EC-C7).
///
/// This is the value the runtime binds `submission.signals[user_identifier]` against, so the proof is
/// cryptographically tied to the exact `userContextData` carried on-chain: an attacker who swaps the
/// address in `userContextData[32:64]` changes this digest and the bind fails (fail-closed I4).
pub fn user_identifier_hash(user_context_data: &[u8]) -> Hash {
    let digest = ripemd160(&sha256(user_context_data));
    let mut out = [0u8; 32];
    out[12..32].copy_from_slice(&digest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    // ---- SHA-256 standard vectors (FIPS 180-4 App. B) ----

    #[test]
    fn sha256_empty() {
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_abc() {
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha256_nist_448bit() {
        // The 448-bit ("two block") NIST vector.
        assert_eq!(
            hex(&sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    // ---- RIPEMD-160 standard vectors ----

    #[test]
    fn ripemd160_empty() {
        assert_eq!(
            hex(&ripemd160(b"")),
            "9c1185a5c5e9fc54612808977ee8f548b2258d31"
        );
    }

    #[test]
    fn ripemd160_abc() {
        assert_eq!(
            hex(&ripemd160(b"abc")),
            "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"
        );
    }

    #[test]
    fn ripemd160_message_digest() {
        // A multi-block vector (> 64 bytes) exercises the padding + chaining path.
        assert_eq!(
            hex(&ripemd160(
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
            )),
            "b0e20b6e3116640286ed3a87a5713079b21f5189"
        );
    }

    // ---- EC-C7 captured ground truth (bit-for-bit vs a real Self staging proof) ----

    /// The exact 106-byte `userContextData` from the EC-C7 capture:
    /// `destChainId(32 BE) || userId_address(32, left-padded) || userDefinedData(ASCII)`.
    fn captured_ucd() -> Vec<u8> {
        // 0xa4ec chain id; 0xf39F…2266 address; ASCII "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".
        const HEX: &str = "000000000000000000000000000000000000000000000000000000000000a4ec\
000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266\
307866333946643665353161616438384636463463653661423838323732373963666646623932323636";
        (0..HEX.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&HEX[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn captured_ucd_intermediate_sha256() {
        let ucd = captured_ucd();
        assert_eq!(ucd.len(), 106, "the captured userContextData is 106 bytes");
        assert_eq!(
            hex(&sha256(&ucd)),
            "8b736a0e707fd621e5d52a6b327a24c7ad5e38dadcc667e6004d6e16e00436f3"
        );
    }

    #[test]
    fn captured_ucd_user_identifier_hash() {
        let ucd = captured_ucd();
        // RIPEMD160(SHA256(ucd)) == captured publicSignals[20] (right-aligned, high 12 bytes zero).
        let uid = user_identifier_hash(&ucd);
        assert_eq!(&uid[0..12], &[0u8; 12], "high 12 bytes are zero");
        assert_eq!(
            hex(&uid[12..32]),
            "28edff481a0eca85f9d91287153aefee1f78a031"
        );
        // The full 32-byte field element equals the captured decimal 233667145612885083532171022959570949293555097649.
        let expected_be = decimal_to_be32("233667145612885083532171022959570949293555097649");
        assert_eq!(
            uid, expected_be,
            "user_identifier matches publicSignals[20]"
        );
    }

    #[test]
    fn captured_ucd_recovered_address() {
        // The REAL submitter is userContextData[32:64] low-20 bytes (= ucd[44:64]).
        let ucd = captured_ucd();
        assert_eq!(
            hex(&ucd[44..64]),
            "f39fd6e51aad88f6f4ce6ab8827279cfffb92266"
        );
    }

    /// Parse a base-10 integer string into a 32-byte big-endian buffer (test helper).
    fn decimal_to_be32(s: &str) -> [u8; 32] {
        let mut bytes = [0u8; 32]; // big-endian accumulator
        for ch in s.bytes() {
            let digit = (ch - b'0') as u16;
            // multiply the 256-base big-endian number by 10 and add `digit`.
            let mut carry = digit;
            for b in bytes.iter_mut().rev() {
                let v = (*b as u16) * 10 + carry;
                *b = (v & 0xff) as u8;
                carry = v >> 8;
            }
            assert_eq!(carry, 0, "value fits in 32 bytes");
        }
        bytes
    }
}
