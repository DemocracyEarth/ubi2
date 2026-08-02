//! Phase B — decode Self's disclosed PUBLIC attributes from `revealedData_packed` (public signals 0-2).
//!
//! The user chose PUBLIC anonymous traits, so the ubi2 PoH NFT surfaces the low-entropy, non-identifying
//! fields Self discloses in an E_PASSPORT `vc_and_disclose` proof — nationality, gender, an age lower-bound,
//! and OFAC-clear — as plaintext. Name, date-of-birth and passport number are NEVER decoded or surfaced
//! (they are only present in `revealedData_packed` if explicitly requested, which the ubi2 flow never does).
//!
//! ## The exact Self encoding (source-verified, confirmed against Self's own unit-test vector)
//! `revealedData_packed` is 3 BN254 field elements (signals 0,1,2). Self's `Formatter.fieldElementsToBytes`
//! reassembles them into a **93-byte** buffer as **31 bytes per element, LITTLE-ENDIAN**: for element `i`,
//! `buffer[31*i + k] = (element >> (8*k)) & 0xff`. Since we store each signal as its 32-byte BIG-endian
//! form, that low byte `k` is `signal[i][31 - k]` — i.e. the buffer is the low 31 bytes of each signal,
//! reversed. (NOT 96 bytes, NOT big-endian — the packing assumption that has burned this integration before.)
//! Field offsets are compile-time constants keyed only on `attestation_id` (E_PASSPORT), fixed regardless of
//! which fields were disclosed (undisclosed fields are 0x00 in place): nationality `[54..=56]` (ISO-3166
//! alpha-3), gender `[64]` (`M`/`F`/`<`), olderThan `[88..=89]` (two ASCII digits), OFAC `[90..=92]`.

/// The public, non-identifying attributes Self discloses in an E_PASSPORT proof, decoded from
/// `revealedData_packed`. Plaintext (public traits); undisclosed fields decode to zero/empty.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SelfAttributes {
    /// ISO-3166 alpha-3 nationality (3 ASCII bytes, e.g. `b"USA"`), or `[0;3]` if not disclosed.
    pub nationality: [u8; 3],
    /// MRZ sex character: `b'M'` / `b'F'` / `b'<'` (unspecified), or `0` if not disclosed.
    pub gender: u8,
    /// The proven age lower bound (`olderThan`), e.g. `18`; `0` if age was not disclosed.
    pub older_than: u8,
    /// OFAC-clear: all three OFAC checks (passportno / namedob / nameyob) passed.
    pub ofac_clear: bool,
}

impl SelfAttributes {
    /// The nationality as an ASCII `&str` (`""` if not disclosed / non-UTF-8).
    pub fn nationality_str(&self) -> &str {
        if self.nationality == [0; 3] {
            return "";
        }
        core::str::from_utf8(&self.nationality).unwrap_or("")
    }
    /// A stable display label for gender: `"male"` / `"female"` / `"other"` / `""` (undisclosed).
    pub fn gender_label(&self) -> &'static str {
        match self.gender {
            b'M' | b'm' => "male",
            b'F' | b'f' => "female",
            b'<' | b'X' | b'x' => "other",
            _ => "",
        }
    }
}

/// Decode the E_PASSPORT public attributes from the 3 packed `revealedData` signals (spec 06b, Phase B).
/// Deterministic + dependency-free (I1). See the module docs for the exact Self packing/offsets; confirmed
/// byte-for-byte against Self's `CircuitAttributeHandler.test.ts` `sampleMRZ` fixture.
pub fn decode_self_attributes(revealed: &[[u8; 32]; 3]) -> SelfAttributes {
    let mut buf = [0u8; 93];
    for i in 0..3 {
        for k in 0..31 {
            // Low 31 bytes of each 32-byte big-endian signal, reversed → the little-endian packed buffer.
            buf[31 * i + k] = revealed[i][31 - k];
        }
    }
    let nationality = [buf[54], buf[55], buf[56]];
    let gender = buf[64];
    let older_than = if buf[88].is_ascii_digit() && buf[89].is_ascii_digit() {
        (buf[88] - b'0') * 10 + (buf[89] - b'0')
    } else {
        0
    };
    let ofac_clear = buf[90] == 1 && buf[91] == 1 && buf[92] == 1;
    SelfAttributes {
        nationality,
        gender,
        older_than,
        ofac_clear,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hx(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    #[test]
    fn decodes_self_golden_vector() {
        // The 3 packed signals derived from Self's own CircuitAttributeHandler.test.ts `sampleMRZ`
        // (issuingState/nationality "UTO", gender 'F', olderThan 18, ofac [1,1,1]).
        let sig = [
            hx("003c3c3c3c3c3c414952414d3c414e4e413c3c4e4f53534b4952454f54553c50"),
            hx("0031383034374f54553633433230393839384c3c3c3c3c3c3c3c3c3c3c3c3c3c"),
            hx("00010101383130313c3c3c3c3c42363232343831455a39353134303231463232"),
        ];
        let a = decode_self_attributes(&sig);
        assert_eq!(&a.nationality, b"UTO", "nationality");
        assert_eq!(a.nationality_str(), "UTO");
        assert_eq!(a.gender, b'F', "gender");
        assert_eq!(a.gender_label(), "female");
        assert_eq!(a.older_than, 18, "olderThan");
        assert!(a.ofac_clear, "ofac-clear");
    }

    #[test]
    fn undisclosed_decodes_to_empty() {
        let a = decode_self_attributes(&[[0u8; 32]; 3]);
        assert_eq!(a, SelfAttributes::default());
        assert_eq!(a.nationality_str(), "");
        assert_eq!(a.gender_label(), "");
        assert!(!a.ofac_clear);
    }
}
