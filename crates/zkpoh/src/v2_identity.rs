//! Strict v2 ZK identity public-signal decoding (spec 10 Stage 1).
//!
//! This module owns no proof-system choice. It pins the lossless 18-field wire
//! layout shared by the TypeScript SDK and Solidity adapter, and rejects every
//! non-canonical BN254 field before a verifier can reduce it modulo the scalar
//! order. Bytes32 values are represented as two 128-bit limbs so policy/root
//! hashes round-trip exactly rather than aliasing modulo the field.

/// BN254 scalar-field order as a 32-byte big-endian integer.
pub const BN254_SCALAR_FIELD: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

pub const V2_PUBLIC_SIGNALS_VERSION: u8 = 1;
pub const V2_PUBLIC_SIGNAL_COUNT: usize = 18;

pub const V2_IDX_LAYOUT_VERSION: usize = 0;
pub const V2_IDX_CIRCUIT_ID_HI: usize = 1;
pub const V2_IDX_ISSUER_KEY_ID_HI: usize = 3;
pub const V2_IDX_ACTIVE_ROOT_HI: usize = 5;
pub const V2_IDX_POLICY_HASH_HI: usize = 7;
pub const V2_IDX_BINDING_HASH_HI: usize = 9;
pub const V2_IDX_NULLIFIER_SCOPE_HASH_HI: usize = 11;
pub const V2_IDX_SCOPED_NULLIFIER: usize = 13;
pub const V2_IDX_SUBJECT: usize = 14;
pub const V2_IDX_RESULT: usize = 15;
pub const V2_IDX_CREDENTIAL_EPOCH: usize = 16;
pub const V2_IDX_STATUS_EPOCH: usize = 17;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum V2PublicSignalError {
    NonCanonicalField(usize),
    UnsupportedLayout,
    InvalidIdentifier(usize),
    InvalidNullifier,
    InvalidSubject,
    InvalidResult,
    InvalidEpoch(usize),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2PublicSignals {
    pub circuit_id: [u8; 32],
    pub issuer_key_id: [u8; 32],
    pub active_root: [u8; 32],
    pub policy_hash: [u8; 32],
    pub presentation_binding_hash: [u8; 32],
    pub nullifier_scope_hash: [u8; 32],
    pub scoped_nullifier: [u8; 32],
    pub subject: [u8; 20],
    pub result: bool,
    pub credential_epoch: u32,
    pub status_epoch: u32,
}

impl V2PublicSignals {
    /// Strictly decode the fixed v1 layout. No signal is ever reduced modulo Fr.
    pub fn decode(
        signals: &[[u8; 32]; V2_PUBLIC_SIGNAL_COUNT],
    ) -> Result<Self, V2PublicSignalError> {
        for (index, signal) in signals.iter().enumerate() {
            if signal >= &BN254_SCALAR_FIELD {
                return Err(V2PublicSignalError::NonCanonicalField(index));
            }
        }
        if read_u8(&signals[V2_IDX_LAYOUT_VERSION]) != Some(V2_PUBLIC_SIGNALS_VERSION) {
            return Err(V2PublicSignalError::UnsupportedLayout);
        }

        let circuit_id = join_identifier(signals, V2_IDX_CIRCUIT_ID_HI)?;
        let issuer_key_id = join_identifier(signals, V2_IDX_ISSUER_KEY_ID_HI)?;
        let active_root = join_identifier(signals, V2_IDX_ACTIVE_ROOT_HI)?;
        let policy_hash = join_identifier(signals, V2_IDX_POLICY_HASH_HI)?;
        let presentation_binding_hash = join_identifier(signals, V2_IDX_BINDING_HASH_HI)?;
        let nullifier_scope_hash = join_identifier(signals, V2_IDX_NULLIFIER_SCOPE_HASH_HI)?;

        let scoped_nullifier = signals[V2_IDX_SCOPED_NULLIFIER];
        if scoped_nullifier == [0; 32] {
            return Err(V2PublicSignalError::InvalidNullifier);
        }

        let subject_signal = &signals[V2_IDX_SUBJECT];
        if subject_signal[..12] != [0; 12] || subject_signal[12..] == [0; 20] {
            return Err(V2PublicSignalError::InvalidSubject);
        }
        let mut subject = [0u8; 20];
        subject.copy_from_slice(&subject_signal[12..]);

        let result = match read_u8(&signals[V2_IDX_RESULT]) {
            Some(0) => false,
            Some(1) => true,
            _ => return Err(V2PublicSignalError::InvalidResult),
        };
        let credential_epoch = read_u32(&signals[V2_IDX_CREDENTIAL_EPOCH])
            .ok_or(V2PublicSignalError::InvalidEpoch(V2_IDX_CREDENTIAL_EPOCH))?;
        let status_epoch = read_u32(&signals[V2_IDX_STATUS_EPOCH])
            .ok_or(V2PublicSignalError::InvalidEpoch(V2_IDX_STATUS_EPOCH))?;

        Ok(Self {
            circuit_id,
            issuer_key_id,
            active_root,
            policy_hash,
            presentation_binding_hash,
            nullifier_scope_hash,
            scoped_nullifier,
            subject,
            result,
            credential_epoch,
            status_epoch,
        })
    }
}

/// Losslessly split a bytes32 into two field-safe, 128-bit big-endian limbs.
pub fn split_bytes32(value: &[u8; 32]) -> [[u8; 32]; 2] {
    let mut high = [0u8; 32];
    let mut low = [0u8; 32];
    high[16..].copy_from_slice(&value[..16]);
    low[16..].copy_from_slice(&value[16..]);
    [high, low]
}

fn join_identifier(
    signals: &[[u8; 32]; V2_PUBLIC_SIGNAL_COUNT],
    high_index: usize,
) -> Result<[u8; 32], V2PublicSignalError> {
    let high = &signals[high_index];
    let low = &signals[high_index + 1];
    if high[..16] != [0; 16]
        || low[..16] != [0; 16]
        || (high[16..] == [0; 16] && low[16..] == [0; 16])
    {
        return Err(V2PublicSignalError::InvalidIdentifier(high_index));
    }
    let mut value = [0u8; 32];
    value[..16].copy_from_slice(&high[16..]);
    value[16..].copy_from_slice(&low[16..]);
    Ok(value)
}

fn read_u8(value: &[u8; 32]) -> Option<u8> {
    if value[..31] != [0; 31] {
        return None;
    }
    Some(value[31])
}

fn read_u32(value: &[u8; 32]) -> Option<u32> {
    if value[..28] != [0; 28] {
        return None;
    }
    Some(u32::from_be_bytes(
        value[28..].try_into().expect("four-byte slice"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_ff::{BigInteger, PrimeField};

    #[test]
    fn scalar_modulus_matches_arkworks_fr() {
        assert_eq!(Fr::MODULUS.to_bytes_be(), BN254_SCALAR_FIELD);
    }

    #[test]
    fn split_is_lossless_and_128_bit() {
        let value = [0xa5; 32];
        let [high, low] = split_bytes32(&value);
        assert_eq!(high[..16], [0; 16]);
        assert_eq!(low[..16], [0; 16]);
        assert_eq!(high[16..], value[..16]);
        assert_eq!(low[16..], value[16..]);
    }
}
