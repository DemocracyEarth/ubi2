//! Cross-language v2 identity vectors mirrored by the TypeScript SDK and Solidity tests.

use alloy_primitives::{keccak256, Address, FixedBytes, B256, U256};
use alloy_sol_types::{sol, SolValue};
use std::str::FromStr;
use ubi2_zkpoh::{
    V2PublicSignalError, V2PublicSignals, BN254_SCALAR_FIELD, V2_PUBLIC_SIGNAL_COUNT,
};

sol! {
    struct PrivateCredentialEncoding {
        bytes32 domain;
        uint16 version;
        bytes32 issuerKeyId;
        bytes32 statusId;
        uint256 holderSecret;
        uint256 credentialBlinding;
        uint32 dateOfBirth;
        bytes3 nationality;
        bytes3 issuingState;
        uint32 expiryDate;
        uint8 documentClass;
        uint8 assurance;
        uint32 issuedAtEpoch;
    }

    struct NullifierScopeEncoding {
        bytes32 domain;
        uint16 version;
        uint8 mode;
        uint256 chainId;
        address verifier;
        address consumer;
        bytes32 context;
        bytes32 policyHash;
    }
}

fn b256(value: &str) -> B256 {
    B256::from_str(value).expect("valid bytes32 fixture")
}

fn signal(value: &str) -> [u8; 32] {
    U256::from_str(value)
        .expect("valid uint256 fixture")
        .to_be_bytes::<32>()
}

fn fixture_signals() -> [[u8; 32]; V2_PUBLIC_SIGNAL_COUNT] {
    [
        signal("1"),
        signal("148470164970938473527131569574145738248"),
        signal("143106528634218877324650955020395841930"),
        signal("3635849571425045330628617071914858755"),
        signal("294515953839665300979725696144129953057"),
        signal("56743338650715011814192789619580272247"),
        signal("283811814910439300292750339907545096601"),
        signal("84332592671497082657127333409566874930"),
        signal("237646548228780080072226119388672926626"),
        signal("335934530153236393154503107393022614242"),
        signal("104498824908571987640421674469385365408"),
        signal("148368269012998052364797751201271282309"),
        signal("126559033271166220203394870356863420182"),
        signal("4242424242"),
        signal("292300327466180583640736966543256603931186508595"),
        signal("1"),
        signal("230"),
        signal("0"),
    ]
}

#[test]
fn private_credential_abi_fingerprint_matches_evm_and_sdk() {
    let encoded = PrivateCredentialEncoding {
        domain: keccak256(b"org.proofofhumanity.zk-private-credential"),
        version: 1,
        issuerKeyId: b256("0x02bc3d3958ba083a8c814e7961433903dd91b59f2af591138467a1202da88d21"),
        statusId: b256("0x84a8b6c45e1e6baf59f05ec3b1fb2317d2ec4b773c7f64d0b8c83d63ba2b3f3a"),
        holderSecret: U256::from(123_456_789u64),
        credentialBlinding: U256::from(987_654_321u64),
        dateOfBirth: 19_900_403,
        nationality: FixedBytes::<3>::from(*b"ARG"),
        issuingState: FixedBytes::<3>::from(*b"ARG"),
        expiryDate: 20_310_709,
        documentClass: 1,
        assurance: 2,
        issuedAtEpoch: 230,
    }
    .abi_encode();
    assert_eq!(
        keccak256(encoded),
        b256("0x5f3113cae53c94a863c5362d229137c767d996e444283541f19b13aac89e7f11")
    );
}

#[test]
fn nullifier_scope_abi_hash_matches_evm_and_sdk() {
    let encoded = NullifierScopeEncoding {
        domain: keccak256(b"org.proofofhumanity.zk-nullifier-scope"),
        version: 1,
        mode: 1,
        chainId: U256::from(84_532u64),
        verifier: Address::from([0x11; 20]),
        consumer: Address::from([0x22; 20]),
        context: keccak256(b"membership:season-1"),
        policyHash: b256("0x3f71ddd64fc1edef180756674529dd32b2c90f7288d2f0ced062e781a0cda3a2"),
    }
    .abi_encode();
    assert_eq!(
        keccak256(encoded),
        b256("0x6f9eb06ffea41fade00efe22ab9a7a855f366218cd9248acb84e7578a4f90716")
    );
}

#[test]
fn public_signal_layout_decodes_losslessly() {
    let decoded = V2PublicSignals::decode(&fixture_signals()).expect("valid fixture");
    assert_eq!(decoded.circuit_id, keccak256(b"circuit:v2-spike:1").0);
    assert_eq!(
        decoded.issuer_key_id,
        b256("0x02bc3d3958ba083a8c814e7961433903dd91b59f2af591138467a1202da88d21").0
    );
    assert_eq!(decoded.active_root, keccak256(b"active-root:testnet:230").0);
    assert_eq!(
        decoded.policy_hash,
        b256("0x3f71ddd64fc1edef180756674529dd32b2c90f7288d2f0ced062e781a0cda3a2").0
    );
    assert_eq!(
        decoded.nullifier_scope_hash,
        b256("0x6f9eb06ffea41fade00efe22ab9a7a855f366218cd9248acb84e7578a4f90716").0
    );
    assert_eq!(decoded.scoped_nullifier, signal("4242424242"));
    assert_eq!(decoded.subject, [0x33; 20]);
    assert!(decoded.result);
    assert_eq!(decoded.credential_epoch, 230);
    assert_eq!(decoded.status_epoch, 0);
}

#[test]
fn public_signal_layout_rejects_noncanonical_or_aliased_values() {
    let mut signals = fixture_signals();
    signals[13] = BN254_SCALAR_FIELD;
    assert_eq!(
        V2PublicSignals::decode(&signals),
        Err(V2PublicSignalError::NonCanonicalField(13))
    );

    let mut signals = fixture_signals();
    signals[7] = [0; 32];
    signals[8] = [0; 32];
    assert_eq!(
        V2PublicSignals::decode(&signals),
        Err(V2PublicSignalError::InvalidIdentifier(7))
    );

    let mut signals = fixture_signals();
    signals[15] = signal("2");
    assert_eq!(
        V2PublicSignals::decode(&signals),
        Err(V2PublicSignalError::InvalidResult)
    );

    let mut signals = fixture_signals();
    signals[14] = [0; 32];
    assert_eq!(
        V2PublicSignals::decode(&signals),
        Err(V2PublicSignalError::InvalidSubject)
    );
}
