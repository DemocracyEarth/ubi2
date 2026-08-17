//! Canonical cross-lane fixture shared with the SDK and Solidity release gate.

use alloy_primitives::{keccak256, Address, FixedBytes, B256, U256};
use alloy_sol_types::{sol, SolValue};
use serde_json::Value;
use std::str::FromStr;
use ubi2_zkpoh::{V2PublicSignalError, V2PublicSignals, V2_PUBLIC_SIGNAL_COUNT};

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

    struct IssuanceDomainEncoding {
        bytes32 domain;
        uint16 version;
        uint256 chainId;
        address registry;
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

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../fixtures/v2-identity/interface-v1.json"
    ))
    .expect("valid shared interface fixture")
}

fn string<'a>(value: &'a Value, pointer: &str) -> &'a str {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing string fixture field {pointer}"))
}

fn number(value: &Value, pointer: &str) -> u64 {
    value
        .pointer(pointer)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("missing numeric fixture field {pointer}"))
}

fn b256(value: &Value, pointer: &str) -> B256 {
    B256::from_str(string(value, pointer)).expect("valid bytes32 fixture")
}

fn u256_string(value: &Value, pointer: &str) -> U256 {
    U256::from_str(string(value, pointer)).expect("valid uint256 fixture")
}

fn date(value: &Value, pointer: &str) -> u32 {
    string(value, pointer)
        .replace('-', "")
        .parse()
        .expect("valid YYYY-MM-DD fixture")
}

fn bytes3(value: &Value, pointer: &str) -> FixedBytes<3> {
    let bytes: [u8; 3] = string(value, pointer)
        .as_bytes()
        .try_into()
        .expect("three-byte fixture");
    FixedBytes::from(bytes)
}

fn signal(value: &str) -> [u8; 32] {
    U256::from_str(value)
        .expect("valid public signal")
        .to_be_bytes::<32>()
}

fn signals(value: &Value) -> [[u8; 32]; V2_PUBLIC_SIGNAL_COUNT] {
    value["publicSignals"]["values"]
        .as_array()
        .expect("signal vector")
        .iter()
        .map(|entry| signal(entry.as_str().expect("decimal signal string")))
        .collect::<Vec<_>>()
        .try_into()
        .expect("exactly 18 signals")
}

fn split(value: B256) -> [U256; 2] {
    let word = U256::from_be_bytes(value.0);
    [word >> 128, word & U256::from(u128::MAX)]
}

#[test]
fn shared_fixture_recomputes_private_and_public_boundaries() {
    let fixture = fixture();
    assert_eq!(
        string(&fixture, "/schema"),
        "org.proofofhumanity.v2-cross-lane-interface/1"
    );
    assert_eq!(
        string(&fixture, "/classification/productionCryptography"),
        "unratified"
    );

    let credential = PrivateCredentialEncoding {
        domain: keccak256(b"org.proofofhumanity.zk-private-credential"),
        version: 1,
        issuerKeyId: b256(&fixture, "/privateCredential/issuerKeyId"),
        statusId: b256(&fixture, "/privateCredential/statusId"),
        holderSecret: u256_string(&fixture, "/privateCredential/holderSecret"),
        credentialBlinding: u256_string(&fixture, "/privateCredential/credentialBlinding"),
        dateOfBirth: date(&fixture, "/privateCredential/dateOfBirth"),
        nationality: bytes3(&fixture, "/privateCredential/nationality"),
        issuingState: bytes3(&fixture, "/privateCredential/issuingState"),
        expiryDate: date(&fixture, "/privateCredential/expiryDate"),
        documentClass: 1,
        assurance: 2,
        issuedAtEpoch: number(&fixture, "/privateCredential/issuedAtEpoch") as u32,
    };
    assert_eq!(
        keccak256(credential.abi_encode()),
        b256(&fixture, "/privateCredential/diagnosticFingerprint")
    );

    let issuance = IssuanceDomainEncoding {
        domain: keccak256(b"org.proofofhumanity.zk-issuance"),
        version: 1,
        chainId: U256::from(number(&fixture, "/issuanceDomain/chainId")),
        registry: Address::from_str(string(&fixture, "/issuanceDomain/registry"))
            .expect("valid registry address"),
    };
    assert_eq!(
        keccak256(issuance.abi_encode()),
        b256(&fixture, "/issuanceDomain/hash")
    );

    let scope = NullifierScopeEncoding {
        domain: keccak256(b"org.proofofhumanity.zk-nullifier-scope"),
        version: 1,
        mode: 1,
        chainId: U256::from(number(&fixture, "/nullifierScope/chainId")),
        verifier: Address::from_str(string(&fixture, "/nullifierScope/verifier"))
            .expect("valid verifier address"),
        consumer: Address::from_str(string(&fixture, "/nullifierScope/consumer"))
            .expect("valid consumer address"),
        context: b256(&fixture, "/nullifierScope/context"),
        policyHash: b256(&fixture, "/nullifierScope/policyHash"),
    };
    let scope_hash = keccak256(scope.abi_encode());
    assert_eq!(scope_hash, b256(&fixture, "/nullifierScope/hash"));

    let domain_limbs = split(keccak256(b"org.proofofhumanity.zk-nullifier-scope:derive"));
    let scope_limbs = split(scope_hash);
    let expected_preimage = [
        domain_limbs[0],
        domain_limbs[1],
        U256::from(1),
        u256_string(&fixture, "/privateCredential/holderSecret"),
        scope_limbs[0],
        scope_limbs[1],
    ];
    let fixture_preimage = fixture["nullifierScope"]["preimage"]
        .as_array()
        .expect("nullifier preimage")
        .iter()
        .map(|entry| U256::from_str(entry.as_str().expect("preimage string")).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(expected_preimage.as_slice(), fixture_preimage.as_slice());

    let decoded = V2PublicSignals::decode(&signals(&fixture)).expect("valid shared signal fixture");
    assert_eq!(
        decoded.circuit_id,
        b256(&fixture, "/publicSignals/semanticValues/circuitId").0
    );
    assert_eq!(
        decoded.issuer_key_id,
        b256(&fixture, "/publicSignals/semanticValues/issuerKeyId").0
    );
    assert_eq!(
        decoded.active_root,
        b256(&fixture, "/publicSignals/semanticValues/activeRoot").0
    );
    assert_eq!(
        decoded.policy_hash,
        b256(&fixture, "/publicSignals/semanticValues/policyHash").0
    );
    assert_eq!(
        decoded.presentation_binding_hash,
        b256(
            &fixture,
            "/publicSignals/semanticValues/presentationBindingHash"
        )
        .0
    );
    assert_eq!(decoded.nullifier_scope_hash, scope_hash.0);
    assert_eq!(
        decoded.scoped_nullifier,
        signal(string(
            &fixture,
            "/publicSignals/semanticValues/scopedNullifier"
        ))
    );
    assert!(decoded.result);
    assert_eq!(decoded.credential_epoch, 230);
    assert_eq!(decoded.status_epoch, 0);
}

#[test]
fn every_declared_fixture_mutation_fails_closed() {
    let fixture = fixture();
    for mutation in fixture["negativeMutations"]
        .as_array()
        .expect("negative mutation list")
    {
        let mut mutated = signals(&fixture);
        let index = mutation["index"].as_u64().expect("mutation index") as usize;
        mutated[index] = signal(mutation["value"].as_str().expect("mutation value"));
        if let Some(also_index) = mutation.get("alsoIndex").and_then(Value::as_u64) {
            mutated[also_index as usize] = signal(
                mutation["alsoValue"]
                    .as_str()
                    .expect("secondary mutation value"),
            );
        }
        let error = V2PublicSignals::decode(&mutated).expect_err("mutation must fail closed");
        let name = mutation["name"].as_str().expect("mutation name");
        match name {
            "unsupported-layout" => assert_eq!(error, V2PublicSignalError::UnsupportedLayout),
            "zero-policy-hash" => assert_eq!(error, V2PublicSignalError::InvalidIdentifier(7)),
            "noncanonical-nullifier" => {
                assert_eq!(error, V2PublicSignalError::NonCanonicalField(13))
            }
            "zero-subject" => assert_eq!(error, V2PublicSignalError::InvalidSubject),
            "nonboolean-result" => assert_eq!(error, V2PublicSignalError::InvalidResult),
            other => panic!("unknown mutation {other}"),
        }
    }
}
