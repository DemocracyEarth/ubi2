use ark_bn254::Fq as Bn254BaseField;
use ark_ec::{twisted_edwards::TECurveConfig, CurveConfig, CurveGroup, PrimeGroup};
use ark_ed_on_bn254::{EdwardsConfig, EdwardsProjective, Fr as JubjubScalar};
use ark_ff::{BigInteger, PrimeField, Zero};
use serde_json::{json, Value};
use sha2::{Digest, Sha512};

use super::{
    holder_credential_field_elements, issuer_key_digest_native, jubjub_scalar_from_circuit_field,
    merkle_root_native, packed_status_chunk_with_active_slot, packed_status_leaf_native,
    packed_status_path_directions_native, poseidon_config, poseidon_native,
    signature_challenge_native, split_field_to_u128_limbs, CircuitField,
    HolderCredentialCommitmentInput, CREDENTIAL_DOMAIN, DYNAMIC_STATUS_NULLIFIER_SCOPE,
    DYNAMIC_STATUS_POLICY_HASH, DYNAMIC_STATUS_PRESENTATION_BINDING, ISSUER_KEY_DOMAIN,
    NULLIFIER_DOMAIN, NULLIFIER_PREIMAGE_DOMAIN, PACKED_STATUS_DEPTH, PACKED_STATUS_LEAF_DOMAIN,
    REGISTRY_NODE_DOMAIN, SIGNATURE_CHALLENGE_DOMAIN,
};

pub const PRODUCTION_CRYPTO_PROFILE_ID: &str =
    "org.proofofhumanity.v2-crypto.groth16-bn254-poseidon/1";
pub const PRODUCTION_CRYPTO_PARAMETER_SCHEMA: &str =
    "org.proofofhumanity.v2-production-crypto-parameters/1";
pub const PRODUCTION_CRYPTO_REFERENCE_VECTOR_SCHEMA: &str =
    "org.proofofhumanity.v2-production-crypto-reference-vector/1";

const NONCE_DOMAIN: &[u8] = b"org.proofofhumanity.v2-issuer-schnorr-nonce/1";
const SANCTIONS_CLEAR_CIRCUIT_ID: &str =
    "0xe04e432671953a25e6aadbb5e59cfa0ff347108e31aac4a5599cb08f5cce11d2";
const AGE_THRESHOLD_CIRCUIT_ID: &str =
    "0xe372a2a117a999d9de9a071f78281a421aaf5562705b34f0e110c7f33f302305";
const NATIONALITY_SET_CIRCUIT_ID: &str =
    "0xcf17502eca9d6173b12a1d6b8149db11a2b3db5e739b336dfbd122b91b21a3a6";
const EXPIRY_VALID_CIRCUIT_ID: &str =
    "0xf0901f3261d5952d6a48fc33f1b8782a064175c6aa96063fa959b2ec41ef806f";
const ASSURANCE_CIRCUIT_ID: &str =
    "0x2ba3a8d0157db6fcd9a82a825cd527347b7629787483f6ff5a3ec900b0999801";

pub(crate) fn synthetic_production_holder_input() -> HolderCredentialCommitmentInput {
    HolderCredentialCommitmentInput {
        schema: "org.proofofhumanity.zk-holder-credential-input/1".to_owned(),
        issuer_key_id: "0x0446b5caa8a2f7a9ed023dc9d2bc9f3a32a1515fce6450231ffd870b4d3fb412"
            .to_owned(),
        status_id: 7,
        holder_secret: "123456789".to_owned(),
        credential_blinding: "987654321".to_owned(),
        date_of_birth: "2000-01-01".to_owned(),
        nationality: "XAA".to_owned(),
        issuing_state: "XAB".to_owned(),
        expiry_date: "2030-01-01".to_owned(),
        document_class: "epassport".to_owned(),
        assurance: "chip-auth".to_owned(),
        issued_at_epoch: 230,
    }
}

fn decimal<F: PrimeField>(value: F) -> String {
    value.into_bigint().to_string()
}

fn fixed_be_bytes<F: PrimeField>(value: F) -> [u8; 32] {
    let bytes = value.into_bigint().to_bytes_be();
    let mut output = [0u8; 32];
    output[32 - bytes.len()..].copy_from_slice(&bytes);
    output
}

fn hex32<F: PrimeField>(value: F) -> String {
    let bytes = fixed_be_bytes(value);
    let mut output = String::with_capacity(66);
    output.push_str("0x");
    for byte in bytes {
        use std::fmt::Write;
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn decode_bytes32(value: &str) -> [u8; 32] {
    assert_eq!(value.len(), 66);
    assert!(value.starts_with("0x"));
    let mut output = [0u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        let start = 2 + index * 2;
        *byte = u8::from_str_radix(&value[start..start + 2], 16)
            .expect("constant bytes32 is valid hex");
    }
    output
}

pub(crate) fn derive_nonce(
    secret: JubjubScalar,
    credential_commitment: CircuitField,
    auxiliary_randomness: [u8; 32],
) -> JubjubScalar {
    let secret_bytes = fixed_be_bytes(secret);
    let commitment_bytes = fixed_be_bytes(credential_commitment);
    for counter in 0u32..=u32::MAX {
        let digest = Sha512::new()
            .chain_update(NONCE_DOMAIN)
            .chain_update(secret_bytes)
            .chain_update(commitment_bytes)
            .chain_update(auxiliary_randomness)
            .chain_update(counter.to_be_bytes())
            .finalize();
        let nonce = JubjubScalar::from_be_bytes_mod_order(&digest);
        if !nonce.is_zero() {
            return nonce;
        }
    }
    unreachable!("a SHA-512 nonce stream cannot exhaust the u32 counter in practice")
}

pub fn production_crypto_parameter_manifest() -> Value {
    let poseidon = poseidon_config();
    let generator = EdwardsProjective::generator().into_affine();
    json!({
        "schema": PRODUCTION_CRYPTO_PARAMETER_SCHEMA,
        "profileId": PRODUCTION_CRYPTO_PROFILE_ID,
        "ratificationScope": "implementation-stable; production activation still requires the admission gate",
        "fields": {
            "bn254BaseFieldModulus": Bn254BaseField::MODULUS.to_string(),
            "bn254ScalarAndCircuitFieldModulus": CircuitField::MODULUS.to_string(),
            "babyJubjubPrimeSubgroupOrder": JubjubScalar::MODULUS.to_string()
        },
        "poseidon": {
            "identifier": "poseidon-bn254-arkworks-0.5-x5-rate2/1",
            "field": "bn254-fr",
            "width": poseidon.rate + poseidon.capacity,
            "rate": poseidon.rate,
            "capacity": poseidon.capacity,
            "alpha": poseidon.alpha,
            "fullRounds": poseidon.full_rounds,
            "partialRounds": poseidon.partial_rounds,
            "generation": "ark-crypto-primitives-0.5.0::find_poseidon_ark_and_mds(modulus_bits=254,rate=2,full_rounds=8,partial_rounds=57,skip_matrices=0)",
            "absorption": "absorb one domain field element, then ordered message field elements, then squeeze one native field element",
            "ark": poseidon.ark.iter().map(|row| row.iter().copied().map(decimal).collect::<Vec<_>>()).collect::<Vec<_>>(),
            "mds": poseidon.mds.iter().map(|row| row.iter().copied().map(decimal).collect::<Vec<_>>()).collect::<Vec<_>>()
        },
        "domains": {
            "credentialCommitment": CREDENTIAL_DOMAIN,
            "scopedNullifier": NULLIFIER_DOMAIN,
            "statusNode": REGISTRY_NODE_DOMAIN,
            "issuerSignatureChallenge": SIGNATURE_CHALLENGE_DOMAIN,
            "issuerKeyId": ISSUER_KEY_DOMAIN,
            "packedStatusLeaf": PACKED_STATUS_LEAF_DOMAIN
        },
        "credentialCommitment": {
            "identifier": "poseidon-bn254-arkworks-0.5-x5-rate2/1",
            "privateCredentialSchema": "org.proofofhumanity.zk-private-credential/1",
            "orderedFieldElementCount": 16,
            "statusRaceResolution": "discard the losing allocation, recommit with the new status slot and epoch, and repeat passport binding; never rewrite a signed commitment"
        },
        "issuerAuthentication": {
            "identifier": "schnorr-babyjubjub-poseidon-sha512-nonce/1",
            "curve": "EIP-2494 Baby Jubjub reduced twisted-Edwards form over BN254 Fr",
            "curveA": decimal(EdwardsConfig::COEFF_A),
            "curveD": decimal(EdwardsConfig::COEFF_D),
            "cofactor": EdwardsConfig::COFACTOR[0],
            "generator": { "x": decimal(generator.x), "y": decimal(generator.y) },
            "secretScalarEncoding": "canonical 32-byte big-endian integer less than the prime subgroup order; zero forbidden",
            "responseScalarEncoding": "canonical 32-byte big-endian integer less than the prime subgroup order; zero permitted",
            "pointEncoding": "two canonical 32-byte big-endian BN254-Fr coordinates; on-curve, nonzero and prime-subgroup checks required",
            "keyId": "Poseidon(domain=5,[publicKey.x,publicKey.y]), canonical field element encoded as bytes32",
            "challenge": "Poseidon(domain=4,[R.x,R.y,A.x,A.y,credentialCommitment]) reduced modulo the Baby-Jubjub subgroup order by scalar multiplication",
            "response": "s = r - challenge*secretKey mod subgroupOrder",
            "verification": "s*G + challenge*A = R",
            "nonce": {
                "hash": "SHA-512",
                "preimage": "ASCII nonce domain || sk_be32 || credential_commitment_be32 || auxiliary_randomness_32 || counter_u32_be",
                "conversion": "OS2IP(digest) mod subgroupOrder; increment counter from zero until nonzero",
                "auxiliaryRandomness": "mandatory fresh 32 bytes from the issuer CSPRNG; never logged or included in the public transcript"
            }
        },
        "packedStatus": {
            "identifier": "poseidon-bn254-packed-status-depth24/1",
            "statusId": "nonzero uint32; low 8 bits select the bit and high 24 bits select the Merkle path",
            "chunk": "two little-endian u128 field limbs carrying 256 status bits",
            "activeBit": 0,
            "unallocatedOrRevokedBit": 1,
            "leaf": "Poseidon(domain=8,[chunkLow128,chunkHigh128])",
            "node": "Poseidon(domain=3,[left,right])",
            "depth": PACKED_STATUS_DEPTH
        },
        "proofSystem": {
            "identifier": "groth16-bn254-circuit-specific-mpc/1",
            "curve": "BN254",
            "setup": "circuit-specific MPC with independently verified Phase 1 and Phase 2 transcripts, at least three contributions, and a final beacon",
            "proofEncoding": "EIP-197 affine coordinates in Solidity verifier word order",
            "publicSignalLayoutVersion": 1,
            "publicSignalCount": 18
        },
        "circuitSet": [
            { "name": "sanctions-clear", "circuitId": SANCTIONS_CLEAR_CIRCUIT_ID, "relationStatus": "implemented-candidate" },
            { "name": "age-threshold", "circuitId": AGE_THRESHOLD_CIRCUIT_ID, "relationStatus": "implementation-required" },
            { "name": "nationality-set-membership", "circuitId": NATIONALITY_SET_CIRCUIT_ID, "relationStatus": "implementation-required" },
            { "name": "expiry-valid", "circuitId": EXPIRY_VALID_CIRCUIT_ID, "relationStatus": "implementation-required" },
            { "name": "assurance-minimum", "circuitId": ASSURANCE_CIRCUIT_ID, "relationStatus": "implementation-required" }
        ],
        "compiler": {
            "language": "Rust",
            "rustc": "1.96.0",
            "constraintSystem": "ark-relations 0.5.1 R1CS",
            "groth16": "ark-groth16 0.5.0",
            "curve": "ark-bn254 0.5.0",
            "poseidon": "ark-crypto-primitives 0.5.0",
            "babyJubjub": "ark-ed-on-bn254 0.5.0",
            "browserBinding": "wasm-bindgen 0.2.125",
            "solidity": "solc 0.8.28; optimizer 200; evm_version cancun",
            "reproducibility": "Cargo.lock plus rust-toolchain.toml; source-to-constraint and verifier reproduction must be independently attested before admission"
        }
    })
}

pub fn synthetic_production_crypto_reference_vector() -> Result<Value, super::HolderCredentialError>
{
    let poseidon = poseidon_config();
    let issuer_secret = JubjubScalar::from(4_242_424u64);
    let issuer_public_key = EdwardsProjective::generator() * issuer_secret;
    let issuer_public_key_affine = issuer_public_key.into_affine();
    let issuer_key_digest = issuer_key_digest_native(&poseidon, &issuer_public_key);
    let issuer_key_id = hex32(issuer_key_digest);
    let issued_at_epoch = 230u32;
    let input = synthetic_production_holder_input();
    assert_eq!(input.issuer_key_id, issuer_key_id);
    let (_, credential_fields) = holder_credential_field_elements(&input)?;
    let credential_commitment = poseidon_native(&poseidon, CREDENTIAL_DOMAIN, &credential_fields);
    let auxiliary_randomness = [0x42u8; 32];
    let signature_nonce = derive_nonce(issuer_secret, credential_commitment, auxiliary_randomness);
    let signature_commitment = EdwardsProjective::generator() * signature_nonce;
    let signature_commitment_affine = signature_commitment.into_affine();
    let signature_challenge = signature_challenge_native(
        &poseidon,
        &signature_commitment,
        &issuer_public_key,
        credential_commitment,
    );
    let challenge_scalar = jubjub_scalar_from_circuit_field(signature_challenge);
    let signature_response = signature_nonce - challenge_scalar * issuer_secret;
    let verified_r =
        EdwardsProjective::generator() * signature_response + issuer_public_key * challenge_scalar;
    assert_eq!(verified_r, signature_commitment);

    let status_id = CircuitField::from(input.status_id);
    let packed_chunk = packed_status_chunk_with_active_slot(status_id);
    let status_siblings = (0..PACKED_STATUS_DEPTH)
        .map(|index| CircuitField::from((index as u64 + 1) * 7_000_001))
        .collect::<Vec<_>>();
    let status_directions = packed_status_path_directions_native(status_id);
    let status_leaf = packed_status_leaf_native(&poseidon, packed_chunk);
    let status_root =
        merkle_root_native(&poseidon, status_leaf, &status_siblings, &status_directions);
    let status_root_limbs = split_field_to_u128_limbs(status_root);

    let nullifier_preimage = [
        CircuitField::from(NULLIFIER_PREIMAGE_DOMAIN[0]),
        CircuitField::from(NULLIFIER_PREIMAGE_DOMAIN[1]),
        CircuitField::from(1u64),
        credential_fields[7],
        CircuitField::from(DYNAMIC_STATUS_NULLIFIER_SCOPE[0]),
        CircuitField::from(DYNAMIC_STATUS_NULLIFIER_SCOPE[1]),
    ];
    let scoped_nullifier = poseidon_native(&poseidon, NULLIFIER_DOMAIN, &nullifier_preimage);
    let circuit_id_bytes = decode_bytes32(SANCTIONS_CLEAR_CIRCUIT_ID);
    let circuit_id_high = CircuitField::from_be_bytes_mod_order(&circuit_id_bytes[..16]);
    let circuit_id_low = CircuitField::from_be_bytes_mod_order(&circuit_id_bytes[16..]);
    let subject = CircuitField::from_be_bytes_mod_order(&[0x33; 20]);
    let public_signals = [
        CircuitField::from(1u64),
        circuit_id_high,
        circuit_id_low,
        split_field_to_u128_limbs(issuer_key_digest)[0],
        split_field_to_u128_limbs(issuer_key_digest)[1],
        status_root_limbs[0],
        status_root_limbs[1],
        CircuitField::from(DYNAMIC_STATUS_POLICY_HASH[0]),
        CircuitField::from(DYNAMIC_STATUS_POLICY_HASH[1]),
        CircuitField::from(DYNAMIC_STATUS_PRESENTATION_BINDING[0]),
        CircuitField::from(DYNAMIC_STATUS_PRESENTATION_BINDING[1]),
        CircuitField::from(DYNAMIC_STATUS_NULLIFIER_SCOPE[0]),
        CircuitField::from(DYNAMIC_STATUS_NULLIFIER_SCOPE[1]),
        scoped_nullifier,
        subject,
        CircuitField::from(1u64),
        CircuitField::from(issued_at_epoch),
        CircuitField::from(1_788_480_000u32),
    ];

    Ok(json!({
        "schema": PRODUCTION_CRYPTO_REFERENCE_VECTOR_SCHEMA,
        "profileId": PRODUCTION_CRYPTO_PROFILE_ID,
        "warning": "synthetic reserved-country and public test-key vector only; never use its identity, secrets, key, nonce or status path in production",
        "privateSyntheticCredential": {
            "issuerKeyId": issuer_key_id,
            "statusId": input.status_id,
            "holderSecret": input.holder_secret,
            "credentialBlinding": input.credential_blinding,
            "dateOfBirth": input.date_of_birth,
            "nationality": input.nationality,
            "issuingState": input.issuing_state,
            "expiryDate": input.expiry_date,
            "documentClass": input.document_class,
            "assurance": input.assurance,
            "issuedAtEpoch": input.issued_at_epoch
        },
        "credentialFieldElements": credential_fields.iter().copied().map(decimal).collect::<Vec<_>>(),
        "credentialCommitment": decimal(credential_commitment),
        "issuerAuthentication": {
            "issuerSecretScalar": decimal(issuer_secret),
            "issuerPublicKey": { "x": decimal(issuer_public_key_affine.x), "y": decimal(issuer_public_key_affine.y) },
            "issuerKeyId": hex32(issuer_key_digest),
            "auxiliaryRandomness": format!("0x{}", "42".repeat(32)),
            "nonceCounter": 0,
            "nonceScalar": decimal(signature_nonce),
            "R": { "x": decimal(signature_commitment_affine.x), "y": decimal(signature_commitment_affine.y) },
            "challengeField": decimal(signature_challenge),
            "challengeScalar": decimal(challenge_scalar),
            "responseScalar": decimal(signature_response),
            "verified": true
        },
        "packedStatus": {
            "chunkLimbsLittleEndian": packed_chunk.iter().copied().map(decimal).collect::<Vec<_>>(),
            "leaf": decimal(status_leaf),
            "siblingsBottomUp": status_siblings.iter().copied().map(decimal).collect::<Vec<_>>(),
            "directionsBottomUp": status_directions,
            "root": decimal(status_root),
            "rootLimbsHighFirst": status_root_limbs.iter().copied().map(decimal).collect::<Vec<_>>()
        },
        "nullifierPreimage": nullifier_preimage.iter().copied().map(decimal).collect::<Vec<_>>(),
        "publicSignalNames": [
            "layoutVersion", "circuitIdHi", "circuitIdLo", "issuerKeyIdHi", "issuerKeyIdLo",
            "activeRootHi", "activeRootLo", "policyHashHi", "policyHashLo",
            "presentationBindingHashHi", "presentationBindingHashLo", "nullifierScopeHashHi",
            "nullifierScopeHashLo", "scopedNullifier", "subject", "result", "credentialEpoch",
            "statusEpoch"
        ],
        "publicSignals": public_signals.iter().copied().map(decimal).collect::<Vec<_>>()
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Sha256;
    use std::{fs, path::Path};

    fn pretty(value: &Value) -> String {
        format!("{}\n", serde_json::to_string_pretty(value).unwrap())
    }

    #[test]
    fn parameter_manifest_pins_every_poseidon_constant_and_the_frozen_abi() {
        let manifest = production_crypto_parameter_manifest();
        assert_eq!(manifest["poseidon"]["ark"].as_array().unwrap().len(), 65);
        assert_eq!(manifest["poseidon"]["mds"].as_array().unwrap().len(), 3);
        assert_eq!(manifest["proofSystem"]["publicSignalCount"], 18);
        assert_eq!(manifest["circuitSet"].as_array().unwrap().len(), 5);
        assert_eq!(
            pretty(&manifest),
            include_str!("../../../fixtures/v2-production-crypto/parameters-v1.json")
        );
    }

    #[test]
    fn synthetic_vector_is_end_to_end_consistent_and_uses_reserved_countries() {
        let vector = synthetic_production_crypto_reference_vector().unwrap();
        assert_eq!(vector["publicSignals"].as_array().unwrap().len(), 18);
        assert_eq!(vector["privateSyntheticCredential"]["nationality"], "XAA");
        assert_eq!(vector["privateSyntheticCredential"]["issuingState"], "XAB");
        assert_eq!(vector["issuerAuthentication"]["verified"], true);
        assert_eq!(
            pretty(&vector),
            include_str!("../../../fixtures/v2-production-crypto/reference-vector-v1.json")
        );
    }

    #[test]
    fn nonce_is_bound_to_commitment_and_auxiliary_randomness() {
        let secret = JubjubScalar::from(42u64);
        let first = derive_nonce(secret, CircuitField::from(1u64), [1u8; 32]);
        let different_commitment = derive_nonce(secret, CircuitField::from(2u64), [1u8; 32]);
        let different_aux = derive_nonce(secret, CircuitField::from(1u64), [2u8; 32]);
        assert_ne!(first, different_commitment);
        assert_ne!(first, different_aux);
        assert!(!first.is_zero());
    }

    #[test]
    fn component_mutations_fail_closed() {
        let poseidon = poseidon_config();
        let secret = JubjubScalar::from(4_242_424u64);
        let public_key = EdwardsProjective::generator() * secret;
        let commitment = CircuitField::from(123_456u64);
        let nonce = derive_nonce(secret, commitment, [0x42; 32]);
        let r = EdwardsProjective::generator() * nonce;
        let challenge = jubjub_scalar_from_circuit_field(signature_challenge_native(
            &poseidon,
            &r,
            &public_key,
            commitment,
        ));
        let response = nonce - challenge * secret;
        assert_eq!(
            EdwardsProjective::generator() * response + public_key * challenge,
            r
        );
        assert_ne!(
            EdwardsProjective::generator() * (response + JubjubScalar::from(1u64))
                + public_key * challenge,
            r
        );

        let status_id = CircuitField::from(7u64);
        let active = packed_status_chunk_with_active_slot(status_id);
        let mut revoked = active;
        revoked[0] += CircuitField::from(1u64 << 7);
        assert_ne!(
            packed_status_leaf_native(&poseidon, active),
            packed_status_leaf_native(&poseidon, revoked)
        );

        let mut fields = [CircuitField::from(0u64); 16];
        fields[10] = CircuitField::from_be_bytes_mod_order(b"XAA");
        let original = poseidon_native(&poseidon, CREDENTIAL_DOMAIN, &fields);
        fields[10] = CircuitField::from_be_bytes_mod_order(b"XAB");
        assert_ne!(
            original,
            poseidon_native(&poseidon, CREDENTIAL_DOMAIN, &fields)
        );
    }

    #[test]
    fn artifact_index_matches_every_published_byte() {
        let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let index_path = repository.join("fixtures/v2-production-crypto/artifact-index-v1.json");
        let index: Value = serde_json::from_str(&fs::read_to_string(index_path).unwrap()).unwrap();
        for artifact in index["artifacts"].as_array().unwrap() {
            let path = artifact["path"].as_str().unwrap();
            let bytes = fs::read(repository.join(path)).unwrap();
            let actual = format!("{:x}", Sha256::digest(&bytes));
            assert_eq!(actual, artifact["sha256"].as_str().unwrap(), "{path}");
            assert_eq!(
                bytes.len() as u64,
                artifact["bytes"].as_u64().unwrap(),
                "{path}"
            );
        }
    }
}
