use ark_ff::{BigInteger, PrimeField, Zero};
use serde::{Deserialize, Serialize};
use std::{error::Error, fmt, str::FromStr};

use super::{poseidon_config, poseidon_native, CircuitField, CREDENTIAL_DOMAIN};

pub const HOLDER_CREDENTIAL_INPUT_SCHEMA: &str = "org.proofofhumanity.zk-holder-credential-input/1";
pub const HOLDER_CREDENTIAL_COMMITMENT_SCHEMA: &str =
    "org.proofofhumanity.zk-holder-credential-commitment/1";
pub const HOLDER_CREDENTIAL_PRIVATE_SCHEMA: &str = "org.proofofhumanity.zk-private-credential/1";
pub const HOLDER_CREDENTIAL_COMMITMENT_SCHEME: &str = "poseidon-bn254-arkworks-0.5-x5-rate2/1";
pub const HOLDER_CREDENTIAL_VERSION: u16 = 1;

const MAX_PRIVATE_INPUT_JSON_BYTES: usize = 8 * 1024;
const CREDENTIAL_ELEMENT_COUNT: usize = 16;

// keccak256("org.proofofhumanity.zk-private-credential"), split high first.
const PRIVATE_CREDENTIAL_DOMAIN_LIMBS: [u128; 2] = [
    228_312_244_747_383_326_810_442_479_638_509_350_429,
    108_915_475_269_134_690_892_806_380_524_430_507_010,
];

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct HolderCredentialCommitmentInput {
    pub schema: String,
    pub issuer_key_id: String,
    pub status_id: u32,
    pub holder_secret: String,
    pub credential_blinding: String,
    pub date_of_birth: String,
    pub nationality: String,
    pub issuing_state: String,
    pub expiry_date: String,
    pub document_class: String,
    pub assurance: String,
    pub issued_at_epoch: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HolderCredentialCommitment {
    pub schema: &'static str,
    pub credential_schema: &'static str,
    pub commitment_scheme: &'static str,
    pub issuer_key_id: String,
    pub status_id: u32,
    pub issued_at_epoch: u32,
    pub commitment: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HolderCredentialReferenceVector {
    pub schema: &'static str,
    pub warning: &'static str,
    pub input_schema: &'static str,
    pub commitment: HolderCredentialCommitment,
    pub field_elements: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HolderCredentialError {
    InputTooLarge,
    InvalidJson,
    UnsupportedSchema,
    InvalidIssuerKeyId,
    InvalidStatusId,
    InvalidFieldElement(&'static str),
    InvalidDate(&'static str),
    InvalidDateOrder,
    InvalidCountryCode(&'static str),
    UnsupportedDocumentClass,
    UnsupportedAssurance,
    ZeroCommitment,
}

impl fmt::Display for HolderCredentialError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLarge => formatter.write_str("holder credential input exceeds 8 KiB"),
            Self::InvalidJson => formatter.write_str("holder credential input is not strict JSON"),
            Self::UnsupportedSchema => {
                formatter.write_str("unsupported holder credential input schema")
            }
            Self::InvalidIssuerKeyId => {
                formatter.write_str("issuer key id must be nonzero bytes32")
            }
            Self::InvalidStatusId => formatter.write_str("status id must be a nonzero uint32"),
            Self::InvalidFieldElement(label) => {
                write!(
                    formatter,
                    "{label} must be a nonzero canonical BN254 field element"
                )
            }
            Self::InvalidDate(label) => {
                write!(formatter, "{label} must be a valid YYYY-MM-DD date")
            }
            Self::InvalidDateOrder => {
                formatter.write_str("expiry date must be after date of birth")
            }
            Self::InvalidCountryCode(label) => {
                write!(
                    formatter,
                    "{label} must be a three-letter ASCII country code"
                )
            }
            Self::UnsupportedDocumentClass => formatter.write_str("unsupported document class"),
            Self::UnsupportedAssurance => formatter.write_str("unsupported assurance class"),
            Self::ZeroCommitment => formatter.write_str("credential commitment must not be zero"),
        }
    }
}

impl Error for HolderCredentialError {}

pub fn holder_credential_commitment_from_json(
    source: &str,
) -> Result<String, HolderCredentialError> {
    if source.len() > MAX_PRIVATE_INPUT_JSON_BYTES {
        return Err(HolderCredentialError::InputTooLarge);
    }
    let input: HolderCredentialCommitmentInput =
        serde_json::from_str(source).map_err(|_| HolderCredentialError::InvalidJson)?;
    let commitment = build_holder_credential_commitment(&input)?;
    serde_json::to_string(&commitment).map_err(|_| HolderCredentialError::InvalidJson)
}

pub fn build_holder_credential_commitment(
    input: &HolderCredentialCommitmentInput,
) -> Result<HolderCredentialCommitment, HolderCredentialError> {
    let (issuer_key_id, fields) = holder_credential_field_elements(input)?;
    let commitment = poseidon_native(&poseidon_config(), CREDENTIAL_DOMAIN, &fields);
    if commitment.is_zero() {
        return Err(HolderCredentialError::ZeroCommitment);
    }

    Ok(HolderCredentialCommitment {
        schema: HOLDER_CREDENTIAL_COMMITMENT_SCHEMA,
        credential_schema: HOLDER_CREDENTIAL_PRIVATE_SCHEMA,
        commitment_scheme: HOLDER_CREDENTIAL_COMMITMENT_SCHEME,
        issuer_key_id,
        status_id: input.status_id,
        issued_at_epoch: input.issued_at_epoch,
        commitment: field_hex(commitment),
    })
}

pub fn holder_credential_field_elements(
    input: &HolderCredentialCommitmentInput,
) -> Result<(String, [CircuitField; CREDENTIAL_ELEMENT_COUNT]), HolderCredentialError> {
    if input.schema != HOLDER_CREDENTIAL_INPUT_SCHEMA {
        return Err(HolderCredentialError::UnsupportedSchema);
    }
    let issuer_key_bytes = parse_nonzero_bytes32(&input.issuer_key_id)?;
    if input.status_id == 0 {
        return Err(HolderCredentialError::InvalidStatusId);
    }
    let holder_secret = parse_private_field(&input.holder_secret, "holder secret")?;
    let credential_blinding =
        parse_private_field(&input.credential_blinding, "credential blinding")?;
    let date_of_birth = packed_date(&input.date_of_birth, "date of birth")?;
    let expiry_date = packed_date(&input.expiry_date, "expiry date")?;
    if expiry_date <= date_of_birth {
        return Err(HolderCredentialError::InvalidDateOrder);
    }
    let nationality = country_code(&input.nationality, "nationality")?;
    let issuing_state = country_code(&input.issuing_state, "issuing state")?;
    if input.document_class != "epassport" {
        return Err(HolderCredentialError::UnsupportedDocumentClass);
    }
    let assurance = match input.assurance.as_str() {
        "passive-auth" => 1u64,
        "chip-auth" => 2u64,
        _ => return Err(HolderCredentialError::UnsupportedAssurance),
    };

    let issuer_key_id = format!("0x{}", encode_hex(&issuer_key_bytes));
    Ok((
        issuer_key_id,
        [
            CircuitField::from(PRIVATE_CREDENTIAL_DOMAIN_LIMBS[0]),
            CircuitField::from(PRIVATE_CREDENTIAL_DOMAIN_LIMBS[1]),
            CircuitField::from(HOLDER_CREDENTIAL_VERSION),
            CircuitField::from_be_bytes_mod_order(&issuer_key_bytes[..16]),
            CircuitField::from_be_bytes_mod_order(&issuer_key_bytes[16..]),
            CircuitField::from(0u64),
            CircuitField::from(input.status_id),
            holder_secret,
            credential_blinding,
            CircuitField::from(date_of_birth),
            CircuitField::from(nationality),
            CircuitField::from(issuing_state),
            CircuitField::from(expiry_date),
            CircuitField::from(1u64),
            CircuitField::from(assurance),
            CircuitField::from(input.issued_at_epoch),
        ],
    ))
}

pub fn synthetic_holder_credential_reference_vector(
) -> Result<HolderCredentialReferenceVector, HolderCredentialError> {
    let input = synthetic_input();
    let commitment = build_holder_credential_commitment(&input)?;
    let (_, fields) = holder_credential_field_elements(&input)?;
    Ok(HolderCredentialReferenceVector {
        schema: "org.proofofhumanity.zk-holder-credential-reference-vector/1",
        warning: "synthetic reserved-country fixture; contains no real passport or person data",
        input_schema: HOLDER_CREDENTIAL_INPUT_SCHEMA,
        commitment,
        field_elements: fields.iter().map(ToString::to_string).collect(),
    })
}

fn synthetic_input() -> HolderCredentialCommitmentInput {
    HolderCredentialCommitmentInput {
        schema: HOLDER_CREDENTIAL_INPUT_SCHEMA.to_owned(),
        issuer_key_id: "0x02bc3d3958ba083a8c814e7961433903dd91b59f2af591138467a1202da88d21"
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

fn parse_nonzero_bytes32(value: &str) -> Result<[u8; 32], HolderCredentialError> {
    if value.len() != 66 || !value.starts_with("0x") {
        return Err(HolderCredentialError::InvalidIssuerKeyId);
    }
    let mut output = [0u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        let start = 2 + index * 2;
        *byte = u8::from_str_radix(&value[start..start + 2], 16)
            .map_err(|_| HolderCredentialError::InvalidIssuerKeyId)?;
    }
    if output.iter().all(|byte| *byte == 0) {
        return Err(HolderCredentialError::InvalidIssuerKeyId);
    }
    Ok(output)
}

fn parse_private_field(
    value: &str,
    label: &'static str,
) -> Result<CircuitField, HolderCredentialError> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(HolderCredentialError::InvalidFieldElement(label));
    }
    let field = CircuitField::from_str(value)
        .map_err(|_| HolderCredentialError::InvalidFieldElement(label))?;
    if field.is_zero() || field.to_string() != value {
        return Err(HolderCredentialError::InvalidFieldElement(label));
    }
    Ok(field)
}

fn packed_date(value: &str, label: &'static str) -> Result<u32, HolderCredentialError> {
    let bytes = value.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || !bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| index == 4 || index == 7 || byte.is_ascii_digit())
    {
        return Err(HolderCredentialError::InvalidDate(label));
    }
    let year = value[0..4]
        .parse::<u32>()
        .map_err(|_| HolderCredentialError::InvalidDate(label))?;
    let month = value[5..7]
        .parse::<u32>()
        .map_err(|_| HolderCredentialError::InvalidDate(label))?;
    let day = value[8..10]
        .parse::<u32>()
        .map_err(|_| HolderCredentialError::InvalidDate(label))?;
    if !(1900..=2500).contains(&year) || !(1..=12).contains(&month) {
        return Err(HolderCredentialError::InvalidDate(label));
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if day == 0 || day > days {
        return Err(HolderCredentialError::InvalidDate(label));
    }
    Ok(year * 10_000 + month * 100 + day)
}

fn country_code(value: &str, label: &'static str) -> Result<u32, HolderCredentialError> {
    let normalized = value.trim().to_ascii_uppercase();
    let bytes = normalized.as_bytes();
    if bytes.len() != 3 || !bytes.iter().all(|byte| byte.is_ascii_uppercase()) {
        return Err(HolderCredentialError::InvalidCountryCode(label));
    }
    Ok(u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]))
}

fn field_hex(value: CircuitField) -> String {
    let bytes = value.into_bigint().to_bytes_be();
    format!("0x{:0>64}", encode_hex(&bytes))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn synthetic_vector_is_circuit_native_and_deterministic() {
        let input = synthetic_input();
        let descriptor = build_holder_credential_commitment(&input).unwrap();
        let (_, elements) = holder_credential_field_elements(&input).unwrap();
        let native = poseidon_native(&poseidon_config(), CREDENTIAL_DOMAIN, &elements);
        assert_eq!(descriptor.commitment, field_hex(native));

        let cs = ConstraintSystem::<CircuitField>::new_ref();
        let variables = elements
            .iter()
            .map(|value| FpVar::new_witness(cs.clone(), || Ok(*value)).unwrap())
            .collect::<Vec<_>>();
        let gadget = super::super::poseidon_gadget(
            cs.clone(),
            &poseidon_config(),
            CREDENTIAL_DOMAIN,
            &variables,
        )
        .unwrap();
        let expected = FpVar::new_input(cs.clone(), || Ok(native)).unwrap();
        gadget.enforce_equal(&expected).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn normalization_and_all_private_fields_are_bound() {
        let baseline = synthetic_input();
        let expected = build_holder_credential_commitment(&baseline).unwrap();

        let mut normalized = baseline.clone();
        normalized.nationality = "  xaa ".to_owned();
        normalized.issuing_state = "xab".to_owned();
        assert_eq!(
            build_holder_credential_commitment(&normalized)
                .unwrap()
                .commitment,
            expected.commitment
        );

        type CredentialMutation = Box<dyn Fn(&mut HolderCredentialCommitmentInput)>;
        let mutations: Vec<CredentialMutation> = vec![
            Box::new(|input| input.issuer_key_id.replace_range(2..4, "03")),
            Box::new(|input| input.status_id += 1),
            Box::new(|input| input.holder_secret = "123456788".to_owned()),
            Box::new(|input| input.credential_blinding = "987654320".to_owned()),
            Box::new(|input| input.date_of_birth = "2000-01-02".to_owned()),
            Box::new(|input| input.nationality = "XAC".to_owned()),
            Box::new(|input| input.issuing_state = "XAC".to_owned()),
            Box::new(|input| input.expiry_date = "2030-01-02".to_owned()),
            Box::new(|input| input.assurance = "passive-auth".to_owned()),
            Box::new(|input| input.issued_at_epoch += 1),
        ];
        for mutate in mutations {
            let mut changed = baseline.clone();
            mutate(&mut changed);
            assert_ne!(
                build_holder_credential_commitment(&changed)
                    .unwrap()
                    .commitment,
                expected.commitment
            );
        }
    }

    #[test]
    fn rejects_malformed_or_noncanonical_private_inputs_without_echoing_them() {
        let mut invalid = synthetic_input();
        invalid.status_id = 0;
        assert_eq!(
            build_holder_credential_commitment(&invalid).unwrap_err(),
            HolderCredentialError::InvalidStatusId
        );

        invalid = synthetic_input();
        invalid.holder_secret = CircuitField::MODULUS.to_string();
        let error = build_holder_credential_commitment(&invalid).unwrap_err();
        assert_eq!(
            error,
            HolderCredentialError::InvalidFieldElement("holder secret")
        );
        assert!(!error.to_string().contains(&invalid.holder_secret));

        invalid = synthetic_input();
        invalid.date_of_birth = "2001-02-29".to_owned();
        assert_eq!(
            build_holder_credential_commitment(&invalid).unwrap_err(),
            HolderCredentialError::InvalidDate("date of birth")
        );
    }

    #[test]
    fn strict_json_api_never_returns_private_input() {
        let source = r#"{
            "schema":"org.proofofhumanity.zk-holder-credential-input/1",
            "issuerKeyId":"0x02bc3d3958ba083a8c814e7961433903dd91b59f2af591138467a1202da88d21",
            "statusId":7,
            "holderSecret":"123456789",
            "credentialBlinding":"987654321",
            "dateOfBirth":"2000-01-01",
            "nationality":"XAA",
            "issuingState":"XAB",
            "expiryDate":"2030-01-01",
            "documentClass":"epassport",
            "assurance":"chip-auth",
            "issuedAtEpoch":230
        }"#;
        let output = holder_credential_commitment_from_json(source).unwrap();
        assert!(!output.contains("dateOfBirth"));
        assert!(!output.contains("holderSecret"));
        assert!(!output.contains("nationality"));

        let with_unknown = source.replacen(
            "\"issuedAtEpoch\":230",
            "\"issuedAtEpoch\":230,\"passportNumber\":\"synthetic\"",
            1,
        );
        assert_eq!(
            holder_credential_commitment_from_json(&with_unknown).unwrap_err(),
            HolderCredentialError::InvalidJson
        );
    }
}
