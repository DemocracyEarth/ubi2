use std::{error::Error, io::Read};
use ubi2_v2_crypto_bench::{
    advance_packed_status_snapshot_from_json, build_packed_status_snapshot_from_json,
    generate_dynamic_status_evm_fixture, generate_packed_status_evm_fixture,
    holder_credential_commitment_from_json, production_crypto_parameter_manifest,
    production_sanctions_canonical_constraints, production_sanctions_constraint_manifest,
    production_sanctions_source_freeze_manifest, run_registry_depth_suite,
    run_registry_transport_estimates, run_status_distribution_bakeoff, run_suite,
    synthetic_holder_credential_reference_vector, synthetic_production_crypto_reference_vector,
};

fn main() -> Result<(), Box<dyn Error>> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let constraints_only = arguments.iter().any(|arg| arg == "--constraints-only");
    if arguments
        .iter()
        .any(|arg| arg == "--production-crypto-parameters")
    {
        println!(
            "{}",
            serde_json::to_string_pretty(&production_crypto_parameter_manifest())?
        );
    } else if let Some(index) = arguments
        .iter()
        .position(|arg| arg == "--write-production-sanctions-constraints")
    {
        let output = arguments
            .get(index + 1)
            .ok_or("--write-production-sanctions-constraints requires an output path")?;
        std::fs::write(output, production_sanctions_canonical_constraints()?)?;
        println!(
            "{}",
            serde_json::to_string_pretty(&production_sanctions_constraint_manifest()?)?
        );
    } else if arguments
        .iter()
        .any(|arg| arg == "--production-sanctions-constraint-manifest")
    {
        println!(
            "{}",
            serde_json::to_string_pretty(&production_sanctions_constraint_manifest()?)?
        );
    } else if arguments
        .iter()
        .any(|arg| arg == "--production-sanctions-source-freeze")
    {
        println!(
            "{}",
            serde_json::to_string_pretty(&production_sanctions_source_freeze_manifest())?
        );
    } else if arguments
        .iter()
        .any(|arg| arg == "--production-crypto-reference-vector")
    {
        println!(
            "{}",
            serde_json::to_string_pretty(&synthetic_production_crypto_reference_vector()?)?
        );
    } else if arguments
        .iter()
        .any(|arg| arg == "--holder-credential-reference-vector")
    {
        println!(
            "{}",
            serde_json::to_string_pretty(&synthetic_holder_credential_reference_vector()?)?
        );
    } else if arguments
        .iter()
        .any(|arg| arg == "--holder-credential-commitment")
    {
        let mut source = String::new();
        std::io::stdin().read_to_string(&mut source)?;
        println!("{}", holder_credential_commitment_from_json(&source)?);
    } else if let Some(index) = arguments
        .iter()
        .position(|arg| arg == "--advance-status-snapshot")
    {
        let checkpoint_path = arguments
            .get(index + 1)
            .ok_or("--advance-status-snapshot requires CHECKPOINT and SOURCE JSON paths")?;
        let source_path = arguments
            .get(index + 2)
            .ok_or("--advance-status-snapshot requires CHECKPOINT and SOURCE JSON paths")?;
        let checkpoint = std::fs::read_to_string(checkpoint_path)?;
        let source = std::fs::read_to_string(source_path)?;
        println!(
            "{}",
            advance_packed_status_snapshot_from_json(&checkpoint, &source)?
        );
    } else if let Some(index) = arguments
        .iter()
        .position(|arg| arg == "--build-status-snapshot")
    {
        let input = arguments
            .get(index + 1)
            .ok_or("--build-status-snapshot requires a JSON path or - for stdin")?;
        let mut source = String::new();
        if input == "-" {
            std::io::stdin().read_to_string(&mut source)?;
        } else {
            source = std::fs::read_to_string(input)?;
        }
        println!("{}", build_packed_status_snapshot_from_json(&source)?);
    } else if arguments
        .iter()
        .any(|arg| arg == "--dynamic-status-evm-fixture")
    {
        println!(
            "{}",
            serde_json::to_string_pretty(&generate_dynamic_status_evm_fixture()?)?
        );
    } else if arguments.iter().any(|arg| arg == "--packed-evm-fixture") {
        println!(
            "{}",
            serde_json::to_string_pretty(&generate_packed_status_evm_fixture()?)?
        );
    } else if arguments.iter().any(|arg| arg == "--status-distribution") {
        println!(
            "{}",
            serde_json::to_string_pretty(&run_status_distribution_bakeoff())?
        );
    } else if arguments.iter().any(|arg| arg == "--transport-estimates") {
        println!(
            "{}",
            serde_json::to_string_pretty(&run_registry_transport_estimates())?
        );
    } else if arguments.iter().any(|arg| arg == "--registry-depths") {
        let report = run_registry_depth_suite(!constraints_only)?;
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        let report = run_suite(!constraints_only)?;
        println!("{}", serde_json::to_string_pretty(&report)?);
    }
    Ok(())
}
