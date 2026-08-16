use std::{error::Error, io::Read};
use ubi2_v2_crypto_bench::{
    advance_packed_status_snapshot_from_json, build_packed_status_snapshot_from_json,
    generate_dynamic_status_evm_fixture, generate_packed_status_evm_fixture,
    run_registry_depth_suite, run_registry_transport_estimates, run_status_distribution_bakeoff,
    run_suite,
};

fn main() -> Result<(), Box<dyn Error>> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let constraints_only = arguments.iter().any(|arg| arg == "--constraints-only");
    if let Some(index) = arguments
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
