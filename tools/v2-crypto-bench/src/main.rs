use std::error::Error;
use ubi2_v2_crypto_bench::{
    generate_dynamic_status_evm_fixture, generate_packed_status_evm_fixture,
    run_registry_depth_suite, run_registry_transport_estimates, run_status_distribution_bakeoff,
    run_suite,
};

fn main() -> Result<(), Box<dyn Error>> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let constraints_only = arguments.iter().any(|arg| arg == "--constraints-only");
    if arguments
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
