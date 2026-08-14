use std::error::Error;
use ubi2_v2_crypto_bench::{run_registry_depth_suite, run_suite};

fn main() -> Result<(), Box<dyn Error>> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let constraints_only = arguments.iter().any(|arg| arg == "--constraints-only");
    if arguments.iter().any(|arg| arg == "--registry-depths") {
        let report = run_registry_depth_suite(!constraints_only)?;
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        let report = run_suite(!constraints_only)?;
        println!("{}", serde_json::to_string_pretty(&report)?);
    }
    Ok(())
}
