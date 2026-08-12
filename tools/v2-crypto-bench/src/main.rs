use std::error::Error;
use ubi2_v2_crypto_bench::run_suite;

fn main() -> Result<(), Box<dyn Error>> {
    let constraints_only = std::env::args()
        .skip(1)
        .any(|arg| arg == "--constraints-only");
    let report = run_suite(!constraints_only)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
