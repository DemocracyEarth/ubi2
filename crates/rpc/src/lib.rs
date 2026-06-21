//! ubi2 EVM-compatible JSON-RPC (M0 skeleton).
//!
//! Goal (M1, see `docs/specs/01-evm-rpc-and-wallet.md`): expose enough of the Ethereum JSON-RPC
//! surface that unmodified wallets (MetaMask) can add the devnet and read streaming balances —
//! invariant I3. The `protocol-engineer` builds the transport (e.g. jsonrpsee) and the full method
//! set on top of this skeleton; here we pin the method names and the devnet chain id.

use ubi2_runtime::Account;

/// Default devnet chain id (0x5542). Configurable per deployment.
pub const DEVNET_CHAIN_ID: u64 = 0x5542;

/// The EVM JSON-RPC methods M1 must implement.
pub const M1_METHODS: &[&str] = &[
    "eth_chainId",
    "net_version",
    "eth_blockNumber",
    "eth_getBalance",
    "eth_getTransactionCount",
    "eth_gasPrice",
    "eth_estimateGas",
    "eth_call",
    "eth_sendRawTransaction",
    "eth_getBlockByNumber",
    "eth_getBlockByHash",
    "eth_getTransactionByHash",
    "eth_getTransactionReceipt",
    "eth_subscribe",
    "eth_unsubscribe",
];

/// `eth_getBalance` semantics: the live streaming balance at `now`, hex-encoded like Ethereum.
/// Wired here against the runtime so the contract is exercised even before the transport exists.
pub fn eth_get_balance(account: &Account, now: u64) -> String {
    format!("0x{:x}", account.balance(now))
}

/// `eth_chainId` hex encoding.
pub fn eth_chain_id(chain_id: u64) -> String {
    format!("0x{chain_id:x}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ubi2_runtime::{EMISSION_PERIOD_SECS, UBI};

    #[test]
    fn chain_id_is_hex() {
        assert_eq!(eth_chain_id(DEVNET_CHAIN_ID), "0x5542");
    }

    #[test]
    fn balance_rpc_reflects_stream() {
        let a = Account { verified: true, verified_at: 0, last_settled_at: 0, ..Default::default() };
        assert_eq!(eth_get_balance(&a, EMISSION_PERIOD_SECS), format!("0x{:x}", UBI));
    }
}
