//! Print receive addresses for a BIP39 seed on a given network.
//!
//! MNEMONIC (default: "Default 2"), NETWORK (default: regtest), COUNT (default: 3).
//! Run: cargo run -p joinstr --example wallet_addr

use std::str::FromStr;

use bitcoin::Network;
use joinstr::{interface::list_coins, signer::WpkhHotSigner};

// Canonical BIP39 test vector. The Rust signer is BIP39-only; Electrum wallets use a
// different (Electrum) seed scheme, so the Rust peer uses its own independent wallet.
const DEFAULT_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn main() {
    let mnemonic = std::env::var("MNEMONIC").unwrap_or_else(|_| DEFAULT_MNEMONIC.to_string());
    let network = Network::from_str(&std::env::var("NETWORK").unwrap_or_else(|_| "regtest".into()))
        .expect("invalid NETWORK");
    let count: u32 = std::env::var("COUNT")
        .unwrap_or_else(|_| "3".into())
        .parse()
        .expect("invalid COUNT");

    let signer = WpkhHotSigner::new_from_mnemonics(network, &mnemonic).expect("bad mnemonic");
    for i in 0..count {
        println!("recv/{i}\t{}", signer.recv_addr_at(i));
    }

    // If ELECTRUM (host:port) is set, scan for spendable coins via electrs.
    if let Ok(electrum) = std::env::var("ELECTRUM") {
        let (host, port) = electrum
            .rsplit_once(':')
            .expect("ELECTRUM must be host:port");
        let coins = list_coins(
            &mnemonic,
            host.to_string(),
            port.parse().expect("bad port"),
            (0, count),
            network,
            None,
        )
        .expect("list_coins failed");
        println!("--- coins seen via {electrum} ---");
        for c in &coins {
            println!("{}\t{} sat", c.outpoint, c.txout.value.to_sat());
        }
        println!("total: {} coin(s)", coins.len());
    }
}
