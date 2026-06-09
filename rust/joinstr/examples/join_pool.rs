//! Join an existing joinstr pool as a peer.
//!
//! Drives the Rust implementation against a live nostr relay + electrum server so
//! it can complete a coinjoin alongside the Python Electrum joinstr plugin.
//!
//! Configurable via env vars (all optional, defaults target the local Polar regtest):
//!   MNEMONIC   - BIP39 seed of the wallet providing the input (default: canonical test vector)
//!   RELAY      - nostr relay url            (default: wss://nos.lol)
//!   ELECTRUM   - electrum server host:port  (default: 127.0.0.1:50001)
//!   NETWORK    - bitcoin/testnet/signet/regtest (default: regtest)
//!   DENOM_SATS - pool denomination in sats  (default: 49000 == 0.00049 BTC)
//!   RECV_INDEX - receive-address index for the coinjoin output (default: 100)
//!
//! Run: cargo run -p joinstr --example join_pool

use std::str::FromStr;

use bitcoin::{Address, Network};
use joinstr::{
    bip39::Mnemonic,
    interface::{join_coinjoin, list_coins, list_pools, PeerConfig},
    signer::WpkhHotSigner,
};

// Canonical BIP39 test vector. The Rust signer is BIP39-only and Electrum wallets use a
// different seed scheme, so the Rust peer runs its own independent (funded) wallet.
const DEFAULT_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn main() {
    env_logger::try_init().ok();

    let mnemonic = env_or("MNEMONIC", DEFAULT_MNEMONIC);
    let relay = env_or("RELAY", "wss://nos.lol");
    let electrum = env_or("ELECTRUM", "127.0.0.1:50001");
    let network = Network::from_str(&env_or("NETWORK", "regtest")).expect("invalid NETWORK");
    let denom_sats: u64 = env_or("DENOM_SATS", "49000")
        .parse()
        .expect("invalid DENOM_SATS");
    let recv_index: u32 = env_or("RECV_INDEX", "100")
        .parse()
        .expect("invalid RECV_INDEX");

    let (electrum_host, electrum_port) = {
        let (h, p) = electrum
            .rsplit_once(':')
            .expect("ELECTRUM must be host:port");
        (
            h.to_string(),
            p.parse::<u16>().expect("invalid electrum port"),
        )
    };

    // Per-input acceptable range required by the protocol: denom+500 ..= denom+5000.
    let min_input = denom_sats + 500;
    let max_input = denom_sats + 5000;

    println!("network={network} relay={relay} electrum={electrum_host}:{electrum_port} denom={denom_sats}sat");

    // 1. Discover the pool announced by the Python coordinator (kind 2022).
    println!("listing pools (looking back 1h)...");
    let pools = list_pools(3600, 10_000_000, relay.clone()).expect("list_pools failed");
    println!("found {} pool(s)", pools.len());
    let pool = pools
        .into_iter()
        .find(|p| {
            p.payload
                .as_ref()
                .map(|pl| pl.denomination.to_sat() == denom_sats)
                .unwrap_or(false)
        })
        .unwrap_or_else(|| panic!("no pool with denomination {denom_sats} sats found on {relay}"));
    println!("joining pool id={}", pool.id);

    // 2. Select a confirmed UTXO from our wallet within the accepted input range.
    let coins = list_coins(
        mnemonic.clone(),
        electrum_host.clone(),
        electrum_port,
        (0, 50),
        network,
    )
    .expect("list_coins failed");
    let input = coins
        .into_iter()
        .find(|c| {
            let v = c.txout.value.to_sat();
            (min_input..=max_input).contains(&v)
        })
        .unwrap_or_else(|| {
            panic!("no UTXO in range {min_input}..={max_input} sats; fund the wallet first")
        });
    println!(
        "using input {} ({} sats)",
        input.outpoint,
        input.txout.value.to_sat()
    );

    // 3. Derive a fresh receive address for the coinjoin output (same wallet).
    let signer = WpkhHotSigner::new_from_mnemonics(network, &mnemonic).expect("bad mnemonic");
    let output: Address = signer.recv_addr_at(recv_index);
    println!("output address {output} (m/.../0/{recv_index})");

    let peer = PeerConfig {
        mnemonics: Mnemonic::from_str(&mnemonic).expect("bad mnemonic"),
        electrum_address: electrum_host,
        electrum_port,
        input,
        output: output.as_unchecked().clone(),
        relay,
        network,
    };

    // 4. Run the coinjoin to completion. The Python coordinator aggregates & broadcasts.
    println!("starting coinjoin...");
    match join_coinjoin(pool, peer) {
        Ok(txid) => println!("coinjoin complete, txid={txid}"),
        Err(e) => {
            eprintln!("coinjoin failed: {e}");
            std::process::exit(1);
        }
    }
}
