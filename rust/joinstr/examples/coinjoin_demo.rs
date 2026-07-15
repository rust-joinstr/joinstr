//! Full Rust-driven coinjoin against an external regtest chain.
//!
//! An initiator plus two peers complete and broadcast a real coinjoin transaction
//! through the configured electrum server. Uses a local in-process nostr relay so the
//! run is self-contained; the bitcoin side is whatever electrum points at (e.g. your
//! Polar regtest electrs on 127.0.0.1:50001).
//!
//! The wallet must already hold >= 2 confirmed UTXOs in [denom+500, denom+5000] sats
//! (see `wallet_addr` to get funding addresses).
//!
//! Env: ELECTRUM (default 127.0.0.1:50001), NETWORK (default regtest),
//!      MNEMONIC (default BIP39 test vector), DENOM_SATS (default 49000), FEE (default 1).
//! Run: cargo run -p joinstr --example coinjoin_demo

use std::{str::FromStr, thread, thread::sleep, time::Duration};

use bitcoin::Network;
use joinstr::{
    electrum::Client, interface::list_coins, joinstr::Joinstr, nostr::sync::NostrClient,
    signer::WpkhHotSigner, utils::now,
};
use nostrd::NostrD;
use simple_nostr_client::nostr::Keys;

const DEFAULT_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn env_or(k: &str, d: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| d.to_string())
}

fn main() {
    joinstr::log::set_max_level(joinstr::log::LevelFilter::Info);
    env_logger::builder()
        .filter_level(joinstr::log::LevelFilter::Info)
        .try_init()
        .ok();

    let mnemonic = env_or("MNEMONIC", DEFAULT_MNEMONIC);
    let network = Network::from_str(&env_or("NETWORK", "regtest")).expect("invalid NETWORK");
    let electrum = env_or("ELECTRUM", "127.0.0.1:50001");
    let (host, port_s) = electrum
        .rsplit_once(':')
        .expect("ELECTRUM must be host:port");
    let port: u16 = port_s.parse().expect("invalid port");
    let denom_sats: u64 = env_or("DENOM_SATS", "49000")
        .parse()
        .expect("invalid DENOM_SATS");
    let fee: u32 = env_or("FEE", "1").parse().expect("invalid FEE");
    let denom_btc = denom_sats as f64 / 100_000_000.0;

    // self-contained local relay
    let nostrd = NostrD::new().expect("start local relay");
    let relay = nostrd.url();
    println!("relay={relay} electrum={electrum} denom={denom_sats}sat fee={fee}");

    // discover two funded inputs in the protocol's accepted range
    let (min, max) = (denom_sats + 500, denom_sats + 5000);
    let coins = list_coins(&mnemonic, host.to_string(), port, (0, 10), network, None)
        .expect("list_coins failed");
    let mut usable: Vec<_> = coins
        .into_iter()
        .filter(|c| (min..=max).contains(&c.txout.value.to_sat()))
        .collect();
    assert!(
        usable.len() >= 2,
        "need >=2 UTXOs in {min}..={max} sats, found {}",
        usable.len()
    );
    let coin_a = usable.remove(0);
    let coin_b = usable.remove(0);
    println!(
        "inputs: {} ({}sat) / {} ({}sat)",
        coin_a.outpoint,
        coin_a.txout.value.to_sat(),
        coin_b.outpoint,
        coin_b.txout.value.to_sat()
    );

    let mut signer = WpkhHotSigner::new_from_mnemonics(network, &mnemonic).expect("bad mnemonic");
    signer.set_client(Client::new(host, port).expect("electrum"));
    let addr_a = signer.recv_addr_at(200).as_unchecked().clone();
    let addr_b = signer.recv_addr_at(201).as_unchecked().clone();

    // initiator: creates the pool and runs the rounds like any peer, but contributes
    // no input/output of its own here (every participant builds & broadcasts the tx)
    let mut initiator = Joinstr::new_initiator(
        Keys::generate(),
        relay.clone(),
        (host, port),
        network,
        None,
        "initiator",
    )
    .expect("initiator")
    .denomination(denom_btc)
    .expect("denomination")
    .fee(fee)
    .expect("fee")
    .simple_timeout(now() + 60)
    .expect("timeout")
    .min_peers(2)
    .expect("min_peers");

    let init_handle = thread::spawn(move || {
        initiator
            .start_coinjoin_blocking(None, Option::<WpkhHotSigner>::None, || {})
            .expect("initiator coinjoin");
        initiator.final_tx()
    });

    // fetch the pool the initiator just posted
    let mut listener = NostrClient::new("listener")
        .relay(relay.clone())
        .expect("relay")
        .keys(Keys::generate())
        .expect("keys");
    listener.connect_nostr().expect("connect");
    listener.subscribe_pools(3600).expect("subscribe");
    let pool = loop {
        if let Some(p) = listener.receive_pool_notification().expect("pool notif") {
            break p;
        }
        sleep(Duration::from_millis(300));
    };
    println!("pool discovered: {}", pool.id);

    // two peers join, register outputs, sign and submit inputs
    let mut peer_a = Joinstr::new_peer(
        relay.clone(),
        &pool,
        coin_a,
        addr_a,
        network,
        None,
        "peer_a",
    )
    .expect("peer_a");
    let mut peer_b = Joinstr::new_peer(
        relay.clone(),
        &pool,
        coin_b,
        addr_b,
        network,
        None,
        "peer_b",
    )
    .expect("peer_b");
    let s_a = signer.clone();
    let p_a = pool.clone();
    let h_a = thread::spawn(move || {
        let _ = peer_a.start_coinjoin_blocking(Some(p_a), Some(s_a), || {});
    });
    let h_b = thread::spawn(move || {
        let _ = peer_b.start_coinjoin_blocking(Some(pool), Some(signer), || {});
    });

    let final_tx = init_handle
        .join()
        .expect("initiator thread")
        .expect("coinjoin produced a tx");
    let _ = h_a.join();
    let _ = h_b.join();
    println!("COINJOIN TX: {}", final_tx.compute_txid());
}
