//! End-to-end coinjoin on regtest with a local nostr relay, driven entirely
//! through the `interface::` functions the Dart FFI wraps (`list_coins`,
//! `list_pools`, `initiate_coinjoin`, `join_coinjoin`). This is the recipe the
//! on-device test reuses with one joiner moved to Dart.
//!
//! Three participants, all contributing a coin: an initiator that opens the
//! pool and publishes its address (per the NIP the initiator is a full peer,
//! there is no separate coordinator) and two joiners. `peers` is the total
//! participant count, so a `peers = 3` pool is the initiator plus two joiners,
//! three equal-value inputs and outputs.

pub mod utils;

use std::{thread, time::Duration};

use crate::utils::{bootstrap_electrs, generate, send_to_address};
use electrsd::bitcoind::bitcoincore_rpc::RpcApi;
use joinstr::{
    bip39::Mnemonic,
    interface::{self, PeerConfig, PoolConfig},
    miniscript::bitcoin::{address::NetworkUnchecked, Address, Amount, Network},
    signer::{Coin, WpkhHotSigner},
};

use nostrd::NostrD;

const INIT_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const JOIN_MNEMONIC: &str = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";
const JOIN2_MNEMONIC: &str =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";

const DENOMINATION_BTC: f64 = 0.01;
// Input value must land in `denomination + 500 ..= denomination + 5000` sats.
const FUNDING_BTC: f64 = 0.01003;

fn peer_config(mnemonic: &str, url: &str, port: u16, relay: &str, input: Coin) -> PeerConfig {
    let signer = WpkhHotSigner::new_from_mnemonics(Network::Regtest, mnemonic).unwrap();
    let output: Address<NetworkUnchecked> = signer.recv_addr_at(100).to_string().parse().unwrap();
    PeerConfig {
        mnemonics: Mnemonic::parse(mnemonic).unwrap(),
        electrum_address: url.to_string(),
        electrum_port: port,
        input,
        output,
        relay: relay.to_string(),
        network: Network::Regtest,
        proxy: None,
    }
}

fn first_coin(mnemonic: &str, url: &str, port: u16) -> Coin {
    let coins = interface::list_coins(
        mnemonic,
        url.to_string(),
        port,
        (0, 5),
        Network::Regtest,
        None,
    )
    .unwrap();
    coins.into_iter().next().expect("funded coin present")
}

#[test]
fn interface_coinjoin_regtest() {
    let _ = env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(false)
        .try_init();
    let nostrd = NostrD::new().unwrap();
    let relay = nostrd.url();
    let (url, port, _electrsd, bitcoind) = bootstrap_electrs();

    // Fund every participant's first receive address on regtest.
    for m in [INIT_MNEMONIC, JOIN_MNEMONIC, JOIN2_MNEMONIC] {
        let signer = WpkhHotSigner::new_from_mnemonics(Network::Regtest, m).unwrap();
        send_to_address(
            &bitcoind,
            &signer.recv_addr_at(0),
            Amount::from_btc(FUNDING_BTC).unwrap(),
        );
    }
    generate(&bitcoind, 2);

    // Give electrs a moment to index the funding transactions.
    thread::sleep(Duration::from_secs(2));

    let init_peer = peer_config(
        INIT_MNEMONIC,
        &url,
        port,
        &relay,
        first_coin(INIT_MNEMONIC, &url, port),
    );

    let pool_config = PoolConfig {
        denomination: DENOMINATION_BTC,
        fee: 1,
        // `initiate_coinjoin` sets the pool timeout to `now() + max_duration`.
        max_duration: 120,
        // Total participants, initiator included: this initiator plus two
        // joiners, three equal-value outputs.
        peers: 3,
        network: Network::Regtest,
    };

    // The test relay does not replay stored events, so each joiner must be
    // subscribed before the pool is broadcast. Joiners open a 30s listening
    // window immediately; the initiator publishes 3s into it.
    let initiator = thread::spawn(move || {
        thread::sleep(Duration::from_secs(3));
        interface::initiate_coinjoin(pool_config, init_peer)
    });

    let spawn_joiner = |mnemonic: &'static str, relay: String, url: String, port: u16| {
        thread::spawn(move || {
            let coin = first_coin(mnemonic, &url, port);
            let peer = peer_config(mnemonic, &url, port, &relay, coin);
            let pools = interface::list_pools(60, 30_000_000, relay, None).unwrap();
            let mut pool = pools.into_iter().next().expect("pool advertised in window");
            // `Pool::network` is skip_serializing and decodes as mainnet; the
            // peer reapplies the network it is on (as the FFI wrapper does).
            pool.network = Network::Regtest;
            interface::join_coinjoin(pool, peer)
        })
    };

    let joiner1 = spawn_joiner(JOIN_MNEMONIC, relay.clone(), url.clone(), port);
    let joiner2 = spawn_joiner(JOIN2_MNEMONIC, relay.clone(), url.clone(), port);

    let init_txid = initiator.join().unwrap().expect("initiator finalized");
    let join1_txid = joiner1.join().unwrap().expect("joiner 1 finalized");
    let join2_txid = joiner2.join().unwrap().expect("joiner 2 finalized");

    assert_eq!(init_txid.to_string(), join1_txid, "joiner 1 agrees on txid");
    assert_eq!(init_txid.to_string(), join2_txid, "joiner 2 agrees on txid");

    // The coinjoin transaction reached the node mempool.
    let mempool_tx = bitcoind
        .client
        .get_raw_transaction(&init_txid, None)
        .expect("coinjoin tx in mempool");
    assert_eq!(mempool_tx.input.len(), 3, "three inputs");
    assert_eq!(mempool_tx.output.len(), 3, "three equal-value outputs");
    // The coinjoin property: every output carries the same value, so the
    // participants are indistinguishable on-chain.
    let value = mempool_tx.output[0].value;
    assert!(
        mempool_tx.output.iter().all(|o| o.value == value),
        "all outputs carry an equal value"
    );

    // And it mines into the next block (leaving the mempool).
    generate(&bitcoind, 1);
    assert!(
        !bitcoind
            .client
            .get_raw_mempool()
            .unwrap()
            .contains(&init_txid),
        "coinjoin tx confirmed out of the mempool"
    );
    println!(
        "COINJOIN_OK txid={init_txid} inputs={} outputs={}",
        mempool_tx.input.len(),
        mempool_tx.output.len()
    );
}
