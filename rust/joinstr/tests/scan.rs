pub mod utils;

use crate::utils::{bootstrap_electrs, funded_wallet, generate, send_to_address, tcp_client};
use joinstr::interface::list_coins;
use joinstr::signer::{CoinPath, WpkhHotSigner};
use miniscript::bitcoin::{Amount, Network};

// Fund a few receive addresses, then make sure a single batched scan over a
// wider range finds exactly those coins. This is the path `interface::list_coins`
// uses to populate the coin picker; scanning one address per round trip was too
// slow to be usable over tor.
#[test]
fn batched_scan_finds_funded_coins() {
    let (mut signer, client, _electrsd, _bitcoind) = funded_wallet(&[0.1, 0.2, 0.3]);
    signer.set_client(client);

    let paths: Vec<CoinPath> = (0..10)
        .flat_map(|i| [CoinPath::new(0, i), CoinPath::new(1, i)])
        .collect();

    let found = signer.get_coins_at_batch(&paths).unwrap();
    assert_eq!(found, 3, "batched scan should find all three funded coins");

    let mut values: Vec<Amount> = signer
        .list_coins()
        .into_iter()
        .map(|(_, c)| c.txout.value)
        .collect();
    values.sort();
    assert_eq!(
        values,
        vec![
            Amount::from_btc(0.1).unwrap(),
            Amount::from_btc(0.2).unwrap(),
            Amount::from_btc(0.3).unwrap(),
        ]
    );
}

// A wallet that has spent holds its balance on a change address (depth 1), not
// a receive address. The create-pool coin scan must find those too, so fund a
// change address directly and assert the batched scan picks it up.
#[test]
fn batched_scan_finds_a_change_coin() {
    let (client, _electrsd, bitcoind) = tcp_client();
    let mut signer = WpkhHotSigner::new(Network::Regtest).unwrap();
    let change0 = signer.address_at(&CoinPath::new(1, 0)).unwrap();
    send_to_address(&bitcoind, &change0, Amount::from_btc(0.05).unwrap());
    generate(&bitcoind, 2);
    signer.set_client(client);

    let paths: Vec<CoinPath> = (0..10)
        .flat_map(|i| [CoinPath::new(0, i), CoinPath::new(1, i)])
        .collect();

    assert_eq!(
        signer.get_coins_at_batch(&paths).unwrap(),
        1,
        "batched scan should find the coin on change address 1/0"
    );
    let coins = signer.list_coins();
    assert_eq!(coins.len(), 1);
    assert_eq!(coins[0].0, CoinPath::new(1, 0));
    assert_eq!(coins[0].1.txout.value, Amount::from_btc(0.05).unwrap());
}

// The scan is chunked into batches, so a coin past the first batch boundary
// must still be found. Fund a receive address well beyond one batch and assert
// the scan crosses batch boundaries to reach it.
#[test]
fn batched_scan_finds_a_coin_past_the_first_batch() {
    let (client, _electrsd, bitcoind) = tcp_client();
    let mut signer = WpkhHotSigner::new(Network::Regtest).unwrap();
    let far = signer.address_at(&CoinPath::new(0, 15)).unwrap();
    send_to_address(&bitcoind, &far, Amount::from_btc(0.02).unwrap());
    generate(&bitcoind, 2);
    signer.set_client(client);

    let paths: Vec<CoinPath> = (0..25)
        .flat_map(|i| [CoinPath::new(0, i), CoinPath::new(1, i)])
        .collect();

    assert_eq!(signer.get_coins_at_batch(&paths).unwrap(), 1);
    assert_eq!(signer.list_coins()[0].0, CoinPath::new(0, 15));
}

// list_coins stops after a gap of empty indexes, so a coin sitting past the gap
// (here index 40, with index 0 funded and nothing between) is intentionally not
// returned, the same tradeoff as a wallet stop gap. Drives the public entry
// point end to end against regtest electrs.
#[test]
fn list_coins_stops_at_the_gap_limit() {
    let (url, port, _electrsd, bitcoind) = bootstrap_electrs();
    let m = "abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon about";
    let signer = WpkhHotSigner::new_from_mnemonics(Network::Regtest, m).unwrap();
    send_to_address(
        &bitcoind,
        &signer.address_at(&CoinPath::new(0, 0)).unwrap(),
        Amount::from_btc(0.01).unwrap(),
    );
    send_to_address(
        &bitcoind,
        &signer.address_at(&CoinPath::new(0, 40)).unwrap(),
        Amount::from_btc(0.02).unwrap(),
    );
    generate(&bitcoind, 2);

    let coins = list_coins(m, url, port, (0, 100), Network::Regtest, None).unwrap();
    assert_eq!(
        coins.len(),
        1,
        "index 40 is past the gap and must be skipped"
    );
    assert_eq!(coins[0].txout.value, Amount::from_btc(0.01).unwrap());
}

// A coinjoin waits minutes over tor, so the electrum connection can go stale
// mid-round; the client must recover by reconnecting. Reconnect explicitly and
// confirm a request still succeeds on the rebuilt connection.
#[test]
fn client_recovers_after_reconnect() {
    let (mut signer, mut client, _electrsd, _bitcoind) = funded_wallet(&[0.04]);
    let paths: Vec<CoinPath> = (0..5)
        .flat_map(|i| [CoinPath::new(0, i), CoinPath::new(1, i)])
        .collect();

    client.reconnect().unwrap();
    signer.set_client(client);
    assert_eq!(
        signer.get_coins_at_batch(&paths).unwrap(),
        1,
        "a request after reconnect must succeed on the rebuilt connection"
    );
}

#[test]
fn batched_scan_of_empty_wallet_finds_nothing() {
    let (mut signer, client, _electrsd, _bitcoind) = funded_wallet(&[]);
    signer.set_client(client);

    let paths: Vec<CoinPath> = (0..10)
        .flat_map(|i| [CoinPath::new(0, i), CoinPath::new(1, i)])
        .collect();

    assert_eq!(signer.get_coins_at_batch(&paths).unwrap(), 0);
    assert!(signer.list_coins().is_empty());
}
