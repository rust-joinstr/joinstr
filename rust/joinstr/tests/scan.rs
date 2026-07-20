pub mod utils;

use crate::utils::funded_wallet;
use joinstr::signer::CoinPath;
use miniscript::bitcoin::Amount;

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
